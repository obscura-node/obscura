package swapsession

import (
	"encoding/binary"
	"errors"
	"math/big"

	"filippo.io/edwards25519"

	"obscura/pkg/swap"
	"obscura/pkg/swapd"
)

// The handshake messages exchanged between MAKER and TAKER. Each is a flat,
// length-prefixed binary struct with Serialize/Parse + a self-contained Validate
// that re-derives and checks the cross-party crypto bindings (proofs-of-
// possession, joint-key derivation, adaptor point) BEFORE the receiver acts on
// it. They are passed by in-process Go calls today; a future P2P/RPC transport
// only has to move these []byte blobs — no protocol logic lives in the wire.
//
// Message order (see session.go for the full flow):
//
//	TAKER --Init----------> MAKER   (taker's public shares A, Sa, PoP_A, Ra, T=Sa·G)
//	MAKER --MakerCommit---> TAKER   (maker's public shares B, Sb, PoP_B, Rb; joint keys agreed)
//	MAKER --Funded--------> TAKER   (the OBX SwapOut is on-chain — taker verifies, then locks XNO)
//	TAKER --XNOLocked-----> MAKER   (the XNO lock id; maker confirms it before co-signing)
//	TAKER --ClaimRequest--> MAKER   (claim tx core hash + taker's half ŝ_a = r_a + e·a)
//	MAKER --ClaimPreSig---> TAKER   (maker's pre-signature half s_b = r_b + e·b)
//
// The TAKER (claimer) then combines the two halves, ADAPTS with its own sA, and
// mines the claim — publishing sA on-chain. The MAKER observes the mined claim and
// EXTRACTS sA INDEPENDENTLY (sA = S_full − ŝ_a − ŝ_b, using the ŝ_a it verified and
// stored from ClaimRequest plus its own recomputed ŝ_b), derives the joint key sA+sB,
// and sweeps the XNO — with NO further taker cooperation. Carrying ŝ_a in ClaimRequest
// is the griefing fix: a taker that claims the OBX can no longer freeze the maker's XNO
// by withholding/corrupting any post-claim relay. The claim and the sweep are on-chain
// / on-ledger actions, not handshake messages.

// roleByte tags which role authored a message, so a transport can't trivially
// confuse the two halves of the handshake.
const (
	roleMaker byte = 1
	roleTaker byte = 2
)

var errMsg = errors.New("swapsession: malformed or invalid message")

// ErrFundingNotVisible signals that the maker's OBX SwapOut is not yet in the taker's
// local chain view — a transient SYNC lag, not a swap failure. The coordinator polls on
// this (rather than aborting) until the funding block syncs; no XNO is locked until it
// does. See Taker.VerifyFundedAndLock.
var ErrFundingNotVisible = errors.New("swapsession: maker's OBX SwapOut not visible yet (sync lag)")

// ErrXNOLockNotConfirmed signals that the taker's XNO lock exists but Nano has not yet
// cemented it — a transient few-second delay, not a swap failure. The coordinator polls
// on this (rather than aborting+refunding) until the lock confirms. See
// Maker.ConfirmXNOLock.
var ErrXNOLockNotConfirmed = errors.New("swapsession: taker's XNO lock not cemented yet")

// ---- Init (TAKER -> MAKER) --------------------------------------------------

// Init opens the session from the TAKER (XNO-side). It carries ONLY the taker's
// PUBLIC material: its claim-key share A=a·G, its XNO-key share Sa=sA·G, a
// proof-of-possession for A, the taker's claim nonce point Ra=ra·G, and the
// adaptor point T=sA·G. The taker's private a, sA, ra NEVER leave the taker.
type Init struct {
	SwapID    [32]byte
	OBXAmount uint64   // OBX the maker will lock
	XNOAmount *big.Int // RAW XNO (128-bit) the taker will lock — uint64 cannot hold raw
	// Fee is the OBX fee BOTH parties must use for funding/claim/refund. Carried
	// IN-BAND so the maker can prove the taker agreed to the same number it funds
	// with (the maker rejects an Init whose Fee differs from its configured Fee in
	// HandleInit) — closing the out-of-band-fee gap where the two sides could
	// silently disagree on the fee a co-signed claim spends.
	Fee uint64
	A   []byte // 32B  a·G   (taker claim-key share)
	Sa        []byte // 32B  sA·G  (taker XNO-key share)
	PoPA      []byte // proof-of-possession of A's discrete log
	Ra        []byte // 32B  ra·G  (taker claim nonce point)
	T         []byte // 32B  sA·G  adaptor point (== Sa; the claim reveals sA)
}

// MakerCommit (MAKER -> TAKER) answers Init with the maker's PUBLIC material:
// its claim-key share B=b·G, its XNO-key share Sb=sB·G, a proof-of-possession
// for B, and the maker's claim nonce point Rb=rb·G. After exchanging Init +
// MakerCommit both parties can derive the SAME joint keys (K=A+B, account=Sa+Sb)
// and aggregate nonce R=Ra+Rb from public data alone.
type MakerCommit struct {
	SwapID [32]byte
	B      []byte // 32B  b·G   (maker claim-key share)
	Sb     []byte // 32B  sB·G  (maker XNO-key share)
	PoPB   []byte // proof-of-possession of B's discrete log
	Rb     []byte // 32B  rb·G  (maker claim nonce point)
}

// Funded (MAKER -> TAKER) announces that the OBX SwapOut is funded + confirmed
// on the OBX chain, identifying it by its swap key and the agreed unlock height.
// The taker re-derives the expected SwapOutput and verifies it on-chain before
// locking any XNO (safe leg ordering — fix #2).
type Funded struct {
	SwapID       [32]byte
	SwapKey      []byte // 32B on-chain swap-output id
	UnlockHeight uint64
}

// XNOLocked (TAKER -> MAKER) reports that the XNO has been locked to the joint
// account, identifying the lock. Once the maker confirms this lock it will
// co-sign the claim (ClaimPreSig), after which the taker can take the OBX and
// thereby reveal sA, letting the maker sweep this XNO with sA+sB.
type XNOLocked struct {
	SwapID [32]byte
	LockID string
}

// ClaimRequest (TAKER -> MAKER) carries the core hash of the claim transaction
// the taker has built (it pays the OBX to the taker). The maker needs this exact
// hash to compute the challenge e and produce its pre-signature half. The taker
// also echoes its own nonce point Ra so the maker can reconstruct R = Ra+Rb and
// bind the challenge to R+T identically.
//
// TakerHalf is the taker's OWN half of the 2-of-2 adaptor pre-signature over this
// core hash: ŝ_a = ra + e·a (the SAME half the taker will aggregate in
// FinalizeClaim). Revealing it BEFORE the claim is published is SOUND for the
// taker: ŝ_a alone does not let the maker complete the claim (the maker still
// lacks the taker's adaptor secret sA, so it cannot form S_full = ŝ_a+ŝ_b+sA),
// and it does not leak a's discrete log (ŝ_a is a single Schnorr response under
// the committed nonce ra, used exactly once). It is what makes the maker able to
// EXTRACT sA INDEPENDENTLY from the on-chain claim — sA = S_full − ŝ_a − ŝ_b —
// with ZERO taker cooperation after co-signing (the griefing fix: a taker can no
// longer freeze the maker's XNO sweep by withholding/corrupting the post-claim
// relay). The maker VERIFIES ŝ_a·G == Ra + e·A before co-signing (CoSignClaim).
type ClaimRequest struct {
	SwapID    [32]byte
	CoreHash  []byte // 32B+ tx core hash the claim sig is computed over
	TakerHalf []byte // 32B  ŝ_a = ra + e·a  (taker's pre-signature half)
}

// ClaimPreSig (MAKER -> TAKER) is the maker's HALF of the 2-of-2 adaptor
// pre-signature: PreR = rb·G (the maker's nonce point) and Sb = rb + e·b. The
// taker adds its own half sa = ra + e·a to get the aggregate pre-response, then
// ADAPTS with sA. The maker giving this half lets the taker complete the claim
// (and take the OBX) — but the claim necessarily reveals sA (R+T binding), which
// the maker extracts to sweep the XNO; if the taker never finalizes, the maker
// refunds the OBX at the timelock. So releasing the half is safe for the maker.
type ClaimPreSig struct {
	SwapID [32]byte
	Sb     []byte // 32B  rb + e·b  (maker's pre-response half)
}

// ---- serialization ----------------------------------------------------------

func put32b(b *[]byte, p []byte) {
	var x [32]byte
	copy(x[:], p)
	*b = append(*b, x[:]...)
}

func putU64(b *[]byte, v uint64) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], v)
	*b = append(*b, n[:]...)
}

func putLen(b *[]byte, p []byte) {
	putU64(b, uint64(len(p)))
	*b = append(*b, p...)
}

// putBig encodes a non-negative *big.Int as a length-prefixed big-endian magnitude
// (nil → length 0). Used for the 128-bit raw XNO amount, which does not fit uint64.
func putBig(b *[]byte, v *big.Int) {
	var raw []byte
	if v != nil {
		raw = v.Bytes()
	}
	putLen(b, raw)
}

type reader struct {
	b   []byte
	pos int
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if r.pos+n > len(r.b) {
		r.err = errMsg
		return nil
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v
}

func (r *reader) u64() uint64 {
	v := r.take(8)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint64(v)
}

func (r *reader) bytes32() []byte {
	v := r.take(32)
	if v == nil {
		return nil
	}
	return append([]byte(nil), v...)
}

func (r *reader) lenBytes() []byte {
	n := r.u64()
	if r.err != nil || n > 1<<16 {
		r.err = errMsg
		return nil
	}
	v := r.take(int(n))
	if v == nil {
		return nil
	}
	return append([]byte(nil), v...)
}

// bigInt reads a length-prefixed big-endian magnitude as a non-negative *big.Int
// (length 0 → 0). The 16-byte cap matches Nano raw being a 128-bit quantity, so a
// malformed/oversized amount is rejected rather than accepted.
func (r *reader) bigInt() *big.Int {
	raw := r.lenBytes()
	if r.err != nil {
		return new(big.Int)
	}
	if len(raw) > 16 {
		r.err = errMsg
		return new(big.Int)
	}
	return new(big.Int).SetBytes(raw)
}

func (r *reader) swapID() [32]byte {
	var id [32]byte
	copy(id[:], r.take(32))
	return id
}

func (r *reader) done() error {
	if r.err != nil {
		return r.err
	}
	if r.pos != len(r.b) {
		return errMsg
	}
	return nil
}

// Serialize encodes the Init message.
func (m *Init) Serialize() []byte {
	b := []byte{roleTaker}
	b = append(b, m.SwapID[:]...)
	putU64(&b, m.OBXAmount)
	putBig(&b, m.XNOAmount)
	putU64(&b, m.Fee)
	put32b(&b, m.A)
	put32b(&b, m.Sa)
	putLen(&b, m.PoPA)
	put32b(&b, m.Ra)
	put32b(&b, m.T)
	return b
}

// ParseInit decodes an Init message (without validating the crypto).
func ParseInit(b []byte) (*Init, error) {
	if len(b) == 0 || b[0] != roleTaker {
		return nil, errMsg
	}
	r := &reader{b: b, pos: 1}
	m := &Init{}
	m.SwapID = r.swapID()
	m.OBXAmount = r.u64()
	m.XNOAmount = r.bigInt()
	m.Fee = r.u64()
	m.A = r.bytes32()
	m.Sa = r.bytes32()
	m.PoPA = r.lenBytes()
	m.Ra = r.bytes32()
	m.T = r.bytes32()
	if err := r.done(); err != nil {
		return nil, err
	}
	return m, nil
}

// Serialize encodes the MakerCommit message.
func (m *MakerCommit) Serialize() []byte {
	b := []byte{roleMaker}
	b = append(b, m.SwapID[:]...)
	put32b(&b, m.B)
	put32b(&b, m.Sb)
	putLen(&b, m.PoPB)
	put32b(&b, m.Rb)
	return b
}

// ParseMakerCommit decodes a MakerCommit message.
func ParseMakerCommit(b []byte) (*MakerCommit, error) {
	if len(b) == 0 || b[0] != roleMaker {
		return nil, errMsg
	}
	r := &reader{b: b, pos: 1}
	m := &MakerCommit{}
	m.SwapID = r.swapID()
	m.B = r.bytes32()
	m.Sb = r.bytes32()
	m.PoPB = r.lenBytes()
	m.Rb = r.bytes32()
	if err := r.done(); err != nil {
		return nil, err
	}
	return m, nil
}

// Serialize encodes the Funded message.
func (m *Funded) Serialize() []byte {
	b := []byte{roleMaker}
	b = append(b, m.SwapID[:]...)
	putLen(&b, m.SwapKey)
	putU64(&b, m.UnlockHeight)
	return b
}

// ParseFunded decodes a Funded message.
func ParseFunded(b []byte) (*Funded, error) {
	if len(b) == 0 || b[0] != roleMaker {
		return nil, errMsg
	}
	r := &reader{b: b, pos: 1}
	m := &Funded{}
	m.SwapID = r.swapID()
	m.SwapKey = r.lenBytes()
	m.UnlockHeight = r.u64()
	if err := r.done(); err != nil {
		return nil, err
	}
	return m, nil
}

// Serialize encodes the XNOLocked message.
func (m *XNOLocked) Serialize() []byte {
	b := []byte{roleTaker}
	b = append(b, m.SwapID[:]...)
	putLen(&b, []byte(m.LockID))
	return b
}

// ParseXNOLocked decodes an XNOLocked message.
func ParseXNOLocked(b []byte) (*XNOLocked, error) {
	if len(b) == 0 || b[0] != roleTaker {
		return nil, errMsg
	}
	r := &reader{b: b, pos: 1}
	m := &XNOLocked{}
	m.SwapID = r.swapID()
	m.LockID = string(r.lenBytes())
	if err := r.done(); err != nil {
		return nil, err
	}
	return m, nil
}

// Serialize encodes the ClaimRequest message.
func (m *ClaimRequest) Serialize() []byte {
	b := []byte{roleTaker}
	b = append(b, m.SwapID[:]...)
	putLen(&b, m.CoreHash)
	put32b(&b, m.TakerHalf)
	return b
}

// ParseClaimRequest decodes a ClaimRequest message.
func ParseClaimRequest(b []byte) (*ClaimRequest, error) {
	if len(b) == 0 || b[0] != roleTaker {
		return nil, errMsg
	}
	r := &reader{b: b, pos: 1}
	m := &ClaimRequest{}
	m.SwapID = r.swapID()
	m.CoreHash = r.lenBytes()
	m.TakerHalf = r.bytes32()
	if err := r.done(); err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// Validate checks the ClaimRequest is structurally well-formed: a non-empty core
// hash and a canonical 32-byte TakerHalf scalar. The CRYPTO binding of TakerHalf
// to the swap (ŝ_a·G == Ra + e·A) is checked by the maker in CoSignClaim, where Ra,
// A, and the challenge e are available from the agreed state.
func (m *ClaimRequest) Validate() error {
	if len(m.CoreHash) == 0 {
		return errMsg
	}
	if len(m.TakerHalf) != 32 {
		return errMsg
	}
	if _, err := new(edwards25519.Scalar).SetCanonicalBytes(m.TakerHalf); err != nil {
		return errMsg
	}
	return nil
}

// Serialize encodes the ClaimPreSig message.
func (m *ClaimPreSig) Serialize() []byte {
	b := []byte{roleMaker}
	b = append(b, m.SwapID[:]...)
	put32b(&b, m.Sb)
	return b
}

// ParseClaimPreSig decodes a ClaimPreSig message.
func ParseClaimPreSig(b []byte) (*ClaimPreSig, error) {
	if len(b) == 0 || b[0] != roleMaker {
		return nil, errMsg
	}
	r := &reader{b: b, pos: 1}
	m := &ClaimPreSig{}
	m.SwapID = r.swapID()
	m.Sb = r.bytes32()
	if err := r.done(); err != nil {
		return nil, err
	}
	return m, nil
}

// ---- validation -------------------------------------------------------------

// Validate checks the TAKER's Init is well-formed and crypto-sound: A and Sa are
// non-identity curve points, the proof-of-possession for A holds (defeating
// rogue-key cancellation), Ra is a valid point, and the adaptor point T equals
// the published Sa (so claiming the OBX — which reveals the adaptor secret —
// reveals exactly the taker's XNO share sA). The MAKER calls this before
// committing its own shares.
func (m *Init) Validate() error {
	if m.OBXAmount == 0 || m.XNOAmount == nil || m.XNOAmount.Sign() <= 0 {
		return errMsg
	}
	if !swap.VerifyPossession(m.A, m.PoPA) {
		return errMsg
	}
	if _, err := pointOf(m.Sa); err != nil {
		return errMsg
	}
	if _, err := pointOf(m.Ra); err != nil {
		return errMsg
	}
	// T MUST equal Sa: the claim's adaptor secret is the taker's XNO share sA, so
	// the adaptor point must be sA·G == Sa. A T≠Sa would let the claim reveal a
	// secret unrelated to the XNO account, breaking atomicity.
	if string(m.T) != string(m.Sa) {
		return errMsg
	}
	if _, err := pointOf(m.T); err != nil {
		return errMsg
	}
	return nil
}

// Validate checks the MAKER's MakerCommit: B and Sb are non-identity points, the
// proof-of-possession for B holds, and Rb is a valid point. The TAKER calls this
// before deriving the joint keys and proceeding.
func (m *MakerCommit) Validate() error {
	if !swap.VerifyPossession(m.B, m.PoPB) {
		return errMsg
	}
	if _, err := pointOf(m.Sb); err != nil {
		return errMsg
	}
	if _, err := pointOf(m.Rb); err != nil {
		return errMsg
	}
	return nil
}

// pointOf parses a 32-byte point and rejects the identity (a degenerate share
// that would let a rogue cancel the honest contribution).
func pointOf(b []byte) (*edwards25519.Point, error) {
	p, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		return nil, err
	}
	if p.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, errMsg
	}
	return p, nil
}

// jointKeys derives, from the two parties' PUBLIC shares only, the OBX claim key
// K=A+B, the aggregate claim nonce R=Ra+Rb, and the joint XNO account public key
// Sa+Sb. Neither private share is needed or revealed.
func jointKeys(init *Init, mc *MakerCommit) (K, R *edwards25519.Point, xnoPub []byte, err error) {
	A, err := pointOf(init.A)
	if err != nil {
		return nil, nil, nil, err
	}
	B, err := pointOf(mc.B)
	if err != nil {
		return nil, nil, nil, err
	}
	Ra, err := pointOf(init.Ra)
	if err != nil {
		return nil, nil, nil, err
	}
	Rb, err := pointOf(mc.Rb)
	if err != nil {
		return nil, nil, nil, err
	}
	K = swap.AggregateKey(A, B)
	R = new(edwards25519.Point).Add(Ra, Rb)
	xnoPub, err = swapd.NanoAccountPub(init.Sa, mc.Sb)
	if err != nil {
		return nil, nil, nil, err
	}
	return K, R, xnoPub, nil
}
