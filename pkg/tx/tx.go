// Package tx defines the Obscura transaction model. A transaction spends
// existing accumulated outputs by proving membership in the global UTXO
// accumulator in zero knowledge (hiding which output) and revealing a nullifier
// to prevent double-spends, and creates new confidential stealth outputs.
package tx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/blake2b"

	"obscura/pkg/config"
)

// Consensus limits (anti-DoS): bound counts and field sizes so a tiny message
// cannot force huge allocations or unbounded crypto work.
const (
	MaxInputs     = 1024    // max inputs per transaction
	MaxOutputs    = 1024    // max outputs per transaction
	MaxFieldBytes = 1 << 16 // max bytes for any single length-prefixed field (64 KiB)
	MaxTxBytes    = 1 << 21 // max serialized transaction size (2 MiB)
)

// Output is a confidential stealth output.
type Output struct {
	OneTimeKey []byte // stealth one-time public key P (32B compressed point)
	TxPubKey   []byte // stealth transaction public key R = r·G (32B)
	Commitment []byte // Pedersen commitment to the amount (32B)
	RangeProof []byte // serialized bit-decomposition range proof
	PrimeNonce uint64 // hash-to-prime nonce for deriving this output's prime rep
	LockUntil  uint64 // block height before which this output cannot be spent (holding bonus); 0 = none
	EncAmount  []byte // amount XOR keystream(shared secret) — recipient decrypts
	EncMask    []byte // blinding XOR keystream(shared secret) — recipient decrypts
	ViewTag    byte   // 1-byte scan hint H(shared)[0] — lets a wallet skip non-owned outputs cheaply
}

// ZKOutput mints a coin into the Poseidon commitment tree (the "shield" leg). Its
// value Amount is PUBLIC (it leaves the confidential pool as publicOut, like a
// vault deposit) and is BOUND to the commitment Leaf by a STARK mint proof, so a
// creator cannot mint a leaf worth more than they declare. The coin is spendable
// ONLY anonymously via a ZKInput (it creates no transparent UTXO), so there is no
// cross-system double-spend. See docs/ZK_MEMBERSHIP_SPEND.md.
type ZKOutput struct {
	Leaf      []byte // 8B Felt commitment L=Hash2(Hash2(serial,amount),blind)
	Amount    uint64 // public minted value (added to publicOut at creation)
	MintProof []byte // serialized stark proof that Leaf commits to Amount (excluded from CoreHash)
	// Stealth delivery (for ZK→ZK transfer): the recipient reconstructs the coin's
	// (serial, blind) from a shared secret derived via Key/TxPubKey, so only they can
	// spend it. ViewTag is a 1-byte scan hint. Empty for mint-to-self.
	Key      []byte // 32B stealth one-time key (for scan matching)
	TxPubKey []byte // 32B ephemeral R = r·G
	ViewTag  byte
}

// CZKSpend is a CONFIDENTIAL fully-anonymous ZK→ZK spend: ONE transparent zk-STARK
// (pkg/stark/cspend_full.go, zero-knowledge-masked engine) atomically (a) proves the
// spent coin is a member of the commitment tree at Anchor and reveals its nullifier
// Serial, AND (b) mints a fresh output coin LeafOut, proving value conservation
// a_in = a_out + Fee — with BOTH amounts HIDDEN. Only the public Fee leaks. It is a
// fused ZKInput(Fee)+ZKOutput(LeafOut): the spent value re-enters the public ledger
// only as Fee (added to publicIn, balanced by the tx fee); a_out stays in the pool.
// Consensus MUST range-check Fee ∈ [0, 2^ConfidentialBits) (SECURITY_AUDIT FINDING 5):
// the circuit does field balance, so a wrapped "negative" fee would inflate.
type CZKSpend struct {
	Nullifier []byte // 32B recipient-secret nullifier nf=H(nsk,rho); only the recipient (who holds nsk) can compute it. Revealed; double-spend = reuse
	Anchor    []byte // 32B commitment-tree (epoch) root the membership proof targets
	LeafOut   []byte // 32B new coin commitment, HIDDEN amount (appended to the tree)
	Fee       uint64 // PUBLIC confidential fee; range-checked 0 ≤ Fee < 2^ConfidentialBits
	Proof     []byte // serialized cspendFull stark.AIRProof (excluded from CoreHash)
	// Stealth delivery of LeafOut to the recipient (as in ZKOutput).
	Key      []byte // 32B stealth one-time key (scan matching)
	TxPubKey []byte // 32B ephemeral R = r·G
	ViewTag  byte
	// EncAmount carries the HIDDEN a_out to the recipient (8B little-endian XOR a
	// shared-secret keystream); consensus ignores it, the recipient decrypts then checks
	// LeafOut = leaf(serial_out, a_out, blind_out). Bound in CoreHash (not malleable).
	EncAmount []byte
}

// ZKInput is a fully sender-anonymous spend (the 100B endgame): it proves, with a
// transparent zk-STARK, membership of a coin commitment in the Poseidon
// commitment-tree (against a recent root Anchor) and reveals a nullifier Serial,
// while hiding WHICH coin is spent. No ring, no named output — the node verifies
// against the O(1) tree root with no coin/ring set. See pkg/stark/spend_air.go.
type ZKInput struct {
	Nullifier []byte // 32B recipient-secret nullifier nf=H(nsk,rho) (revealed); double-spend = reuse
	Amount    uint64 // public spent value (bound into the note; for conservation)
	Anchor    []byte // 32B commitment-tree root the membership proof targets
	Proof     []byte // serialized stark.AIRProof (excluded from CoreHash)
}

// Input spends a previously created output.
//
// SECURITY MODEL (v2, sound): a spend is authenticated and value-bound.
//   - OutputRef identifies the spent UTXO by its one-time key P.
//   - OwnershipProof is a Schnorr proof of knowledge of x with P = x·G, so only
//     the owner can spend (closes the "anyone can spend anyone's output" hole).
//   - PseudoCommitment re-blinds the spent amount; EqualityProof proves it
//     commits to the SAME value as the referenced output's on-chain commitment
//     (closes the inflation hole where the pseudo value was unconstrained).
//   - Double-spends are prevented by the consensus UTXO spent-set keyed on
//     OutputRef (no forgeable nullifier).
//
// Amounts (Pedersen commitments) and recipients (stealth addresses) remain
// private; sender-output linkage is revealed in this sound model. The
// accumulator-based witness-hiding ZK spend that also hides the sender is
// retained in pkg/accumulator as an experimental, not-yet-sound layer (see
// WHITEPAPER.md "Security Status").
type Input struct {
	OutputRef        []byte // spent output's one-time key P (32B)
	OwnershipProof   []byte // Schnorr PoK of x with P = x·G, bound to CoreHash
	PseudoCommitment []byte // re-blinded commitment to the spent amount (32B)
	EqualityProof    []byte // Schnorr PoK that PseudoCommitment ≡ UTXO commitment in value
	// KeyImage is the coin's canonical nullifier T = x·U — the SAME value an
	// anonymous spend of this coin would publish — so transparent and anonymous
	// spends share ONE nullifier set and a coin cannot be spent both ways.
	KeyImage []byte // 32B; T = x·U
	// KeyImageProof is a DLEQ proving T = x·U uses the same x as P = x·G, so the
	// nullifier cannot be forged to dodge the cross-domain double-spend check.
	KeyImageProof []byte
}

// AnonInput is a SENDER-ANONYMOUS spend: instead of naming the spent output, it
// proves (in zero knowledge) that one coin in a ring is owned and value-matched,
// via the Triptych-style joint one-out-of-many proof, and reveals a key-image
// Tag for double-spend prevention. A verifier learns only that SOME coin in the
// ring is spent, never which.
type AnonInput struct {
	PoolID           uint64 // anonymity pool whose complete membership is the ring
	Tag              []byte // key image / nullifier (32B), unique per coin
	PseudoCommitment []byte // re-blinded commitment to the spent amount (32B)
	Proof            []byte // serialized joint anon-spend proof
}

// SwapOut locks OBX value in an on-chain atomic-swap contract (cleartext amount).
// It is spendable only via a SwapIn: the CLAIM path (signature under ClaimKey,
// before UnlockHeight) or the REFUND path (signature under RefundKey, at/after
// UnlockHeight). See docs/INVENTION_SWAPS.md.
type SwapOut struct {
	SwapKey      []byte // unique 32B id of this swap output
	Amount       uint64 // locked amount (cleartext; swaps reveal the amount)
	ClaimKey     []byte // 32B 2-of-2 aggregate key for the claim path (== ClaimA+ClaimB)
	RefundKey    []byte // 32B funder key for the refund path
	UnlockHeight uint64 // refund allowed at/after this height
	// Rogue-key & atomicity binding (audit fix — see pkg/swap.AggregateKeyVerified
	// and ClaimBindingOK). Consensus requires ClaimKey == ClaimA+ClaimB with a
	// verified proof-of-possession for each share, and binds the claim signature
	// to the adaptor pre-signature via ClaimR/ClaimT.
	ClaimA []byte // 32B contributed claim-key share A
	ClaimB []byte // 32B contributed claim-key share B
	PoPA   []byte // proof-of-possession of A's discrete log
	PoPB   []byte // proof-of-possession of B's discrete log
	ClaimR []byte // 32B adaptor pre-signature nonce R
	ClaimT []byte // 32B adaptor point T (non-identity)
}

// SwapIn spends a SwapOut via the claim or refund path.
type SwapIn struct {
	SwapKey  []byte // which swap output
	IsRefund bool   // false = claim (under ClaimKey), true = refund (under RefundKey)
	Sig      []byte // 64B Schnorr signature over the tx CoreHash
}

// VaultOut deposits a public Amount of OBX into a staking vault for Term blocks.
// The amount is locked (a public value leg leaving the confidential pool, like a
// SwapOut) and earns yield, claimable after maturity (depositHeight+Term) by a
// signature under OwnerKey. See docs/INVENTION_VAULTS.md.
type VaultOut struct {
	VaultKey []byte // unique 32B id of this vault deposit
	Amount   uint64 // locked principal (cleartext; vaults reveal the staked amount)
	Term     uint64 // lock term in blocks (must be an allowed config.VaultTerms)
	OwnerKey []byte // 32B Schnorr pubkey authorized to claim
}

// VaultIn claims a matured vault, paying principal + yield as public value
// re-entering the confidential pool (the proceeds land in fresh stealth outputs).
type VaultIn struct {
	VaultKey []byte // which vault
	Yield    uint64 // yield claimed from the incentive pool; consensus CAPS it at the
	// vault's entitled yield-at-claim-height (full for fixed terms, pro-rata for a
	// flexible Term==0 vault). Bound in the CoreHash so the signature + value-
	// conservation proof commit to it — the claimer states the exact payout, which
	// stays valid however many blocks later the claim is actually mined.
	Sig []byte // 64B Schnorr signature over the tx CoreHash under OwnerKey
}

// PQOutput is a POST-QUANTUM confidential output (experimental Version-2 path).
// Its one-time key is the hybrid key BLAKE2b(P‖R) (pkg/pqsign), its amount is a
// lattice commitment (pkg/pqcommit), and its stealth material is an ML-KEM-768
// announcement (pkg/pqstealth). It is plain data here; the crypto lives in the
// pq* packages and validation in pkg/chain. See docs/POST_QUANTUM_ROADMAP.md.
type PQOutput struct {
	OneTimeKey []byte // 32B hybrid one-time key = BLAKE2b(P‖R)
	Amount     uint64 // PUBLIC amount — the consensus PQ value layer is public
	// (sound: no wraparound inflation) pending the compact PQ
	// range proof that will re-enable confidential amounts.
	KEMCiphertext []byte // ML-KEM-768 ciphertext (stealth: recipient detection)
	ViewTag       []byte // stealth detection tag
	// Reserved for confidential amounts once the PQ range proof (Ligero/STARK)
	// lands; UNUSED by current consensus (see docs/POST_QUANTUM_ROADMAP.md):
	Commitment []byte // serialized pqcommit.Commitment
	EncAmount  []byte // encrypted amount
	MAC        []byte // amount authenticator
}

// PQInput authorizes spending a PQOutput with a hybrid (Schnorr ⊕ WOTS+)
// signature, revealing (P, R) and a nullifier = BLAKE2b(R) bound to the output.
type PQInput struct {
	OutputRef  []byte // spent PQOutput's OneTimeKey
	P          []byte // 32B classical point P = x·G revealed at spend
	WotsRoot   []byte // 32B WOTS+ root R revealed at spend
	Nullifier  []byte // 32B = BLAKE2b(R); bound by CoreHash, like the classical KeyImage
	Anchor     []byte // 32B PQ anonymity-set root the Membership proof targets (Zcash-style anchor)
	HybridSig  []byte // serialized hybrid signature (excluded from CoreHash)
	Membership []byte // serialized PQ anonymity-set membership proof (excluded from CoreHash)
}

// Transaction is a confidential transaction or a coinbase.
type Transaction struct {
	Version      uint16
	IsCoinbase   bool
	Inputs       []Input     // transparent-sender inputs
	AnonInputs   []AnonInput // sender-anonymous inputs
	SwapInputs   []SwapIn    // atomic-swap claim/refund spends
	SwapOutputs  []SwapOut   // atomic-swap contract outputs
	Outputs      []Output
	Fee          uint64 // explicit fee (atomic units); 0 for coinbase
	Conservation []byte // serialized Schnorr proof that value balances
	// Coinbase-only fields:
	Height      uint64 // block height (binds coinbase to its block)
	Minted      uint64 // reward + collected fees (public)
	ReferrerTag []byte // optional referrer address tag for the viral-loop bonus
	ExtraNonce  uint64 // miner extranonce (expands PoW search space)
	// Post-quantum (Version 2) fields — experimental, separate value space from
	// the classical Pedersen amounts (see pkg/chain PQ validation):
	PQInputs    []PQInput  // PQ spends (hybrid-signed)
	PQOutputs   []PQOutput // PQ confidential outputs
	PQBlindDiff []byte     // aggregate blinding witness for PQ value conservation
	// Staking vaults (docs/INVENTION_VAULTS.md): deposits lock public value, claims
	// release principal+yield. Empty for ordinary txs.
	VaultInputs  []VaultIn  // vault claims
	VaultOutputs []VaultOut // vault deposits
	// Fully-anonymous ZK coins: ZKOutputs mint commitments into the Poseidon tree
	// (public value out); ZKInputs spend them anonymously (public value in). Appended
	// at the end of the wire form so older fields' hashing is stable.
	ZKInputs  []ZKInput
	ZKOutputs []ZKOutput
	// Confidential ZK→ZK spends (hidden amounts; pkg/stark/cspend_full.go). Appended
	// last so older fields' wire/hash layout is unchanged.
	CZKSpends []CZKSpend
}

// --- canonical serialization (for hashing, storage, and the wire) ---

func wB(buf *bytes.Buffer, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	buf.Write(l[:])
	buf.Write(b)
}
func rB(r *bytes.Reader) ([]byte, error) {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(l[:])
	if int(n) > MaxFieldBytes {
		return nil, errors.New("tx: field too large")
	}
	if int(n) > r.Len() {
		return nil, errors.New("tx: field length exceeds remaining input")
	}
	b := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
	}
	return b, nil
}
func wU64(buf *bytes.Buffer, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	buf.Write(b[:])
}
func rU64(r *bytes.Reader) (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// Serialize encodes the transaction canonically.
func (t *Transaction) Serialize() []byte {
	var buf bytes.Buffer
	var v [2]byte
	binary.BigEndian.PutUint16(v[:], t.Version)
	buf.Write(v[:])
	if t.IsCoinbase {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	wU64(&buf, uint64(len(t.Inputs)))
	for _, in := range t.Inputs {
		wB(&buf, in.OutputRef)
		wB(&buf, in.OwnershipProof)
		wB(&buf, in.PseudoCommitment)
		wB(&buf, in.EqualityProof)
		wB(&buf, in.KeyImage)
		wB(&buf, in.KeyImageProof)
	}
	wU64(&buf, uint64(len(t.AnonInputs)))
	for _, in := range t.AnonInputs {
		wU64(&buf, in.PoolID)
		wB(&buf, in.Tag)
		wB(&buf, in.PseudoCommitment)
		wB(&buf, in.Proof)
	}
	wU64(&buf, uint64(len(t.SwapInputs)))
	for _, in := range t.SwapInputs {
		wB(&buf, in.SwapKey)
		if in.IsRefund {
			buf.WriteByte(1)
		} else {
			buf.WriteByte(0)
		}
		wB(&buf, in.Sig)
	}
	wU64(&buf, uint64(len(t.SwapOutputs)))
	for _, so := range t.SwapOutputs {
		wB(&buf, so.SwapKey)
		wU64(&buf, so.Amount)
		wB(&buf, so.ClaimKey)
		wB(&buf, so.RefundKey)
		wU64(&buf, so.UnlockHeight)
		wB(&buf, so.ClaimA)
		wB(&buf, so.ClaimB)
		wB(&buf, so.PoPA)
		wB(&buf, so.PoPB)
		wB(&buf, so.ClaimR)
		wB(&buf, so.ClaimT)
	}
	wU64(&buf, uint64(len(t.Outputs)))
	for _, o := range t.Outputs {
		wB(&buf, o.OneTimeKey)
		wB(&buf, o.TxPubKey)
		wB(&buf, o.Commitment)
		wB(&buf, o.RangeProof)
		wU64(&buf, o.PrimeNonce)
		wU64(&buf, o.LockUntil)
		wB(&buf, o.EncAmount)
		wB(&buf, o.EncMask)
		buf.WriteByte(o.ViewTag)
	}
	wU64(&buf, t.Fee)
	wB(&buf, t.Conservation)
	wU64(&buf, t.Height)
	wU64(&buf, t.Minted)
	wB(&buf, t.ReferrerTag)
	wU64(&buf, t.ExtraNonce)
	wU64(&buf, uint64(len(t.PQInputs)))
	for _, in := range t.PQInputs {
		wB(&buf, in.OutputRef)
		wB(&buf, in.P)
		wB(&buf, in.WotsRoot)
		wB(&buf, in.Nullifier)
		wB(&buf, in.Anchor)
		wB(&buf, in.HybridSig)
		wB(&buf, in.Membership)
	}
	wU64(&buf, uint64(len(t.PQOutputs)))
	for _, o := range t.PQOutputs {
		wB(&buf, o.OneTimeKey)
		wU64(&buf, o.Amount)
		wB(&buf, o.KEMCiphertext)
		wB(&buf, o.ViewTag)
		wB(&buf, o.Commitment)
		wB(&buf, o.EncAmount)
		wB(&buf, o.MAC)
	}
	wB(&buf, t.PQBlindDiff)
	wU64(&buf, uint64(len(t.VaultInputs)))
	for _, in := range t.VaultInputs {
		wB(&buf, in.VaultKey)
		wU64(&buf, in.Yield)
		wB(&buf, in.Sig)
	}
	wU64(&buf, uint64(len(t.VaultOutputs)))
	for _, o := range t.VaultOutputs {
		wB(&buf, o.VaultKey)
		wU64(&buf, o.Amount)
		wU64(&buf, o.Term)
		wB(&buf, o.OwnerKey)
	}
	wU64(&buf, uint64(len(t.ZKInputs)))
	for _, in := range t.ZKInputs {
		wB(&buf, in.Nullifier)
		wU64(&buf, in.Amount)
		wB(&buf, in.Anchor)
		wB(&buf, in.Proof)
	}
	wU64(&buf, uint64(len(t.ZKOutputs)))
	for _, o := range t.ZKOutputs {
		wB(&buf, o.Leaf)
		wU64(&buf, o.Amount)
		wB(&buf, o.MintProof)
		wB(&buf, o.Key)
		wB(&buf, o.TxPubKey)
		buf.WriteByte(o.ViewTag)
	}
	wU64(&buf, uint64(len(t.CZKSpends)))
	for _, s := range t.CZKSpends {
		wB(&buf, s.Nullifier)
		wB(&buf, s.Anchor)
		wB(&buf, s.LeafOut)
		wU64(&buf, s.Fee)
		wB(&buf, s.Proof)
		wB(&buf, s.Key)
		wB(&buf, s.TxPubKey)
		buf.WriteByte(s.ViewTag)
		wB(&buf, s.EncAmount)
	}
	return buf.Bytes()
}

// Deserialize parses a transaction with strict size/count bounds.
func Deserialize(data []byte) (*Transaction, error) {
	if len(data) > MaxTxBytes {
		return nil, errors.New("tx: serialized transaction too large")
	}
	r := bytes.NewReader(data)
	t := &Transaction{}
	var v [2]byte
	if _, err := io.ReadFull(r, v[:]); err != nil {
		return nil, err
	}
	t.Version = binary.BigEndian.Uint16(v[:])
	cb, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	t.IsCoinbase = cb == 1
	nin, err := rU64(r)
	if err != nil {
		return nil, err
	}
	if nin > MaxInputs {
		return nil, errors.New("tx: too many inputs")
	}
	for i := uint64(0); i < nin; i++ {
		var in Input
		if in.OutputRef, err = rB(r); err != nil {
			return nil, err
		}
		if in.OwnershipProof, err = rB(r); err != nil {
			return nil, err
		}
		if in.PseudoCommitment, err = rB(r); err != nil {
			return nil, err
		}
		if in.EqualityProof, err = rB(r); err != nil {
			return nil, err
		}
		if in.KeyImage, err = rB(r); err != nil {
			return nil, err
		}
		if in.KeyImageProof, err = rB(r); err != nil {
			return nil, err
		}
		t.Inputs = append(t.Inputs, in)
	}
	nanon, err := rU64(r)
	if err != nil {
		return nil, err
	}
	if nanon > MaxInputs {
		return nil, errors.New("tx: too many anon inputs")
	}
	for i := uint64(0); i < nanon; i++ {
		var in AnonInput
		if in.PoolID, err = rU64(r); err != nil {
			return nil, err
		}
		if in.Tag, err = rB(r); err != nil {
			return nil, err
		}
		if in.PseudoCommitment, err = rB(r); err != nil {
			return nil, err
		}
		if in.Proof, err = rB(r); err != nil {
			return nil, err
		}
		t.AnonInputs = append(t.AnonInputs, in)
	}
	nsi, err := rU64(r)
	if err != nil {
		return nil, err
	}
	if nsi > MaxInputs {
		return nil, errors.New("tx: too many swap inputs")
	}
	for i := uint64(0); i < nsi; i++ {
		var in SwapIn
		if in.SwapKey, err = rB(r); err != nil {
			return nil, err
		}
		rb, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		in.IsRefund = rb == 1
		if in.Sig, err = rB(r); err != nil {
			return nil, err
		}
		t.SwapInputs = append(t.SwapInputs, in)
	}
	nso, err := rU64(r)
	if err != nil {
		return nil, err
	}
	if nso > MaxOutputs {
		return nil, errors.New("tx: too many swap outputs")
	}
	for i := uint64(0); i < nso; i++ {
		var so SwapOut
		if so.SwapKey, err = rB(r); err != nil {
			return nil, err
		}
		if so.Amount, err = rU64(r); err != nil {
			return nil, err
		}
		if so.ClaimKey, err = rB(r); err != nil {
			return nil, err
		}
		if so.RefundKey, err = rB(r); err != nil {
			return nil, err
		}
		if so.UnlockHeight, err = rU64(r); err != nil {
			return nil, err
		}
		if so.ClaimA, err = rB(r); err != nil {
			return nil, err
		}
		if so.ClaimB, err = rB(r); err != nil {
			return nil, err
		}
		if so.PoPA, err = rB(r); err != nil {
			return nil, err
		}
		if so.PoPB, err = rB(r); err != nil {
			return nil, err
		}
		if so.ClaimR, err = rB(r); err != nil {
			return nil, err
		}
		if so.ClaimT, err = rB(r); err != nil {
			return nil, err
		}
		t.SwapOutputs = append(t.SwapOutputs, so)
	}
	nout, err := rU64(r)
	if err != nil {
		return nil, err
	}
	if nout > MaxOutputs {
		return nil, errors.New("tx: too many outputs")
	}
	for i := uint64(0); i < nout; i++ {
		var o Output
		if o.OneTimeKey, err = rB(r); err != nil {
			return nil, err
		}
		if o.TxPubKey, err = rB(r); err != nil {
			return nil, err
		}
		if o.Commitment, err = rB(r); err != nil {
			return nil, err
		}
		if o.RangeProof, err = rB(r); err != nil {
			return nil, err
		}
		if o.PrimeNonce, err = rU64(r); err != nil {
			return nil, err
		}
		if o.LockUntil, err = rU64(r); err != nil {
			return nil, err
		}
		if o.EncAmount, err = rB(r); err != nil {
			return nil, err
		}
		if o.EncMask, err = rB(r); err != nil {
			return nil, err
		}
		if o.ViewTag, err = r.ReadByte(); err != nil {
			return nil, err
		}
		t.Outputs = append(t.Outputs, o)
	}
	if t.Fee, err = rU64(r); err != nil {
		return nil, err
	}
	if t.Conservation, err = rB(r); err != nil {
		return nil, err
	}
	if t.Height, err = rU64(r); err != nil {
		return nil, err
	}
	if t.Minted, err = rU64(r); err != nil {
		return nil, err
	}
	if t.ReferrerTag, err = rB(r); err != nil {
		return nil, err
	}
	if t.ExtraNonce, err = rU64(r); err != nil {
		return nil, err
	}
	npqi, err := rU64(r)
	if err != nil {
		return nil, err
	}
	if npqi > MaxInputs {
		return nil, errors.New("tx: too many pq inputs")
	}
	for i := uint64(0); i < npqi; i++ {
		var in PQInput
		if in.OutputRef, err = rB(r); err != nil {
			return nil, err
		}
		if in.P, err = rB(r); err != nil {
			return nil, err
		}
		if in.WotsRoot, err = rB(r); err != nil {
			return nil, err
		}
		if in.Nullifier, err = rB(r); err != nil {
			return nil, err
		}
		if in.Anchor, err = rB(r); err != nil {
			return nil, err
		}
		if in.HybridSig, err = rB(r); err != nil {
			return nil, err
		}
		if in.Membership, err = rB(r); err != nil {
			return nil, err
		}
		t.PQInputs = append(t.PQInputs, in)
	}
	npqo, err := rU64(r)
	if err != nil {
		return nil, err
	}
	if npqo > MaxOutputs {
		return nil, errors.New("tx: too many pq outputs")
	}
	for i := uint64(0); i < npqo; i++ {
		var o PQOutput
		if o.OneTimeKey, err = rB(r); err != nil {
			return nil, err
		}
		if o.Amount, err = rU64(r); err != nil {
			return nil, err
		}
		if o.KEMCiphertext, err = rB(r); err != nil {
			return nil, err
		}
		if o.ViewTag, err = rB(r); err != nil {
			return nil, err
		}
		if o.Commitment, err = rB(r); err != nil {
			return nil, err
		}
		if o.EncAmount, err = rB(r); err != nil {
			return nil, err
		}
		if o.MAC, err = rB(r); err != nil {
			return nil, err
		}
		t.PQOutputs = append(t.PQOutputs, o)
	}
	if t.PQBlindDiff, err = rB(r); err != nil {
		return nil, err
	}
	nvi, err := rU64(r)
	if err != nil {
		return nil, err
	}
	if nvi > MaxInputs {
		return nil, errors.New("tx: too many vault inputs")
	}
	for i := uint64(0); i < nvi; i++ {
		var in VaultIn
		if in.VaultKey, err = rB(r); err != nil {
			return nil, err
		}
		if in.Yield, err = rU64(r); err != nil {
			return nil, err
		}
		if in.Sig, err = rB(r); err != nil {
			return nil, err
		}
		t.VaultInputs = append(t.VaultInputs, in)
	}
	nvo, err := rU64(r)
	if err != nil {
		return nil, err
	}
	if nvo > MaxOutputs {
		return nil, errors.New("tx: too many vault outputs")
	}
	for i := uint64(0); i < nvo; i++ {
		var o VaultOut
		if o.VaultKey, err = rB(r); err != nil {
			return nil, err
		}
		if o.Amount, err = rU64(r); err != nil {
			return nil, err
		}
		if o.Term, err = rU64(r); err != nil {
			return nil, err
		}
		if o.OwnerKey, err = rB(r); err != nil {
			return nil, err
		}
		t.VaultOutputs = append(t.VaultOutputs, o)
	}
	nzk, err := rU64(r)
	if err != nil {
		return nil, err
	}
	if nzk > MaxInputs {
		return nil, errors.New("tx: too many zk inputs")
	}
	for i := uint64(0); i < nzk; i++ {
		var in ZKInput
		if in.Nullifier, err = rB(r); err != nil {
			return nil, err
		}
		if in.Amount, err = rU64(r); err != nil {
			return nil, err
		}
		if in.Anchor, err = rB(r); err != nil {
			return nil, err
		}
		if in.Proof, err = rB(r); err != nil {
			return nil, err
		}
		t.ZKInputs = append(t.ZKInputs, in)
	}
	nzko, err := rU64(r)
	if err != nil {
		return nil, err
	}
	if nzko > MaxOutputs {
		return nil, errors.New("tx: too many zk outputs")
	}
	for i := uint64(0); i < nzko; i++ {
		var o ZKOutput
		if o.Leaf, err = rB(r); err != nil {
			return nil, err
		}
		if o.Amount, err = rU64(r); err != nil {
			return nil, err
		}
		if o.MintProof, err = rB(r); err != nil {
			return nil, err
		}
		if o.Key, err = rB(r); err != nil {
			return nil, err
		}
		if o.TxPubKey, err = rB(r); err != nil {
			return nil, err
		}
		if o.ViewTag, err = r.ReadByte(); err != nil {
			return nil, err
		}
		t.ZKOutputs = append(t.ZKOutputs, o)
	}
	ncz, err := rU64(r)
	if err != nil {
		return nil, err
	}
	if ncz > MaxInputs {
		return nil, errors.New("tx: too many confidential zk spends")
	}
	for i := uint64(0); i < ncz; i++ {
		var s CZKSpend
		if s.Nullifier, err = rB(r); err != nil {
			return nil, err
		}
		if s.Anchor, err = rB(r); err != nil {
			return nil, err
		}
		if s.LeafOut, err = rB(r); err != nil {
			return nil, err
		}
		if s.Fee, err = rU64(r); err != nil {
			return nil, err
		}
		if s.Proof, err = rB(r); err != nil {
			return nil, err
		}
		if s.Key, err = rB(r); err != nil {
			return nil, err
		}
		if s.TxPubKey, err = rB(r); err != nil {
			return nil, err
		}
		if s.ViewTag, err = r.ReadByte(); err != nil {
			return nil, err
		}
		if s.EncAmount, err = rB(r); err != nil {
			return nil, err
		}
		t.CZKSpends = append(t.CZKSpends, s)
	}
	return t, nil
}

// Hash returns the transaction id (blake2b-256 of canonical bytes).
func (t *Transaction) Hash() [32]byte {
	return blake2b.Sum256(t.Serialize())
}

// CoreHash returns the Fiat-Shamir context that binds every per-input ownership
// and equality proof and the conservation proof to the transaction's content.
// It excludes the signature/proof fields themselves (which would be circular)
// and operates on a COPY, so it is safe to call concurrently (no data race).
func (t *Transaction) CoreHash() [32]byte {
	c := *t // shallow copy
	c.Conservation = nil
	c.Inputs = make([]Input, len(t.Inputs))
	for i, in := range t.Inputs {
		c.Inputs[i] = Input{
			OutputRef:        in.OutputRef,
			PseudoCommitment: in.PseudoCommitment,
			KeyImage:         in.KeyImage, // nullifier value is bound; proof is not
			// OwnershipProof, EqualityProof, KeyImageProof deliberately excluded
		}
	}
	c.AnonInputs = make([]AnonInput, len(t.AnonInputs))
	for i, in := range t.AnonInputs {
		c.AnonInputs[i] = AnonInput{
			PoolID:           in.PoolID,
			Tag:              in.Tag,
			PseudoCommitment: in.PseudoCommitment,
			// Proof deliberately excluded (it is the signature over CoreHash)
		}
	}
	c.SwapInputs = make([]SwapIn, len(t.SwapInputs))
	for i, in := range t.SwapInputs {
		c.SwapInputs[i] = SwapIn{
			SwapKey:  in.SwapKey,
			IsRefund: in.IsRefund,
			// Sig deliberately excluded (it signs CoreHash)
		}
	}
	// SwapOutputs are content (no signatures) → included as-is.
	// PQ inputs: bind content (OutputRef, P, WotsRoot, Nullifier); exclude the
	// HybridSig (it signs this) and the Membership proof (bound to a root, not
	// the tx). PQBlindDiff is a conservation witness → excluded like Conservation.
	c.PQBlindDiff = nil
	c.PQInputs = make([]PQInput, len(t.PQInputs))
	for i, in := range t.PQInputs {
		c.PQInputs[i] = PQInput{
			OutputRef: in.OutputRef,
			P:         in.P,
			WotsRoot:  in.WotsRoot,
			Nullifier: in.Nullifier,
			Anchor:    in.Anchor, // bound: a spender cannot swap the anchor
		}
	}
	// PQOutputs are content → included as-is.
	// Vault inputs: bind the VaultKey, exclude the Sig (which signs this CoreHash).
	// Vault outputs are content → included as-is (shallow copy in c).
	c.VaultInputs = make([]VaultIn, len(t.VaultInputs))
	for i, in := range t.VaultInputs {
		c.VaultInputs[i] = VaultIn{VaultKey: in.VaultKey, Yield: in.Yield}
	}
	// ZK inputs: bind Serial/Amount/Anchor; exclude the STARK Proof (which is itself
	// bound to this CoreHash via the proof's transcript domain — see chain validation).
	c.ZKInputs = make([]ZKInput, len(t.ZKInputs))
	for i, in := range t.ZKInputs {
		c.ZKInputs[i] = ZKInput{Nullifier: in.Nullifier, Amount: in.Amount, Anchor: in.Anchor}
	}
	// Confidential ZK spends: bind Serial/Anchor/LeafOut/Fee + stealth metadata; exclude
	// the STARK Proof (itself bound to this CoreHash via its transcript domain).
	c.CZKSpends = make([]CZKSpend, len(t.CZKSpends))
	for i, s := range t.CZKSpends {
		c.CZKSpends[i] = CZKSpend{Nullifier: s.Nullifier, Anchor: s.Anchor, LeafOut: s.LeafOut,
			Fee: s.Fee, Key: s.Key, TxPubKey: s.TxPubKey, ViewTag: s.ViewTag, EncAmount: s.EncAmount}
	}
	// ZK outputs: bind Leaf/Amount + stealth metadata; exclude the MintProof.
	c.ZKOutputs = make([]ZKOutput, len(t.ZKOutputs))
	for i, o := range t.ZKOutputs {
		c.ZKOutputs[i] = ZKOutput{Leaf: o.Leaf, Amount: o.Amount, Key: o.Key, TxPubKey: o.TxPubKey, ViewTag: o.ViewTag}
	}
	// Bind the network/instance id (config.NetID) into the Fiat-Shamir context so
	// every proof/signature keyed on CoreHash — per-input ownership/equality/
	// conservation Schnorr proofs, anon-spend proofs, swap claim/refund signatures
	// (which sign CoreHash), PQ hybrid signatures, and the ZK/CZK STARK tx-binding
	// domain (zkBind = CoreHash) — is unique to THIS chain instance and cannot
	// replay verbatim on a sibling instance that re-minted the same coins
	// (SECURITY_AUDIT: cross-instance replay).
	nid := config.NetID()
	var buf bytes.Buffer
	buf.Write([]byte("OBX/tx/corehash/v1"))
	buf.Write(nid[:])
	buf.Write(c.Serialize())
	return blake2b.Sum256(buf.Bytes())
}

// HashHex returns the hex-encoded transaction id.
func (t *Transaction) HashHex() string {
	h := t.Hash()
	return toHex(h[:])
}

func toHex(b []byte) string {
	const hexdig = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdig[c>>4]
		out[i*2+1] = hexdig[c&0xf]
	}
	return string(out)
}
