// Package swapsession implements the in-process TWO-PARTY core of a trustless
// XNO<->OBX atomic swap. It removes the structural flaw of the original
// single-process orchestration (cmd/obscura-swap doAtomicSwap), where ONE
// caller minted BOTH secret shares (sA,sB,a,b) and played both sides — meaning
// the "two-of-two" was only nominal. Here the protocol is split into two
// independent party objects, a MAKER and a TAKER, that each mint ONLY their own
// share and exchange messages (today via direct Go calls; a P2P/RPC transport
// can later move the same serialized messages — see messages.go).
//
// Roles & keys (see also state.go):
//   - MAKER (OBX-side funder): holds claim share b and XNO share sB, and nonce
//     rb. Knows b·G=B and sB·G=Sb; learns sA only when the on-chain claim REVEALS
//     it. Funds the OBX SwapOut, co-signs the claim, then sweeps the XNO.
//   - TAKER (XNO-side funder, OBX claimer): holds claim share a and XNO share sA,
//     and nonce ra. Knows a·G=A, sA·G=Sa. Locks XNO, builds+adapts+mines the OBX
//     claim (which pays it the OBX and reveals sA).
//
// The OBX claim key is K = A+B (rogue-key-safe via per-share PoP); the joint XNO
// account key is sA+sB, whose PUBLIC key Sa+Sb both sides derive from the public
// shares alone. The adaptor point is T = sA·G, so the published OBX claim (an
// adapted 2-of-2 signature) reveals sA, which the maker combines with sB to sweep
// the XNO.
//
// Safe leg ordering (audit fix #2): the MAKER funds the OBX SwapOut FIRST and the
// TAKER verifies it on-chain (correct claim key, amount, timelock, binding)
// before locking any XNO. The maker's downside (the locked OBX) is protected by
// the SwapOutput's on-chain refund timelock; the taker's downside is protected by
// sequencing — no XNO leaves until the OBX is provably locked. Critically, the
// party who locks XNO (taker) is NOT the party who funds OBX (maker), and NEITHER
// party mints both secret shares — directly fixing #2.
package swapsession

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"filippo.io/edwards25519"

	"obscura/pkg/commit"
	"obscura/pkg/config"
	"obscura/pkg/swap"
	"obscura/pkg/tx"
)

func pt(s *edwards25519.Scalar) *edwards25519.Point {
	return new(edwards25519.Point).ScalarBaseMult(s)
}

// randID returns a fresh 32-byte unique id (used for the on-chain swap key).
func randID() []byte { return commit.RandomScalar().Bytes() }

// ---- transport abstractions the parties depend on ---------------------------

// OBXChain is the read access both parties need to the OBX chain: the current
// height (for timelocks) and a way to verify a confirmed SwapOut by its swap key,
// so the TAKER can independently confirm the maker's lock before locking XNO.
type OBXChain interface {
	Height() uint64
	// FindSwapOut returns the confirmed on-chain SwapOut for swapKey, or ok=false
	// if it is not (yet) present in a block.
	FindSwapOut(swapKey []byte) (swap.SwapOutput, bool)
}

// MakerOBX is the MAKER's OBX-side capability: fund the SwapOut and (on abort)
// refund it. The session drives these; the host (test / cmd) owns the chain+miner.
type MakerOBX interface {
	OBXChain
	// FundSwapOut funds a SwapOut locking obxAmount OBX to claimKey (=K) with the
	// given refund key and atomicity binding, then mines it to confirmation.
	FundSwapOut(swapKey []byte, obxAmount uint64, claimKey, refundKey, claimA, claimB, popA, popB, claimR, claimT []byte, unlockHeight, fee uint64) error
	// MineRefund advances to unlockHeight and mines the refund spend (sign signs
	// the tx core hash under the refund key).
	MineRefund(swapKey []byte, obxAmount, fee, unlockHeight uint64, sign func(coreHash []byte) []byte) error
	// FindSwapSpend returns the mined CLAIM spend of swapKey if one exists on-chain:
	// the published full claim signature (64B Schnorr) and the exact tx core hash it
	// signed. ok=false if no claim has been mined for this swapKey (it is still live
	// or was refunded). This is a READ used by the F-B chain-scrape fallback: when a
	// malicious taker claims the OBX (publishing the claim sig that REVEALS the
	// adaptor secret on-chain) but withholds the off-chain ClaimDone relay, the maker
	// reads the claim straight from the chain so it can still sweep the XNO it is owed.
	FindSwapSpend(swapKey []byte) (fullSig []byte, coreHash []byte, ok bool)
}

// TakerOBX is the TAKER's OBX-side capability: build the claim spend (so its core
// hash is known) and, once signed, mine it. The taker is the claimer, so the
// claim pays the OBX into the taker's own wallet.
type TakerOBX interface {
	OBXChain
	// BuildClaim builds the claim spend paying obxAmount−fee to the taker, with
	// the signature deferred: it returns the unsigned tx and its core hash.
	BuildClaim(swapKey []byte, obxAmount, fee uint64) (t *tx.Transaction, coreHash []byte, err error)
	// MineClaim attaches sig to the claim's swap input and mines it.
	MineClaim(t *tx.Transaction, sig []byte) error
}

// XNOLocker is the TAKER's XNO-side capability (the swapd.NanoClient surface).
// amount is RAW XNO (*big.Int, 128-bit) — see swapd.NanoClient on why uint64 cannot
// hold real raw.
type XNOLocker interface {
	Lock(amount *big.Int, accountPub []byte) (string, error)
	Confirmed(lockID string) bool
}

// XNOSweeper is the MAKER's XNO-side capability: sweep a lock with the recovered
// joint account secret (swapd.NanoClient.Sweep), and read a lock's authoritative
// destination account + amount (LockInfo) so the maker can verify the taker locked
// the agreed XNO to the JOINT account BEFORE co-signing.
type XNOSweeper interface {
	Sweep(lockID string, accountSecret *edwards25519.Scalar, dest string) error
	Confirmed(lockID string) bool
	LockInfo(lockID string) (amount *big.Int, accountPub []byte, err error)
}

// ---- Maker ------------------------------------------------------------------

// Maker is the OBX-side party. It mints ONLY b (claim), sB (XNO) and nonce rb; it
// never holds a or sA (it learns sA only via the on-chain claim).
type Maker struct {
	st   *SwapState
	b    *edwards25519.Scalar
	sB   *edwards25519.Scalar
	rb   *edwards25519.Scalar
	obx  MakerOBX
	init *Init
	// The one claim core hash this maker has co-signed lives DURABLY in
	// st.CoSignedCoreHash (F3 fix). The pre-signature nonce rb is committed on-chain
	// (R=Ra+Rb) BEFORE any claim exists, so it cannot bind the core hash. Co-signing
	// two DISTINCT core hashes under the same rb would expose b=(sb1-sb2)/(e1-e2). We
	// co-sign at most ONE core hash (re-co-signing the SAME one is harmless and allowed
	// for retries). Persisting it means a maker that co-signs, crashes, and resumes via
	// ResumeMaker still refuses a second distinct co-sign. See CoSignClaim.
}

// NewMaker creates the OBX-side party. It mints fresh b and sB. xnoAmount is RAW
// XNO (*big.Int, 128-bit). A nil xnoAmount is treated as 0.
func NewMaker(swapID [32]byte, obxAmount uint64, xnoAmount *big.Int, fee uint64, sweepDest string, obx MakerOBX) *Maker {
	b := commit.RandomScalar()
	sB := commit.RandomScalar()
	return &Maker{
		b: b, sB: sB, obx: obx,
		st: &SwapState{
			SwapID: swapID, Role: RoleMaker, Phase: PhaseInit,
			OwnShareClaim: b.Bytes(), OwnShareXNO: sB.Bytes(),
			OBXAmount: obxAmount, XNOAmount: cloneAmount(xnoAmount), Fee: fee, SweepDest: sweepDest,
		},
	}
}

// cloneAmount returns a non-nil copy of a raw XNO amount (nil → 0), so SwapState
// never carries a nil *big.Int (which would panic the BigEndian serializer / Cmp).
func cloneAmount(v *big.Int) *big.Int {
	if v == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(v)
}

// ResumeMaker reconstructs a Maker from a persisted SwapState (e.g. after a crash),
// rebinding its OBX capability. It re-derives the private scalars b, sB from the
// stored own shares and re-derives the deterministic nonce rb from the SAME term hash
// used at HandleInit time, so the resumed maker is byte-identical to the pre-crash one.
// Crucially, the F3 nonce guard (st.CoSignedCoreHash) is carried in the state, so a
// maker that already co-signed comes back STILL refusing a second distinct co-sign.
func ResumeMaker(st *SwapState, obx MakerOBX) (*Maker, error) {
	if st == nil || st.Role != RoleMaker {
		return nil, errors.New("swapsession: ResumeMaker needs a maker SwapState")
	}
	b, err := new(edwards25519.Scalar).SetCanonicalBytes(st.OwnShareClaim)
	if err != nil {
		return nil, fmt.Errorf("swapsession: bad stored claim share: %w", err)
	}
	sB, err := new(edwards25519.Scalar).SetCanonicalBytes(st.OwnShareXNO)
	if err != nil {
		return nil, fmt.Errorf("swapsession: bad stored XNO share: %w", err)
	}
	th := ownTermHash(st.SwapID, pt(b).Bytes(), pt(sB).Bytes(), st.OBXAmount, st.XNOAmount)
	rb := DeriveNonce(sB, th)
	return &Maker{st: st, b: b, sB: sB, rb: rb, obx: obx}, nil
}

// State returns the maker's persistable state.
func (m *Maker) State() *SwapState { return m.st }

// HandleInit consumes+verifies the taker's Init and returns the MakerCommit.
func (m *Maker) HandleInit(init *Init) (*MakerCommit, error) {
	if init.SwapID != m.st.SwapID {
		return nil, errMsg
	}
	if init.OBXAmount != m.st.OBXAmount || cloneAmount(init.XNOAmount).Cmp(cloneAmount(m.st.XNOAmount)) != 0 {
		return nil, fmt.Errorf("swapsession: amounts disagree (maker %d/%s, init %d/%s)",
			m.st.OBXAmount, cloneAmount(m.st.XNOAmount), init.OBXAmount, cloneAmount(init.XNOAmount))
	}
	// In-band FEE agreement (F-A hardening): the maker funds/claims/refunds with its
	// own configured Fee. The taker MUST commit to the SAME number in its Init, so a
	// co-signed claim spends the fee both sides expect. A mismatch is rejected here
	// (the maker funds nothing) rather than silently funding with a fee the taker
	// never agreed to.
	if init.Fee != m.st.Fee {
		return nil, fmt.Errorf("swapsession: fee disagrees (maker %d, init %d)", m.st.Fee, init.Fee)
	}
	if err := init.Validate(); err != nil {
		return nil, fmt.Errorf("swapsession: invalid taker Init: %w", err)
	}
	m.init = init
	th := ownTermHash(m.st.SwapID, pt(m.b).Bytes(), pt(m.sB).Bytes(), m.st.OBXAmount, m.st.XNOAmount)
	m.rb = DeriveNonce(m.sB, th)

	mc := &MakerCommit{
		SwapID: m.st.SwapID,
		B:      pt(m.b).Bytes(), Sb: pt(m.sB).Bytes(),
		PoPB: swap.ProvePossession(m.b), Rb: pt(m.rb).Bytes(),
	}
	K, R, xnoPub, err := jointKeys(init, mc)
	if err != nil {
		return nil, err
	}
	m.st.PeerClaimShare = append([]byte(nil), init.A...)
	m.st.PeerXNOShare = append([]byte(nil), init.Sa...)
	m.st.OwnNonceR = mc.Rb
	m.st.PeerNonceR = append([]byte(nil), init.Ra...)
	m.st.AdaptorT = append([]byte(nil), init.T...)
	m.st.ClaimKey = K.Bytes()
	m.st.AggNonceR = R.Bytes()
	m.st.XNOAccountPub = xnoPub
	return mc, nil
}

// Fund runs the FIRST leg: lock OBX to K=A+B (refund key = own B) with binding
// R+T at unlockHeight, confirm it, and announce via Funded. After HandleInit.
func (m *Maker) Fund(unlockHeight uint64) (*Funded, error) {
	if m.init == nil {
		return nil, errors.New("swapsession: Fund before HandleInit")
	}
	// F-1 FIX (fund-freeze): an HONEST maker must not misconfigure an unclaimable swap.
	// The chosen unlockHeight must leave an OPEN claim window above the reorg margin at
	// the maker's current height (claim valid iff height + SwapReorgMargin <= UnlockHeight),
	// with SwapMinClaimWindow headroom for the off-chain XNO lock + co-sign + claim mining.
	// Funding below this would lock the maker's OBX into a swap the taker can never claim
	// (it would refuse to lock XNO), and consensus rejects an even tighter unlock outright.
	if min := m.obx.Height() + config.SwapReorgMargin + config.SwapMinClaimWindow; unlockHeight < min {
		return nil, fmt.Errorf("swapsession: unlock height %d leaves no claim window at height %d (need >= %d)",
			unlockHeight, m.obx.Height(), min)
	}
	swapKey := randID()
	if err := m.obx.FundSwapOut(swapKey, m.st.OBXAmount,
		m.st.ClaimKey, pt(m.b).Bytes(),
		m.init.A, pt(m.b).Bytes(), m.init.PoPA, swap.ProvePossession(m.b),
		m.st.AggNonceR, m.st.AdaptorT, unlockHeight, m.st.Fee); err != nil {
		return nil, fmt.Errorf("swapsession: fund OBX swap: %w", err)
	}
	m.st.SwapKey = swapKey
	m.st.UnlockHeight = unlockHeight
	m.st.Phase = PhaseFunded
	return &Funded{SwapID: m.st.SwapID, SwapKey: swapKey, UnlockHeight: unlockHeight}, nil
}

// ConfirmXNOLock records the taker's XNO lock after confirming it on the Nano
// ledger. The maker only co-signs the claim once the XNO it expects is locked.
func (m *Maker) ConfirmXNOLock(nano XNOSweeper, msg *XNOLocked) error {
	if msg.SwapID != m.st.SwapID {
		return errMsg
	}
	if m.st.Phase != PhaseFunded {
		return fmt.Errorf("swapsession: ConfirmXNOLock in phase %s", m.st.Phase)
	}
	if !nano.Confirmed(msg.LockID) {
		// RETRYABLE: the taker just broadcast the XNO lock; Nano needs a few seconds to
		// cement it. Distinguished so the maker POLLS for confirmation instead of aborting
		// (which would strand the taker's just-locked XNO). The account/amount checks below
		// are still terminal — only "not cemented yet" is transient.
		return ErrXNOLockNotConfirmed
	}
	// F1 FIX: existence/confirmation is NOT enough. A malicious taker can lock XNO to a
	// SELF-controlled account (or a smaller amount), get the maker to co-sign, take the
	// OBX, and leave the maker's SweepXNO unable to recover (sA+sB does not control the
	// wrong account) → the maker loses OBX with no path back. So BEFORE co-signing we
	// read the lock's AUTHORITATIVE destination account + amount from the ledger and
	// require it pays EXACTLY the joint account (sA+sB)·G the AGREED XNOAmount. Equality
	// is used for the amount (the safest choice — no silent over/under-payment tolerance).
	amount, accountPub, err := nano.LockInfo(msg.LockID)
	if err != nil {
		return fmt.Errorf("swapsession: cannot read XNO lock info — refusing to co-sign: %w", err)
	}
	if !bytes.Equal(accountPub, m.st.XNOAccountPub) {
		return errors.New("swapsession: XNO lock pays the WRONG account (not the joint sA+sB key) — refusing to co-sign")
	}
	if cloneAmount(amount).Cmp(cloneAmount(m.st.XNOAmount)) != 0 {
		return fmt.Errorf("swapsession: XNO lock amount %s != agreed %s — refusing to co-sign", cloneAmount(amount), cloneAmount(m.st.XNOAmount))
	}
	m.st.XNOLockID = msg.LockID
	m.st.Phase = PhaseXNOLock
	return nil
}

// CoSignClaim returns the maker's HALF of the 2-of-2 adaptor pre-signature for
// the claim core hash in req: ClaimPreSig{Sb = rb + e·b}. Releasing this lets the
// taker complete+publish the claim (taking OBX and revealing sA). The maker is
// protected because the claim reveals sA (which it extracts to sweep XNO) and,
// failing that, by the OBX refund timelock.
func (m *Maker) CoSignClaim(req *ClaimRequest) (*ClaimPreSig, error) {
	if req.SwapID != m.st.SwapID {
		return nil, errMsg
	}
	if m.st.XNOLockID == "" {
		return nil, errors.New("swapsession: refusing to co-sign before the XNO lock is confirmed")
	}
	// NONCE-REUSE GUARD: rb is committed on-chain (in R) before any claim exists, so
	// co-signing two DISTINCT core hashes under the same rb would leak b via
	// b=(sb1-sb2)/(e1-e2), giving the taker the full claim key K=A+B (claim OBX
	// without revealing sA → maker loses OBX, XNO frozen). Co-sign at most ONE core
	// hash; re-co-signing the SAME one (a benign retry) returns the identical half.
	if len(m.st.CoSignedCoreHash) != 0 && !bytes.Equal(m.st.CoSignedCoreHash, req.CoreHash) {
		return nil, errors.New("swapsession: refusing to co-sign a second distinct claim under the committed nonce (would leak the maker's share b)")
	}
	// GRIEFING FIX (maker-loss): verify the taker's pre-signature half ŝ_a BEFORE
	// co-signing. The taker must reveal ŝ_a = ra + e·a in the ClaimRequest; we check
	// ŝ_a·G == Ra + e·A (Ra = taker's committed nonce point from Init, A = taker's claim
	// pubkey, e = the SAME challenge preResponseHalf binds). If it does not verify we do
	// NOT co-sign — a forged/garbage ŝ_a is rejected here, so the maker never releases
	// its half against a half it cannot later use to extract sA.
	//
	// SAFE TO REVEAL PRE-CLAIM: knowing ŝ_a does NOT let the maker claim the OBX — it
	// still lacks the taker's adaptor secret sA, so it cannot form the full claim
	// signature S_full = ŝ_a + ŝ_b + sA. ŝ_a is a one-time Schnorr response that the
	// taker will publish on-chain anyway when it claims. Its value to the maker is purely
	// recovery: with ŝ_a stored, ŝ_b recomputed, and S_full scraped from the on-chain
	// claim, the maker extracts sA = S_full − ŝ_a − ŝ_b with ZERO taker cooperation.
	takerHalf, err := new(edwards25519.Scalar).SetCanonicalBytes(req.TakerHalf)
	if err != nil {
		return nil, fmt.Errorf("swapsession: bad taker pre-sig half: %w", err)
	}
	if !m.verifyTakerHalf(takerHalf, req.CoreHash) {
		return nil, errors.New("swapsession: taker pre-signature half does not verify (ŝ_a·G != Ra + e·A) — refusing to co-sign")
	}
	sb := m.preResponseHalf(m.b, m.rb, req.CoreHash)
	// Record the co-signed core hash AND the verified taker half DURABLY before returning
	// our half (F3 + griefing fix): a caller that Saves the state after CoSignClaim
	// persists both, so a crashed+resumed maker (ResumeMaker over LoadState) still refuses
	// a second distinct co-sign AND still holds ŝ_a to extract sA from the chain alone.
	m.st.CoSignedCoreHash = append([]byte(nil), req.CoreHash...)
	m.st.PeerClaimHalf = append([]byte(nil), req.TakerHalf...)
	return &ClaimPreSig{SwapID: m.st.SwapID, Sb: sb.Bytes()}, nil
}

// challenge computes e = AdaptorChallenge(R+T, K, coreHash) from the agreed state —
// the single challenge convention both halves (maker's ŝ_b and taker's ŝ_a) are
// computed under.
func (m *Maker) challenge(coreHash []byte) *edwards25519.Scalar {
	R, _ := new(edwards25519.Point).SetBytes(m.st.AggNonceR)
	T, _ := new(edwards25519.Point).SetBytes(m.st.AdaptorT)
	K, _ := new(edwards25519.Point).SetBytes(m.st.ClaimKey)
	return commit.AdaptorChallenge(new(edwards25519.Point).Add(R, T), K, coreHash)
}

// verifyTakerHalf checks the taker's claimed pre-sig half ŝ_a against the equation
// ŝ_a·G == Ra + e·A, where Ra = m.st.PeerNonceR (the taker's committed nonce point)
// and A = m.st.PeerClaimShare (the taker's claim pubkey). This is the maker's
// independent guarantee that the ŝ_a it stores will subtract correctly out of the
// on-chain S_full to reveal sA, regardless of any later taker (mis)behaviour.
func (m *Maker) verifyTakerHalf(takerHalf *edwards25519.Scalar, coreHash []byte) bool {
	Ra, err := new(edwards25519.Point).SetBytes(m.st.PeerNonceR)
	if err != nil {
		return false
	}
	A, err := new(edwards25519.Point).SetBytes(m.st.PeerClaimShare)
	if err != nil {
		return false
	}
	e := m.challenge(coreHash)
	lhs := new(edwards25519.Point).ScalarBaseMult(takerHalf)
	rhs := new(edwards25519.Point).Add(Ra, new(edwards25519.Point).ScalarMult(e, A))
	return lhs.Equal(rhs) == 1
}

// preResponseHalf computes this party's adaptor pre-response half s_i = r_i + e·x_i
// where e = AdaptorChallenge(R+T, K, m), with R, T, K taken from the agreed state.
func (m *Maker) preResponseHalf(x, r *edwards25519.Scalar, coreHash []byte) *edwards25519.Scalar {
	e := m.challenge(coreHash)
	return new(edwards25519.Scalar).Add(r, new(edwards25519.Scalar).Multiply(e, x))
}

// SweepXNO runs a maker sweep from a FULLY-FORMED aggregate pre-signature (R, ŝ) plus
// the published full sig, extracting sA = full.S − ŝ via commit.Extract. It is the
// happy-path convenience used by the in-process flow where the taker hands the maker
// the aggregate pre-sig directly. For the transport path the maker uses
// SweepXNOIndependent instead, which needs NO taker-provided aggregate — it recomputes
// ŝ_b and uses the ŝ_a it stored at co-sign time, so a taker cannot strand the maker by
// withholding the aggregate. Both end in the SAME finishSweep safety re-verification.
func (m *Maker) SweepXNO(nano XNOSweeper, presig *commit.AdaptorSig, fullSig *commit.FullSig) error {
	if m.st.Phase != PhaseXNOLock {
		return fmt.Errorf("swapsession: SweepXNO in phase %s", m.st.Phase)
	}
	recovered, err := commit.Extract(presig, fullSig)
	if err != nil {
		return fmt.Errorf("swapsession: extract sA: %w", err)
	}
	return m.finishSweep(nano, recovered)
}

// SweepXNOIndependent runs the FINAL maker leg WITHOUT any taker-relayed aggregate
// pre-signature. It extracts the adaptor secret sA from the on-chain claim ALONE:
//
//	sA = S_full − ŝ_a − ŝ_b
//
// where S_full is the published full claim response (scraped from the chain), ŝ_a is
// the taker's pre-sig half the maker VERIFIED and stored in CoSignClaim (PeerClaimHalf),
// and ŝ_b is the maker's own half, recomputed from b, rb and the co-signed core hash.
// This matches the code's sign convention exactly: Adapt sets S_full = Ŝ + sA with
// Ŝ = ŝ_a + ŝ_b (see commit.Adapt / FinalizeClaim), so S_full − ŝ_a − ŝ_b = sA.
//
// The maker NO LONGER depends on any taker cooperation after co-signing to recover its
// XNO: every input here is either on-chain (S_full) or held durably by the maker (ŝ_a,
// b, rb). The existing SweepXNO re-verification (sA·G == Sa ∧ (sA+sB)·G == account) is
// reused UNCHANGED as the safety check before paying out.
func (m *Maker) SweepXNOIndependent(nano XNOSweeper, fullSig *commit.FullSig) error {
	if m.st.Phase != PhaseXNOLock {
		return fmt.Errorf("swapsession: SweepXNOIndependent in phase %s", m.st.Phase)
	}
	if len(m.st.PeerClaimHalf) != 32 {
		return errors.New("swapsession: no stored taker pre-sig half ŝ_a — cannot extract sA independently (did the maker co-sign?)")
	}
	if len(m.st.CoSignedCoreHash) == 0 {
		return errors.New("swapsession: no co-signed core hash on record — cannot recompute the maker half ŝ_b")
	}
	saHat, err := new(edwards25519.Scalar).SetCanonicalBytes(m.st.PeerClaimHalf)
	if err != nil {
		return fmt.Errorf("swapsession: stored taker half malformed: %w", err)
	}
	sFull, err := new(edwards25519.Scalar).SetCanonicalBytes(fullSig.S)
	if err != nil {
		return fmt.Errorf("swapsession: on-chain claim response malformed: %w", err)
	}
	// recompute the maker's own half ŝ_b = rb + e·b over the co-signed core hash.
	sbHat := m.preResponseHalf(m.b, m.rb, m.st.CoSignedCoreHash)
	// sA = S_full − ŝ_a − ŝ_b.
	recovered := new(edwards25519.Scalar).Subtract(sFull, saHat)
	recovered = recovered.Subtract(recovered, sbHat)
	return m.finishSweep(nano, recovered)
}

// finishSweep performs the common tail of both sweep paths: re-verify the recovered
// adaptor secret is the taker's sA and that sA+sB controls the locked account, then
// sweep. This is the UNCHANGED safety gate — a wrong recovered value only errors here,
// never moves XNO.
func (m *Maker) finishSweep(nano XNOSweeper, recovered *edwards25519.Scalar) error {
	// recovered must equal the taker's sA: check sA·G == Sa.
	if string(pt(recovered).Bytes()) != string(m.st.PeerXNOShare) {
		return errors.New("swapsession: extracted secret is not the taker's sA — NOT sweeping")
	}
	accountSecret := new(edwards25519.Scalar).Add(recovered, m.sB)
	if string(pt(accountSecret).Bytes()) != string(m.st.XNOAccountPub) {
		return errors.New("swapsession: recovered key does not control the joint account")
	}
	m.st.Phase = PhaseClaimed
	if err := nano.Sweep(m.st.XNOLockID, accountSecret, m.st.SweepDest); err != nil {
		return fmt.Errorf("swapsession: XNO sweep: %w", err)
	}
	m.st.Phase = PhaseSwept
	return nil
}

// Refund reclaims the locked OBX via the refund branch after the unlock height.
// Used when the swap aborts after Fund but before the claim is mined (the OBX is
// still unspent). Signs the refund under the maker's own share b.
func (m *Maker) Refund() error {
	if m.st.SwapKey == nil {
		return errors.New("swapsession: nothing funded to refund")
	}
	if m.st.Phase == PhaseClaimed || m.st.Phase == PhaseSwept {
		return errors.New("swapsession: claim already settled — no refund")
	}
	err := m.obx.MineRefund(m.st.SwapKey, m.st.OBXAmount, m.st.Fee, m.st.UnlockHeight,
		func(coreHash []byte) []byte { return commit.Sign(m.b, coreHash).Serialize() })
	if err != nil {
		return fmt.Errorf("swapsession: refund: %w", err)
	}
	m.st.Phase = PhaseRefunded
	return nil
}

// ---- Taker ------------------------------------------------------------------

// Taker is the XNO-side party and OBX claimer. It mints ONLY a (claim), sA (XNO)
// and nonce ra; it never holds b or sB.
type Taker struct {
	st  *SwapState
	a   *edwards25519.Scalar
	sA  *edwards25519.Scalar
	ra  *edwards25519.Scalar
	obx TakerOBX
	mc  *MakerCommit
	// claim-time scratch, retained between BuildClaimRequest and FinalizeClaim:
	claimTx  *tx.Transaction
	coreHash []byte
	presig   *commit.AdaptorSig // the aggregate pre-sig (set in FinalizeClaim)
}

// NewTaker creates the XNO-side party. It mints fresh a and sA, derives nonce ra
// and the adaptor point T = sA·G, and prepares the Init message.
func NewTaker(swapID [32]byte, obxAmount uint64, xnoAmount *big.Int, fee uint64, obx TakerOBX) *Taker {
	a := commit.RandomScalar()
	sA := commit.RandomScalar()
	t := &Taker{
		a: a, sA: sA, obx: obx,
		st: &SwapState{
			SwapID: swapID, Role: RoleTaker, Phase: PhaseInit,
			OwnShareClaim: a.Bytes(), OwnShareXNO: sA.Bytes(),
			OBXAmount: obxAmount, XNOAmount: cloneAmount(xnoAmount), Fee: fee,
		},
	}
	th := ownTermHash(swapID, pt(a).Bytes(), pt(sA).Bytes(), obxAmount, xnoAmount)
	t.ra = DeriveNonce(sA, th)
	t.st.AdaptorT = pt(sA).Bytes()
	t.st.OwnNonceR = pt(t.ra).Bytes()
	return t
}

// State returns the taker's persistable state.
func (t *Taker) State() *SwapState { return t.st }

// Init builds the opening message carrying the taker's PUBLIC shares.
func (t *Taker) Init() *Init {
	return &Init{
		SwapID: t.st.SwapID, OBXAmount: t.st.OBXAmount, XNOAmount: cloneAmount(t.st.XNOAmount),
		Fee: t.st.Fee,
		A:   pt(t.a).Bytes(), Sa: pt(t.sA).Bytes(), PoPA: swap.ProvePossession(t.a),
		Ra:  pt(t.ra).Bytes(), T: pt(t.sA).Bytes(),
	}
}

// HandleMakerCommit verifies the maker's commit and derives the joint keys.
func (t *Taker) HandleMakerCommit(mc *MakerCommit) error {
	if mc.SwapID != t.st.SwapID {
		return errMsg
	}
	if err := mc.Validate(); err != nil {
		return fmt.Errorf("swapsession: invalid MakerCommit: %w", err)
	}
	t.mc = mc
	K, R, xnoPub, err := jointKeys(t.Init(), mc)
	if err != nil {
		return err
	}
	t.st.PeerClaimShare = append([]byte(nil), mc.B...)
	t.st.PeerXNOShare = append([]byte(nil), mc.Sb...)
	t.st.PeerNonceR = append([]byte(nil), mc.Rb...)
	t.st.ClaimKey = K.Bytes()
	t.st.AggNonceR = R.Bytes()
	t.st.XNOAccountPub = xnoPub
	return nil
}

// VerifyFundedAndLock implements SAFE LEG ORDERING. It independently verifies the
// maker's on-chain OBX SwapOut announced in `funded` — correct claim key K,
// amount, unlock height, and the atomicity binding (ClaimR=R, ClaimT=T) — and
// ONLY THEN locks the XNO to the joint account, returning the XNOLocked message.
// If verification fails it locks NOTHING (the taker keeps its XNO).
func (t *Taker) VerifyFundedAndLock(nano XNOLocker, funded *Funded) (*XNOLocked, error) {
	if funded.SwapID != t.st.SwapID {
		return nil, errMsg
	}
	if t.mc == nil {
		return nil, errors.New("swapsession: lock before MakerCommit")
	}
	so, ok := t.obx.FindSwapOut(funded.SwapKey)
	if !ok {
		// RETRYABLE: the maker may have funded a block this taker hasn't SYNCED yet (it
		// can lag the maker's miner). Distinguished so the driver polls instead of
		// aborting — and SAFE to retry because no XNO is locked until the funding is
		// found AND its terms pass checkSwapOut below.
		return nil, ErrFundingNotVisible
	}
	if err := t.checkSwapOut(so, funded.UnlockHeight); err != nil {
		return nil, fmt.Errorf("swapsession: OBX lock mismatch — NOT locking XNO: %w", err)
	}
	lockID, err := nano.Lock(cloneAmount(t.st.XNOAmount), t.st.XNOAccountPub)
	if err != nil {
		return nil, fmt.Errorf("swapsession: lock XNO: %w", err)
	}
	t.st.SwapKey = append([]byte(nil), funded.SwapKey...)
	t.st.UnlockHeight = funded.UnlockHeight
	t.st.XNOLockID = lockID
	t.st.Phase = PhaseXNOLock
	return &XNOLocked{SwapID: t.st.SwapID, LockID: lockID}, nil
}

// checkSwapOut verifies the on-chain SwapOut matches the agreed swap exactly.
func (t *Taker) checkSwapOut(so swap.SwapOutput, unlockHeight uint64) error {
	if string(so.ClaimKey) != string(t.st.ClaimKey) {
		return errors.New("claim key != K=A+B")
	}
	// F2 FIX: verify the AUTHORITATIVE on-chain locked OBX value equals the agreed
	// amount. so.Amount is the SwapEntry.Amount, which consensus binds to the real
	// committed input value via the funding conservation proof (pkg/chain/validate.go),
	// so the maker cannot fund the SwapOut underweight (e.g. half) while announcing the
	// full amount. Without this, a maker funds HALF, the taker locks FULL XNO, and the
	// taker can never claim (conservation fails) → its XNO is frozen.
	if so.Amount != t.st.OBXAmount {
		return fmt.Errorf("locked OBX amount %d != agreed %d", so.Amount, t.st.OBXAmount)
	}
	if so.UnlockHeight != unlockHeight {
		return errors.New("unlock height mismatch")
	}
	// F-1 FIX (fund-freeze): matching the announced unlock height is NOT enough — the
	// SwapOut must leave a USABLE claim window above the reorg margin at the taker's
	// CURRENT height. A claim is valid iff height + SwapReorgMargin <= UnlockHeight, so
	// a maker who funds with UnlockHeight too close to now (e.g. height+1) creates a
	// swap whose claim path is already (or imminently) DEAD: the taker would lock XNO it
	// can NEVER claim while the maker refunds risk-free → frozen XNO. Require an OPEN
	// window with SwapMinClaimWindow blocks of headroom for the off-chain XNO lock, the
	// maker co-sign, and mining the claim. Overflow-safe (the RHS only adds constants).
	if so.UnlockHeight < t.obx.Height()+config.SwapReorgMargin+config.SwapMinClaimWindow {
		return fmt.Errorf("unclaimable swap: unlock height %d leaves no claim window at height %d (need >= %d) — NOT locking XNO",
			so.UnlockHeight, t.obx.Height(), t.obx.Height()+config.SwapReorgMargin+config.SwapMinClaimWindow)
	}
	if string(so.ClaimR) != string(t.st.AggNonceR) {
		return errors.New("ClaimR != R=Ra+Rb")
	}
	if string(so.ClaimT) != string(t.st.AdaptorT) {
		return errors.New("ClaimT != T=sA·G")
	}
	// the refund key must be the maker's B (so only the maker can refund), and the
	// claim key must verifiably aggregate from the two PoP'd shares.
	if string(so.RefundKey) != string(t.st.PeerClaimShare) {
		return errors.New("refund key != maker's B")
	}
	return nil
}

// preResponseHalf computes the taker's adaptor pre-response half ŝ_a = ra + e·a,
// with e = AdaptorChallenge(R+T, K, coreHash) over the agreed aggregate nonce R, the
// adaptor point T, and the claim key K. This is computed IDENTICALLY in
// BuildClaimRequest (so the maker can verify it before co-signing) and in
// FinalizeClaim (where it is aggregated with the maker's half) — one definition, no
// divergence.
func (t *Taker) preResponseHalf(coreHash []byte) *edwards25519.Scalar {
	R, _ := new(edwards25519.Point).SetBytes(t.st.AggNonceR)
	T, _ := new(edwards25519.Point).SetBytes(t.st.AdaptorT)
	K, _ := new(edwards25519.Point).SetBytes(t.st.ClaimKey)
	e := commit.AdaptorChallenge(new(edwards25519.Point).Add(R, T), K, coreHash)
	return new(edwards25519.Scalar).Add(t.ra, new(edwards25519.Scalar).Multiply(e, t.a))
}

// BuildClaimRequest builds the (unsigned) claim spend paying the OBX to the taker
// and returns the ClaimRequest carrying its core hash AND the taker's pre-signature
// half ŝ_a for the maker to verify and co-sign. Including ŝ_a is what lets the maker
// extract sA independently from the on-chain claim (sA = S_full − ŝ_a − ŝ_b),
// removing the taker-cooperation dependency in the maker's fund-recovery path.
func (t *Taker) BuildClaimRequest() (*ClaimRequest, error) {
	if t.st.Phase != PhaseXNOLock {
		return nil, fmt.Errorf("swapsession: BuildClaimRequest in phase %s", t.st.Phase)
	}
	claimTx, coreHash, err := t.obx.BuildClaim(t.st.SwapKey, t.st.OBXAmount, t.st.Fee)
	if err != nil {
		return nil, fmt.Errorf("swapsession: build claim: %w", err)
	}
	t.claimTx = claimTx
	t.coreHash = append([]byte(nil), coreHash...)
	half := t.preResponseHalf(t.coreHash)
	return &ClaimRequest{SwapID: t.st.SwapID, CoreHash: t.coreHash, TakerHalf: half.Bytes()}, nil
}

// FinalizeClaim combines the maker's pre-sig half with the taker's own half to
// form the aggregate adaptor pre-signature, ADAPTS it with sA into a full claim
// signature, VERIFIES the full sig under K before publishing (so a bad maker half
// can't trick the taker into a useless on-chain spend), then mines the claim.
// Returns the aggregate pre-signature and the published full signature so the
// maker can extract sA (these are also on-chain). Publishing reveals sA.
func (t *Taker) FinalizeClaim(presig *ClaimPreSig) (*commit.AdaptorSig, *commit.FullSig, error) {
	if presig.SwapID != t.st.SwapID {
		return nil, nil, errMsg
	}
	if t.claimTx == nil {
		return nil, nil, errors.New("swapsession: FinalizeClaim before BuildClaimRequest")
	}
	sbHalf, err := new(edwards25519.Scalar).SetCanonicalBytes(presig.Sb)
	if err != nil {
		return nil, nil, fmt.Errorf("swapsession: bad maker half: %w", err)
	}
	// taker's own half sa = ra + e·a — the SAME ŝ_a it already revealed (and the maker
	// verified) in BuildClaimRequest's ClaimRequest. Reusing preResponseHalf guarantees
	// the two are byte-identical, so the maker's independent extraction (sA = S_full −
	// ŝ_a − ŝ_b) recovers exactly the sA baked into this published claim.
	T, _ := new(edwards25519.Point).SetBytes(t.st.AdaptorT)
	sa := t.preResponseHalf(t.coreHash)
	sHat := new(edwards25519.Scalar).Add(sa, sbHalf)
	presigAgg := &commit.AdaptorSig{R: t.st.AggNonceR, S: sHat.Bytes()}

	// sanity: the aggregate pre-sig must verify under K before we adapt+publish.
	if !commit.PreVerify(t.st.ClaimKey, t.coreHash, T, presigAgg) {
		return nil, nil, errors.New("swapsession: aggregate pre-signature invalid (bad maker half) — not publishing")
	}
	full, err := commit.Adapt(presigAgg, t.sA, T)
	if err != nil {
		return nil, nil, err
	}
	if !commit.VerifyFull(t.st.ClaimKey, t.coreHash, full) {
		return nil, nil, errors.New("swapsession: adapted claim signature invalid — not publishing")
	}
	t.presig = presigAgg
	if err := t.obx.MineClaim(t.claimTx, full.Serialize()); err != nil {
		return nil, nil, fmt.Errorf("swapsession: mine claim: %w", err)
	}
	t.st.Phase = PhaseClaimed
	return presigAgg, full, nil
}
