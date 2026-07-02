// Package swap implements the Obscura side of a trustless XMR↔Obscura atomic
// swap (Block 13 — see docs/INVENTION_SWAPS.md): a timelocked swap output whose
// claim path is a 2-of-2 (maker+taker) Schnorr signature produced via an adaptor
// pre-signature, so completing the claim on-chain REVEALS the swap secret to the
// counterparty (atomicity), and whose refund path returns funds after a
// timelock. It reuses the adaptor-signature cornerstone in pkg/commit.
package swap

import (
	"errors"

	"filippo.io/edwards25519"

	"obscura/pkg/commit"
	"obscura/pkg/config"
)

// AggregateKey returns the 2-of-2 claim key K = A + B.
//
// SECURITY: plain key addition is rogue-key-vulnerable. A claimer can pick a
// rogue contribution A' = R − B (for any point R they fully control) so that
// K = A' + B = R is a key whose discrete log they alone know; they then sign
// the OBX claim with a fresh independent signature INSTEAD of adapting the
// 2-of-2 pre-signature, stealing the OBX while revealing NOTHING the
// counterparty can extract → the cross-chain leg never unlocks (direct theft).
//
// This raw aggregation is therefore NEVER used by consensus on its own. The
// chain stores BOTH contributions A and B together with a proof-of-possession
// for each (see VerifyPossession / AggregateKeyVerified) so a rogue A' = R − B
// cannot be registered (the attacker cannot prove knowledge of its discrete
// log), AND it binds the pre-signature nonce R and adaptor point T into the
// swap output so the claim path can enforce sig.R == R + T (ClaimBindingOK),
// guaranteeing the published signature is the ADAPTED pre-signature and hence
// that Extract recovers the real adaptor secret (atomicity). See validate.go.
func AggregateKey(A, B *edwards25519.Point) *edwards25519.Point {
	return new(edwards25519.Point).Add(A, B)
}

// popDomain separates swap proof-of-possession challenges from every other
// Schnorr proof in the system (Fiat-Shamir domain separation).
var popDomain = []byte("Obscura/swap/pop")

// ProvePossession returns a Schnorr proof of knowledge of the discrete log x of
// the contributed claim-key share P = x·G. Each cosigner attaches one for their
// half before the shares are aggregated, defeating rogue-key key cancellation.
func ProvePossession(x *edwards25519.Scalar) []byte {
	P := new(edwards25519.Point).ScalarBaseMult(x)
	return commit.ProveDLog(P, x, popDomain).Serialize()
}

// VerifyPossession checks a proof-of-possession for the 32-byte contributed key
// share P. It rejects the identity point (whose trivial discrete log 0 would let
// a rogue cancel the honest share to control the aggregate alone).
func VerifyPossession(P []byte, proof []byte) bool {
	Pp, err := new(edwards25519.Point).SetBytes(P)
	if err != nil {
		return false
	}
	if Pp.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}
	pf, err := commit.ParseSchnorrProof(proof)
	if err != nil {
		return false
	}
	return commit.VerifyDLog(Pp, pf, popDomain)
}

// AggregateKeyVerified verifies a proof-of-possession for EACH contributed share
// A and B and, only if both hold, returns the aggregate claim key K = A + B.
// This is the rogue-key-safe aggregation consensus uses: an attacker cannot
// register a cancelling share A' = R − B because they cannot prove knowledge of
// its discrete log. Returns nil on any failure.
func AggregateKeyVerified(A, B, popA, popB []byte) *edwards25519.Point {
	if !VerifyPossession(A, popA) || !VerifyPossession(B, popB) {
		return nil
	}
	Ap, err := new(edwards25519.Point).SetBytes(A)
	if err != nil {
		return nil
	}
	Bp, err := new(edwards25519.Point).SetBytes(B)
	if err != nil {
		return nil
	}
	return AggregateKey(Ap, Bp)
}

// ClaimBindingOK enforces the atomicity binding at the consensus claim path: the
// published full signature's nonce sigR MUST equal R + T, where R is the
// pre-signature nonce and T the adaptor point committed into the swap output at
// funding time. Adapt produces exactly full.R = R + T, so ONLY a signature
// adapted from the agreed pre-signature passes — which forces the published
// signature to reveal the adaptor secret t (Extract = s_full − s' = t). A rogue
// independent signature uses a different, unbound nonce and is rejected.
func ClaimBindingOK(sigR, R, T []byte) bool {
	sr, err := new(edwards25519.Point).SetBytes(sigR)
	if err != nil {
		return false
	}
	Rp, err := new(edwards25519.Point).SetBytes(R)
	if err != nil {
		return false
	}
	Tp, err := new(edwards25519.Point).SetBytes(T)
	if err != nil {
		return false
	}
	// Reject identity adaptor point: T = 0 ⇒ R+T = R ⇒ a plain signature would
	// satisfy the binding while revealing nothing (atomicity collapse).
	if Tp.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}
	want := new(edwards25519.Point).Add(Rp, Tp)
	return sr.Equal(want) == 1
}

// CoSignClaim builds the AGGREGATE adaptor pre-signature for spending the swap
// output's claim path, from both cosigners' secret keys (a, b) and nonces
// (ra, rb), bound to adaptor point T. In a real swap each party computes only
// its own half (r_i + e·x_i) and they exchange halves; this combines them.
//
//	K = A + B ; R = Ra + Rb ; e = AdaptorChallenge(R+T, K, m)
//	ŝ = (ra + e·a) + (rb + e·b)
//
// The result verifies via commit.PreVerify(K, m, T, ·); the holder of t adapts
// it (commit.Adapt) into a full signature valid under K; and from the pre-sig +
// the published full signature anyone runs commit.Extract to recover t.
func CoSignClaim(a, b, ra, rb *edwards25519.Scalar, m []byte, T *edwards25519.Point) (*commit.AdaptorSig, *edwards25519.Point) {
	A := new(edwards25519.Point).ScalarBaseMult(a)
	B := new(edwards25519.Point).ScalarBaseMult(b)
	K := AggregateKey(A, B)
	R := new(edwards25519.Point).Add(
		new(edwards25519.Point).ScalarBaseMult(ra),
		new(edwards25519.Point).ScalarBaseMult(rb),
	)
	e := commit.AdaptorChallenge(new(edwards25519.Point).Add(R, T), K, m)
	sa := new(edwards25519.Scalar).Add(ra, new(edwards25519.Scalar).Multiply(e, a))
	sb := new(edwards25519.Scalar).Add(rb, new(edwards25519.Scalar).Multiply(e, b))
	sHat := new(edwards25519.Scalar).Add(sa, sb)
	return &commit.AdaptorSig{R: R.Bytes(), S: sHat.Bytes()}, K
}

// SwapOutput locks OBX value with two mutually-exclusive spend paths:
//   - CLAIM:  before UnlockHeight, a valid Schnorr signature under ClaimKey
//     (the 2-of-2 aggregate key) — its publication reveals the secret.
//   - REFUND: at/after UnlockHeight, a valid Schnorr signature under RefundKey
//     (the funder's key).
//
// This is the consensus-enforceable shape; wiring it into the transaction format
// is a follow-on, but the verification logic is final here.
type SwapOutput struct {
	ClaimKey     []byte // 32B aggregate key K = A + B
	RefundKey    []byte // 32B funder key
	UnlockHeight uint64
	// Amount is the OBX value locked in this contract. When read back from the chain
	// it is the AUTHORITATIVE on-chain value (the SwapEntry.Amount that consensus
	// folds into the funding conservation proof — see pkg/chain/validate.go), NOT a
	// funder-self-reported number. The taker checks it == the agreed OBXAmount before
	// locking any XNO, so it cannot be funded underweight.
	Amount uint64
	// Atomicity binding (see ClaimBindingOK): the agreed pre-signature nonce R and
	// adaptor point T committed at funding time. The claim path enforces
	// sig.R == ClaimR + ClaimT so a claim cannot be a rogue independent signature.
	ClaimR []byte // 32B pre-signature nonce R
	ClaimT []byte // 32B adaptor point T (must be non-identity)
}

// VerifyClaim accepts a claim spend: only a reorg margin BEFORE the unlock height
// (height + config.SwapReorgMargin <= UnlockHeight), with a valid signature under the
// aggregate ClaimKey, AND only if the signature is bound to the committed pre-signature
// (sig.R == ClaimR + ClaimT), so the on-chain claim necessarily reveals the adaptor
// secret (atomicity).
//
// The +SwapReorgMargin is the #11 reorg grace margin: it pulls the claim deadline a
// margin of blocks BEFORE UnlockHeight, leaving a dead-zone [UnlockHeight-margin,
// UnlockHeight) where neither claim nor refund is valid. See config.SwapReorgMargin
// for the full invariant — this method and VerifyRefund and pkg/chain/validate.go all
// enforce the SAME bound. The subtraction is guarded against underflow so swaps with a
// tiny UnlockHeight (< margin) simply have no claim window (refund-only), never wrap.
func (s SwapOutput) VerifyClaim(height uint64, msg []byte, sig *commit.FullSig) bool {
	// claim valid iff height + margin <= UnlockHeight, underflow-safe.
	if s.UnlockHeight < config.SwapReorgMargin || height > s.UnlockHeight-config.SwapReorgMargin {
		return false
	}
	if !ClaimBindingOK(sig.R, s.ClaimR, s.ClaimT) {
		return false
	}
	return commit.VerifyFull(s.ClaimKey, msg, sig)
}

// VerifyRefund accepts a refund spend: only at/after the unlock height, and only
// with a valid signature under RefundKey. The refund boundary is UNCHANGED; the #11
// reorg margin is applied entirely on the claim side (see VerifyClaim /
// config.SwapReorgMargin) so the claim and refund windows are disjoint with a
// margin-wide gap.
func (s SwapOutput) VerifyRefund(height uint64, msg []byte, sig *commit.FullSig) bool {
	if height < s.UnlockHeight {
		return false
	}
	return commit.VerifyFull(s.RefundKey, msg, sig)
}

var errSwap = errors.New("swap: invalid")
