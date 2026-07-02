package commit

import (
	"errors"

	"filippo.io/edwards25519"
)

// Spend-authentication proofs for the sound transaction model.
//
//   - Ownership: a Schnorr proof of knowledge of the one-time secret x with
//     P = x·G, proving the spender owns the output. Bound to the tx CoreHash.
//   - Value equality: a Schnorr proof that a re-blinded pseudo-commitment C'
//     commits to the SAME value as the output's on-chain commitment C, i.e.
//     C' − C = d·G for a known d = r' − r. This binds the spent amount so it
//     cannot be inflated at spend time.

// domCtx prefixes a per-proof-type domain label to ctx so a Schnorr-DLog proof
// produced for one statement type (ownership / value-equality / conservation)
// can never be accepted as another, even when the points and ctx coincide
// (defense-in-depth against cross-protocol confusion).
func domCtx(tag string, ctx []byte) []byte {
	out := make([]byte, 0, len(tag)+1+len(ctx))
	out = append(out, tag...)
	out = append(out, 0x1f) // unit separator
	return append(out, ctx...)
}

const (
	domOwnership    = "Obscura/dlog/ownership/v1"
	domValueEq      = "Obscura/dlog/value-equality/v1"
	domConservation = "Obscura/dlog/conservation/v1"
)

// ProveOwnership proves knowledge of x with P = x·G, bound to ctx.
func ProveOwnership(P []byte, x *edwards25519.Scalar, ctx []byte) ([]byte, error) {
	Pp, err := parsePoint(P)
	if err != nil {
		return nil, err
	}
	return ProveDLog(Pp, x, domCtx(domOwnership, ctx)).Serialize(), nil
}

// VerifyOwnership checks an ownership proof for output key P.
func VerifyOwnership(P, proofBytes, ctx []byte) bool {
	Pp, err := parsePoint(P)
	if err != nil {
		return false
	}
	// reject the identity point (x=0) and low-order points
	if Pp.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}
	pf, err := ParseSchnorrProof(proofBytes)
	if err != nil {
		return false
	}
	return VerifyDLog(Pp, pf, domCtx(domOwnership, ctx))
}

// ProveValueEquality proves pseudo and commitment hide the same value, where
// d = (pseudoBlinding − commitmentBlinding). Bound to ctx.
func ProveValueEquality(pseudo, commitment []byte, d *edwards25519.Scalar, ctx []byte) ([]byte, error) {
	pp, err := parsePoint(pseudo)
	if err != nil {
		return nil, err
	}
	cp, err := parsePoint(commitment)
	if err != nil {
		return nil, err
	}
	diff := new(edwards25519.Point).Subtract(pp, cp)
	return ProveDLog(diff, d, domCtx(domValueEq, ctx)).Serialize(), nil
}

// VerifyValueEquality checks that pseudo and commitment commit to the same value.
func VerifyValueEquality(pseudo, commitment, proofBytes, ctx []byte) bool {
	pp, err := parsePoint(pseudo)
	if err != nil {
		return false
	}
	cp, err := parsePoint(commitment)
	if err != nil {
		return false
	}
	diff := new(edwards25519.Point).Subtract(pp, cp)
	pf, err := ParseSchnorrProof(proofBytes)
	if err != nil {
		return false
	}
	return VerifyDLog(diff, pf, domCtx(domValueEq, ctx))
}

var errSpend = errors.New("commit: spend proof invalid")
