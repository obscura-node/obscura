package commit

import (
	"errors"

	"filippo.io/edwards25519"
)

// High-level value-conservation checks operating on serialized 32-byte
// commitment points. These let the chain verify that a transaction creates no
// money without handling curve points directly.

func parsePoint(b []byte) (*edwards25519.Point, error) {
	if len(b) != 32 {
		return nil, errors.New("commit: bad point length")
	}
	return new(edwards25519.Point).SetBytes(b)
}

// sumPoints adds a list of serialized points.
func sumPoints(pts [][]byte) (*edwards25519.Point, error) {
	acc := edwards25519.NewIdentityPoint()
	for _, b := range pts {
		p, err := parsePoint(b)
		if err != nil {
			return nil, err
		}
		acc.Add(acc, p)
	}
	return acc, nil
}

// ConservationResidual computes Σ pseudoIns − Σ outs − fee·H, which a balanced
// transaction proves equals z·G via a Schnorr proof.
func ConservationResidual(pseudoIns, outs [][]byte, fee uint64) (*edwards25519.Point, error) {
	in, err := sumPoints(pseudoIns)
	if err != nil {
		return nil, err
	}
	out, err := sumPoints(outs)
	if err != nil {
		return nil, err
	}
	feeH := new(edwards25519.Point).ScalarMult(ScalarFromUint64(fee), hPoint)
	res := new(edwards25519.Point).Subtract(in, out)
	res.Subtract(res, feeH)
	return res, nil
}

// CoinbaseResidual computes minted·H − Σ outs, which a valid coinbase proves
// equals z·G.
func CoinbaseResidual(minted uint64, outs [][]byte) (*edwards25519.Point, error) {
	out, err := sumPoints(outs)
	if err != nil {
		return nil, err
	}
	mintedH := new(edwards25519.Point).ScalarMult(ScalarFromUint64(minted), hPoint)
	return new(edwards25519.Point).Subtract(mintedH, out), nil
}

// GenResidual computes Σ pseudoIns + publicIn·H − Σ outs − publicOut·H, the
// generalized balance residual used when a tx mixes confidential inputs/outputs
// with PUBLIC (cleartext) value legs — e.g. swap outputs (public value leaving)
// and swap inputs (public value re-entering). A balanced tx proves this equals
// z·G via a Schnorr proof.
func GenResidual(pseudoIns, outs [][]byte, publicIn, publicOut uint64) (*edwards25519.Point, error) {
	in, err := sumPoints(pseudoIns)
	if err != nil {
		return nil, err
	}
	out, err := sumPoints(outs)
	if err != nil {
		return nil, err
	}
	res := new(edwards25519.Point).Subtract(in, out)
	if publicIn > 0 {
		res.Add(res, new(edwards25519.Point).ScalarMult(ScalarFromUint64(publicIn), hPoint))
	}
	if publicOut > 0 {
		res.Subtract(res, new(edwards25519.Point).ScalarMult(ScalarFromUint64(publicOut), hPoint))
	}
	return res, nil
}

// VerifyConservationGen checks the generalized balance proof.
func VerifyConservationGen(pseudoIns, outs [][]byte, publicIn, publicOut uint64, proofBytes, ctx []byte) bool {
	res, err := GenResidual(pseudoIns, outs, publicIn, publicOut)
	if err != nil {
		return false
	}
	pf, err := ParseSchnorrProof(proofBytes)
	if err != nil {
		return false
	}
	return VerifyDLog(res, pf, domCtx(domConservation, ctx))
}

// ProveConservationGen builds the generalized balance proof given the residual
// blinding z = Σ r'_in − Σ r_out.
func ProveConservationGen(pseudoIns, outs [][]byte, publicIn, publicOut uint64, z *edwards25519.Scalar, ctx []byte) ([]byte, error) {
	res, err := GenResidual(pseudoIns, outs, publicIn, publicOut)
	if err != nil {
		return nil, err
	}
	return ProveDLog(res, z, domCtx(domConservation, ctx)).Serialize(), nil
}

// VerifyConservation checks a normal transaction's balance proof.
func VerifyConservation(pseudoIns, outs [][]byte, fee uint64, proofBytes, ctx []byte) bool {
	res, err := ConservationResidual(pseudoIns, outs, fee)
	if err != nil {
		return false
	}
	pf, err := ParseSchnorrProof(proofBytes)
	if err != nil {
		return false
	}
	return VerifyDLog(res, pf, domCtx(domConservation, ctx))
}

// VerifyCoinbaseConservation checks a coinbase's balance proof.
func VerifyCoinbaseConservation(minted uint64, outs [][]byte, proofBytes, ctx []byte) bool {
	res, err := CoinbaseResidual(minted, outs)
	if err != nil {
		return false
	}
	pf, err := ParseSchnorrProof(proofBytes)
	if err != nil {
		return false
	}
	return VerifyDLog(res, pf, domCtx(domConservation, ctx))
}

// ProveConservation builds the Schnorr proof for a normal transaction given the
// residual blinding z = Σ r'_in − Σ r_out.
func ProveConservation(pseudoIns, outs [][]byte, fee uint64, z *edwards25519.Scalar, ctx []byte) ([]byte, error) {
	res, err := ConservationResidual(pseudoIns, outs, fee)
	if err != nil {
		return nil, err
	}
	return ProveDLog(res, z, domCtx(domConservation, ctx)).Serialize(), nil
}

// ProveCoinbaseConservation builds the Schnorr proof for a coinbase given
// z = −Σ r_out.
func ProveCoinbaseConservation(minted uint64, outs [][]byte, z *edwards25519.Scalar, ctx []byte) ([]byte, error) {
	res, err := CoinbaseResidual(minted, outs)
	if err != nil {
		return nil, err
	}
	return ProveDLog(res, z, domCtx(domConservation, ctx)).Serialize(), nil
}
