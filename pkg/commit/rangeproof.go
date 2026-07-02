package commit

import (
	"errors"

	"filippo.io/edwards25519"
)

// RangeBits is the bit-width of confidential amounts (values in [0, 2^64)).
const RangeBits = 64

// RangeProof proves that a Pedersen commitment C hides a value in [0, 2^64)
// without revealing it. Construction: commit to each bit b_i with
// C_i = b_i·2^i·H + r_i·G, prove each C_i opens to 0 or 2^i·H via a Schnorr OR
// proof, and require Σ C_i = C. Size is O(RangeBits); sound under the discrete
// log assumption. (Bulletproofs would compress this to O(log n); documented as
// a future optimization.)
type RangeProof struct {
	BitComms [][]byte // compressed C_i for each bit
	OrProofs []orProof
}

type orProof struct {
	E0, E1 []byte // challenges (32-byte scalars)
	S0, S1 []byte // responses  (32-byte scalars)
}

// ProveRange returns (C, blinding, proof) for value v. The returned blinding is
// the sum of per-bit blindings so the caller can use C as the canonical value
// commitment for the output.
func ProveRange(v uint64) (C *edwards25519.Point, blinding *edwards25519.Scalar, proof *RangeProof, err error) {
	C = edwards25519.NewIdentityPoint()
	blinding = edwards25519.NewScalar()
	proof = &RangeProof{
		BitComms: make([][]byte, RangeBits),
		OrProofs: make([]orProof, RangeBits),
	}

	for i := 0; i < RangeBits; i++ {
		bit := (v >> uint(i)) & 1
		ri := RandomScalar()
		// weight = 2^i
		weight := powerOfTwoScalar(i)
		// C_i = bit*2^i*H + r_i*G
		var Ci *edwards25519.Point
		if bit == 1 {
			wH := new(edwards25519.Point).ScalarMult(weight, hPoint)
			riG := new(edwards25519.Point).ScalarBaseMult(ri)
			Ci = new(edwards25519.Point).Add(wH, riG)
		} else {
			Ci = new(edwards25519.Point).ScalarBaseMult(ri)
		}
		proof.BitComms[i] = Ci.Bytes()

		// Schnorr OR: P0 = C_i (commits to 0), P1 = C_i - 2^i*H (commits to 0 too if bit=1)
		P0 := new(edwards25519.Point).Set(Ci)
		wH := new(edwards25519.Point).ScalarMult(weight, hPoint)
		P1 := new(edwards25519.Point).Subtract(Ci, wH)
		proof.OrProofs[i] = proveOR(P0, P1, ri, int(bit))

		// accumulate
		C.Add(C, Ci)
		blinding.Add(blinding, ri)
	}
	return C, blinding, proof, nil
}

// VerifyRange checks that commitment C is well-formed for proof and lies in
// range. C must equal the provided commitment the caller is validating.
func VerifyRange(C *edwards25519.Point, proof *RangeProof) bool {
	if proof == nil || len(proof.BitComms) != RangeBits || len(proof.OrProofs) != RangeBits {
		return false
	}
	sum := edwards25519.NewIdentityPoint()
	for i := 0; i < RangeBits; i++ {
		Ci, err := new(edwards25519.Point).SetBytes(proof.BitComms[i])
		if err != nil {
			return false
		}
		weight := powerOfTwoScalar(i)
		P0 := new(edwards25519.Point).Set(Ci)
		wH := new(edwards25519.Point).ScalarMult(weight, hPoint)
		P1 := new(edwards25519.Point).Subtract(Ci, wH)
		if !verifyOR(P0, P1, proof.OrProofs[i]) {
			return false
		}
		sum.Add(sum, Ci)
	}
	return sum.Equal(C) == 1
}

// proveOR proves knowledge of x with P0=x·G OR P1=x·G; `realBranch` is 0 or 1.
func proveOR(P0, P1 *edwards25519.Point, x *edwards25519.Scalar, realBranch int) orProof {
	Ps := [2]*edwards25519.Point{P0, P1}
	var T [2]*edwards25519.Point
	var e [2]*edwards25519.Scalar
	var s [2]*edwards25519.Scalar

	fake := 1 - realBranch
	// simulate fake branch
	s[fake] = RandomScalar()
	e[fake] = RandomScalar()
	// T_fake = s_fake·G - e_fake·P_fake
	sG := new(edwards25519.Point).ScalarBaseMult(s[fake])
	eP := new(edwards25519.Point).ScalarMult(e[fake], Ps[fake])
	T[fake] = new(edwards25519.Point).Subtract(sG, eP)

	// real branch commitment
	k := RandomScalar()
	T[realBranch] = new(edwards25519.Point).ScalarBaseMult(k)

	// overall challenge
	eFull := HashToScalar(netDom(), P0.Bytes(), P1.Bytes(), T[0].Bytes(), T[1].Bytes())
	// e_real = eFull - e_fake
	e[realBranch] = new(edwards25519.Scalar).Subtract(eFull, e[fake])
	// s_real = k + e_real·x
	exr := new(edwards25519.Scalar).Multiply(e[realBranch], x)
	s[realBranch] = new(edwards25519.Scalar).Add(k, exr)

	return orProof{
		E0: e[0].Bytes(), E1: e[1].Bytes(),
		S0: s[0].Bytes(), S1: s[1].Bytes(),
	}
}

func verifyOR(P0, P1 *edwards25519.Point, pf orProof) bool {
	e0, err := new(edwards25519.Scalar).SetCanonicalBytes(pf.E0)
	if err != nil {
		return false
	}
	e1, err := new(edwards25519.Scalar).SetCanonicalBytes(pf.E1)
	if err != nil {
		return false
	}
	s0, err := new(edwards25519.Scalar).SetCanonicalBytes(pf.S0)
	if err != nil {
		return false
	}
	s1, err := new(edwards25519.Scalar).SetCanonicalBytes(pf.S1)
	if err != nil {
		return false
	}
	// T_i = s_i·G - e_i·P_i
	T0 := new(edwards25519.Point).Subtract(
		new(edwards25519.Point).ScalarBaseMult(s0),
		new(edwards25519.Point).ScalarMult(e0, P0))
	T1 := new(edwards25519.Point).Subtract(
		new(edwards25519.Point).ScalarBaseMult(s1),
		new(edwards25519.Point).ScalarMult(e1, P1))
	eFull := HashToScalar(netDom(), P0.Bytes(), P1.Bytes(), T0.Bytes(), T1.Bytes())
	sum := new(edwards25519.Scalar).Add(e0, e1)
	return eFull.Equal(sum) == 1
}

// VerifyRangeBytes verifies a range proof given a serialized 32-byte commitment
// and serialized proof. Convenience wrapper for consensus code.
func VerifyRangeBytes(commitment, proofBytes []byte) bool {
	C, err := new(edwards25519.Point).SetBytes(commitment)
	if err != nil {
		return false
	}
	proof, err := ParseRangeProof(proofBytes)
	if err != nil {
		return false
	}
	return VerifyRange(C, proof)
}

// powerOfTwoScalar returns 2^i as a scalar.
func powerOfTwoScalar(i int) *edwards25519.Scalar {
	// represent 2^i in little-endian 32 bytes if i < 256
	var b [64]byte
	b[i/8] = 1 << uint(i%8)
	s, _ := edwards25519.NewScalar().SetUniformBytes(b[:])
	return s
}

// ---------------------------------------------------------------------------
// Conservation proof: prove a residual point R equals z·G for a known z
// (Schnorr proof of knowledge of discrete log). Used to prove that
// Σ inputs − Σ outputs − fee·H is a commitment to zero value.
// ---------------------------------------------------------------------------

// SchnorrProof is a NIZK proof of knowledge of x with P = x·G.
type SchnorrProof struct {
	R []byte // commitment k·G
	S []byte // response k + e·x
}

// ProveDLog proves knowledge of x with P = x·G.
func ProveDLog(P *edwards25519.Point, x *edwards25519.Scalar, ctx []byte) *SchnorrProof {
	k := RandomScalar()
	R := new(edwards25519.Point).ScalarBaseMult(k)
	e := HashToScalar(netDom(), ctx, P.Bytes(), R.Bytes())
	s := new(edwards25519.Scalar).Add(k, new(edwards25519.Scalar).Multiply(e, x))
	return &SchnorrProof{R: R.Bytes(), S: s.Bytes()}
}

// VerifyDLog checks a Schnorr proof: s·G == R + e·P.
func VerifyDLog(P *edwards25519.Point, pf *SchnorrProof, ctx []byte) bool {
	R, err := new(edwards25519.Point).SetBytes(pf.R)
	if err != nil {
		return false
	}
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(pf.S)
	if err != nil {
		return false
	}
	e := HashToScalar(netDom(), ctx, P.Bytes(), R.Bytes())
	lhs := new(edwards25519.Point).ScalarBaseMult(s)
	rhs := new(edwards25519.Point).Add(R, new(edwards25519.Point).ScalarMult(e, P))
	return lhs.Equal(rhs) == 1
}

var errRange = errors.New("commit: range proof invalid")
