package stark

// Goldilocks DEGREE-2 EXTENSION FIELD F_{p^2}.
//
// WHY THIS EXISTS (crypto-audit, Fiat-Shamir soundness): every soundness-critical
// STARK challenge — the FRI fold α, the out-of-domain point z, the composition and
// DEEP combination coefficients — must be sampled from a field large enough that the
// algebraic error terms (Schwartz-Zippel / FRI proximity-gap bounds, all of the form
// deg/|F|) are negligible. Sampling them from the base Goldilocks field F_p caps |F|
// at 2^64 ≈ 1.8·10^19, so a single soundness term is floored at ~2^-64 BEFORE the
// per-query / number-of-constraints multipliers erode it further (the audit measured
// the effective level at ~2^-46). The standard fix used by Plonky2, Winterfell and
// ethSTRARK is to draw these challenges from a small EXTENSION field while keeping the
// trace and Merkle commitments in the base field. This file provides that extension.
//
// CONSTRUCTION: F_{p^2} = F_p[u]/(u^2 − NR), where NR is a quadratic NON-RESIDUE of
// F_p. We use NR = 7, the multiplicative generator of Goldilocks (ntt.go): a generator
// has order p−1 (even) and therefore is not a square, so u^2 − 7 is irreducible over
// F_p and the quotient is a field. (init() below verifies this at startup via the Euler
// criterion 7^((p−1)/2) = −1.)
//
// An element is a + b·u, stored as {A, B} with A, B ∈ F_p. Embedding F_p ↪ F_{p^2} is
// x ↦ x + 0·u. |F_{p^2}| = p^2 ≈ 2^128, so the floored soundness term drops to ~2^-128.

// ext2NonResidue is the quadratic non-residue NR with u^2 = NR. It equals the
// multiplicative generator 7 (see ntt.go), which is provably a non-residue.
const ext2NonResidue uint64 = generator // = 7

// audit:SECURITY_AUDIT_2026-07-01 — irreducibility of u^2−NR is soundness-critical
// (if NR were a square, F_p[u]/(u^2−NR) would not be a field and every extension-field
// Fiat-Shamir challenge would be unsound). Enforce it at startup, not only in tests:
// by Euler's criterion a quadratic non-residue r satisfies r^((p−1)/2) = −1 = p−1.
// Panic immediately if the constant is ever miswired. Mirrors TestExt2NonResidue.
func init() {
	if uint64(Felt(ext2NonResidue).Exp((P-1)/2)) != P-1 {
		panic("stark: ext2NonResidue is not a quadratic non-residue of Goldilocks; u^2−NR is reducible and the extension field is unsound")
	}
}

// Felt2 is an element a + b·u of F_{p^2} = F_p[u]/(u^2 − 7).
type Felt2 struct {
	A Felt // constant term
	B Felt // coefficient of u
}

// Felt2From embeds a base-field element x as x + 0·u.
func Felt2From(x Felt) Felt2 { return Felt2{A: x, B: 0} }

// NewFelt2 builds a + b·u from two base elements.
func NewFelt2(a, b Felt) Felt2 { return Felt2{A: a, B: b} }

// Zero2 / One2 are the additive and multiplicative identities.
func Zero2() Felt2 { return Felt2{A: 0, B: 0} }
func One2() Felt2  { return Felt2{A: 1, B: 0} }

// IsZero reports whether x == 0.
func (x Felt2) IsZero() bool { return x.A == 0 && x.B == 0 }

// Equal reports whether x == y.
func (x Felt2) Equal(y Felt2) bool { return x.A == y.A && x.B == y.B }

// IsBase reports whether x lies in the embedded base field (b == 0).
func (x Felt2) IsBase() bool { return x.B == 0 }

// Add returns x + y (componentwise).
func (x Felt2) Add(y Felt2) Felt2 {
	return Felt2{A: x.A.Add(y.A), B: x.B.Add(y.B)}
}

// Sub returns x − y (componentwise).
func (x Felt2) Sub(y Felt2) Felt2 {
	return Felt2{A: x.A.Sub(y.A), B: x.B.Sub(y.B)}
}

// Neg returns −x.
func (x Felt2) Neg() Felt2 {
	return Felt2{A: Felt(0).Sub(x.A), B: Felt(0).Sub(x.B)}
}

// Mul returns x · y. With u^2 = NR:
//
//	(a + b·u)(c + d·u) = (a·c + b·d·NR) + (a·d + b·c)·u.
func (x Felt2) Mul(y Felt2) Felt2 {
	nr := Felt(ext2NonResidue)
	ac := x.A.Mul(y.A)
	bd := x.B.Mul(y.B)
	ad := x.A.Mul(y.B)
	bc := x.B.Mul(y.A)
	return Felt2{
		A: ac.Add(bd.Mul(nr)),
		B: ad.Add(bc),
	}
}

// MulBase returns x · s for a base-field scalar s (cheaper than a full Felt2 mul).
func (x Felt2) MulBase(s Felt) Felt2 {
	return Felt2{A: x.A.Mul(s), B: x.B.Mul(s)}
}

// Square returns x². (a + b·u)² = (a² + b²·NR) + (2·a·b)·u.
func (x Felt2) Square() Felt2 {
	nr := Felt(ext2NonResidue)
	aa := x.A.Mul(x.A)
	bb := x.B.Mul(x.B)
	ab := x.A.Mul(x.B)
	return Felt2{
		A: aa.Add(bb.Mul(nr)),
		B: ab.Add(ab),
	}
}

// Norm returns the field norm N(x) = x · Frobenius(x) = a² − NR·b² ∈ F_p. It is the
// product of x with its conjugate; x is invertible iff N(x) ≠ 0.
func (x Felt2) Norm() Felt {
	nr := Felt(ext2NonResidue)
	aa := x.A.Mul(x.A)
	bb := x.B.Mul(x.B)
	return aa.Sub(bb.Mul(nr))
}

// Conj returns the conjugate (Frobenius) a − b·u. Since u^p = −u for a non-residue u,
// Frobenius (x ↦ x^p) sends a + b·u to a − b·u.
func (x Felt2) Conj() Felt2 {
	return Felt2{A: x.A, B: Felt(0).Sub(x.B)}
}

// Inv returns x^(−1) = Conj(x)/N(x). Inv(0) is 0 by convention (matching Felt.Inv).
func (x Felt2) Inv() Felt2 {
	if x.IsZero() {
		return Zero2()
	}
	ninv := x.Norm().Inv()
	c := x.Conj()
	return Felt2{A: c.A.Mul(ninv), B: c.B.Mul(ninv)}
}

// Exp returns x^e by square-and-multiply (e a base-field-sized exponent).
func (x Felt2) Exp(e uint64) Felt2 {
	result := One2()
	base := x
	for e > 0 {
		if e&1 == 1 {
			result = result.Mul(base)
		}
		base = base.Square()
		e >>= 1
	}
	return result
}

// Frobenius returns x^p, the generator of Gal(F_{p^2}/F_p). For this quadratic
// extension it coincides with conjugation: (a + b·u)^p = a − b·u.
func (x Felt2) Frobenius() Felt2 { return x.Conj() }
