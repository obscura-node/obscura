// SECURITY: PROTOTYPE — NOT CONSENSUS-REACHABLE. The zero-knowledge class-group
// membership machinery in this file (PoKE2 / zkmem / nullifier / non-membership) has
// KNOWN, DISCLOSED soundness gaps: no prime/range proof on the exponent (membership
// forgery = inflation), a nonce-malleable nullifier (double-spend), a deterministic
// (linkable) blinder, and known-dlog auxiliary generators on the class-group backend.
// It is NOT wired into pkg/chain or pkg/mempool and MUST NOT be — the live anonymous
// spend is the Poseidon-STARK path (pkg/stark/*_air.go) + key-image nullifiers.
// tests/critical/layering/cryptoboundary_test.go enforces this boundary. Closing the
// gaps + an external crypto review are required before any of this may gate value.
// See docs/CRYPTO_AUDIT_2026-07-02.md.
package accumulator

import (
	"math/big"

	"obscura/pkg/group"
)

// ---------------------------------------------------------------------------
// Witness-hiding zero-knowledge accumulator membership.
//
// Plain PoKE2 hides the secret exponent but still needs the witness base in the
// clear, which would reveal *which* output is spent. To hide the output we also
// blind the witness: commit C = w · h^s (h an independent generator) and prove
// knowledge of (p, y=-s·p) with C^p · h^y = acc, using a multi-exponent PoKE.
//
// This gives the sender a global anonymity set: a verifier learns only that
// *some* accumulated prime is being spent, not which.
//
// NOTE (soundness scope): the prototype proves knowledge of exponents
// satisfying the relation. A production deployment additionally binds p to a
// double-spend nullifier in zero knowledge and proves p is a valid prime in
// range (Zerocoin-style serial binding). See WHITEPAPER.md "Security Status".
// ---------------------------------------------------------------------------

// MultiPoKE proves knowledge of (x1, x2) with B1^x1 · B2^x2 = T.
type MultiPoKE struct {
	Z1, Z2 group.Element // g^x1, g^x2 (commitments)
	Q      group.Element // B1^q1 · B2^q2 · g^(α1 q1 + α2 q2)
	R1, R2 *big.Int      // x1 mod ℓ, x2 mod ℓ
}

// ProveMultiPoKE proves T = B1^x1 · B2^x2.
func ProveMultiPoKE(G group.Group, B1, B2, T group.Element, x1, x2 *big.Int) *MultiPoKE {
	g := G.Generator()
	z1 := G.Exp(g, x1)
	z2 := G.Exp(g, x2)
	ell := multiChallenge(G, B1, B2, T, z1, z2)
	a1 := multiAlpha(G, "a1", B1, B2, T, z1, z2, ell)
	a2 := multiAlpha(G, "a2", B1, B2, T, z1, z2, ell)

	q1 := new(big.Int).Div(x1, ell)
	q2 := new(big.Int).Div(x2, ell)
	r1 := new(big.Int).Mod(x1, ell)
	r2 := new(big.Int).Mod(x2, ell)

	// Q = B1^q1 · B2^q2 · g^(α1 q1 + α2 q2)
	Q := G.Op(G.Exp(B1, q1), G.Exp(B2, q2))
	gexp := new(big.Int).Add(new(big.Int).Mul(a1, q1), new(big.Int).Mul(a2, q2))
	Q = G.Op(Q, G.Exp(g, gexp))
	return &MultiPoKE{Z1: z1, Z2: z2, Q: Q, R1: r1, R2: r2}
}

// VerifyMultiPoKE checks Q^ℓ · B1^r1 · B2^r2 · g^(α1 r1 + α2 r2) == T · z1^α1 · z2^α2.
func VerifyMultiPoKE(G group.Group, B1, B2, T group.Element, pf *MultiPoKE) bool {
	g := G.Generator()
	ell := multiChallenge(G, B1, B2, T, pf.Z1, pf.Z2)
	if pf.R1.Sign() < 0 || pf.R1.Cmp(ell) >= 0 || pf.R2.Sign() < 0 || pf.R2.Cmp(ell) >= 0 {
		return false
	}
	a1 := multiAlpha(G, "a1", B1, B2, T, pf.Z1, pf.Z2, ell)
	a2 := multiAlpha(G, "a2", B1, B2, T, pf.Z1, pf.Z2, ell)

	lhs := G.Op(G.Exp(pf.Q, ell), G.Op(G.Exp(B1, pf.R1), G.Exp(B2, pf.R2)))
	gexp := new(big.Int).Add(new(big.Int).Mul(a1, pf.R1), new(big.Int).Mul(a2, pf.R2))
	lhs = G.Op(lhs, G.Exp(g, gexp))

	rhs := G.Op(T, G.Op(G.Exp(pf.Z1, a1), G.Exp(pf.Z2, a2)))
	return G.Equal(lhs, rhs)
}

func multiChallenge(G group.Group, parts ...group.Element) *big.Int {
	var t []byte
	t = append(t, []byte("OBX-MultiPoKE-ell")...)
	for _, p := range parts {
		t = append(t, G.Marshal(p)...)
	}
	return HashToPrimeChallenge(t)
}

func multiAlpha(G group.Group, tag string, B1, B2, T, z1, z2 group.Element, ell *big.Int) *big.Int {
	var t []byte
	t = append(t, []byte("OBX-MultiPoKE-"+tag)...)
	for _, p := range []group.Element{B1, B2, T, z1, z2} {
		t = append(t, G.Marshal(p)...)
	}
	t = append(t, ell.Bytes()...)
	return HashToInt(t, 256)
}

// ZKMembership is a witness-hiding membership proof for the accumulator.
type ZKMembership struct {
	C     group.Element // blinded witness commitment C = w · h^s
	Proof *MultiPoKE    // proof that C^p · h^y = acc
}

// hGenerator derives the independent commitment generator h for a group.
func hGenerator(G group.Group) group.Element {
	switch g := G.(type) {
	case *group.RSAGroup:
		return g.HashToRSAGroup([]byte("OBX/acc/h"))
	default:
		// Independent generator via hashing the generator to a large exponent.
		// (Production: use a true hash-to-group with unknown dlog; documented.)
		e := HashToInt([]byte("OBX/acc/h/"+G.Name()), 256)
		return G.Exp(G.Generator(), e)
	}
}

// ProveZKMembership proves, in zero knowledge w.r.t. which element, that the
// output with prime p (witness w, w^p = acc) is accumulated.
func ProveZKMembership(G group.Group, acc group.Element, p *big.Int, w group.Element) *ZKMembership {
	h := hGenerator(G)
	s := HashToInt(append([]byte("OBX/blind"), G.Marshal(w)...), 256) // deterministic blinder
	// C = w · h^s
	C := G.Op(w, G.Exp(h, s))
	// C^p · h^y = acc, with y = -s·p
	y := new(big.Int).Mul(s, p)
	y.Neg(y)
	pf := ProveMultiPoKE(G, C, h, acc, p, y)
	return &ZKMembership{C: C, Proof: pf}
}

// VerifyZKMembership checks a witness-hiding membership proof against acc.
func VerifyZKMembership(G group.Group, acc group.Element, m *ZKMembership) bool {
	h := hGenerator(G)
	return VerifyMultiPoKE(G, m.C, h, acc, m.Proof)
}
