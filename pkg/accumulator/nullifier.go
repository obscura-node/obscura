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
// Nullifier binding for witness-hiding accumulator membership (Track A / ZK
// membership spend, docs/ZK_MEMBERSHIP_SPEND.md — gap 1).
//
// A witness-hiding ZKMembership proves "some accumulated prime p is in acc" but
// binds p to NOTHING — so the same coin could be spent repeatedly. This binds p
// to a deterministic, unlinkable nullifier N = U^p (U an independent generator),
// so each coin yields exactly one N (double-spends collide on N) while N reveals
// nothing about p (discrete log in a group of unknown order). The binding reuses
// the membership proof's existing commitment Z1 = g^p: an EqualExp proof shows
// N = U^p uses the SAME exponent as Z1 = g^p.
//
// SOUNDNESS SCOPE: this closes gap 1 (nullifier binding). It does NOT close gap 2
// — proving p is a valid prime in range so the underlying PoKE membership cannot
// be forged. Gap 2 is the Zerocoin-style serial/range proof (the transparent
// zk-STARK route). So this is an EXPERIMENTAL building block, not yet a sound
// stand-alone spend. See the design doc.
// ---------------------------------------------------------------------------

// uGenerator derives the independent nullifier generator U for a group.
func uGenerator(G group.Group) group.Element {
	switch g := G.(type) {
	case *group.RSAGroup:
		return g.HashToRSAGroup([]byte("OBX/acc/nullifier-U"))
	default:
		e := HashToInt([]byte("OBX/acc/nullifier-U/"+G.Name()), 256)
		return G.Exp(G.Generator(), e)
	}
}

// EqualExp is a proof that two targets share one secret exponent:
// t1 = b1^x AND t2 = b2^x. (Wesolowski PoKE on each base with one common r = x mod ℓ,
// where ℓ is bound to the full transcript — so the same x underlies both.)
type EqualExp struct {
	Q1 group.Element
	Q2 group.Element
	R  *big.Int
}

func equalExpChallenge(G group.Group, b1, b2, t1, t2 group.Element) *big.Int {
	var t []byte
	t = append(t, []byte("OBX/equalexp/"+G.Name())...)
	for _, e := range []group.Element{b1, b2, t1, t2} {
		t = append(t, G.Marshal(e)...)
	}
	return HashToPrimeChallenge(t)
}

// ProveEqualExp proves t1 = b1^x and t2 = b2^x for the same x.
func ProveEqualExp(G group.Group, b1, b2, t1, t2 group.Element, x *big.Int) *EqualExp {
	ell := equalExpChallenge(G, b1, b2, t1, t2)
	q := new(big.Int).Div(x, ell)
	r := new(big.Int).Mod(x, ell)
	return &EqualExp{Q1: G.Exp(b1, q), Q2: G.Exp(b2, q), R: r}
}

// VerifyEqualExp checks Q1^ℓ·b1^r == t1 AND Q2^ℓ·b2^r == t2 (same r ⇒ same x).
func VerifyEqualExp(G group.Group, b1, b2, t1, t2 group.Element, pf *EqualExp) bool {
	if pf == nil || pf.R == nil {
		return false
	}
	ell := equalExpChallenge(G, b1, b2, t1, t2)
	if pf.R.Sign() < 0 || pf.R.Cmp(ell) >= 0 {
		return false
	}
	lhs1 := G.Op(G.Exp(pf.Q1, ell), G.Exp(b1, pf.R))
	if !G.Equal(lhs1, t1) {
		return false
	}
	lhs2 := G.Op(G.Exp(pf.Q2, ell), G.Exp(b2, pf.R))
	return G.Equal(lhs2, t2)
}

// MembershipNullifier is a witness-hiding membership proof bound to a nullifier.
type MembershipNullifier struct {
	Mem  *ZKMembership // proves some accumulated prime p is in acc (hides which)
	N    group.Element // nullifier U^p (deterministic per coin)
	Bind *EqualExp     // proves N = U^p uses the same p as Mem's Z1 = g^p
}

// ProveMembershipNullifier produces a nullifier-bound membership proof for the
// accumulated prime p with witness w (w^p = acc).
func ProveMembershipNullifier(G group.Group, acc group.Element, p *big.Int, w group.Element) *MembershipNullifier {
	m := ProveZKMembership(G, acc, p, w) // m.Proof.Z1 == g^p
	U := uGenerator(G)
	N := G.Exp(U, p)
	bind := ProveEqualExp(G, G.Generator(), U, m.Proof.Z1, N, p)
	return &MembershipNullifier{Mem: m, N: N, Bind: bind}
}

// VerifyMembershipNullifier checks the membership proof AND that its nullifier is
// bound to the same accumulated element (so one coin ⇒ one nullifier). The caller
// rejects a spend whose N is already in the spent-nullifier set (double-spend).
func VerifyMembershipNullifier(G group.Group, acc group.Element, mn *MembershipNullifier) bool {
	if mn == nil || mn.Mem == nil || mn.Mem.Proof == nil || mn.N == nil {
		return false
	}
	if !VerifyZKMembership(G, acc, mn.Mem) {
		return false
	}
	U := uGenerator(G)
	// Z1 (= g^p) is bound to the membership relation's exponent by the MultiPoKE,
	// so binding N = U^p to Z1 ties the nullifier to the accumulated element.
	return VerifyEqualExp(G, G.Generator(), U, mn.Mem.Proof.Z1, mn.N, mn.Bind)
}
