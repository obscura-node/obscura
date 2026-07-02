package commit

import (
	"crypto/sha512"
	"errors"
	"math/bits"

	"filippo.io/edwards25519"
)

// Triptych-style linkable one-out-of-many proof (Block 2 — see
// docs/INVENTION_ANONYMITY.md). It proves, for a public list of coin keys
// C_0..C_{N-1} (each C_i = x_i·G, a Pedersen commitment to value 0):
//
//   ∃ hidden index l and secret x_l such that C_l = x_l·G   (membership+ownership)
//
// and binds a linking tag (key image) T = x_l·U to that same hidden index, used
// as the double-spend nullifier. Log-size in N, pure Sigma over edwards25519, no
// trusted setup. Based on Groth-Kohlweiss with the Triptych key-image coupling:
// the GK response z_d and randomizers ρ_k are reused against U so the verifier's
// U-equation holds iff T = x_l·U for the same l.
//
// This is the cryptographic core of Obscura's sender anonymity: a verifier
// learns only that SOME coin in the set is being spent, never which.

// uGen is the third NUMS generator for key images (independent of G and H).
var uGen = mustHashToPoint([]byte("Obscura/keyimage/U/v1"))

// U returns the key-image generator.
func U() *edwards25519.Point { return new(edwards25519.Point).Set(uGen) }

// KeyImage returns the double-spend tag T = x·U for one-time secret x.
func KeyImage(x *edwards25519.Scalar) *edwards25519.Point {
	return new(edwards25519.Point).ScalarMult(x, uGen)
}

// canonicalTag cofactor-clears a key-image / anon tag so that the (up to 8)
// torsion variants T + Q (Q of order | 8) of one coin all collapse to the SAME
// canonical point 8·T. It also rejects a low-order tag — one for which 8·T is the
// identity (this includes the x=0 identity tag and any pure-torsion point) — since
// such a tag carries no per-coin entropy and could not pin a real nullifier.
// Returns the canonical point and false if the tag is low-order. The verification
// equations and the stored/compared nullifier MUST both use this value so that a
// torsion-mutated tag verifies as, and collides with, the original coin's spend
// (closes the Monero CVE-2017-12424 key-image torsion double-spend).
func canonicalTag(T *edwards25519.Point) (*edwards25519.Point, bool) {
	if T == nil {
		return nil, false
	}
	c := new(edwards25519.Point).MultByCofactor(T)
	if c.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, false
	}
	return c, true
}

// CanonicalNullifier maps a serialized key-image / anon tag to its canonical
// nullifier bytes (the cofactor-cleared 8·T). All chain-level nullifier storage
// and comparison MUST go through this so torsion variants of one coin's tag map
// to a single nullifier and cannot be double-spent. Returns false for a
// non-canonical encoding or a low-order (torsion-only) tag.
func CanonicalNullifier(tag []byte) ([]byte, bool) {
	T, err := new(edwards25519.Point).SetBytes(tag)
	if err != nil {
		return nil, false
	}
	c, ok := canonicalTag(T)
	if !ok {
		return nil, false
	}
	return c.Bytes(), true
}

// keyImageDom domain-separates the transparent-spend key-image proof.
const keyImageDom = "Obscura/keyimage/v1"

// ProveKeyImageProof proves that the key image T = x·U shares the secret x with
// the output key P = x·G (a DLEQ over bases G and U, bound to ctx). This lets a
// TRANSPARENT spend publish the SAME nullifier an anonymous spend of the coin
// would, unifying the two double-spend domains. Returns the serialized proof.
func ProveKeyImageProof(x *edwards25519.Scalar, ctx []byte) []byte {
	_, _, dl := ProveDLEQ(x, BasePoint, uGen, keyImageDom, ctx)
	return dl.Serialize()
}

// VerifyKeyImage checks that `keyImage` is the canonical T = x·U for the output
// one-time key P, using the same x (rejects identity points via VerifyDLEQ).
func VerifyKeyImage(P, keyImage, proof, ctx []byte) bool {
	Pp, err := new(edwards25519.Point).SetBytes(P)
	if err != nil {
		return false
	}
	T, err := new(edwards25519.Point).SetBytes(keyImage)
	if err != nil {
		return false
	}
	dl, err := ParseDLEQ(proof)
	if err != nil {
		return false
	}
	return VerifyDLEQ(BasePoint, Pp, uGen, T, dl, keyImageDom, ctx)
}

// OneOfManyProof is a log-size linkable membership proof.
type OneOfManyProof struct {
	m   int      // log2(N)
	Cl  [][]byte // m commitments to the index bits
	Ca  [][]byte // m commitments to the a_j
	Cb  [][]byte // m commitments to l_j*a_j
	Cd  [][]byte // m lower-degree-cancelling commitments (G side)
	Cdt [][]byte // m tag commitments ρ_k·U (U side)
	F   [][]byte // m responses f_j
	Za  [][]byte // m responses z_{a,j}
	Zb  [][]byte // m responses z_{b,j}
	Zd  []byte   // response z_d (shared by G and U equations)
}

// scalar helpers
func sZero() *edwards25519.Scalar { return edwards25519.NewScalar() }
func sOne() *edwards25519.Scalar  { return ScalarFromUint64(1) }
func sNeg(a *edwards25519.Scalar) *edwards25519.Scalar {
	return new(edwards25519.Scalar).Subtract(sZero(), a)
}
func sAdd(a, b *edwards25519.Scalar) *edwards25519.Scalar { return new(edwards25519.Scalar).Add(a, b) }
func sMul(a, b *edwards25519.Scalar) *edwards25519.Scalar {
	return new(edwards25519.Scalar).Multiply(a, b)
}

func commScalar(v, r *edwards25519.Scalar) *edwards25519.Point { return CommitScalar(v, r) }

// polyMulLinear multiplies polynomial p(x) (coeffs low→high) by (c0 + c1·x).
func polyMulLinear(p []*edwards25519.Scalar, c0, c1 *edwards25519.Scalar) []*edwards25519.Scalar {
	out := make([]*edwards25519.Scalar, len(p)+1)
	for i := range out {
		out[i] = sZero()
	}
	for i, coef := range p {
		out[i] = sAdd(out[i], sMul(coef, c0))
		out[i+1] = sAdd(out[i+1], sMul(coef, c1))
	}
	return out
}

// ProveOneOfMany proves C[l] = x·G (and tag T = x·U), hiding l. ctx binds the
// proof to its transaction context. Returns the proof and the tag T.
func ProveOneOfMany(ring []*edwards25519.Point, l int, x *edwards25519.Scalar, ctx []byte) (*OneOfManyProof, *edwards25519.Point, error) {
	n := len(ring)
	if n == 0 || n&(n-1) != 0 {
		return nil, nil, errors.New("commit: ring size must be a power of two")
	}
	if l < 0 || l >= n {
		return nil, nil, errors.New("commit: index out of range")
	}
	m := bits.TrailingZeros(uint(n)) // log2(n)

	// tag T = x·U
	T := new(edwards25519.Point).ScalarMult(x, uGen)

	// per-bit secrets
	lj := make([]*edwards25519.Scalar, m)
	aj := make([]*edwards25519.Scalar, m)
	rl := make([]*edwards25519.Scalar, m)
	ra := make([]*edwards25519.Scalar, m)
	rb := make([]*edwards25519.Scalar, m)
	cl := make([]*edwards25519.Point, m)
	ca := make([]*edwards25519.Point, m)
	cb := make([]*edwards25519.Point, m)
	for j := 0; j < m; j++ {
		bit := uint64((l >> j) & 1)
		lj[j] = ScalarFromUint64(bit)
		aj[j] = RandomScalar()
		rl[j] = RandomScalar()
		ra[j] = RandomScalar()
		rb[j] = RandomScalar()
		cl[j] = commScalar(lj[j], rl[j])
		ca[j] = commScalar(aj[j], ra[j])
		cb[j] = commScalar(sMul(lj[j], aj[j]), rb[j])
	}

	// rho_k randomizers and Cd_k (G side), Cdt_k (U side)
	rho := make([]*edwards25519.Scalar, m)
	cd := make([]*edwards25519.Point, m)
	cdt := make([]*edwards25519.Point, m)
	// accumulate Σ_i p_{i,k}·C_i for k=0..m-1
	sum := make([]*edwards25519.Point, m)
	for k := 0; k < m; k++ {
		sum[k] = edwards25519.NewIdentityPoint()
	}
	for i := 0; i < n; i++ {
		// p_i(x) coefficients from the per-bit factors
		poly := []*edwards25519.Scalar{sOne()}
		for j := 0; j < m; j++ {
			if (i>>j)&1 == 1 {
				// factor f_j = a_j + l_j·x  → (c0=a_j, c1=l_j)
				poly = polyMulLinear(poly, aj[j], lj[j])
			} else {
				// factor (x - f_j) = -a_j + (1-l_j)·x
				poly = polyMulLinear(poly, sNeg(aj[j]), new(edwards25519.Scalar).Subtract(sOne(), lj[j]))
			}
		}
		for k := 0; k < m; k++ {
			sum[k].Add(sum[k], new(edwards25519.Point).ScalarMult(poly[k], ring[i]))
		}
	}
	for k := 0; k < m; k++ {
		rho[k] = RandomScalar()
		cd[k] = new(edwards25519.Point).Add(sum[k], new(edwards25519.Point).ScalarBaseMult(rho[k]))
		cdt[k] = new(edwards25519.Point).ScalarMult(rho[k], uGen)
	}

	// Fiat-Shamir challenge x_c (include ring, T, ctx, and all commitments)
	xc := oomChallenge(ctx, ring, T, cl, ca, cb, cd, cdt)

	// responses
	f := make([]*edwards25519.Scalar, m)
	za := make([]*edwards25519.Scalar, m)
	zb := make([]*edwards25519.Scalar, m)
	for j := 0; j < m; j++ {
		f[j] = sAdd(sMul(lj[j], xc), aj[j])  // f_j = l_j·x + a_j
		za[j] = sAdd(sMul(rl[j], xc), ra[j]) // z_{a,j} = r_{l,j}·x + r_{a,j}
		xmf := new(edwards25519.Scalar).Subtract(xc, f[j])
		zb[j] = sAdd(sMul(rl[j], xmf), rb[j]) // z_{b,j} = r_{l,j}·(x-f_j) + r_{b,j}
	}
	// z_d = x·x^m − Σ_k ρ_k·x^k
	xm := sOne()
	for k := 0; k < m; k++ {
		xm = sMul(xm, xc)
	}
	zd := sMul(x, xm)
	xk := sOne()
	for k := 0; k < m; k++ {
		zd = new(edwards25519.Scalar).Subtract(zd, sMul(rho[k], xk))
		xk = sMul(xk, xc)
	}

	return &OneOfManyProof{
		m:  m,
		Cl: marshalPts(cl), Ca: marshalPts(ca), Cb: marshalPts(cb),
		Cd: marshalPts(cd), Cdt: marshalPts(cdt),
		F: marshalScs(f), Za: marshalScs(za), Zb: marshalScs(zb),
		Zd: zd.Bytes(),
	}, T, nil
}

// VerifyOneOfMany checks a proof and the tag T against the ring and ctx.
func VerifyOneOfMany(ring []*edwards25519.Point, T *edwards25519.Point, pf *OneOfManyProof, ctx []byte) bool {
	n := len(ring)
	if n == 0 || n&(n-1) != 0 {
		return false
	}
	// Cofactor-clear the tag (and reject a low-order / identity tag). The
	// U-equation below is checked in the cofactor-cleared subgroup so that any
	// torsion component an attacker adds to T (and matches into cdt_k) is wiped
	// out — every torsion variant of one coin's tag verifies against, and is
	// stored as, the SAME canonical nullifier (Monero CVE-2017-12424 class).
	Tc, ok := canonicalTag(T)
	if !ok {
		return false
	}
	m := bits.TrailingZeros(uint(n))
	if pf.m != m || len(pf.Cl) != m || len(pf.Ca) != m || len(pf.Cb) != m ||
		len(pf.Cd) != m || len(pf.Cdt) != m || len(pf.F) != m || len(pf.Za) != m || len(pf.Zb) != m {
		return false
	}
	cl, e1 := unmarshalPts(pf.Cl)
	ca, e2 := unmarshalPts(pf.Ca)
	cb, e3 := unmarshalPts(pf.Cb)
	cd, e4 := unmarshalPts(pf.Cd)
	cdt, e5 := unmarshalPts(pf.Cdt)
	f, e6 := unmarshalScs(pf.F)
	za, e7 := unmarshalScs(pf.Za)
	zb, e8 := unmarshalScs(pf.Zb)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || e7 != nil || e8 != nil {
		return false
	}
	zd, err := new(edwards25519.Scalar).SetCanonicalBytes(pf.Zd)
	if err != nil {
		return false
	}

	xc := oomChallenge(ctx, ring, T, cl, ca, cb, cd, cdt)

	// bit-proof checks
	for j := 0; j < m; j++ {
		// x·cl_j + ca_j == Com(f_j; z_{a,j})
		lhs := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarMult(xc, cl[j]), ca[j])
		if lhs.Equal(commScalar(f[j], za[j])) != 1 {
			return false
		}
		// (x-f_j)·cl_j + cb_j == Com(0; z_{b,j})
		xmf := new(edwards25519.Scalar).Subtract(xc, f[j])
		lhs2 := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarMult(xmf, cl[j]), cb[j])
		if lhs2.Equal(commScalar(sZero(), zb[j])) != 1 {
			return false
		}
	}

	// powers
	xpow := make([]*edwards25519.Scalar, m+1)
	xpow[0] = sOne()
	for k := 1; k <= m; k++ {
		xpow[k] = sMul(xpow[k-1], xc)
	}

	// G-equation: Σ_i p_i(x)·C_i − Σ_k x^k·cd_k == z_d·G
	accG := edwards25519.NewIdentityPoint()
	for i := 0; i < n; i++ {
		pi := sOne()
		for j := 0; j < m; j++ {
			if (i>>j)&1 == 1 {
				pi = sMul(pi, f[j]) // f_j
			} else {
				pi = sMul(pi, new(edwards25519.Scalar).Subtract(xc, f[j])) // x - f_j
			}
		}
		accG.Add(accG, new(edwards25519.Point).ScalarMult(pi, ring[i]))
	}
	for k := 0; k < m; k++ {
		accG.Subtract(accG, new(edwards25519.Point).ScalarMult(xpow[k], cd[k]))
	}
	if accG.Equal(new(edwards25519.Point).ScalarBaseMult(zd)) != 1 {
		return false
	}

	// U-equation (tag binding): x^m·T − Σ_k x^k·cdt_k == z_d·U, checked in the
	// cofactor-cleared subgroup (×8 both sides) so torsion in T and cdt_k cancels
	// and the bound tag is the canonical 8·T.
	accU := new(edwards25519.Point).ScalarMult(xpow[m], Tc)
	for k := 0; k < m; k++ {
		accU.Subtract(accU, new(edwards25519.Point).MultByCofactor(new(edwards25519.Point).ScalarMult(xpow[k], cdt[k])))
	}
	rhsU := new(edwards25519.Point).MultByCofactor(new(edwards25519.Point).ScalarMult(zd, uGen))
	if accU.Equal(rhsU) != 1 {
		return false
	}
	return true
}

// --- Fiat-Shamir + (de)serialization helpers ---

func oomChallenge(ctx []byte, ring []*edwards25519.Point, T *edwards25519.Point, groups ...[]*edwards25519.Point) *edwards25519.Scalar {
	h := sha512.New()
	h.Write([]byte("Obscura/OneOfMany/v1"))
	h.Write(netDom())
	h.Write(ctx)
	for _, p := range ring {
		h.Write(p.Bytes())
	}
	h.Write(T.Bytes())
	for _, g := range groups {
		for _, p := range g {
			h.Write(p.Bytes())
		}
	}
	s, _ := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil)[:64])
	return s
}

func marshalPts(ps []*edwards25519.Point) [][]byte {
	out := make([][]byte, len(ps))
	for i, p := range ps {
		out[i] = p.Bytes()
	}
	return out
}
func marshalScs(ss []*edwards25519.Scalar) [][]byte {
	out := make([][]byte, len(ss))
	for i, s := range ss {
		out[i] = s.Bytes()
	}
	return out
}
func unmarshalPts(bs [][]byte) ([]*edwards25519.Point, error) {
	out := make([]*edwards25519.Point, len(bs))
	for i, b := range bs {
		p, err := new(edwards25519.Point).SetBytes(b)
		if err != nil {
			return nil, err
		}
		out[i] = p
	}
	return out, nil
}
func unmarshalScs(bs [][]byte) ([]*edwards25519.Scalar, error) {
	out := make([]*edwards25519.Scalar, len(bs))
	for i, b := range bs {
		s, err := new(edwards25519.Scalar).SetCanonicalBytes(b)
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}
