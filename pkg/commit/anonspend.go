package commit

import (
	"crypto/sha512"
	"errors"
	"math/bits"

	"filippo.io/edwards25519"
)

// Joint anonymous-spend proof (Block 3 — see docs/INVENTION_ANONYMITY.md).
//
// It proves, for ONE hidden index l shared across two rings:
//   - ownership: ownRing[l] = x·G   (knowledge of the coin's one-time secret x)
//   - key image: T = x·U            (double-spend tag / nullifier)
//   - value:     valRing[l] = d·G   (valRing[l] is a commitment to 0 with
//                                     opening d) — i.e. the spent coin's amount
//                                     commitment minus the pseudo-commitment
//                                     opens to zero ⟹ SAME value.
//
// The index-encoding machinery (bit commitments + f_j responses, hence the
// selector polynomials p_i(x)) is SHARED between the two rings, which forces the
// same hidden l in both. This is what makes an anonymous spend sound: the
// spender cannot prove ownership of one coin while matching the value of a
// different (larger) coin — closing the inflation hole without revealing which
// coin is spent. Log-size, no trusted setup.

// AnonSpendProof is the joint shared-index proof.
type AnonSpendProof struct {
	M   int
	Cl  [][]byte // shared bit commitments
	Ca  [][]byte
	Cb  [][]byte
	CdO [][]byte // ownership-ring lower-degree commitments (G side)
	Cdt [][]byte // tag commitments (U side)
	CdV [][]byte // value-ring lower-degree commitments (G side)
	F   [][]byte // shared responses f_j
	Za  [][]byte
	Zb  [][]byte
	ZdO []byte // ownership response
	ZdV []byte // value response
}

// polySumsOverRing returns Σ_i p_{i,k}·ring[i] for k = 0..m-1, where p_i is the
// selector polynomial determined by the secret index bits lj and randomizers aj.
func polySumsOverRing(ring []*edwards25519.Point, lj, aj []*edwards25519.Scalar, m, n int) []*edwards25519.Point {
	sum := make([]*edwards25519.Point, m)
	for k := 0; k < m; k++ {
		sum[k] = edwards25519.NewIdentityPoint()
	}
	for i := 0; i < n; i++ {
		poly := []*edwards25519.Scalar{sOne()}
		for j := 0; j < m; j++ {
			if (i>>j)&1 == 1 {
				poly = polyMulLinear(poly, aj[j], lj[j])
			} else {
				poly = polyMulLinear(poly, sNeg(aj[j]), new(edwards25519.Scalar).Subtract(sOne(), lj[j]))
			}
		}
		for k := 0; k < m; k++ {
			sum[k].Add(sum[k], new(edwards25519.Point).ScalarMult(poly[k], ring[i]))
		}
	}
	return sum
}

// ProveAnonSpend builds the joint proof. x opens ownRing[l]; d opens valRing[l].
func ProveAnonSpend(ownRing, valRing []*edwards25519.Point, l int, x, d *edwards25519.Scalar, ctx []byte) (*AnonSpendProof, *edwards25519.Point, error) {
	n := len(ownRing)
	if n == 0 || n&(n-1) != 0 {
		return nil, nil, errors.New("commit: ring size must be a power of two")
	}
	if len(valRing) != n {
		return nil, nil, errors.New("commit: ring length mismatch")
	}
	if l < 0 || l >= n {
		return nil, nil, errors.New("commit: index out of range")
	}
	m := bits.TrailingZeros(uint(n))
	T := new(edwards25519.Point).ScalarMult(x, uGen)

	lj := make([]*edwards25519.Scalar, m)
	aj := make([]*edwards25519.Scalar, m)
	rl := make([]*edwards25519.Scalar, m)
	ra := make([]*edwards25519.Scalar, m)
	rb := make([]*edwards25519.Scalar, m)
	cl := make([]*edwards25519.Point, m)
	ca := make([]*edwards25519.Point, m)
	cb := make([]*edwards25519.Point, m)
	for j := 0; j < m; j++ {
		lj[j] = ScalarFromUint64(uint64((l >> j) & 1))
		aj[j] = RandomScalar()
		rl[j] = RandomScalar()
		ra[j] = RandomScalar()
		rb[j] = RandomScalar()
		cl[j] = commScalar(lj[j], rl[j])
		ca[j] = commScalar(aj[j], ra[j])
		cb[j] = commScalar(sMul(lj[j], aj[j]), rb[j])
	}

	sumsO := polySumsOverRing(ownRing, lj, aj, m, n)
	sumsV := polySumsOverRing(valRing, lj, aj, m, n)
	rhoO := make([]*edwards25519.Scalar, m)
	rhoV := make([]*edwards25519.Scalar, m)
	cdO := make([]*edwards25519.Point, m)
	cdt := make([]*edwards25519.Point, m)
	cdV := make([]*edwards25519.Point, m)
	for k := 0; k < m; k++ {
		rhoO[k] = RandomScalar()
		rhoV[k] = RandomScalar()
		cdO[k] = new(edwards25519.Point).Add(sumsO[k], new(edwards25519.Point).ScalarBaseMult(rhoO[k]))
		cdt[k] = new(edwards25519.Point).ScalarMult(rhoO[k], uGen)
		cdV[k] = new(edwards25519.Point).Add(sumsV[k], new(edwards25519.Point).ScalarBaseMult(rhoV[k]))
	}

	xc := anonChallenge(ctx, ownRing, valRing, T, cl, ca, cb, cdO, cdt, cdV)

	f := make([]*edwards25519.Scalar, m)
	za := make([]*edwards25519.Scalar, m)
	zb := make([]*edwards25519.Scalar, m)
	for j := 0; j < m; j++ {
		f[j] = sAdd(sMul(lj[j], xc), aj[j])
		za[j] = sAdd(sMul(rl[j], xc), ra[j])
		zb[j] = sAdd(sMul(rl[j], new(edwards25519.Scalar).Subtract(xc, f[j])), rb[j])
	}
	xm := sOne()
	for k := 0; k < m; k++ {
		xm = sMul(xm, xc)
	}
	zdO := sMul(x, xm)
	zdV := sMul(d, xm)
	xk := sOne()
	for k := 0; k < m; k++ {
		zdO = new(edwards25519.Scalar).Subtract(zdO, sMul(rhoO[k], xk))
		zdV = new(edwards25519.Scalar).Subtract(zdV, sMul(rhoV[k], xk))
		xk = sMul(xk, xc)
	}

	return &AnonSpendProof{
		M:  m,
		Cl: marshalPts(cl), Ca: marshalPts(ca), Cb: marshalPts(cb),
		CdO: marshalPts(cdO), Cdt: marshalPts(cdt), CdV: marshalPts(cdV),
		F: marshalScs(f), Za: marshalScs(za), Zb: marshalScs(zb),
		ZdO: zdO.Bytes(), ZdV: zdV.Bytes(),
	}, T, nil
}

// VerifyAnonSpend checks the joint proof and tag T against the two rings + ctx.
func VerifyAnonSpend(ownRing, valRing []*edwards25519.Point, T *edwards25519.Point, pf *AnonSpendProof, ctx []byte) bool {
	n := len(ownRing)
	if n == 0 || n&(n-1) != 0 || len(valRing) != n {
		return false
	}
	// Cofactor-clear the tag (and reject a low-order / identity tag). The tag
	// U-equation below is checked in the cofactor-cleared subgroup so any torsion
	// component an attacker adds to T (and matches into cdt_k) is wiped out: every
	// torsion variant of one coin's tag verifies against, and is stored as, the
	// SAME canonical nullifier (Monero CVE-2017-12424 key-image torsion class).
	Tc, ok := canonicalTag(T)
	if !ok {
		return false
	}
	m := bits.TrailingZeros(uint(n))
	if pf.M != m {
		return false
	}
	for _, g := range [][][]byte{pf.Cl, pf.Ca, pf.Cb, pf.CdO, pf.Cdt, pf.CdV, pf.F, pf.Za, pf.Zb} {
		if len(g) != m {
			return false
		}
	}
	cl, e1 := unmarshalPts(pf.Cl)
	ca, e2 := unmarshalPts(pf.Ca)
	cb, e3 := unmarshalPts(pf.Cb)
	cdO, e4 := unmarshalPts(pf.CdO)
	cdt, e5 := unmarshalPts(pf.Cdt)
	cdV, e6 := unmarshalPts(pf.CdV)
	f, e7 := unmarshalScs(pf.F)
	za, e8 := unmarshalScs(pf.Za)
	zb, e9 := unmarshalScs(pf.Zb)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || e6 != nil || e7 != nil || e8 != nil || e9 != nil {
		return false
	}
	zdO, ea := new(edwards25519.Scalar).SetCanonicalBytes(pf.ZdO)
	zdV, eb := new(edwards25519.Scalar).SetCanonicalBytes(pf.ZdV)
	if ea != nil || eb != nil {
		return false
	}

	xc := anonChallenge(ctx, ownRing, valRing, T, cl, ca, cb, cdO, cdt, cdV)

	// shared bit-proofs
	for j := 0; j < m; j++ {
		lhs := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarMult(xc, cl[j]), ca[j])
		if lhs.Equal(commScalar(f[j], za[j])) != 1 {
			return false
		}
		xmf := new(edwards25519.Scalar).Subtract(xc, f[j])
		lhs2 := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarMult(xmf, cl[j]), cb[j])
		if lhs2.Equal(commScalar(sZero(), zb[j])) != 1 {
			return false
		}
	}

	xpow := make([]*edwards25519.Scalar, m+1)
	xpow[0] = sOne()
	for k := 1; k <= m; k++ {
		xpow[k] = sMul(xpow[k-1], xc)
	}

	// p_i(x) shared selector over both rings
	pi := make([]*edwards25519.Scalar, n)
	for i := 0; i < n; i++ {
		p := sOne()
		for j := 0; j < m; j++ {
			if (i>>j)&1 == 1 {
				p = sMul(p, f[j])
			} else {
				p = sMul(p, new(edwards25519.Scalar).Subtract(xc, f[j]))
			}
		}
		pi[i] = p
	}

	// ownership G-equation
	accO := edwards25519.NewIdentityPoint()
	for i := 0; i < n; i++ {
		accO.Add(accO, new(edwards25519.Point).ScalarMult(pi[i], ownRing[i]))
	}
	for k := 0; k < m; k++ {
		accO.Subtract(accO, new(edwards25519.Point).ScalarMult(xpow[k], cdO[k]))
	}
	if accO.Equal(new(edwards25519.Point).ScalarBaseMult(zdO)) != 1 {
		return false
	}

	// tag U-equation (binds T = x·U at the same hidden index), checked in the
	// cofactor-cleared subgroup (×8 both sides) so torsion in T and cdt_k cancels
	// and the bound tag is the canonical 8·T.
	accU := new(edwards25519.Point).ScalarMult(xpow[m], Tc)
	for k := 0; k < m; k++ {
		accU.Subtract(accU, new(edwards25519.Point).MultByCofactor(new(edwards25519.Point).ScalarMult(xpow[k], cdt[k])))
	}
	rhsU := new(edwards25519.Point).MultByCofactor(new(edwards25519.Point).ScalarMult(zdO, uGen))
	if accU.Equal(rhsU) != 1 {
		return false
	}

	// value G-equation (same hidden index ⟹ same value)
	accV := edwards25519.NewIdentityPoint()
	for i := 0; i < n; i++ {
		accV.Add(accV, new(edwards25519.Point).ScalarMult(pi[i], valRing[i]))
	}
	for k := 0; k < m; k++ {
		accV.Subtract(accV, new(edwards25519.Point).ScalarMult(xpow[k], cdV[k]))
	}
	if accV.Equal(new(edwards25519.Point).ScalarBaseMult(zdV)) != 1 {
		return false
	}
	return true
}

func anonChallenge(ctx []byte, ownRing, valRing []*edwards25519.Point, T *edwards25519.Point, groups ...[]*edwards25519.Point) *edwards25519.Scalar {
	h := sha512.New()
	h.Write([]byte("Obscura/AnonSpend/v1"))
	h.Write(netDom())
	h.Write(ctx)
	for _, p := range ownRing {
		h.Write(p.Bytes())
	}
	for _, p := range valRing {
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

// Serialize encodes the proof as a flat byte blob (length-prefixed groups).
func (pf *AnonSpendProof) Serialize() []byte {
	var out []byte
	put := func(b []byte) {
		var l [4]byte
		l[0] = byte(len(b) >> 24)
		l[1] = byte(len(b) >> 16)
		l[2] = byte(len(b) >> 8)
		l[3] = byte(len(b))
		out = append(out, l[:]...)
		out = append(out, b...)
	}
	putGroup := func(g [][]byte) {
		var l [4]byte
		n := len(g)
		l[0] = byte(n >> 24)
		l[1] = byte(n >> 16)
		l[2] = byte(n >> 8)
		l[3] = byte(n)
		out = append(out, l[:]...)
		for _, b := range g {
			put(b)
		}
	}
	var mb [4]byte
	mb[0] = byte(pf.M >> 24)
	mb[1] = byte(pf.M >> 16)
	mb[2] = byte(pf.M >> 8)
	mb[3] = byte(pf.M)
	out = append(out, mb[:]...)
	putGroup(pf.Cl)
	putGroup(pf.Ca)
	putGroup(pf.Cb)
	putGroup(pf.CdO)
	putGroup(pf.Cdt)
	putGroup(pf.CdV)
	putGroup(pf.F)
	putGroup(pf.Za)
	putGroup(pf.Zb)
	put(pf.ZdO)
	put(pf.ZdV)
	return out
}

// ParseAnonSpendProof decodes a serialized proof.
func ParseAnonSpendProof(data []byte) (*AnonSpendProof, error) {
	pos := 0
	rd := func() ([]byte, error) {
		if pos+4 > len(data) {
			return nil, errors.New("commit: truncated proof")
		}
		n := int(data[pos])<<24 | int(data[pos+1])<<16 | int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4
		if n < 0 || pos+n > len(data) || n > 1<<16 {
			return nil, errors.New("commit: bad proof field")
		}
		b := data[pos : pos+n]
		pos += n
		return b, nil
	}
	rdGroup := func() ([][]byte, error) {
		if pos+4 > len(data) {
			return nil, errors.New("commit: truncated group")
		}
		n := int(data[pos])<<24 | int(data[pos+1])<<16 | int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4
		if n < 0 || n > 64 {
			return nil, errors.New("commit: bad group count")
		}
		g := make([][]byte, n)
		for i := 0; i < n; i++ {
			b, err := rd()
			if err != nil {
				return nil, err
			}
			g[i] = b
		}
		return g, nil
	}
	if len(data) < 4 {
		return nil, errors.New("commit: short proof")
	}
	m := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	pos = 4
	pf := &AnonSpendProof{M: m}
	var err error
	if pf.Cl, err = rdGroup(); err != nil {
		return nil, err
	}
	if pf.Ca, err = rdGroup(); err != nil {
		return nil, err
	}
	if pf.Cb, err = rdGroup(); err != nil {
		return nil, err
	}
	if pf.CdO, err = rdGroup(); err != nil {
		return nil, err
	}
	if pf.Cdt, err = rdGroup(); err != nil {
		return nil, err
	}
	if pf.CdV, err = rdGroup(); err != nil {
		return nil, err
	}
	if pf.F, err = rdGroup(); err != nil {
		return nil, err
	}
	if pf.Za, err = rdGroup(); err != nil {
		return nil, err
	}
	if pf.Zb, err = rdGroup(); err != nil {
		return nil, err
	}
	if pf.ZdO, err = rd(); err != nil {
		return nil, err
	}
	if pf.ZdV, err = rd(); err != nil {
		return nil, err
	}
	// audit: ROUND2 [93] reject trailing bytes — Serialize() consumes the whole
	// buffer, so leftover bytes are attacker-appended garbage that would change
	// the txid (Transaction.Hash() covers full wire bytes) without affecting
	// proof validity. Honest proofs parse exactly to the end.
	if pos != len(data) {
		return nil, errors.New("commit: trailing bytes after anon-spend proof")
	}
	return pf, nil
}

// VerifyAnonSpendBytes verifies an anonymous spend from serialized inputs:
// ring one-time keys (ownership ring), the ring members' amount commitments,
// the published pseudo-commitment, the key-image tag, and the serialized proof.
// valRing[i] = ringCommits[i] - pseudo. Returns false on any parse error.
func VerifyAnonSpendBytes(ringKeys, ringCommits [][]byte, pseudo, tag, proofBytes, ctx []byte) bool {
	if len(ringKeys) != len(ringCommits) || len(ringKeys) == 0 {
		return false
	}
	own, err := unmarshalPts(ringKeys)
	if err != nil {
		return false
	}
	cprime, err := new(edwards25519.Point).SetBytes(pseudo)
	if err != nil {
		return false
	}
	val := make([]*edwards25519.Point, len(ringCommits))
	for i, cb := range ringCommits {
		cp, err := new(edwards25519.Point).SetBytes(cb)
		if err != nil {
			return false
		}
		val[i] = new(edwards25519.Point).Subtract(cp, cprime)
	}
	T, err := new(edwards25519.Point).SetBytes(tag)
	if err != nil {
		return false
	}
	pf, err := ParseAnonSpendProof(proofBytes)
	if err != nil {
		return false
	}
	return VerifyAnonSpend(own, val, T, pf, ctx)
}
