package group

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
)

// ----------------------------------------------------------------------------
// Imaginary quadratic class group via reduced binary quadratic forms.
//
// An element is a positive-definite primitive reduced form (a, b, c) with
// discriminant D = b^2 - 4ac < 0. The group operation is Gauss/Dirichlet
// composition followed by reduction. The identity is the principal form. The
// inverse of (a,b,c) is (a,-b,c).
//
// The order of the class group h(D) is hard to compute for large |D|, giving a
// group of unknown order WITHOUT any trusted setup: D is a public
// "nothing-up-my-sleeve" prime discriminant. This is the property that lets
// Obscura instantiate a trustless accumulator.
// ----------------------------------------------------------------------------

// Form is a binary quadratic form ax^2 + bxy + cy^2.
type Form struct {
	A, B, C *big.Int
}

func (f *Form) String() string {
	return fmt.Sprintf("(%s, %s, %s)", f.A.String(), f.B.String(), f.C.String())
}

func (f *Form) clone() *Form {
	return &Form{new(big.Int).Set(f.A), new(big.Int).Set(f.B), new(big.Int).Set(f.C)}
}

// ClassGroup implements Group over the class group of discriminant D.
type ClassGroup struct {
	D    *big.Int // negative prime discriminant, D ≡ 1 (mod 8)
	gen  *Form
	name string
}

var (
	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
	big4 = big.NewInt(4)
)

// NewClassGroup builds the class group for discriminant D (must be < 0 and
// ≡ 1 mod 4). The generator is the canonical small form (2, 1, c).
func NewClassGroup(D *big.Int, name string) (*ClassGroup, error) {
	if D.Sign() >= 0 {
		return nil, errors.New("classgroup: discriminant must be negative")
	}
	if new(big.Int).And(new(big.Int).Neg(D), big.NewInt(7)).Cmp(big.NewInt(7)) != 0 {
		// require -D ≡ 7 mod 8  <=> D ≡ 1 mod 8, so the (2,1,*) generator exists.
		return nil, errors.New("classgroup: require D ≡ 1 (mod 8)")
	}
	cg := &ClassGroup{D: new(big.Int).Set(D), name: name}
	// principal form is the identity; generator is the reduced (2,1,(1-D)/8).
	c := new(big.Int).Sub(big1, D)
	c.Rsh(c, 3) // (1 - D)/8
	g := &Form{big.NewInt(2), big.NewInt(1), c}
	cg.gen = cg.reduce(g)
	return cg, nil
}

// DeriveDiscriminant deterministically produces a negative prime discriminant
// D ≡ 1 (mod 8) of approximately `bits` bits from a public seed. Because the
// derivation is a public hash, the result is nothing-up-my-sleeve: no party
// chose D and nobody knows h(D) or the group order.
func DeriveDiscriminant(seed []byte, bits int) *big.Int {
	// Build a candidate p ≡ 7 (mod 8), prime, then set D = -p (so D ≡ 1 mod 8).
	counter := 0
	for {
		buf := make([]byte, 0, bits/8+64)
		for len(buf)*8 < bits {
			h := sha512.Sum512(append(append([]byte("OBSCURA-DISC"), seed...), byte(counter), byte(counter>>8), byte(counter>>16), byte(counter>>24)))
			buf = append(buf, h[:]...)
			counter++
		}
		p := new(big.Int).SetBytes(buf[:bits/8])
		p.SetBit(p, bits-1, 1) // ensure full bit length
		p.SetBit(p, bits-2, 1) // raise entropy in top bits
		// force p ≡ 7 (mod 8)
		p.Sub(p, new(big.Int).Mod(p, big.NewInt(8)))
		p.Add(p, big.NewInt(7))
		// advance to the next prime ≡ 7 mod 8
		for !p.ProbablyPrime(40) {
			p.Add(p, big.NewInt(8))
		}
		return new(big.Int).Neg(p)
	}
}

func (G *ClassGroup) Name() string { return G.name }

// Identity returns the principal form (1, 1, (1-D)/4).
func (G *ClassGroup) Identity() Element {
	c := new(big.Int).Sub(big1, G.D)
	c.Rsh(c, 2) // (1-D)/4
	return G.reduce(&Form{big.NewInt(1), big.NewInt(1), c})
}

func (G *ClassGroup) Generator() Element { return G.gen.clone() }

// --- form normalization & reduction ---

// floorDiv returns floor(n/d) for d > 0.
func floorDiv(n, d *big.Int) *big.Int {
	q := new(big.Int)
	m := new(big.Int)
	q.DivMod(n, d, m) // Euclidean: 0 <= m < d, so q is floor for d>0
	return q
}

// normalize brings b into the range (-a, a].
func (G *ClassGroup) normalize(f *Form) *Form {
	a, b, c := f.A, f.B, f.C
	// if -a < b <= a already, nothing to do
	negA := new(big.Int).Neg(a)
	if b.Cmp(negA) > 0 && b.Cmp(a) <= 0 {
		return &Form{new(big.Int).Set(a), new(big.Int).Set(b), new(big.Int).Set(c)}
	}
	twoA := new(big.Int).Lsh(a, 1)
	// k = floor((a - b) / (2a))
	num := new(big.Int).Sub(a, b)
	k := floorDiv(num, twoA)
	bNew := new(big.Int).Add(b, new(big.Int).Mul(new(big.Int).Lsh(a, 1), k))
	// c' = (b'^2 - D)/(4a)
	cNew := new(big.Int).Mul(bNew, bNew)
	cNew.Sub(cNew, G.D)
	cNew.Div(cNew, new(big.Int).Lsh(a, 2))
	return &Form{new(big.Int).Set(a), bNew, cNew}
}

// reduce returns the unique reduced form equivalent to f.
func (G *ClassGroup) reduce(f *Form) *Form {
	r := G.normalize(f)
	for {
		// reduced iff a <= c and (b >= 0 if a == c)
		if r.A.Cmp(r.C) < 0 {
			break
		}
		if r.A.Cmp(r.C) == 0 {
			if r.B.Sign() >= 0 {
				break
			}
			// a == c, b < 0 -> flip b
			r = &Form{new(big.Int).Set(r.A), new(big.Int).Neg(r.B), new(big.Int).Set(r.C)}
			break
		}
		// rho step: (a,b,c) -> (c, -b, a) then normalize
		r = G.normalize(&Form{new(big.Int).Set(r.C), new(big.Int).Neg(r.B), new(big.Int).Set(r.A)})
	}
	return r
}

// --- composition ---

// xgcd returns (g, x, y) with a*x + b*y = g = gcd(a,b).
func xgcd(a, b *big.Int) (g, x, y *big.Int) {
	g = new(big.Int)
	x = new(big.Int)
	y = new(big.Int)
	g.GCD(x, y, new(big.Int).Abs(a), new(big.Int).Abs(b))
	if a.Sign() < 0 {
		x.Neg(x)
	}
	if b.Sign() < 0 {
		y.Neg(y)
	}
	return
}

// compose returns the reduced Dirichlet composition of f1 and f2.
//
// General formula (validated empirically by the group-axiom tests):
//
//	s = (b1+b2)/2
//	g = gcd(a1,a2)            with a1*x + a2*y = g
//	e = gcd(g,s)             with g*X + s*Y = e
//	a3 = a1*a2/e^2
//	t  = ((b1-b2)/2 * y*X - c2 * Y) mod (a1/e)
//	B  = b2 + 2*(a2/e)*t
//	C  = (B^2 - D)/(4*a3)
//
// then reduce. For coprime forms (e=1) this collapses to the standard CRT
// solution B ≡ b1 (mod 2a1), B ≡ b2 (mod 2a2).
func (G *ClassGroup) compose(f1, f2 *Form) *Form {
	a1, b1, c1 := f1.A, f1.B, f1.C
	a2, b2, c2 := f2.A, f2.B, f2.C
	_ = c1

	s := new(big.Int).Add(b1, b2)
	s.Rsh(s, 1) // (b1+b2)/2

	// a1*x + a2*y = g; we only need g and y. xgcd is deterministic, so a single call
	// gives the same (g, y) the previous double call used (x was unused), at half the
	// extended-GCD cost per composition (and composition is the hot primitive).
	g, _, y := xgcd(a1, a2)

	e, X, Y := xgcd(g, s) // g*X + s*Y = e

	eSq := new(big.Int).Mul(e, e)
	a3 := new(big.Int).Mul(a1, a2)
	a3.Div(a3, eSq)

	a1e := new(big.Int).Div(a1, e)
	a2e := new(big.Int).Div(a2, e)

	// t = ((b1-b2)/2 * y * X - c2 * Y) mod (a1/e)
	half := new(big.Int).Sub(b1, b2)
	half.Rsh(half, 1) // (b1-b2)/2
	t := new(big.Int).Mul(half, y)
	t.Mul(t, X)
	t.Sub(t, new(big.Int).Mul(c2, Y))
	t.Mod(t, a1e) // Euclidean mod, 0 <= t < a1/e

	B := new(big.Int).Mul(big2, a2e)
	B.Mul(B, t)
	B.Add(B, b2)

	// C = (B^2 - D)/(4*a3)
	C := new(big.Int).Mul(B, B)
	C.Sub(C, G.D)
	C.Div(C, new(big.Int).Lsh(a3, 2))

	return G.reduce(&Form{a3, B, C})
}

func (G *ClassGroup) Op(a, b Element) Element {
	return G.compose(a.(*Form), b.(*Form))
}

func (G *ClassGroup) Inverse(a Element) Element {
	f := a.(*Form)
	return G.reduce(&Form{new(big.Int).Set(f.A), new(big.Int).Neg(f.B), new(big.Int).Set(f.C)})
}

// Exp computes a^e. It uses a 4-bit fixed-window method, which performs the same
// squarings as binary square-and-multiply but ~half the multiplications (one per
// non-zero window instead of one per set bit). The result is the canonical reduced
// form a^e, mathematically identical to the binary method (group exponentiation is
// method-independent), so it is consensus-safe; TestExpWindowedMatchesBinary pins this
// against the naive reference on the production discriminant. This speeds EVERY
// class-group operation: accumulator adds (apply path), Wesolowski/PoKE verification,
// and membership-witness checks.
func (G *ClassGroup) Exp(a Element, e *big.Int) Element {
	base := a.(*Form)
	exp := e
	if e.Sign() < 0 {
		base = G.Inverse(a).(*Form)
		exp = new(big.Int).Neg(e)
	}
	if exp.Sign() == 0 {
		return G.Identity()
	}
	const w = 4
	// Precompute tbl[i] = base^i for i in [0, 2^w).
	var tbl [1 << w]*Form
	tbl[0] = G.Identity().(*Form)
	tbl[1] = base.clone()
	for i := 2; i < len(tbl); i++ {
		tbl[i] = G.compose(tbl[i-1], base)
	}
	result := G.Identity().(*Form)
	nbits := exp.BitLen()
	top := ((nbits + w - 1) / w) * w // align the top window to a multiple of w
	for pos := top - w; pos >= 0; pos -= w {
		for s := 0; s < w; s++ { // square w times between windows
			result = G.compose(result, result)
		}
		win := 0 // the w-bit window value at [pos, pos+w)
		for b := pos + w - 1; b >= pos; b-- {
			win <<= 1
			if b < nbits && exp.Bit(b) == 1 {
				win |= 1
			}
		}
		if win != 0 {
			result = G.compose(result, tbl[win])
		}
	}
	return result
}

func (G *ClassGroup) Equal(a, b Element) bool {
	fa := a.(*Form)
	fb := b.(*Form)
	return fa.A.Cmp(fb.A) == 0 && fa.B.Cmp(fb.B) == 0 && fa.C.Cmp(fb.C) == 0
}

// MarshalSize: two field elements (a, b); c is recoverable from D. We bound by
// the discriminant size.
func (G *ClassGroup) MarshalSize() int {
	n := (G.D.BitLen() + 7) / 8
	return 2*(n/2+1) + 2 // a and b are ~sqrt(|D|) sized; +sign/len bytes
}

// Marshal encodes (a, b) with length prefixes; c is derived on Unmarshal.
func (G *ClassGroup) Marshal(a Element) []byte {
	f := a.(*Form)
	ab := f.A.Bytes()
	bb := f.B.Bytes()
	bsign := byte(0)
	if f.B.Sign() < 0 {
		bsign = 1
	}
	out := make([]byte, 0, len(ab)+len(bb)+5)
	out = append(out, byte(len(ab)>>8), byte(len(ab)))
	out = append(out, ab...)
	out = append(out, bsign)
	out = append(out, byte(len(bb)>>8), byte(len(bb)))
	out = append(out, bb...)
	return out
}

func (G *ClassGroup) Unmarshal(buf []byte) (Element, error) {
	if len(buf) < 5 {
		return nil, errors.New("classgroup: short buffer")
	}
	// audit:SECURITY_AUDIT_2026-07-01 — bound coefficient lengths by the REAL
	// discriminant size, not just the wire buffer. In a reduced form |a|,|b| ≤
	// √|D|, so each coordinate fits in at most the full discriminant byte size
	// (a generous bound +1 for sign-free magnitude). This rejects pathological
	// length prefixes before allocating big.Ints; the canonical-reduced check
	// below is the authoritative backstop (defense-in-depth).
	maxCoord := (G.D.BitLen()+7)/8 + 1
	la := int(buf[0])<<8 | int(buf[1])
	off := 2
	if la > maxCoord {
		return nil, errors.New("classgroup: a length exceeds discriminant size")
	}
	if off+la+3 > len(buf) {
		return nil, errors.New("classgroup: bad a length")
	}
	A := new(big.Int).SetBytes(buf[off : off+la])
	off += la
	bsign := buf[off]
	off++
	lb := int(buf[off])<<8 | int(buf[off+1])
	off += 2
	if lb > maxCoord {
		return nil, errors.New("classgroup: b length exceeds discriminant size")
	}
	if off+lb > len(buf) {
		return nil, errors.New("classgroup: bad b length")
	}
	// audit: ROUND2 [94] reject trailing garbage — Marshal emits exactly
	// 2+la+1+2+lb bytes, so any leftover is non-canonical padding that would let
	// two distinct encodings decode to the same element (malleability).
	if off+lb != len(buf) {
		return nil, errors.New("classgroup: trailing bytes after element")
	}
	B := new(big.Int).SetBytes(buf[off : off+lb])
	if bsign == 1 {
		B.Neg(B)
	}
	if A.Sign() <= 0 {
		return nil, errors.New("classgroup: non-positive a")
	}
	// C must satisfy B^2 - 4AC = D exactly, i.e. 4A | (B^2 - D).
	num := new(big.Int).Mul(B, B)
	num.Sub(num, G.D)
	fourA := new(big.Int).Lsh(A, 2)
	C, rem := new(big.Int).DivMod(num, fourA, new(big.Int))
	if rem.Sign() != 0 {
		return nil, errors.New("classgroup: element not on discriminant (4A ∤ B²−D)")
	}
	f := &Form{A, B, C}
	// verify discriminant and that the form is the canonical reduced form, so
	// every node agrees on element identity (no consensus split via aliasing).
	if disc := new(big.Int).Sub(new(big.Int).Mul(B, B), new(big.Int).Mul(fourA, C)); disc.Cmp(G.D) != 0 {
		return nil, errors.New("classgroup: wrong discriminant")
	}
	if !G.Equal(G.reduce(f), f) {
		return nil, errors.New("classgroup: form not reduced (non-canonical)")
	}
	return f, nil
}

var _ Group = (*ClassGroup)(nil)
