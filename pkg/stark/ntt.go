package stark

// Number-theoretic transform (NTT) over Goldilocks — the FFT the STARK needs to
// move between coefficient and evaluation form in O(n log n). Goldilocks has
// 2-adicity 32 (P−1 = 2^32·(2^32−1)), so primitive 2^k-th roots of unity exist for
// every k ≤ 32; that bounds the largest power-of-two domain at 2^32 points.

// generator is the multiplicative generator of the Goldilocks field.
const generator uint64 = 7

// twoAdicity is the largest k with 2^k | (P−1).
const twoAdicity = 32

// RootOfUnity returns a primitive 2^logN-th root of unity. Panics if logN > 32.
func RootOfUnity(logN uint) Felt {
	if logN > twoAdicity {
		panic("stark: NTT domain larger than 2^32 (Goldilocks 2-adicity)")
	}
	// g^((P-1)/2^logN) has order exactly 2^logN.
	exp := (P - 1) >> logN
	return Felt(generator).Exp(exp)
}

// bitReverse permutes a in place into bit-reversed index order (length must be a
// power of two).
func bitReverse(a []Felt) {
	n := len(a)
	for i, j := 1, 0; i < n; i++ {
		bit := n >> 1
		for ; j&bit != 0; bit >>= 1 {
			j ^= bit
		}
		j ^= bit
		if i < j {
			a[i], a[j] = a[j], a[i]
		}
	}
}

// ntt runs an in-place iterative Cooley-Tukey transform; if inverse, it uses the
// inverse root but does NOT scale by 1/n (the caller-facing INTT does).
func ntt(a []Felt, inverse bool) {
	n := len(a)
	if n&(n-1) != 0 {
		panic("stark: NTT length must be a power of two")
	}
	logN := uint(0)
	for 1<<logN < n {
		logN++
	}
	bitReverse(a)

	for s := uint(1); s <= logN; s++ {
		m := 1 << s
		w := RootOfUnity(s)
		if inverse {
			w = w.Inv()
		}
		for k := 0; k < n; k += m {
			wj := Felt(1)
			for j := 0; j < m/2; j++ {
				t := wj.Mul(a[k+j+m/2])
				u := a[k+j]
				a[k+j] = u.Add(t)
				a[k+j+m/2] = u.Sub(t)
				wj = wj.Mul(w)
			}
		}
	}
}

// NTT transforms coefficients → evaluations over the 2^logN-th roots of unity.
func NTT(coeffs []Felt) []Felt {
	a := append([]Felt(nil), coeffs...)
	ntt(a, false)
	return a
}

// INTT transforms evaluations → coefficients (the inverse of NTT), scaling by 1/n.
func INTT(evals []Felt) []Felt {
	a := append([]Felt(nil), evals...)
	ntt(a, true)
	nInv := Felt(uint64(len(a)) % P).Inv()
	for i := range a {
		a[i] = a[i].Mul(nInv)
	}
	return a
}

// EvalPoly evaluates a polynomial (given by coefficients, low-degree first) at x
// via Horner's rule.
func EvalPoly(coeffs []Felt, x Felt) Felt {
	acc := Felt(0)
	for i := len(coeffs) - 1; i >= 0; i-- {
		acc = acc.Mul(x).Add(coeffs[i])
	}
	return acc
}
