package stark

// Polynomial helpers over the degree-2 extension field F_{p^2}, used by the DEEP/OOD
// layer once the out-of-domain point z and the DEEP/composition challenges are drawn
// from F_{p^2}. Trace and composition polynomials keep BASE-field coefficients; only
// their evaluation at z (and the resulting DEEP quotient g) live in F_{p^2}. These
// helpers mirror poly.go exactly, lifted to Felt2.

// evalBaseAt2 evaluates a BASE-coefficient polynomial p at an extension point x ∈ F_{p^2}
// via Horner. Result is f(x) ∈ F_{p^2}.
func evalBaseAt2(p []Felt, x Felt2) Felt2 {
	acc := Zero2()
	for i := len(p) - 1; i >= 0; i-- {
		acc = acc.Mul(x).Add(Felt2From(p[i]))
	}
	return acc
}

// evalPoly2 evaluates an EXTENSION-coefficient polynomial at x ∈ F_{p^2} via Horner.
func evalPoly2(p []Felt2, x Felt2) Felt2 {
	acc := Zero2()
	for i := len(p) - 1; i >= 0; i-- {
		acc = acc.Mul(x).Add(p[i])
	}
	return acc
}

// trim2 drops trailing zero coefficients.
func trim2(p []Felt2) []Felt2 {
	i := len(p)
	for i > 0 && p[i-1].IsZero() {
		i--
	}
	return p[:i]
}

// baseToExt2 lifts a base-coefficient polynomial to extension coefficients.
func baseToExt2(p []Felt) []Felt2 {
	out := make([]Felt2, len(p))
	for i := range p {
		out[i] = Felt2From(p[i])
	}
	return out
}

// subExtConst2 returns the extension-coefficient polynomial p(x) − c, where p has BASE
// coefficients and c ∈ F_{p^2}. This is the DEEP numerator f(x) − f(z): only the
// constant term gains an extension part.
func subExtConst2(p []Felt, c Felt2) []Felt2 {
	out := baseToExt2(p)
	if len(out) == 0 {
		return []Felt2{c.Neg()}
	}
	out[0] = out[0].Sub(c)
	return out
}

// polyAdd2 adds two extension-coefficient polynomials.
func polyAdd2(a, b []Felt2) []Felt2 {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	out := make([]Felt2, n)
	for i := range out {
		var x, y Felt2
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		out[i] = x.Add(y)
	}
	return trim2(out)
}

// polyScale2 multiplies an extension-coefficient polynomial by an extension scalar.
func polyScale2(a []Felt2, s Felt2) []Felt2 {
	out := make([]Felt2, len(a))
	for i := range a {
		out[i] = a[i].Mul(s)
	}
	return trim2(out)
}

// divLinear2 divides an extension-coefficient polynomial p(x) by (x − a), a ∈ F_{p^2},
// via synthetic division, returning quotient and remainder p(a) (mirror of divLinear).
func divLinear2(p []Felt2, a Felt2) (quot []Felt2, rem Felt2) {
	n := len(p)
	if n == 0 {
		return nil, Zero2()
	}
	q := make([]Felt2, n-1)
	carry := p[n-1]
	for i := n - 2; i >= 0; i-- {
		q[i] = carry
		carry = p[i].Add(carry.Mul(a))
	}
	return trim2(q), carry
}

// evalExtOnBaseDomain evaluates an extension-coefficient polynomial g over the
// base-field LDE domain coset·⟨ω_{N0}⟩ (the domain FRI commits over), returning N0
// extension values. The domain points are BASE elements, embedded into F_{p^2}. This is
// the bridge from the DEEP polynomial g (extension coeffs) to the FRI layer-0 evals.
func evalExtOnBaseDomain(g []Felt2, N0 int, coset Felt) []Felt2 {
	logN0 := log2(N0)
	w := RootOfUnity(logN0)
	out := make([]Felt2, N0)
	x := coset
	for i := 0; i < N0; i++ {
		out[i] = evalPoly2(g, Felt2From(x))
		x = x.Mul(w)
	}
	return out
}
