package stark

// Dense univariate polynomials over Goldilocks, coefficients low-degree-first.
// Schoolbook arithmetic — clarity over speed; trace lengths here are small and the
// soundness-critical path is FRI, not these helpers.

func polyTrim(p []Felt) []Felt {
	i := len(p)
	for i > 0 && p[i-1] == 0 {
		i--
	}
	return p[:i]
}

func polyAdd(a, b []Felt) []Felt {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	out := make([]Felt, n)
	for i := range out {
		var x, y Felt
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		out[i] = x.Add(y)
	}
	return polyTrim(out)
}

func polySub(a, b []Felt) []Felt {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	out := make([]Felt, n)
	for i := range out {
		var x, y Felt
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		out[i] = x.Sub(y)
	}
	return polyTrim(out)
}

func polyScale(a []Felt, s Felt) []Felt {
	out := make([]Felt, len(a))
	for i := range a {
		out[i] = a[i].Mul(s)
	}
	return polyTrim(out)
}

func polyMul(a, b []Felt) []Felt {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	out := make([]Felt, len(a)+len(b)-1)
	for i := range a {
		if a[i] == 0 {
			continue
		}
		for j := range b {
			out[i+j] = out[i+j].Add(a[i].Mul(b[j]))
		}
	}
	return polyTrim(out)
}

// polyShiftArg returns the coefficients of p(c·x): coefficient k scaled by c^k.
func polyShiftArg(p []Felt, c Felt) []Felt {
	out := make([]Felt, len(p))
	ck := Felt(1)
	for k := range p {
		out[k] = p[k].Mul(ck)
		ck = ck.Mul(c)
	}
	return out
}

// divLinear divides p(x) by (x − a) via synthetic division, returning the quotient
// and the remainder p(a). If a is a root the remainder is 0.
func divLinear(p []Felt, a Felt) (quot []Felt, rem Felt) {
	n := len(p)
	if n == 0 {
		return nil, 0
	}
	q := make([]Felt, n-1)
	carry := p[n-1]
	for i := n - 2; i >= 0; i-- {
		q[i] = carry
		carry = p[i].Add(carry.Mul(a))
	}
	return polyTrim(q), carry
}
