package stark

// Generic constraint algebra. A circuit writes its transition constraints ONCE as
// a function over an abstract field-like environment `cenv[T]`; the prover
// instantiates it with polynomials (T=Poly) to build constraint polynomials, and
// the verifier instantiates the SAME code with scalars (T=Felt) to evaluate them at
// the out-of-domain point. One source of truth ⇒ prover and verifier can't drift.

// cenv is the arithmetic environment a constraint is written against.
type cenv[T any] interface {
	Add(a, b T) T
	Sub(a, b T) T
	Mul(a, b T) T
	Const(c Felt) T // lift a field constant into T
}

// feltEnv evaluates constraints over scalars (verifier side).
type feltEnv struct{}

func (feltEnv) Add(a, b Felt) Felt { return a.Add(b) }
func (feltEnv) Sub(a, b Felt) Felt { return a.Sub(b) }
func (feltEnv) Mul(a, b Felt) Felt { return a.Mul(b) }
func (feltEnv) Const(c Felt) Felt  { return c }

// felt2Env evaluates constraints over the DEGREE-2 EXTENSION field (verifier side, at
// the out-of-domain point z ∈ F_{p^2}). It satisfies cenv[Felt2] using the SAME
// constraint source code as feltEnv/polyEnv, so the extension-field evaluation of every
// circuit's transition constraints is EXACTLY the embedded image of the base-field
// polynomial identity — no separate constraint code, hence no prover/verifier drift and
// no in-circuit/native mismatch. Const lifts a base constant via the field embedding.
type felt2Env struct{}

func (felt2Env) Add(a, b Felt2) Felt2 { return a.Add(b) }
func (felt2Env) Sub(a, b Felt2) Felt2 { return a.Sub(b) }
func (felt2Env) Mul(a, b Felt2) Felt2 { return a.Mul(b) }
func (felt2Env) Const(c Felt) Felt2   { return Felt2From(c) }

// Poly is a dense polynomial (coefficients low-degree first) with method-form
// arithmetic, so it satisfies cenv[Poly] (prover side).
type Poly []Felt

func (polyEnv) Add(a, b Poly) Poly { return Poly(polyAdd(a, b)) }
func (polyEnv) Sub(a, b Poly) Poly { return Poly(polySub(a, b)) }
func (polyEnv) Mul(a, b Poly) Poly { return Poly(polyMul(a, b)) }
func (polyEnv) Const(c Felt) Poly {
	if c == 0 {
		return Poly{}
	}
	return Poly{c}
}

type polyEnv struct{}
