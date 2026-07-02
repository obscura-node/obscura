// Package group defines a "group of unknown order" abstraction and two
// concrete backends used by the Obscura accumulator:
//
//   - rsa:        modular arithmetic in (Z/NZ)^* for a fixed RSA modulus N
//     whose factorization is unknown. Simple, fast, fully correct.
//     Requires that nobody knows the factorization of N (the
//     classic "RSA-2048 challenge modulus" is used by default as a
//     nothing-up-my-sleeve instantiation; a production deployment
//     should run a multi-party modulus ceremony OR use the
//     classgroup backend which needs no setup at all).
//
//   - classgroup: the ideal class group of an imaginary quadratic field,
//     represented by reduced binary quadratic forms. Requires NO
//     trusted setup whatsoever — the discriminant is a public
//     "nothing-up-my-sleeve" prime. This is Obscura's production
//     target and the source of its defensibility claim.
//
// Both backends satisfy the same Group interface so the accumulator, PoKE
// proofs, and the rest of the protocol are written once and run over either.
//
// SECURITY NOTE: groups of unknown order are the substrate for trustless
// accumulators (Boneh-Bunz-Fisch, EUROCRYPT'19) and Wesolowski's proof of
// exponentiation. The hardness assumptions are the Adaptive Root Assumption
// and the Strong RSA / Strong Root Assumption in the chosen group.
package group

import (
	"math/big"
)

// Element is an opaque group element. Each backend uses its own concrete type;
// callers must only pass elements back to the same Group that produced them.
type Element interface {
	// String returns a human-readable representation (for logging/debugging).
	String() string
}

// Group is a finite abelian group whose order is unknown (or hard to compute).
//
// The accumulator and proof systems rely on the following properties:
//   - Op is associative and commutative with Identity as the neutral element.
//   - Exp(g, e) computes g^e (repeated Op) for e >= 0; negative e uses Inverse.
//   - It is infeasible to find the order of a random element, or to extract
//     non-trivial roots of a random element (Strong Root Assumption).
type Group interface {
	// Name identifies the backend, e.g. "rsa2048" or "classgroup-d2048".
	Name() string

	// Identity returns the neutral element.
	Identity() Element

	// Generator returns the canonical generator used to seed the accumulator.
	Generator() Element

	// Op returns a ∘ b (multiplicatively: a*b).
	Op(a, b Element) Element

	// Exp returns a^e. For e < 0 it returns (a^-1)^|e|.
	Exp(a Element, e *big.Int) Element

	// Inverse returns a^-1.
	Inverse(a Element) Element

	// Equal reports whether a and b are the same element.
	Equal(a, b Element) bool

	// Marshal serializes an element to a canonical byte slice.
	Marshal(a Element) []byte

	// Unmarshal parses bytes produced by Marshal.
	Unmarshal(b []byte) (Element, error)

	// MarshalSize is the fixed (or maximum) marshaled size in bytes, used for
	// transaction size accounting.
	MarshalSize() int
}

// MultiExp computes the product of bases[i]^exps[i]. A naive sequential
// implementation; backends may override for speed but correctness is what
// matters for consensus. Provided as a helper for proof systems.
func MultiExp(g Group, bases []Element, exps []*big.Int) Element {
	acc := g.Identity()
	for i := range bases {
		acc = g.Op(acc, g.Exp(bases[i], exps[i]))
	}
	return acc
}

// ProductOfPrimes returns the product p_0 * p_1 * ... of a slice of big.Ints.
// Used to fold a batch of accumulator members into a single exponent.
func ProductOfPrimes(ps []*big.Int) *big.Int {
	prod := big.NewInt(1)
	for _, p := range ps {
		prod.Mul(prod, p)
	}
	return prod
}
