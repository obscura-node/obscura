// Package stark builds the foundation of a TRANSPARENT zk-STARK proof system —
// no trusted setup, post-quantum (security rests only on a collision-resistant
// hash). It is the engine the ZK accumulator-membership spend needs to prove
// "I know a coin in the committed set + its nullifier" without revealing which
// (docs/ZK_MEMBERSHIP_SPEND.md gap 2 / docs/SCALING_100M.md Track A endgame), and
// it converges with the post-quantum roadmap (same machinery).
//
// Layered build: field (this file) → NTT → Reed-Solomon LDE → Merkle commitment →
// FRI low-degree test → AIR constraint system → the membership/nullifier circuit.
// This file is the bedrock: arithmetic over the Goldilocks field
// p = 2^64 − 2^32 + 1, chosen for STARKs (fast 64-bit reduction, 2-adicity 2^32 so
// large power-of-two NTTs exist).
package stark

import "math/bits"

// P is the Goldilocks prime 2^64 − 2^32 + 1.
const P uint64 = 0xFFFFFFFF00000001

// epsilon = 2^32 − 1 = 2^64 mod P (since 2^64 ≡ 2^32 − 1 (mod P)).
const epsilon uint64 = 0xFFFFFFFF

// Felt is a Goldilocks field element, always kept reduced in [0, P).
type Felt uint64

// reduce128 reduces a 128-bit product (hi·2^64 + lo) modulo P, exploiting
// 2^64 ≡ epsilon and 2^96 ≡ epsilon·2^32 ≡ −1 (mod P). Returns a value in [0, P).
func reduce128(hi, lo uint64) uint64 {
	hiHi := hi >> 32     // contributes hiHi·2^96 ≡ −hiHi
	hiLo := hi & epsilon // contributes hiLo·2^64 ≡ hiLo·epsilon

	// t0 = lo − hiHi (mod 2^64); a borrow means subtract epsilon to correct mod P.
	t0, borrow := bits.Sub64(lo, hiHi, 0)
	t0 -= epsilon * borrow

	// t1 = hiLo · epsilon (fits: hiLo < 2^32, epsilon < 2^32 → < 2^64).
	t1 := hiLo * epsilon

	// t2 = t0 + t1 (mod 2^64); a carry means add epsilon.
	t2, carry := bits.Add64(t0, t1, 0)
	t2 += epsilon * carry

	if t2 >= P {
		t2 -= P
	}
	return t2
}

// NewFelt reduces an arbitrary uint64 into the field.
func NewFelt(x uint64) Felt {
	if x >= P {
		x -= P
	}
	return Felt(x)
}

// Add returns a + b.
func (a Felt) Add(b Felt) Felt {
	s, carry := bits.Add64(uint64(a), uint64(b), 0)
	// fold the carry (2^64 ≡ epsilon) and reduce
	s += epsilon * carry
	if s >= P {
		s -= P
	}
	return Felt(s)
}

// Sub returns a − b. With a,b in [0,P): no borrow → a−b ∈ [0,P); borrow (a<b) →
// the wrap is d = a−b+2^64, and a−b+P = d−(2^32−1) = d−epsilon, which lands in
// [1,P). So d−epsilon·borrow is already reduced in both cases.
func (a Felt) Sub(b Felt) Felt {
	d, borrow := bits.Sub64(uint64(a), uint64(b), 0)
	d -= epsilon * borrow
	return Felt(d)
}

// Mul returns a · b.
func (a Felt) Mul(b Felt) Felt {
	hi, lo := bits.Mul64(uint64(a), uint64(b))
	return Felt(reduce128(hi, lo))
}

// Exp returns a^e by square-and-multiply.
func (a Felt) Exp(e uint64) Felt {
	result := Felt(1)
	base := a
	for e > 0 {
		if e&1 == 1 {
			result = result.Mul(base)
		}
		base = base.Mul(base)
		e >>= 1
	}
	return result
}

// Inv returns a^(−1) = a^(P−2) (Fermat). Inv(0) is 0 by convention.
func (a Felt) Inv() Felt {
	if a == 0 {
		return 0
	}
	return a.Exp(P - 2)
}

// IsZero reports whether a == 0.
func (a Felt) IsZero() bool { return a == 0 }

// Uint64 returns the canonical representative.
func (a Felt) Uint64() uint64 { return uint64(a) }
