package stark

import "crypto/rand"

// Zero-knowledge trace masking for the AIR engine (FINDING 4 fix). A transparent
// FRI-STARK is sound but NOT zero-knowledge: it reveals out-of-domain (DEEP) and
// FRI-query openings of every trace column, from which a witness can be recovered.
// We close that gap with the standard two-part construction:
//
//  1. COSET LDE. Commit/evaluate/FRI on the coset airCoset·⟨ω_{N0}⟩, which is DISJOINT
//     from the trace domain H = ⟨ω_T⟩ (airCoset = the field's multiplicative generator,
//     in no proper subgroup). So NO opened point is ever an H point — without this, a
//     query landing on H would reveal a raw trace row regardless of masking.
//
//  2. POLYNOMIAL MASKING. Replace each trace column polynomial t(x) (degree < T) with
//     t'(x) = t(x) + Z_H(x)·r(x), Z_H(x) = x^T − 1, r random of degree ≥ (#revealed
//     evaluations per column). Z_H vanishes on H, so t' = t on H ⇒ every constraint and
//     boundary still holds (soundness untouched), while at every off-H point (z, gH·z,
//     and all coset query points) t' is masked by Z_H·r ⇒ the revealed evaluations are
//     uniformly random and leak nothing.
//
// Honest-verifier ZK then follows: the (#queries + OOD) revealed values per column are a
// bijective image of r's coefficients (Vandermonde over distinct off-H points), hence
// independent of the witness. NOTE: the formal ZK *bound* (joint over the derived CP/g
// openings too) follows the ethSTARK ZK analysis and, like the FRI soundness figure,
// warrants external cryptographer sign-off; the construction here is the standard one.

// airCoset shifts the LDE/FRI domain off H. generator (7) lies in no proper subgroup of
// F_p^*, so airCoset·⟨ω_{N0}⟩ ∩ ⟨ω_{N0}⟩ = ∅ (in particular it misses H ⊂ ⟨ω_{N0}⟩).
var airCoset = Felt(generator)

// maskCoeffs is the number of random coefficients in each column's mask r. It must be ≥
// the number of evaluations of a column the proof reveals: 2 OOD points (z, gH·z) plus
// the ± pair per FRI query (2·nQueries). A small margin is added.
func maskCoeffs(nQueries int) int { return 2*nQueries + 4 }

// randFelt draws a uniform field element (rejection-sampled to avoid modulo bias).
func randFelt() Felt {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic("stark: crypto/rand failure: " + err.Error())
		}
		v := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
			uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
		if v < P { // reject the few values ≥ P so the result is uniform in [0,P)
			return Felt(v)
		}
	}
}

// randPoly returns a random polynomial with n coefficients (degree n−1).
func randPoly(n int) []Felt {
	out := make([]Felt, n)
	for i := range out {
		out[i] = randFelt()
	}
	return out
}

// mulByZH multiplies r(x) by Z_H(x) = x^T − 1, i.e. (x^T − 1)·r(x) = x^T·r(x) − r(x).
// Result length = T + len(r).
func mulByZH(r []Felt, T int) []Felt {
	out := make([]Felt, T+len(r))
	for k, c := range r {
		out[k+T] = out[k+T].Add(c) // + x^T·r
		out[k] = out[k].Sub(c)     // − r
	}
	return out
}

// maskColumn returns t(x) + Z_H(x)·r(x) for a fresh random r with maskCoeffs(nQueries)
// coefficients. On H it equals t (Z_H vanishes there); off H it is uniformly masked.
func maskColumn(base []Felt, T, nQueries int) []Felt {
	return polyAdd(base, mulByZH(randPoly(maskCoeffs(nQueries)), T))
}
