// Package accumulator implements a dynamic universal accumulator over a group
// of unknown order, with succinct membership / non-membership proofs following
// Boneh-Bunz-Fisch ("Batching Techniques for Accumulators with Applications to
// IOPs and Stateless Blockchains", CRYPTO 2019) and Wesolowski's proof of
// exponentiation.
//
// Obscura uses this accumulator so that every spend proves membership in the
// ENTIRE set of unspent outputs — a global anonymity set — instead of a small
// ring of decoys.
package accumulator

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

// HashToPrime deterministically maps arbitrary data to an odd prime. Every
// transaction output's public key is mapped to a unique prime "representative"
// that is what actually gets accumulated. The mapping must be deterministic and
// collision-resistant: distinct outputs must map to distinct primes with
// overwhelming probability, which holds because primes are dense and the hash
// is collision-resistant.
//
// We use a hash-and-increment ("nonce search") construction: derive a candidate
// from H(data || nonce) and advance the nonce until ProbablyPrime succeeds. The
// nonce is returned so verifiers can recompute the prime in O(1) hashing.
func HashToPrime(data []byte) (*big.Int, uint64) {
	return HashToPrimeFrom(data, 0)
}

// HashToPrimeFrom is like HashToPrime but starts the nonce search at `start`.
func HashToPrimeFrom(data []byte, start uint64) (*big.Int, uint64) {
	const primeBits = 256 // 256-bit prime representatives
	for nonce := start; ; nonce++ {
		cand := expandToPrimeCandidate(data, nonce, primeBits)
		if cand.ProbablyPrime(24) {
			return cand, nonce
		}
	}
}

// VerifyHashToPrime checks that p is the prime produced by HashToPrime for the
// given data and nonce. Verifiers use this instead of re-searching.
func VerifyHashToPrime(data []byte, nonce uint64, p *big.Int) bool {
	const primeBits = 256
	cand := expandToPrimeCandidate(data, nonce, primeBits)
	if cand.Cmp(p) != 0 {
		return false
	}
	return p.ProbablyPrime(24)
}

func expandToPrimeCandidate(data []byte, nonce uint64, bits int) *big.Int {
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], nonce)
	buf := make([]byte, 0, bits/8+8)
	ctr := uint32(0)
	for len(buf)*8 < bits {
		h := sha256.New()
		h.Write([]byte("OBSCURA-H2P"))
		h.Write(data)
		h.Write(nb[:])
		var cb [4]byte
		binary.BigEndian.PutUint32(cb[:], ctr)
		h.Write(cb[:])
		buf = append(buf, h.Sum(nil)...)
		ctr++
	}
	cand := new(big.Int).SetBytes(buf[:bits/8])
	cand.SetBit(cand, bits-1, 1) // ensure full bit length
	cand.SetBit(cand, 0, 1)      // ensure odd
	return cand
}

// HashToPrimeVerifyableData recomputes the prime for (data, nonce) and returns
// its big-endian bytes plus whether it is a valid prime. Used by validators to
// derive an output's accumulator prime without re-searching.
func HashToPrimeVerifyableData(data []byte, nonce uint64) ([]byte, bool) {
	const primeBits = 256
	cand := expandToPrimeCandidate(data, nonce, primeBits)
	if !cand.ProbablyPrime(24) {
		return nil, false
	}
	return cand.Bytes(), true
}

// HashToPrimeChallenge maps a transcript to a prime used as a Fiat-Shamir
// challenge ("ℓ" in Wesolowski's PoE). Smaller (e.g. 128-bit) primes suffice
// for the soundness challenge.
func HashToPrimeChallenge(transcript []byte) *big.Int {
	const challengeBits = 128
	for nonce := uint64(0); ; nonce++ {
		cand := expandToPrimeCandidate(transcript, nonce, challengeBits)
		if cand.ProbablyPrime(24) {
			return cand
		}
	}
}

// HashToInt maps a transcript to an integer in [0, 2^bits) for Fiat-Shamir.
func HashToInt(transcript []byte, bits int) *big.Int {
	buf := make([]byte, 0, bits/8+32)
	ctr := uint32(0)
	for len(buf)*8 < bits {
		h := sha256.New()
		h.Write([]byte("OBSCURA-FS"))
		h.Write(transcript)
		var cb [4]byte
		binary.BigEndian.PutUint32(cb[:], ctr)
		h.Write(cb[:])
		buf = append(buf, h.Sum(nil)...)
		ctr++
	}
	x := new(big.Int).SetBytes(buf[:bits/8])
	return x
}
