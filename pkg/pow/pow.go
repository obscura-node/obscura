// Package pow implements Obscura's proof-of-work: a RandomX-style virtual-machine
// hash (Block 6 / RandomX upgrade — see docs/INVENTION_POW.md and randomx.go).
// It is memory-hard (a seed-derived cache plus a per-nonce random-access
// scratchpad) and compute-diverse (a randomized register VM mixing integer,
// floating-point, and memory ops that differs every nonce), which is what denies
// ASICs/GPUs the efficiency edge they get over CPUs on simple hashes. Verification
// is a single VM run. The function is isolated behind Hash() so it can later be
// bound to canonical Monero-compatible RandomX without touching consensus.
package pow

import (
	"math/big"
)

// Hash computes the PoW hash of the input under the default seed. Deterministic
// and self-contained. The actual hash function is the active backend (see
// backend_vm.go / backend_randomx.go and BackendName).
func Hash(input []byte) [32]byte {
	return backendHash(SeedKey, input)
}

// HashSeed computes the PoW hash under an explicit cache seed (the per-epoch seed
// used by consensus — see config.PoWSeedHeight / chain.PoWSeed). Rotating the seed
// rotates the memory-hard cache, exactly as Monero's RandomX reseeds.
func HashSeed(seed, input []byte) [32]byte {
	return backendHash(seed, input)
}

// Target converts a difficulty value into a 256-bit target threshold. A hash is
// valid iff interpreted as a big-endian integer it is <= target. Difficulty is
// (2^256 - 1) / target, so higher difficulty => smaller target.
func Target(difficulty uint64) *big.Int {
	if difficulty == 0 {
		difficulty = 1
	}
	max := new(big.Int).Lsh(big.NewInt(1), 256)
	max.Sub(max, big.NewInt(1))
	return max.Div(max, new(big.Int).SetUint64(difficulty))
}

// Meets reports whether hash satisfies the given difficulty.
func Meets(hash [32]byte, difficulty uint64) bool {
	hv := new(big.Int).SetBytes(hash[:])
	return hv.Cmp(Target(difficulty)) <= 0
}

// HashDifficulty returns the difficulty a given hash actually achieves
// (= (2^256-1)/hashValue), used for chain work accounting.
func HashDifficulty(hash [32]byte) uint64 {
	hv := new(big.Int).SetBytes(hash[:])
	if hv.Sign() == 0 {
		return ^uint64(0)
	}
	max := new(big.Int).Lsh(big.NewInt(1), 256)
	max.Sub(max, big.NewInt(1))
	d := max.Div(max, hv)
	if !d.IsUint64() {
		return ^uint64(0)
	}
	return d.Uint64()
}
