package group

import (
	"math/big"
	"runtime"
	"sync"
)

// ProductTree returns the product p_0 * p_1 * ... * p_{n-1} using a balanced
// binary product tree instead of a left-to-right fold.
//
// CONSENSUS SAFETY: integer multiplication is associative and commutative, so
// ANY grouping of the operands yields the byte-identical *big.Int. The pairing
// order here is fixed and independent of goroutine scheduling (adjacent pairs at
// each level), so the result is deterministic and equals the serial fold
// ProductOfPrimes / the (accProd.Mul in a loop) used by pkg/chain/apply.go.
// TestProductTreeEqualsSerial pins this byte-for-byte over random prime sets and
// over the exact accumulate-and-filter shape apply.go uses.
//
// PERFORMANCE: a balanced tree keeps operand sizes matched, so Go's Karatsuba /
// Toom-Cook big.Int multiplication kicks in on balanced halves — O(M(N) log n)
// instead of the O(n * M(N/n * i)) skew of the left fold, where the running
// accumulator grows to the full N-bit product and every remaining small prime is
// multiplied against that huge accumulator. Levels are computed in parallel
// across the available CPUs; because the pairing is fixed, parallelism only
// changes timing, never the value.
//
// This is the SAFE half of the class-group accumulator speedup: it accelerates
// the block exponent build (∏ output primes) without touching compose / reduce /
// Exp, whose outputs are frozen by the golden vectors.
func ProductTree(ps []*big.Int) *big.Int {
	if len(ps) == 0 {
		return big.NewInt(1)
	}
	if len(ps) == 1 {
		return new(big.Int).Set(ps[0])
	}
	// Work on a private level slice so we never alias the caller's big.Ints.
	level := make([]*big.Int, len(ps))
	for i, p := range ps {
		level[i] = new(big.Int).Set(p)
	}
	workers := runtime.GOMAXPROCS(0)
	for len(level) > 1 {
		half := (len(level) + 1) / 2
		next := make([]*big.Int, half)
		// Number of real multiplications this level (last element may be carried).
		npair := len(level) / 2
		if npair <= 1 || workers <= 1 {
			for i := 0; i < npair; i++ {
				next[i] = new(big.Int).Mul(level[2*i], level[2*i+1])
			}
		} else {
			var wg sync.WaitGroup
			sem := make(chan struct{}, workers)
			for i := 0; i < npair; i++ {
				wg.Add(1)
				sem <- struct{}{}
				go func(i int) {
					defer wg.Done()
					defer func() { <-sem }()
					next[i] = new(big.Int).Mul(level[2*i], level[2*i+1])
				}(i)
			}
			wg.Wait()
		}
		if len(level)%2 == 1 {
			// carry the unpaired tail element up unchanged
			next[half-1] = level[len(level)-1]
		}
		level = next
	}
	return level[0]
}
