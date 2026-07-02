// Package consensus holds chain-agnostic consensus rules: difficulty
// retargeting and related calculations.
package consensus

import (
	"math/big"

	"obscura/pkg/config"
)

// MinDifficulty is a hard network-wide floor so difficulty can never be driven
// to a trivially-mineable value via timestamp manipulation.
const MinDifficulty uint64 = 16

// NextDifficulty computes the difficulty for the next block using a Linear
// Weighted Moving Average (LWMA), the same family Monero uses. It reacts
// quickly to hashrate changes while resisting timestamp manipulation.
//
// timestamps and difficulties are ordered oldest..newest and cover up to
// config.DifficultyWindow recent blocks. Returns config.GenesisDifficulty until
// enough history exists.
func NextDifficulty(timestamps []int64, difficulties []uint64) uint64 {
	// Devnet/load-test escape hatch: a pegged difficulty disables retargeting so
	// block production is steady on a CPU-contended host (see config.FixedDifficulty).
	if config.FixedDifficulty > 0 {
		return config.FixedDifficulty
	}
	n := len(difficulties)
	if n < 2 {
		return config.GenesisDifficulty
	}
	window := config.DifficultyWindow
	if n < window {
		window = n
	}
	// Use the last `window` blocks.
	ts := timestamps[len(timestamps)-window:]
	df := difficulties[len(difficulties)-window:]

	target := config.TargetBlockTime
	// All retarget arithmetic is done in big.Int to avoid int64 overflow as
	// difficulty grows (which could otherwise be exploited to crater it).
	weightedTime := big.NewInt(0)
	sumDiff := big.NewInt(0)
	denom := big.NewInt(0)
	for i := 1; i < window; i++ {
		solve := ts[i] - ts[i-1]
		if solve < -6*target {
			solve = -6 * target
		}
		if solve > 6*target {
			solve = 6 * target
		}
		w := int64(i) // linear weight: recent blocks weigh more
		weightedTime.Add(weightedTime, big.NewInt(solve*w))
		denom.Add(denom, big.NewInt(w))
		sumDiff.Add(sumDiff, new(big.Int).SetUint64(df[i]))
	}
	// floor weightedTime to avoid blow-up / non-positive divisor.
	minWT := big.NewInt(int64(window) * target / 20)
	if minWT.Sign() <= 0 {
		minWT = big.NewInt(1)
	}
	if weightedTime.Cmp(minWT) < 0 {
		weightedTime = minWT
	}
	avgDiff := new(big.Int).Div(sumDiff, big.NewInt(int64(window-1)))

	// next = avgDiff * (target * denom) / weightedTime
	next := new(big.Int).Mul(avgDiff, big.NewInt(target))
	next.Mul(next, denom)
	next.Div(next, weightedTime)

	last := new(big.Int).SetUint64(df[window-1])
	// clamp per-block change to ±2x for stability.
	upper := new(big.Int).Lsh(last, 1)
	lower := new(big.Int).Rsh(last, 1)
	if next.Cmp(upper) > 0 {
		next = upper
	}
	if next.Cmp(lower) < 0 {
		next = lower
	}
	// enforce the network minimum and guard against uint64 overflow.
	minD := new(big.Int).SetUint64(MinDifficulty)
	if next.Cmp(minD) < 0 {
		next = minD
	}
	if !next.IsUint64() {
		return ^uint64(0)
	}
	return next.Uint64()
}
