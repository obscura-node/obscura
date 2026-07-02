// Package fee implements manipulation-resistant dynamic fee estimation
// (Block 20 — see docs/INVENTION_FEES.md). A wallet asks "what fee-per-byte do I
// need to confirm within `target` blocks?" and gets an answer derived from what
// recent blocks actually required — not from a trusted oracle or a miner-stuffable
// live mempool.
//
// Design (evaluated against Bitcoin estimatesmartfee + Monero dynamic fee):
//   - Per block, decide the marginal fee-rate that was *necessary* to get in.
//     If a block was NOT congested (well under the size cap), even the minimum
//     fee confirmed, so the necessary rate is the network floor. This makes the
//     estimator degrade gracefully to the floor on empty/quiet chains.
//   - Only when a block was congested do we look at the fee-rates it included and
//     take a target-dependent percentile (urgent target → higher percentile →
//     pay to be safely above the cutoff; patient target → near the cutoff).
//   - Combine blocks by the MEDIAN of their per-block samples. A single miner who
//     stuffs one block with high-fee self-paying txs cannot move the median of N
//     blocks — manipulation resistance without any identity or stake.
//   - Floor at the network minimum and cap at a multiple of it, so a suggestion
//     is always sane and bounded.
//
// Inputs are computable by anyone holding recent full blocks (a light client can
// fetch the last N blocks); no global mempool view is required.
package fee

import "sort"

// CongestionThreshold is the block-fullness fraction above which a block is
// treated as congested (the included fee-rates then signal the marginal cost).
// Below it, the minimum fee was sufficient.
const CongestionThreshold = 0.80

// MaxFeeMultiplier bounds a suggestion to this multiple of the floor, so a
// pathological window can never produce an absurd fee.
const MaxFeeMultiplier = 1000

// BlockFees summarizes one block's fee market: the fee-per-byte of each
// non-coinbase transaction, and how full the block was (0..1 of the size cap).
type BlockFees struct {
	Rates    []uint64 // fee-per-byte of each non-coinbase tx
	Fullness float64  // serialized bytes used / max block bytes
}

// percentileForTarget maps a confirmation target (in blocks) to the percentile
// of included fee-rates to aim for. Smaller target (more urgent) → higher
// percentile (pay more to be safely included); larger target → near the cutoff.
func percentileForTarget(target int) float64 {
	switch {
	case target <= 1:
		return 0.80
	case target == 2:
		return 0.60
	case target <= 5:
		return 0.50
	default:
		return 0.25
	}
}

// blockSample returns the fee-per-byte that was necessary to be included in this
// block, given the urgency percentile and the network floor.
func blockSample(b BlockFees, p float64, floor uint64) uint64 {
	if b.Fullness < CongestionThreshold || len(b.Rates) == 0 {
		return floor // underfull: the minimum fee got in
	}
	rates := append([]uint64(nil), b.Rates...)
	sort.Slice(rates, func(i, j int) bool { return rates[i] < rates[j] })
	idx := int(p * float64(len(rates)-1))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(rates) {
		idx = len(rates) - 1
	}
	s := rates[idx]
	if s < floor {
		s = floor
	}
	return s
}

// Estimate returns a suggested fee-per-byte to confirm within `target` blocks,
// derived from recent blocks. floor is the consensus minimum fee-per-byte.
func Estimate(blocks []BlockFees, target int, floor uint64) uint64 {
	if floor == 0 {
		floor = 1
	}
	if len(blocks) == 0 {
		return floor
	}
	p := percentileForTarget(target)
	samples := make([]uint64, 0, len(blocks))
	for _, b := range blocks {
		samples = append(samples, blockSample(b, p, floor))
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	med := samples[len(samples)/2]
	if len(samples)%2 == 0 {
		// average of the two middle samples for an even count
		med = (samples[len(samples)/2-1] + samples[len(samples)/2]) / 2
	}
	if med < floor {
		med = floor
	}
	if capRate := floor * MaxFeeMultiplier; med > capRate {
		med = capRate
	}
	return med
}
