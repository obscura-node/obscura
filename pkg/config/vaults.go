package config

import "math/big"

// Confidential staking-vault parameters. A vault locks OBX and pays yield from the
// (already-emitted, supply-capped) incentive pool — no new inflation.
// See docs/INVENTION_VAULTS.md.
//
// Two vault shapes share one code path:
//   - FLEXIBLE (Term == 0): no lock. Stake/unstake at ANY height; yield accrues
//     PRO-RATA per block elapsed at VaultFlexRateBps (annualised over
//     VaultBlocksPerYear). This is the only shape the wallet UI offers.
//   - FIXED-TERM (Term in VaultTerms): legacy locked vaults, full rate paid at
//     maturity. Kept for compatibility; not surfaced in the wallet.
//
// Terms/rates are vars (not consts) so a devnet/test can use short terms.
// Block time ≈ 120 s ⇒ ≈ 720 blocks/day.
var (
	VaultTerms    = []uint64{21_600, 64_800, 262_800}
	VaultRatesBps = []uint64{100, 400, 2000}

	// VaultFlexRateBps is the ANNUAL yield rate (basis points) for flexible
	// (Term==0) vaults, accrued pro-rata per block. 500 = 5% APY.
	VaultFlexRateBps uint64 = 500
	// VaultBlocksPerYear is the block count one annual period spans, used to
	// annualise the flexible pro-rata yield (≈365 days at 120 s/block).
	VaultBlocksPerYear uint64 = 262_800
)

// VaultRateBps returns the yield rate (basis points) for an allowed term, and
// whether the term is allowed. Term 0 is the FLEXIBLE vault (no lock, pro-rata
// yield) and is always allowed.
func VaultRateBps(term uint64) (uint64, bool) {
	if term == 0 {
		return VaultFlexRateBps, true
	}
	for i, t := range VaultTerms {
		if t == term {
			return VaultRatesBps[i], true
		}
	}
	return 0, false
}

// VaultFlexYield is the pro-rata yield a FLEXIBLE (Term==0) vault has accrued over
// elapsedBlocks since deposit:
//
//	principal · VaultFlexRateBps · elapsedBlocks / (VaultBlocksPerYear · 10_000)
//
// (overflow-safe via big.Int). Shared by the wallet (sizing the claim payout) and
// consensus (capping it) so both agree to the atom. This value-only form is kept for the
// wallet's display sizing; consensus uses VaultFlexYieldChecked so the overflow path is
// observable (audit ROUND2 [102]).
func VaultFlexYield(principal, elapsedBlocks uint64) uint64 {
	v, _ := VaultFlexYieldChecked(principal, elapsedBlocks)
	return v
}

// VaultFlexYieldChecked is VaultFlexYield with the overflow flag exposed, mirroring the
// fixed-term path (chain.vaultYield). ok=false only on an (impossible-in-practice) uint64
// overflow of the big.Int result — previously the flexible branch swallowed it and
// hardcoded success, so the "vault yield overflow" consensus error could never fire for
// flexible vaults (audit ROUND2 [102]).
func VaultFlexYieldChecked(principal, elapsedBlocks uint64) (uint64, bool) {
	if elapsedBlocks == 0 || VaultBlocksPerYear == 0 {
		return 0, true
	}
	y := new(big.Int).Mul(new(big.Int).SetUint64(principal), new(big.Int).SetUint64(VaultFlexRateBps))
	y.Mul(y, new(big.Int).SetUint64(elapsedBlocks))
	den := new(big.Int).Mul(new(big.Int).SetUint64(VaultBlocksPerYear), big.NewInt(10_000))
	y.Div(y, den)
	if !y.IsUint64() {
		return 0, false
	}
	return y.Uint64(), true
}
