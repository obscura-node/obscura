package chain

import (
	"math/big"

	"obscura/pkg/config"
)

// VaultEntry is a live staking-vault deposit. Yield is paid from the incentive
// pool at claim time (docs/INVENTION_VAULTS.md). The rate is SNAPSHOTTED at
// deposit (RateBps) so a later change to the term table can never strand a
// depositor or alter their promised yield. Rolled back on reorg, rebuilt on
// replay — same discipline as swaps.
type VaultEntry struct {
	Amount        uint64
	Term          uint64
	RateBps       uint64 // yield rate locked in at deposit time
	OwnerKey      []byte
	DepositHeight uint64
}

// Maturity is the first height at which the vault may be claimed. For a FLEXIBLE
// vault (Term == 0) this is the deposit height itself, so the maturity gate in
// validation is satisfied at every later height — i.e. it can be unstaked any time.
func (e *VaultEntry) Maturity() uint64 { return e.DepositHeight + e.Term }

// IsFlexible reports whether this is a no-lock, pro-rata-yield vault.
func (e *VaultEntry) IsFlexible() bool { return e.Term == 0 }

// vaultYieldAt computes the yield owed when a vault is claimed at claimHeight.
// FIXED-TERM vaults pay the full snapshotted rate (paid only at/after maturity).
// FLEXIBLE vaults (Term == 0) accrue PRO-RATA per block elapsed since deposit:
//
//	yield = Amount · RateBps · (claimHeight − DepositHeight) / (BlocksPerYear · 10_000)
//
// so an instant deposit→claim in the same block earns 0 (no risk-free skim), and a
// full year staked earns the full annual rate. All callers (block affordability,
// per-tx claim, apply) use this with the SAME block height for a consistent payout.
func vaultYieldAt(v *VaultEntry, claimHeight uint64) (uint64, bool) {
	if !v.IsFlexible() {
		return vaultYield(v.Amount, v.RateBps)
	}
	var elapsed uint64
	if claimHeight > v.DepositHeight {
		elapsed = claimHeight - v.DepositHeight
	}
	// audit: ROUND2 [102] propagate the overflow flag instead of hardcoding ok=true, so the
	// "vault yield overflow" validation path can actually fire for flexible vaults too.
	return config.VaultFlexYieldChecked(v.Amount, elapsed)
}

// vaultYield computes Amount·rateBps/10_000 with no uint64 overflow (Amount can
// approach the money supply). ok=false only on (impossible-in-practice) overflow.
func vaultYield(amount, rateBps uint64) (uint64, bool) {
	y := new(big.Int).Mul(new(big.Int).SetUint64(amount), new(big.Int).SetUint64(rateBps))
	y.Div(y, big.NewInt(10_000))
	if !y.IsUint64() {
		return 0, false
	}
	return y.Uint64(), true
}

// --- read-only queries (RPC / explorer / tests) ---

// Vault returns a copy of a live vault by key.
func (c *Chain) Vault(key []byte) (VaultEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.vaults[hexstr(key)]
	if !ok {
		return VaultEntry{}, false
	}
	return *e, true
}

// VaultCount returns the number of live vaults.
func (c *Chain) VaultCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.vaults)
}

// VaultInfo is a public, explorer-facing view of a live vault. Key is the hex
// vault id so a wallet can match its locally-remembered deposit to the on-chain
// entry (and read the authoritative DepositHeight for pro-rata yield sizing).
type VaultInfo struct {
	Key           string
	Amount        uint64
	Term          uint64
	RateBps       uint64
	DepositHeight uint64
	Maturity      uint64
}

// VaultList returns a snapshot of all live vaults (order not guaranteed).
func (c *Chain) VaultList() []VaultInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]VaultInfo, 0, len(c.vaults))
	for k, e := range c.vaults {
		out = append(out, VaultInfo{
			Key:    k,
			Amount: e.Amount, Term: e.Term, RateBps: e.RateBps,
			DepositHeight: e.DepositHeight, Maturity: e.Maturity(),
		})
	}
	return out
}

// TotalValueLocked returns the sum of all live vault principals (the supply sink).
func (c *Chain) TotalValueLocked() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var tvl uint64
	for _, e := range c.vaults {
		tvl += e.Amount // bounded by total emitted supply; no realistic overflow
	}
	return tvl
}
