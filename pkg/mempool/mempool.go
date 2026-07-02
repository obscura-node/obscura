// Package mempool holds validated, unconfirmed transactions awaiting inclusion
// in a block.
package mempool

import (
	"errors"
	"sort"
	"sync"
	"time"

	"obscura/pkg/chain"
	"obscura/pkg/commit"
	"obscura/pkg/config"
	"obscura/pkg/tx"
)

// Limits (anti-DoS).
const (
	MaxMempoolTxs   = 5000
	MaxMempoolBytes = 32 * 1024 * 1024 // 32 MiB
	TxTTL           = 2 * time.Hour
	// CoinbaseReserveBytes is held back from the block byte budget when selecting
	// fee-paying txs, so the miner's coinbase always fits under MaxBlockBytes.
	CoinbaseReserveBytes = 64 * 1024
	// MaxReplacementConflicts bounds how many pending txs a single replace-by-fee
	// (RBF) tx may evict, capping the work an attacker can trigger per submission.
	MaxReplacementConflicts = 100
)

type entry struct {
	id      string
	tx      *tx.Transaction
	size    int
	added   time.Time
	feeRate uint64
}

// Mempool is a thread-safe set of pending transactions.
type Mempool struct {
	mu       sync.Mutex
	c        *chain.Chain
	txs      map[string]*entry // txid hex -> entry
	spentBy  map[string]string // spend-key (output ref / "tag:"+image) -> owning txid
	curBytes int
}

// New creates a mempool bound to a chain.
func New(c *chain.Chain) *Mempool {
	return &Mempool{
		c:       c,
		txs:     make(map[string]*entry),
		spentBy: make(map[string]string),
	}
}

// spendKeys returns the conflict keys a transaction reserves: one per transparent
// input (its output ref) and one per anonymous input (its key-image tag).
func spendKeys(t *tx.Transaction) []string {
	keys := make([]string, 0, len(t.Inputs)+len(t.AnonInputs)+len(t.SwapInputs))
	for _, in := range t.Inputs {
		keys = append(keys, string(in.OutputRef))
		// audit #5: consensus records a transparent spend's canonical KeyImage in the
		// SAME shared nullifier set as an anon spend's canonical Tag (a coin can't be
		// spent both ways). The mempool conflict key MUST share that "tag:" namespace,
		// else a transparent spend + an anon spend of ONE coin both admit, poisoning the
		// miner's template (block rejected at the unified consensus key = free PoW grief).
		if len(in.KeyImage) == 32 {
			ki := in.KeyImage
			if c2, ok := commit.CanonicalNullifier(in.KeyImage); ok {
				ki = c2
			}
			keys = append(keys, "tag:"+string(ki))
		}
	}
	for _, in := range t.AnonInputs {
		// Canonicalize to the cofactor-cleared nullifier (8·T) so two torsion
		// variants of one coin's tag share a conflict key and cannot both sit in
		// the pool — matching the confirmed nullifier set's canonical storage.
		tg := in.Tag
		if c2, ok := commit.CanonicalNullifier(in.Tag); ok {
			tg = c2
		}
		keys = append(keys, "tag:"+string(tg))
	}
	// swap-claim/refund spends MUST also reserve a conflict key (namespaced to
	// match block validation's "swap:" set), else two spends of one swap key slip
	// into the mempool unchecked — bypassing RBF and yielding invalid templates.
	for _, in := range t.SwapInputs {
		keys = append(keys, "swap:"+string(in.SwapKey))
	}
	// vault claims reserve a conflict key too, so two claims of one vault cannot
	// both sit in the mempool (would yield an invalid template at block build).
	for _, in := range t.VaultInputs {
		keys = append(keys, "vaultin:"+string(in.VaultKey))
	}
	// ZK / CZK / PQ spends are NULLIFIER-based; without a conflict key per revealed
	// nullifier two txs spending the same hidden coin both pass admission, then collide
	// at block validation — admitting an in-pool double-spend that produces invalid
	// templates and stalls block production (audit HIGH). Reserve one key per nullifier.
	// audit fix: ZKInput (public-amount) and CZKSpend (confidential) reveal the SAME
	// coin serial as their nullifier, and consensus unifies them into one "zk:"+serial
	// set (a coin cannot be spent via both paths). The mempool conflict key MUST share
	// that namespace too, else a ZKInput and a CZKSpend revealing the same serial both
	// admit, the miner's template includes both, and the block is rejected at the
	// unified consensus key — a cheap template-poisoning DoS. Use one "zknull:" key.
	for _, in := range t.ZKInputs {
		keys = append(keys, "zknull:"+string(in.Nullifier))
	}
	for _, s := range t.CZKSpends {
		keys = append(keys, "zknull:"+string(s.Nullifier))
	}
	for _, in := range t.PQInputs {
		keys = append(keys, "pqnull:"+string(in.Nullifier))
		keys = append(keys, "pqref:"+string(in.OutputRef))
	}
	return keys
}

// Add validates a transaction against the chain and inserts it.
func (m *Mempool) Add(t *tx.Transaction) error {
	if t.IsCoinbase {
		return errors.New("mempool: coinbase not allowed")
	}
	raw := t.Serialize()
	if len(raw) > tx.MaxTxBytes {
		return errors.New("mempool: transaction too large")
	}
	// fee floor (anti-spam) — cheap check before expensive validation
	minFee := uint64(len(raw)) * config.MinFeePerByte
	if t.Fee < minFee {
		return errors.New("mempool: fee below minimum")
	}

	// audit DoS: reject an EXACT re-submission of an already-pooled tx with a cheap
	// O(1) map lookup BEFORE the ~35ms proof verification, so a duplicate flood can't
	// force repeated expensive verifies (the global RPC rate limiter still caps the
	// overall rate; a re-proofed tx gets a new txid and still pays full verify cost,
	// which costs the attacker the same work).
	m.mu.Lock()
	_, dup := m.txs[t.HashHex()]
	m.mu.Unlock()
	if dup {
		return errors.New("mempool: already present")
	}

	// Full consensus validation runs OUTSIDE the mempool lock so concurrent
	// submissions verify their (expensive ~35ms) proofs in parallel instead of
	// serializing on m.mu. It reads chain state under its own lock and verifies
	// tx-bound proofs; the authoritative double-spend / conflict / capacity checks
	// re-run under m.mu below (a confirmed spend is re-checked there), so a state
	// change between validation and insertion cannot admit an invalid tx.
	if err := m.c.ValidateStandaloneTx(t); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked()

	id := t.HashHex()
	if _, ok := m.txs[id]; ok {
		return errors.New("mempool: already present")
	}
	// A spend already CONFIRMED on-chain can never be replaced — fatal.
	for _, in := range t.Inputs {
		if m.c.OutputSpent(in.OutputRef) {
			return errors.New("mempool: output already spent")
		}
	}
	for _, in := range t.AnonInputs {
		if m.c.TagSpent(in.Tag) {
			return errors.New("mempool: key-image already spent")
		}
	}
	// audit SECURITY_AUDIT_2026-07-01 (TOCTOU): the confirmed-spend recheck must cover
	// EVERY input kind spendKeys() reserves a conflict key for — not just Inputs/AnonInputs.
	// Full validation ran OUTSIDE the lock; if a Swap/Vault/ZK/CZK/PQ input was confirmed
	// on-chain in the interim, omitting it here would admit a now-double-spent tx that only
	// collides at block validation (invalid template). Mirror each consensus spent-marker.
	for _, in := range t.SwapInputs {
		if _, ok := m.c.Swap(in.SwapKey); !ok {
			return errors.New("mempool: swap already closed/spent")
		}
	}
	for _, in := range t.VaultInputs {
		if _, ok := m.c.Vault(in.VaultKey); !ok {
			return errors.New("mempool: vault already claimed")
		}
	}
	for _, in := range t.ZKInputs {
		if m.c.ZKNullifierSpent(in.Nullifier) {
			return errors.New("mempool: zk nullifier already spent")
		}
	}
	for _, s := range t.CZKSpends {
		if m.c.ZKNullifierSpent(s.Nullifier) {
			return errors.New("mempool: czk nullifier already spent")
		}
	}
	for _, in := range t.PQInputs {
		if m.c.PQNullifierSpent(in.Nullifier) {
			return errors.New("mempool: pq nullifier already spent")
		}
	}
	// Find the set of PENDING txs this one conflicts with (shares any spend key).
	conflicts := make(map[string]struct{})
	for _, k := range spendKeys(t) {
		if owner, ok := m.spentBy[k]; ok {
			conflicts[owner] = struct{}{}
		}
	}
	// If it conflicts, it must qualify as a replace-by-fee replacement; then we
	// evict the txs it replaces.
	if len(conflicts) > 0 {
		if err := m.checkReplacementLocked(t, len(raw), conflicts); err != nil {
			return err
		}
		for cid := range conflicts {
			m.deleteLocked(cid)
		}
	}
	// capacity: evict the lowest-fee-rate txs until the incoming one actually
	// FITS (a single eviction may free far less than `raw` bytes, so this must
	// loop — otherwise the byte budget is not really a cap and can be flooded).
	incomingRate := t.Fee / uint64(max1(len(raw)))
	for len(m.txs) >= MaxMempoolTxs || m.curBytes+len(raw) > MaxMempoolBytes {
		if !m.evictLowestLocked(incomingRate) {
			return errors.New("mempool: full")
		}
	}
	m.txs[id] = &entry{id: id, tx: t, size: len(raw), added: time.Now(), feeRate: t.Fee / uint64(max1(len(raw)))}
	m.curBytes += len(raw)
	for _, k := range spendKeys(t) {
		m.spentBy[k] = id
	}
	return nil
}

// checkReplacementLocked enforces the RBF policy (adapted from Bitcoin BIP125):
// a replacement must (1) not displace more than MaxReplacementConflicts txs,
// (2) have a strictly higher fee-RATE than the best tx it replaces (so miners
// and relays genuinely prefer it), and (3) pay an absolute fee covering ALL the
// replaced fees PLUS its own relay bandwidth at the minimum rate (so the network
// is never worse off and an attacker pays real money to churn the mempool).
func (m *Mempool) checkReplacementLocked(t *tx.Transaction, newSize int, conflicts map[string]struct{}) error {
	if len(conflicts) > MaxReplacementConflicts {
		return errors.New("mempool: replacement conflicts with too many transactions")
	}
	var oldFeeTotal, maxOldRate uint64
	for cid := range conflicts {
		e := m.txs[cid]
		oldFeeTotal += e.tx.Fee
		if e.feeRate > maxOldRate {
			maxOldRate = e.feeRate
		}
	}
	newRate := t.Fee / uint64(max1(newSize))
	if newRate <= maxOldRate {
		return errors.New("mempool: replacement fee-rate must exceed the replaced transaction")
	}
	required := oldFeeTotal + uint64(newSize)*config.MinFeePerByte
	if required < oldFeeTotal { // overflow guard
		return errors.New("mempool: replacement fee overflow")
	}
	if t.Fee < required {
		return errors.New("mempool: replacement fee must cover replaced fees plus relay bandwidth")
	}
	return nil
}

// Select returns up to n pending transactions for block construction, ordered by
// fee-rate (highest first) and bounded by the block byte budget. This is what
// makes fee estimation (Block 20) meaningful: miners are economically steered to
// include the highest-paying txs first. Ordering is fully deterministic
// (fee-rate desc, then absolute fee desc, then txid asc) so independent miners
// build identical templates from identical mempools.
func (m *Mempool) Select(n int) []*tx.Transaction {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked()

	ents := make([]*entry, 0, len(m.txs))
	for _, e := range m.txs {
		ents = append(ents, e)
	}
	sort.Slice(ents, func(i, j int) bool {
		if ents[i].feeRate != ents[j].feeRate {
			return ents[i].feeRate > ents[j].feeRate
		}
		if ents[i].tx.Fee != ents[j].tx.Fee {
			return ents[i].tx.Fee > ents[j].tx.Fee
		}
		return ents[i].id < ents[j].id
	})

	budget := config.MaxBlockBytes - CoinbaseReserveBytes
	// audit: ROUND2 [98] running incentive-pool budget. Consensus rejects a block whose
	// Σ vault-claim yield exceeds the incentive pool (chain/validate.go). Mempool admission
	// only checks a claim's OWN cap, so without this several individually-valid claims select
	// together and the mined block is rejected — free, repeatable PoW waste (also organic).
	// Defer vault claims once cumulative committed yield would exceed the pool, mirroring the
	// greedy, deterministic skip-and-continue the byte budget already uses. The block-level
	// check remains as defense-in-depth.
	poolBudget := m.c.IncentivePool()
	var committedYield uint64
	out := make([]*tx.Transaction, 0, n)
	used := 0
	for _, e := range ents {
		if len(out) >= n {
			break
		}
		if used+e.size > budget {
			continue // doesn't fit; keep scanning for a smaller, lower-fee tx
		}
		if len(e.tx.VaultInputs) > 0 {
			y, ok := vaultClaimYield(e.tx)
			if !ok {
				continue // yield sum overflow — consensus would reject; never select it
			}
			next := committedYield + y
			if next < committedYield || next > poolBudget {
				continue // pool can't cover this claim's yield in this block; defer it
			}
			committedYield = next
		}
		out = append(out, e.tx)
		used += e.size
	}
	return out
}

// vaultClaimYield sums the yield a tx claims from the incentive pool across its vault
// inputs (consensus caps each claim at its entitlement and the block total at the pool
// balance). Returns ok=false on a uint64 overflow, matching the block-level guard.
func vaultClaimYield(t *tx.Transaction) (uint64, bool) {
	var sum uint64
	for _, in := range t.VaultInputs {
		s := sum + in.Yield
		if s < sum {
			return 0, false
		}
		sum = s
	}
	return sum, true
}

// Remove drops transactions that were included in a block and evicts any pending
// tx that CONFLICTS with the block (shares a spend-key — i.e. double-spends an
// output the block just consumed). A still-pending tx whose spend-keys were not
// touched by the block remains valid — its proofs were verified at admission and
// nothing it depends on changed — so NO re-verification is needed. This replaces
// a full O(mempool) re-validation on every block (the dominant cost under load)
// with an O(block + mempool) spend-key scan. Correct on mainnet, not just devnet.
func (m *Mempool) Remove(txs []*tx.Transaction) {
	m.mu.Lock()
	defer m.mu.Unlock()
	blockSpent := make(map[string]bool)
	for _, t := range txs {
		if t.IsCoinbase {
			continue
		}
		for _, k := range spendKeys(t) {
			blockSpent[k] = true
		}
		m.deleteLocked(t.HashHex())
	}
	for id, e := range m.txs {
		for _, k := range spendKeys(e.tx) {
			if blockSpent[k] {
				m.deleteLocked(id)
				break
			}
		}
	}
}

func (m *Mempool) deleteLocked(id string) {
	e, ok := m.txs[id]
	if !ok {
		return
	}
	for _, k := range spendKeys(e.tx) {
		// only remove the reservation if THIS tx still owns it (a replacement may
		// have already re-pointed the key at itself)
		if m.spentBy[k] == id {
			delete(m.spentBy, k)
		}
	}
	m.curBytes -= e.size
	delete(m.txs, id)
}

func (m *Mempool) expireLocked() {
	now := time.Now()
	for id, e := range m.txs {
		if now.Sub(e.added) > TxTTL {
			m.deleteLocked(id)
		}
	}
}

// evictLowestLocked removes the lowest fee-rate tx if it is below incomingRate.
func (m *Mempool) evictLowestLocked(incomingRate uint64) bool {
	var lowID string
	var lowRate = ^uint64(0)
	for id, e := range m.txs {
		if e.feeRate < lowRate {
			lowRate = e.feeRate
			lowID = id
		}
	}
	if lowID == "" || lowRate >= incomingRate {
		return false
	}
	m.deleteLocked(lowID)
	return true
}

// Size returns the number of pending transactions.
func (m *Mempool) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.txs)
}

// Stats summarizes the mempool for fee decisions and explorers.
type Stats struct {
	Count      int    `json:"count"`
	Bytes      int    `json:"bytes"`
	MinFeeRate uint64 `json:"min_fee_rate"`
	MedFeeRate uint64 `json:"median_fee_rate"`
	MaxFeeRate uint64 `json:"max_fee_rate"`
	TotalFees  uint64 `json:"total_fees"`
}

// Stats returns a snapshot of the current mempool.
func (m *Mempool) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked()
	st := Stats{Count: len(m.txs), Bytes: m.curBytes}
	if len(m.txs) == 0 {
		return st
	}
	rates := make([]uint64, 0, len(m.txs))
	for _, e := range m.txs {
		rates = append(rates, e.feeRate)
		st.TotalFees += e.tx.Fee
	}
	sort.Slice(rates, func(i, j int) bool { return rates[i] < rates[j] })
	st.MinFeeRate = rates[0]
	st.MaxFeeRate = rates[len(rates)-1]
	st.MedFeeRate = rates[len(rates)/2]
	return st
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
