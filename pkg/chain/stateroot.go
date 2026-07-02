package chain

import (
	"encoding/binary"
	"sort"

	"golang.org/x/crypto/blake2b"

	"obscura/pkg/tx"
)

// stateRootLocked computes a deterministic commitment over ALL consensus state that is NOT
// already bound by an existing header root (AccValue/NullRoot/CMRoot/PQAccRoot/PoRRoot). It is
// a PRE-STATE root: a block header commits the state of its PARENT (the state the block is
// built on). BlockTemplate and validateBlockLocked both run with the chain AT the parent tip,
// so they compute the identical value with NO prediction/mirror-apply — the class of bug that
// makes post-state roots fork-prone is structurally impossible here. A snapshot at height H is
// verified against the PoW-bound header[H+1].StateRoot.
//
// Covered: emitted, incentivePool; the disk-set commitments (spent/tags/outPrimes — the
// classical double-spend + output-uniqueness sets, otherwise committed by NO header root); and
// every in-RAM consensus map (swaps, swapNonces, vaults, accValues, referral, pqUtxo INCLUDING
// amounts [closes audit PQACC-1], pqIndex, pqNull, pqWots, pqRoots, cmRoots, cmFinal, cmRootOrder,
// zkNull). Caller holds the lock.
//
// Memoized: the value only changes when a block is applied / the chain is reset / a snapshot is
// restored, so it is cached and those three sites invalidate it (invalidateStateRoot). This
// removes the redundant recompute when template AND validate run on the same parent state.
func (c *Chain) stateRootLocked() [32]byte {
	// audit: ROUND2 [87] guard the memo with srmu — callers may hold only c.mu.RLock
	// (concurrent BlockTemplate goroutines), so the cache miss-then-write below is a
	// data race without a dedicated lock. computeStateRootLocked reads chain state the
	// caller already pins via c.mu (R or W); we never take c.mu while holding srmu, so
	// srmu stays the innermost lock and introduces no ordering hazard.
	c.srmu.Lock()
	defer c.srmu.Unlock()
	if c.srCacheOK {
		return c.srCache
	}
	r := c.computeStateRootLocked()
	c.srCache, c.srCacheOK = r, true
	return r
}

// invalidateStateRoot drops the memoized state-root. MUST be called after any mutation to the
// state stateRootLocked commits — i.e. at the end of applyBlock, in resetState, and in
// restoreSnapshotLocked (the only places that consensus state transitions).
func (c *Chain) invalidateStateRoot() {
	// audit: ROUND2 [87] same srmu guard. These three call sites hold c.mu exclusively
	// (so no RLock reader runs concurrently), but taking srmu here keeps the field's
	// access discipline uniform and defends against any future caller that invalidates
	// under a read lock.
	c.srmu.Lock()
	c.srCacheOK = false
	c.srmu.Unlock()
}

// residualState is the full set of consensus state NOT bound by an existing header root, fed
// to stateRootOf. Extracted so the live chain AND the snapshot verifier compute the identical
// commitment from ONE code path (no divergence between apply-time and import-time).
type residualState struct {
	emitted, incentivePool                                                   uint64
	spentCommit, tagsCommit, outPrimeCommit                                  [32]byte
	swapNonces, accValues, pqNull, pqWots, pqRoots, cmRoots, cmFinal, zkNull map[string]bool
	referral                                                                 map[string]uint64
	pqIndex                                                                  map[string]int
	cmRootOrder                                                              []string
	swaps                                                                    map[string]*SwapEntry
	vaults                                                                   map[string]*VaultEntry
	pqUtxo                                                                   map[string]*tx.PQOutput
}

// computeStateRootLocked does the actual O(state) hash. Recomputed only on a cache miss; a
// production build would maintain it incrementally like the disksets (future work).
func (c *Chain) computeStateRootLocked() [32]byte {
	return stateRootOf(residualState{
		emitted: c.emitted, incentivePool: c.incentivePool,
		spentCommit: c.spent.Commit(), tagsCommit: c.tags.Commit(), outPrimeCommit: c.outPrimes.Commit(),
		swapNonces: c.swapNonces, accValues: c.accValues, pqNull: c.pqNull, pqWots: c.pqWots, pqRoots: c.pqRoots,
		cmRoots: c.cmRoots, cmFinal: c.cmFinal, zkNull: c.zkNull,
		referral: c.referral, pqIndex: c.pqIndex, cmRootOrder: c.cmRootOrder,
		swaps: c.swaps, vaults: c.vaults, pqUtxo: c.pqUtxo,
	})
}

// stateRootOf is the pure, deterministic residual-state commitment. The byte layout MUST stay
// identical (it is consensus): changing it forks the chain.
func stateRootOf(rs residualState) [32]byte {
	c := rs // local alias so the field accesses below read like the original
	h, _ := blake2b.New256(nil)
	var u8 [8]byte
	putU64 := func(x uint64) { binary.BigEndian.PutUint64(u8[:], x); h.Write(u8[:]) }
	putBytes := func(b []byte) { putU64(uint64(len(b))); h.Write(b) }
	tag := func(s string) { h.Write([]byte(s)) }
	boolSet := func(name string, m map[string]bool) {
		tag(name)
		ks := sortedKeys(m)
		putU64(uint64(len(ks)))
		for _, k := range ks {
			putBytes([]byte(k))
		}
	}

	tag("OBX-stateroot-v1")

	// scalars
	tag("|emit|")
	putU64(c.emitted)
	putU64(c.incentivePool)

	// disk-set commitments (order-independent multiset hashes — see diskset.go)
	tag("|dsets|")
	sc := c.spentCommit
	h.Write(sc[:])
	tc := c.tagsCommit
	h.Write(tc[:])
	oc := c.outPrimeCommit
	h.Write(oc[:])

	// boolean membership sets (sorted keys for determinism)
	boolSet("|swapNonces|", c.swapNonces)
	boolSet("|accValues|", c.accValues)
	boolSet("|pqNull|", c.pqNull)
	boolSet("|pqWots|", c.pqWots)
	boolSet("|pqRoots|", c.pqRoots)
	boolSet("|cmRoots|", c.cmRoots)
	boolSet("|cmFinal|", c.cmFinal)
	boolSet("|zkNull|", c.zkNull)

	// referral: map[string]uint64
	tag("|referral|")
	putU64(uint64(len(c.referral)))
	for _, k := range sortedKeys(c.referral) {
		putBytes([]byte(k))
		putU64(c.referral[k])
	}

	// pqIndex: map[string]int
	tag("|pqIndex|")
	putU64(uint64(len(c.pqIndex)))
	for _, k := range sortedKeys(c.pqIndex) {
		putBytes([]byte(k))
		putU64(uint64(c.pqIndex[k]))
	}

	// cmRootOrder: ordered FIFO slice (order is consensus-relevant)
	tag("|cmRootOrder|")
	putU64(uint64(len(c.cmRootOrder)))
	for _, s := range c.cmRootOrder {
		putBytes([]byte(s))
	}

	// swaps: map[string]*SwapEntry
	tag("|swaps|")
	putU64(uint64(len(c.swaps)))
	for _, k := range sortedKeys(c.swaps) {
		e := c.swaps[k]
		putBytes([]byte(k))
		putU64(e.Amount)
		putU64(e.UnlockHeight)
		putBytes(e.ClaimKey)
		putBytes(e.RefundKey)
		putBytes(e.ClaimR)
		putBytes(e.ClaimT)
	}

	// vaults: map[string]*VaultEntry
	tag("|vaults|")
	putU64(uint64(len(c.vaults)))
	for _, k := range sortedKeys(c.vaults) {
		e := c.vaults[k]
		putBytes([]byte(k))
		putU64(e.Amount)
		putU64(e.Term)
		putU64(e.RateBps)
		putU64(e.DepositHeight)
		putBytes(e.OwnerKey)
	}

	// pqUtxo: map[string]*tx.PQOutput — INCLUDES Amount (closes audit PQACC-1)
	tag("|pqUtxo|")
	putU64(uint64(len(c.pqUtxo)))
	for _, k := range sortedKeys(c.pqUtxo) {
		o := c.pqUtxo[k]
		putBytes([]byte(k))
		putU64(o.Amount)
		putBytes(o.OneTimeKey)
		putBytes(o.KEMCiphertext)
		putBytes(o.ViewTag)
		putBytes(o.Commitment)
		putBytes(o.EncAmount)
		putBytes(o.MAC)
	}

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// sortedKeys returns the map's string keys in ascending order (deterministic iteration).
func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
