// Package chain implements the Obscura blockchain state machine. It maintains
// an ADD-ONLY accumulator over every output ever created (the global anonymity
// set) plus a nullifier set marking spent outputs — the Zerocoin-style model,
// which keeps membership witnesses valid forever and avoids witness updates on
// spend. It also tracks emission, the holding-incentive pool, and referral
// claims.
package chain

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/blake2b"

	"obscura/pkg/accumulator"
	"obscura/pkg/block"
	"obscura/pkg/commit"
	"obscura/pkg/config"
	"obscura/pkg/group"
	"obscura/pkg/pqaccum"
	"obscura/pkg/stark"
	"obscura/pkg/tx"
)

// CoinInfo records a coin that has ever existed (used to build anonymity-set
// rings; never removed, since spent coins remain valid ring decoys).
type CoinInfo struct {
	Key        []byte // one-time key (32B)
	Commitment []byte // amount commitment (32B)
	Height     uint64
	IsCoinbase bool
	LockUntil  uint64 // output not spendable before this height (holding bonus)
	Index      uint64 // canonical creation order (pool = Index / PoolSize)
}

// SwapEntry is a live on-chain atomic-swap contract awaiting claim or refund.
type SwapEntry struct {
	Amount       uint64
	ClaimKey     []byte
	RefundKey    []byte
	UnlockHeight uint64
	// Atomicity binding committed at funding time (audit fix): the claim path
	// requires the claim signature's nonce to equal ClaimR + ClaimT, so a claim
	// must be the adapted pre-signature and hence reveal the adaptor secret.
	ClaimR []byte
	ClaimT []byte
}

// UTXOEntry records an unspent output for the sound spend model.
type UTXOEntry struct {
	Commitment []byte // Pedersen commitment to the amount (32B)
	Height     uint64 // block height at which the output was created
	IsCoinbase bool   // coinbase outputs are subject to maturity
	LockUntil  uint64 // output not spendable before this height (holding bonus)
}

// Chain is the full-node blockchain state.
type Chain struct {
	mu sync.RWMutex

	G group.Group
	// stateRootLocked memoization: the residual-state commitment only changes when a block is
	// applied / the chain is reset / a snapshot is restored, so cache it and invalidate at
	// exactly those points (stateRootLocked is read only by template+validate+genesis, all at a
	// stable pre-state). Same committed value — pure speedup, removes the redundant per-block
	// template+validate recompute. (The deeper O(state)/block → O(1) incremental fix is noted
	// in docs as future work.)
	srCache   [32]byte
	srCacheOK bool
	// audit: ROUND2 [87] dedicated lock for the state-root memo. BlockTemplate runs
	// under c.mu.RLock (one goroutine per live RPC request) and ValidateBlock under
	// c.mu (write), but the cache MISS-then-WRITE in stateRootLocked happens while
	// only a READ lock is held — so two concurrent template builders would race on
	// srCache/srCacheOK (torn StateRoot → honest nodes reject the block). srmu serializes
	// every read/compute/write, mirroring the vmu pattern. It is the INNERMOST lock
	// (only ever taken with c.mu already held, never the reverse) so it does not perturb
	// the existing c.mu→c.vmu ordering.
	srmu sync.Mutex

	acc *accumulator.Accumulator

	// UTXO is DERIVED, not stored: an output is unspent iff its coin record exists
	// (coinstore) and its key is NOT in the `spent` set below — so the live set is
	// disk-backed and O(1) in RAM (Track A; docs/SCALING_100M.md).
	spent *diskSet // output keys spent transparently (the "removed from utxo" set)
	// "every coin ever" (anonymity-set / ring membership) is DISK-backed in bolt
	// (coinstore.go) — only an O(1) count lives in RAM (Track A; docs/SCALING_100M.md).
	coinCount uint64 // number of coins ever created (== next creation index)
	// disk-backed add-only sets (O(1) RAM; docs/SCALING_100M.md): the nullifier
	// double-spend set and the output-prime uniqueness set.
	tags      *diskSet              // key-image / nullifier set (double-spend)
	outPrimes *diskSet              // output-prime uniqueness set
	swaps     map[string]*SwapEntry // hex(SwapKey) -> live atomic-swap contract
	// swapNonces is the CONSENSUS uniqueness set over every atomic-swap adaptor
	// pre-signature nonce ClaimR ever funded on-chain (audit #14). Reusing R across
	// two claims under the same aggregate key leaks the secret share (see
	// swapsession.DeriveNonce): two responses s=r+e·x, s'=r+e'·x solve x=(s−s')/(e−e').
	// The honest path already draws a fresh R per swap (DeriveNonce binds R to the
	// coreHash, so distinct swaps get distinct R); CONSENSUS rejects reuse outright as
	// defence-in-depth. Keyed on ClaimR alone (the SAFE SUPERSET of the precise
	// (ClaimKey,ClaimR) leak condition): rejecting all R-reuse can never reject a
	// legitimate distinct swap (each draws a fresh R) and is strictly stronger.
	// UNBOUNDED, like zkNull — a nonce can never be safely forgotten. Reorg-safe via
	// the SAME snapshot/restore+replay path as zkNull: cleared in resetState, restored
	// from snapshot, repopulated on apply (so a rolled-back swap's R is dropped by the
	// restore and re-added on re-include).
	swapNonces map[string]bool        // hex(ClaimR) -> funded (adaptor-nonce uniqueness)
	vaults     map[string]*VaultEntry // hex(VaultKey) -> live staking vault deposit
	accValues  map[string]bool        // hex(blake2b(accValueBytes)) -> seen (checkpoint set)

	headers []block.Header // active chain, index by height
	byHash  map[[32]byte]uint64
	blocks  map[uint64]*block.Block

	// fork-choice block tree (all known blocks incl. side branches)
	nodes       map[[32]byte]*chainNode     // block hash -> node
	orphans     map[[32]byte][]*block.Block // parent hash -> children awaiting parent
	orphanMeta  map[[32]byte]orphanMeta     // orphan block hash -> {parent, bytes} (for byte-bound + eviction)
	orphanFIFO  [][32]byte                  // orphan block hashes in arrival order (FIFO eviction queue)
	orphanBytes int                         // running sum of buffered orphan body bytes (anti-DoS bound)
	bestHash    [32]byte                    // hash of the active tip (max cumulative work)

	emitted       uint64            // total atomic units emitted
	incentivePool uint64            // accumulated holding-bonus pool
	referral      map[string]uint64 // referrer tag hex -> claims used

	// Post-quantum (experimental Version-2 path). Rebuilt on replay from blocks,
	// so no separate persistence is needed. Separate value space from classical
	// amounts. See docs/POST_QUANTUM_ROADMAP.md.
	// nullAcc is an add-only Merkle accumulator over every key-image/nullifier
	// ever spent. Its root is committed in each header (NullRoot), making the
	// SPENT set part of the trustlessly-verifiable state — the in-design hook
	// that lets a pruned/light node verify a spent-set snapshot. Rebuilt on replay.
	nullAcc *pqaccum.Accumulator

	pqAcc   *pqaccum.Accumulator // global PQ anonymity set (add-only Merkle)
	pqUtxo  map[string]*tx.PQOutput
	pqIndex map[string]int  // hex(OneTimeKey) -> pqAcc leaf index
	pqNull  map[string]bool // hex(nullifier) -> spent
	pqWots  map[string]bool // hex(WOTS+ root R) -> revealed at spend (one-time-key reuse defense)
	pqRoots map[string]bool // hex(historical PQ root) -> valid anchor (Zcash-style)

	// Fully-anonymous ZK spend (docs/ZK_MEMBERSHIP_SPEND.md). cmTree is the
	// Poseidon commitment tree (the STARK-friendly accumulator); coin outputs append
	// their CMLeaf. cmRoots whitelists recent roots as spend anchors; zkNull is the
	// revealed-serial nullifier set. All rebuilt on replay / restored from snapshot.
	cmTree  *stark.EpochIMT
	cmRoots map[string]bool // hex(CM root) -> valid spend anchor (final ∪ windowed current)
	cmFinal map[string]bool // finalized-epoch terminal roots — PERMANENT anchors (never
	// evicted; bounded by #epochs = totalCoins/2^ZKDepth), so coins in
	// old epochs stay spendable (review finding: window-only evicts them)
	cmRootOrder []string        // FIFO of CURRENT-epoch root snapshots, for rolling-window eviction
	zkNull      map[string]bool // hex(serial nullifier) -> spent (UNBOUNDED — nullifiers
	// can never be forgotten without enabling double-spend;
	// bounding needs a non-membership accumulator, Track C)

	// verifiedProofs caches txids whose expensive proofs (range/ownership/value/
	// key-image/anon/conservation) this node has ALREADY verified — once during
	// mempool admission. A tx's proofs are bound to its own bytes and are
	// independent of chain tip, so they never need re-verification: block
	// validation re-checks only the cheap structural / double-spend / UTXO state.
	// This removes the dominant double-validation cost. A peer's novel tx (never
	// seen in our mempool) is NOT cached and gets full verification — so this is
	// mainnet-safe (we only skip re-verifying proofs we personally verified).
	verifiedProofs map[[32]byte]struct{}
	vmu            sync.Mutex

	db *bolt.DB
}

// maxVerifiedProofs bounds the verified-proof cache (entries are immutable, so
// eviction merely causes a re-verification — never a correctness issue).
const maxVerifiedProofs = 500_000

func (c *Chain) proofVerified(id [32]byte) bool {
	c.vmu.Lock()
	_, ok := c.verifiedProofs[id]
	c.vmu.Unlock()
	return ok
}

func (c *Chain) markProofVerified(id [32]byte) {
	c.vmu.Lock()
	if len(c.verifiedProofs) < maxVerifiedProofs {
		c.verifiedProofs[id] = struct{}{}
	}
	c.vmu.Unlock()
}

// ClearVerifiedProofCache empties the verified-proof cache. Diagnostic/benchmark use
// (forces full re-verification of a block's proofs); correctness-neutral since cache
// entries are immutable and merely skip a redundant re-verification.
func (c *Chain) ClearVerifiedProofCache() {
	c.vmu.Lock()
	c.verifiedProofs = make(map[[32]byte]struct{})
	c.vmu.Unlock()
}

var (
	bucketBlocks   = []byte("blocks")
	bucketMeta     = []byte("meta")
	bucketSnapshot = []byte("snapshot")
	bucketCoinList = []byte("coinlist") // creation-index -> CoinInfo (anonymity set)
	bucketCoins    = []byte("coins")    // hex(key) -> CoinInfo
	bucketTagIdx   = []byte("tagidx")
	bucketTagSet   = []byte("tagset")
	bucketPrimeIdx = []byte("primeidx")
	bucketPrimeSet = []byte("primeset")
	bucketSpentIdx = []byte("spentidx")
	bucketSpentSet = []byte("spentset")
	// bucketTxIndex maps a 32-byte txid -> 8-byte active-chain height. ADDITIVE,
	// NON-CONSENSUS query index (powers RPC /tx O(1) lookup); never read during
	// validation. Maintained on block apply + reorg, built once on open if absent.
	bucketTxIndex = []byte("txindex")
	// per-count running set commitments (state-root precursor; see diskset.go).
	bucketTagCommit   = []byte("tagcommit")
	bucketPrimeCommit = []byte("primecommit")
	bucketSpentCommit = []byte("spentcommit")
)

// allBuckets is every bolt bucket the chain creates on open.
var allBuckets = [][]byte{
	bucketBlocks, bucketSnapshot, bucketCoinList, bucketCoins,
	bucketTagIdx, bucketTagSet, bucketPrimeIdx, bucketPrimeSet,
	bucketSpentIdx, bucketSpentSet, bucketMeta,
	bucketTagCommit, bucketPrimeCommit, bucketSpentCommit,
	bucketTxIndex,
}

// New creates (or opens) a chain at dir. If empty, the genesis block is created.
func New(dir string) (*Chain, error) {
	G, err := NewConfiguredGroup()
	if err != nil {
		return nil, err
	}
	c := &Chain{
		G: G,
		// value-only: the accumulator value is a header commitment; the production
		// spend path uses rings, not accumulator witnesses, so the O(n) member set is
		// dropped (Track A — docs/SCALING_100M.md). Archive nodes needing witnesses
		// would use accumulator.New.
		acc:            accumulator.NewValueOnly(G),
		swaps:          make(map[string]*SwapEntry),
		swapNonces:     make(map[string]bool),
		vaults:         make(map[string]*VaultEntry),
		accValues:      make(map[string]bool),
		byHash:         make(map[[32]byte]uint64),
		blocks:         make(map[uint64]*block.Block),
		referral:       make(map[string]uint64),
		nodes:          make(map[[32]byte]*chainNode),
		orphans:        make(map[[32]byte][]*block.Block),
		orphanMeta:     make(map[[32]byte]orphanMeta),
		nullAcc:        pqaccum.NewStreaming(), // O(log n) RAM; only ever root-committed, never proved
		pqAcc:          pqaccum.New(),
		pqUtxo:         make(map[string]*tx.PQOutput),
		pqIndex:        make(map[string]int),
		pqNull:         make(map[string]bool),
		pqWots:         make(map[string]bool),
		pqRoots:        make(map[string]bool),
		cmTree:         stark.NewEpochIMT(stark.ZKDepth),
		cmRoots:        make(map[string]bool),
		cmFinal:        make(map[string]bool),
		zkNull:         make(map[string]bool),
		verifiedProofs: make(map[[32]byte]struct{}),
	}
	// NOTE: the empty-set root is deliberately NOT seeded as an anchor (a spend
	// always references a non-empty set; whitelisting the degenerate all-zero
	// root is an unnecessary sharp edge). Anchors are recorded in apply.go only
	// once the PQ set is non-empty.
	if dir != "" {
		db, err := bolt.Open(dir+"/obscura.db", 0600, nil)
		if err != nil {
			return nil, err
		}
		c.db = db
		if err := db.Update(func(tx *bolt.Tx) error {
			for _, b := range allBuckets {
				if _, err := tx.CreateBucketIfNotExists(b); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	// disk-backed add-only sets (bound to c.db; nil-db is unused in practice).
	c.tags = newDiskSet(c.db, bucketTagIdx, bucketTagSet, bucketTagCommit)
	c.outPrimes = newDiskSet(c.db, bucketPrimeIdx, bucketPrimeSet, bucketPrimeCommit)
	c.spent = newDiskSet(c.db, bucketSpentIdx, bucketSpentSet, bucketSpentCommit)
	if c.db != nil {
		if err := c.replay(); err != nil {
			return nil, err
		}
	}
	if len(c.headers) == 0 {
		if err := c.initGenesis(); err != nil {
			return nil, err
		}
	}
	// Build the additive txid->height query index from persisted bodies if a
	// pre-existing database lacks it (no-op once populated; kept current by the
	// apply/reorg hooks thereafter). Non-consensus — failure here is non-fatal.
	if err := c.buildTxIndexIfAbsent(); err != nil {
		return nil, err
	}
	c.indexActiveChain() // build the fork-choice node tree from the active chain
	return c, nil
}

// Close flushes and closes the database.
func (c *Chain) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// replay rebuilds in-memory state. Fast path: restore the latest state snapshot
// (verified against the header-committed roots) and replay only the blocks ABOVE
// it. Without a valid snapshot it replays from genesis (re-validating every
// block). See docs/SCALING_100M.md. Caller is the single-threaded constructor.
func (c *Chain) replay() error {
	start := uint64(0)
	snapHeight, ok, lerr := c.loadSnapshotLocked()
	if ok && lerr == nil && c.verifySnapshotLocked() == nil {
		start = snapHeight + 1 // state restored from snapshot; replay only newer blocks
	} else {
		c.resetState() // no/invalid snapshot → full replay from genesis
		start = 0
	}
	// reconcile the disk-backed coin set to the restored count: drop any coins
	// from blocks after the snapshot (the replay below re-appends them). On a full
	// replay this truncates to 0 and the whole set is rebuilt.
	c.truncateCoinsLocked(c.coinCount)
	c.tags.truncate(c.tags.Count())
	c.outPrimes.truncate(c.outPrimes.Count())
	c.spent.truncate(c.spent.Count())
	return c.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketBlocks)
		cur := b.Cursor()
		for k, v := cur.Seek(heightKey(start)); k != nil; k, v = cur.Next() {
			blk, err := block.DeserializeBlock(v)
			if err != nil {
				return err
			}
			if blk.Header.Height < start {
				continue
			}
			// Re-validate every replayed block (don't trust the DB). Genesis
			// (height 0) is the trust root and is applied directly. Blocks at or
			// below the snapshot height were already covered by the snapshot.
			if blk.Header.Height > 0 {
				if err := c.validateBlockLocked(blk); err != nil {
					return fmt.Errorf("replay validation height %d: %w", blk.Header.Height, err)
				}
			}
			if err := c.applyBlock(blk, false); err != nil {
				return fmt.Errorf("replay height %d: %w", blk.Header.Height, err)
			}
		}
		return nil
	})
}

// Tip returns the current best header.
func (c *Chain) Tip() block.Header {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.headers[len(c.headers)-1]
}

// Height returns the current tip height.
func (c *Chain) Height() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.headers[len(c.headers)-1].Height
}

// Emitted returns total emitted supply (atomic units).
func (c *Chain) Emitted() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.emitted
}

// IncentivePool returns the current holding-incentive pool balance.
func (c *Chain) IncentivePool() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.incentivePool
}

// AccValue returns the current accumulator value bytes.
func (c *Chain) AccValue() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.G.Marshal(c.acc.Value())
}

// AccSize returns the number of accumulated outputs.
func (c *Chain) AccSize() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return uint64(c.acc.Size())
}

// Group exposes the group of unknown order.
func (c *Chain) Group() group.Group { return c.G }

// blockCacheCap bounds how many recent block BODIES are held in RAM. Older bodies
// live only in bolt and are loaded on demand — this is what keeps node RAM
// O(window) instead of O(chain) (the 2GB-survival fix). It does NOT need to cover
// a reorg's changed suffix: rebuildToBranchLocked persists each replayed block to
// bolt directly (a partition-recovery reorg can replay PoWSeedLag > cap blocks),
// so durability never depends on the cache capacity.
const blockCacheCap = 300

// cacheBlock stores a block body in the bounded in-RAM cache, evicting the oldest
// height when over capacity. Caller holds the write lock.
func (c *Chain) cacheBlock(h uint64, b *block.Block) {
	c.blocks[h] = b
	if len(c.blocks) <= blockCacheCap {
		return
	}
	// evict the lowest height (oldest); its body remains durable in bolt.
	var min uint64 = ^uint64(0)
	for k := range c.blocks {
		if k < min {
			min = k
		}
	}
	delete(c.blocks, min)
}

// loadBlockBolt reads and parses a block body from bolt by height (nil if absent).
func (c *Chain) loadBlockBolt(h uint64) *block.Block {
	if c.db == nil {
		return nil
	}
	var b *block.Block
	_ = c.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketBlocks).Get(heightKey(h))
		if v == nil {
			return nil
		}
		blk, err := block.DeserializeBlock(v)
		if err == nil {
			b = blk
		}
		return nil
	})
	return b
}

// bodyAtHeight returns the active-chain block body at height h from the RAM cache,
// falling back to bolt. Caller holds at least the read lock.
func (c *Chain) bodyAtHeight(h uint64) (*block.Block, bool) {
	if b, ok := c.blocks[h]; ok {
		return b, true
	}
	if b := c.loadBlockBolt(h); b != nil {
		return b, true
	}
	return nil, false
}

// BlockByHeight returns the block at a height (RAM cache or bolt).
func (c *Chain) BlockByHeight(h uint64) (*block.Block, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.bodyAtHeight(h)
}

// HeaderByHeight returns the header at a height.
func (c *Chain) HeaderByHeight(h uint64) (block.Header, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if h >= uint64(len(c.headers)) {
		return block.Header{}, false
	}
	return c.headers[h], true
}

// powSeedLocked returns the per-epoch PoW cache seed for a block at `height`.
// Epoch 0 (and any seed height not yet known) uses the fixed genesis seed; later
// epochs use the id of the block PoWSeedLag-rounded blocks in the past. The
// second return is false only when the seed height is beyond our active chain
// (an out-of-order future block), in which case callers should defer the check.
func (c *Chain) powSeedLocked(height uint64) ([]byte, bool) {
	sh := config.PoWSeedHeight(height)
	if sh == 0 {
		return config.PoWGenesisSeed, true
	}
	if sh >= uint64(len(c.headers)) {
		return nil, false
	}
	id := c.headers[sh].ID()
	return id[:], true
}

// PoWSeed returns the per-epoch PoW cache seed for a block at `height` (for the
// miner). Falls back to the genesis seed when the seed height is not yet known.
func (c *Chain) PoWSeed(height uint64) []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	seed, ok := c.powSeedLocked(height)
	if !ok {
		return config.PoWGenesisSeed
	}
	return seed
}

// OutputSpent reports whether the output identified by its one-time key has
// already been spent (i.e. is no longer in the UTXO set).
func (c *Chain) OutputSpent(outputRef []byte) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.utxoEntryLocked(outputRef)
	return !ok
}

// TagSpent reports whether an anonymous key-image tag has already been used.
// The confirmed nullifier set stores the cofactor-cleared canonical form (8·T),
// so the query MUST be canonicalized too — otherwise a raw torsion variant would
// miss a recorded spend. A low-order / non-canonical tag could never have been
// recorded, so it is reported unspent.
func (c *Chain) TagSpent(tag []byte) bool {
	tg := tag
	if c2, ok := commit.CanonicalNullifier(tag); ok {
		tg = c2
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tags.Has(hexstr(tg))
}

// Swap returns the live swap contract for a swap key, if present.
func (c *Chain) Swap(swapKey []byte) (*SwapEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.swaps[hexstr(swapKey)]
	return e, ok
}

// ZKNullifierSpent reports whether a ZK serial nullifier has already been recorded
// on-chain. The public-amount ZKInput path and the confidential CZKSpend path SHARE
// this set (a coin cannot be spent via both), so both query it the same way — see
// validateZKInputsLocked / validateCZKSpendsLocked (c.zkNull[...]).
// audit SECURITY_AUDIT_2026-07-01: exported so the mempool's confirmed-spend recheck
// can cover ZK/CZK inputs, not just transparent/anon (TOCTOU close).
func (c *Chain) ZKNullifierSpent(nullifier []byte) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.zkNull[hexstr(nullifier)]
}

// PQNullifierSpent reports whether a post-quantum nullifier has already been recorded
// on-chain — the authoritative "already spent" marker checked by validatePQTxLocked
// (c.pqNull[...]).
// audit SECURITY_AUDIT_2026-07-01: exported for the mempool confirmed-spend recheck.
func (c *Chain) PQNullifierSpent(nullifier []byte) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pqNull[hexstr(nullifier)]
}

// UTXO returns the unspent entry for an output key, if present.
func (c *Chain) UTXO(outputRef []byte) (*UTXOEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.utxoEntryLocked(outputRef)
}

// recentHeaders returns up to n recent headers for difficulty calc.
func (c *Chain) recentTimestampsAndDiffs() ([]int64, []uint64) {
	n := config.DifficultyWindow + 1
	start := 0
	if len(c.headers) > n {
		start = len(c.headers) - n
	}
	var ts []int64
	var df []uint64
	for _, h := range c.headers[start:] {
		ts = append(ts, h.Timestamp)
		df = append(df, h.Difficulty)
	}
	return ts, df
}

func hexstr(b []byte) string {
	const hexdig = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdig[c>>4]
		out[i*2+1] = hexdig[c&0xf]
	}
	return string(out)
}

func blakeHash(b []byte) []byte {
	h := blake2b.Sum256(b)
	return h[:]
}

func heightKey(h uint64) []byte {
	var k [8]byte
	binary.BigEndian.PutUint64(k[:], h)
	return k[:]
}

func heightFromKey(k []byte) uint64 {
	if len(k) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(k)
}

var errValidation = errors.New("chain: validation failed")
