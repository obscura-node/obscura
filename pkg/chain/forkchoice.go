package chain

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"time"

	bolt "go.etcd.io/bbolt"

	"obscura/pkg/accumulator"
	"obscura/pkg/block"
	"obscura/pkg/config"
	"obscura/pkg/pow"
	"obscura/pkg/pqaccum"
	"obscura/pkg/stark"
	"obscura/pkg/tx"
)

// ----------------------------------------------------------------------------
// Fork choice (Block 1, invented via the methodology engine — see
// docs/INVENTION_FORKCHOICE.md). Most-cumulative-work selection with three
// improvements over the Bitcoin/Monero baseline:
//   1. lowest-block-hash tie-break on equal work (eclipse/selfish-mining neutral)
//   2. bounded reorg depth (trustless practical finality, no checkpoints/PoS)
//   3. block tree + orphan pool + snapshot/replay reorg (works with the
//      add-only accumulator, which cannot remove elements)
// ----------------------------------------------------------------------------

// MaxReorgDepth bounds how far back a reorg may rewrite the chain. Deeper
// reorgs are rejected outright, giving practical finality without trusted
// checkpoints. Generous enough that honest reorgs are never blocked. A var (not
// const) so tests can exercise the cap without mining 100 blocks.
var MaxReorgDepth uint64 = 100

// PartitionRecoveryMargin enables self-healing from network partitions that
// outlast the finality window. A reorg deeper than MaxReorgDepth is normally
// rejected for finality (a permanent split if the network was partitioned for
// > MaxReorgDepth blocks). With this guard, such a reorg is permitted ONLY when
// the candidate chain has out-worked the active chain by at least this many
// blocks of work (margin = PartitionRecoveryMargin × candidate-tip difficulty).
//
// Rationale: a stealth deep-reorg attacker, by definition, cannot sustain a
// large cumulative-work lead over the honest chain — only the genuinely heavier
// (majority-hashpower) side of a healed partition can. So a strict, large margin
// recovers from real partitions while keeping marginal/balanced forks final and
// un-overridable. Set to 0 to restore the old hard-finality behaviour. A var so
// tests can tune it; default = MaxReorgDepth (a full finality window heavier).
var PartitionRecoveryMargin uint64 = 100

// MaxOrphans bounds the parent-unknown buffer by COUNT (anti-DoS). A count cap
// alone is insufficient: at MaxBlockBytes each, 256 orphans is ~512 MiB, so the
// buffer is ALSO byte-bounded by MaxOrphanBytes below.
const MaxOrphans = 256

// MaxOrphanBytes bounds the parent-unknown buffer by total serialized body bytes
// (anti-DoS). High-height orphans cannot be PoW-verified (their epoch seed is
// beyond our tip — see powSeedLocked), so an attacker could otherwise flood
// large zero-work bodies to exhaust memory. When inserting would exceed this
// bound, the oldest orphans are evicted FIFO until it fits.
const MaxOrphanBytes = 32 << 20 // 32 MiB

// orphanMeta tracks a buffered orphan's parent key and serialized size so it can
// be located and accounted for during FIFO/byte-bound eviction.
type orphanMeta struct {
	parent [32]byte
	bytes  int
}

// chainNode is a vertex in the block tree.
type chainNode struct {
	hash   [32]byte
	prev   [32]byte
	height uint64
	work   *big.Int // cumulative difficulty from genesis to this block
	block  *block.Block
}

// indexActiveChain (re)builds the node tree from the current active chain and
// sets bestHash. Called once at startup.
func (c *Chain) indexActiveChain() {
	c.nodes = make(map[[32]byte]*chainNode)
	cum := big.NewInt(0)
	for h := uint64(0); h < uint64(len(c.headers)); h++ {
		hdr := c.headers[h]
		cum = new(big.Int).Add(cum, new(big.Int).SetUint64(hdr.Difficulty))
		id := hdr.ID()
		c.nodes[id] = &chainNode{
			hash:   id,
			prev:   hdr.PrevHash,
			height: h,
			work:   new(big.Int).Set(cum),
			block:  nil, // active-chain bodies live in bolt; loaded on demand (bodyForNode)
		}
		c.bestHash = id
	}
}

// bodyForNode returns a node's block body: from RAM if still held (recent / side
// branch), else from bolt by height (finalized active blocks). nil if unavailable.
func (c *Chain) bodyForNode(n *chainNode) *block.Block {
	if n.block != nil {
		return n.block
	}
	if b, ok := c.bodyAtHeight(n.height); ok && b.Header.ID() == n.hash {
		return b
	}
	return nil
}

// pruneNodeBodiesLocked frees block BODIES held by fork-tree nodes older than the
// reorg window (their bodies are durable in bolt and can never be reorged). Cheap
// node metadata (hash/prev/work) is kept so the chain still walks to genesis.
func (c *Chain) pruneNodeBodiesLocked() {
	tip := c.headers[len(c.headers)-1].Height
	if tip < MaxReorgDepth {
		return
	}
	normalCutoff := tip - MaxReorgDepth
	// A deep PARTITION-RECOVERY reorg (up to PoWSeedLag deep) must replay the candidate
	// branch's bodies. Active-chain bodies are durable in bolt, so their RAM copy can be
	// freed at the normal reorg window. SIDE-branch bodies live ONLY in RAM (a side branch
	// is never written to bolt until it activates), so they must be retained through the
	// full recovery window or a heal would have nothing to replay. Net: steady state (no
	// side branches) keeps RAM small; only an actual deep fork holds extra bodies, bounded
	// by the recovery window. Beyond the window a side branch can never be adopted, so drop it.
	recoveryWindow := config.PoWSeedLag
	if recoveryWindow < MaxReorgDepth {
		recoveryWindow = MaxReorgDepth
	}
	haveRecoveryCutoff := tip >= recoveryWindow
	recoveryCutoff := uint64(0)
	if haveRecoveryCutoff {
		recoveryCutoff = tip - recoveryWindow
	}
	for _, n := range c.nodes {
		if n.block == nil || n.height > normalCutoff {
			continue
		}
		// onActive: this node is the active block at its height (durable in bolt). The
		// active header set lives in RAM, so this is a hash compare, not a disk read.
		onActive := n.height < uint64(len(c.headers)) && c.headers[n.height].ID() == n.hash
		if onActive {
			n.block = nil // redundant with bolt — free the RAM copy
		} else if haveRecoveryCutoff && n.height <= recoveryCutoff {
			n.block = nil // side branch older than the recovery window — unadoptable, free it
		}
		// else: side branch within the recovery window — KEEP (a heal may need to replay it)
	}
}

// AddBlock adds a block to the tree and, if it (or a branch it completes) has
// the most cumulative work, makes it the active chain — reorganizing if needed.
// Out-of-order blocks are buffered as orphans. Safe for concurrent callers.
func (c *Chain) AddBlock(b *block.Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.addBlockLocked(b)
}

func (c *Chain) addBlockLocked(b *block.Block) error {
	id := b.Header.ID()
	if _, ok := c.nodes[id]; ok {
		return nil // already known
	}
	// Cheap, branch-independent checks before storing (anti-spam). Full
	// transaction/economic validation happens on activation/reorg.
	if b.Header.Difficulty == 0 {
		return fmt.Errorf("%w: zero difficulty", errValidation)
	}
	// Seed-aware anti-spam PoW check. The per-epoch seed comes from confirmed
	// history (>= PoWSeedLag back, within the unreorganizable prefix), so the
	// active chain yields the correct seed for any acceptable block. For a block
	// whose seed height is beyond our tip (out-of-order/future), defer to the
	// authoritative check on activation rather than reject on a guessed seed.
	if seed, known := c.powSeedLocked(b.Header.Height); known {
		if !pow.Meets(b.Header.PoWHashSeed(seed), b.Header.Difficulty) {
			return fmt.Errorf("%w: insufficient proof of work", errValidation)
		}
	}
	if b.Header.Timestamp > time.Now().Unix()+config.MaxFutureDriftSeconds {
		return fmt.Errorf("%w: timestamp too far in future", errValidation)
	}

	parent, ok := c.nodes[b.Header.PrevHash]
	if !ok {
		// Parent unknown: buffer as an orphan, bounded by BOTH count and bytes.
		//
		// PoW note: a block whose seed height is known was already verified above
		// (powSeedLocked + pow.Meets returns/rejects before reaching here), so it is
		// PoW-checked BEFORE being buffered. A block whose seed height is beyond our
		// tip (a high-height orphan) cannot be verified yet and is the flood vector —
		// hence the byte bound + FIFO eviction below, so unverifiable orphans can
		// never exhaust memory regardless of how many an attacker sends.
		c.bufferOrphanLocked(b)
		return errOrphanBlock
	}
	if b.Header.Height != parent.height+1 {
		return fmt.Errorf("%w: height %d not parent+1", errValidation, b.Header.Height)
	}

	work := new(big.Int).Add(parent.work, new(big.Int).SetUint64(b.Header.Difficulty))
	node := &chainNode{hash: id, prev: b.Header.PrevHash, height: b.Header.Height, work: work, block: b}

	best := c.nodes[c.bestHash]
	becomesBest := work.Cmp(best.work) > 0 ||
		(work.Cmp(best.work) == 0 && lowerHash(id, c.bestHash)) // tie-break: lowest hash

	// A fork (becomes-best but does not extend the active tip) needs a reorg, which is
	// bounded by finality — except for PARTITION RECOVERY. Resolve adoptability here; the
	// block is stored either way below, so a not-yet-heavy-enough heavier chain can keep
	// accumulating until a later block clears the margin.
	if becomesBest && b.Header.PrevHash != c.bestHash {
		depth, forkHeight := c.reorgForkLocked(node)
		if depth > MaxReorgDepth {
			if depth > config.PoWSeedLag {
				// SEED FINALITY (hard bound): a reorg this deep would rewrite a PoW epoch-seed
				// block (the seed is taken config.PoWSeedLag back and MUST stay in the
				// unreorganizable prefix, else an attacker can grind it across an epoch). Such a
				// branch can NEVER be adopted, so reject it outright and do not store it — a
				// growing stack of unadoptable deep branches would be a memory-DoS.
				return fmt.Errorf("%w: reorg too deep (%d > seed-finality bound %d) — partition exceeds auto-heal window, manual intervention required",
					errValidation, depth, config.PoWSeedLag)
			}
			// Deeper than practical finality but within the seed bound: adopt only via
			// PARTITION RECOVERY — when the candidate is HEAVIER BY A SAFE MARGIN (the
			// signature of a real partition healing, not a stealth deep reorg, which cannot
			// sustain a large work lead). If it is not yet heavy enough, DON'T adopt but DO
			// keep it (fall through to the side-branch store): the heavier chain must be able
			// to accumulate so a later block can clear the margin — discarding it here would
			// orphan its children and the heal could never complete.
			adopt := PartitionRecoveryMargin != 0
			if adopt {
				lead := new(big.Int).Sub(work, best.work)
				margin := new(big.Int).Mul(new(big.Int).SetUint64(PartitionRecoveryMargin), new(big.Int).SetUint64(b.Header.Difficulty))
				adopt = lead.Cmp(margin) >= 0
			}
			if !adopt {
				becomesBest = false // keep as a side branch, re-evaluated as the branch grows
			}
		}
		if becomesBest {
			branch := c.branchToLocked(node)
			if err := c.reorgToLocked(branch, forkHeight); err != nil {
				return fmt.Errorf("reorg failed: %w", err)
			}
			c.persistActiveChainLocked()
		}
	}

	if becomesBest {
		if b.Header.PrevHash == c.bestHash {
			// fast path: extends the active tip — validate + apply in place.
			if err := c.validateBlockLocked(b); err != nil {
				return err
			}
			if err := c.applyBlock(b, true); err != nil {
				return err
			}
		}
		c.nodes[id] = node
		c.bestHash = id
		// free block bodies that have passed the reorg window (kept durably in bolt)
		c.pruneNodeBodiesLocked()
		// periodic state snapshot for fast restart (and future body pruning)
		if h := b.Header.Height; h > 0 && h%SnapshotInterval == 0 {
			_ = c.saveSnapshotLocked()
		}
	} else {
		// side branch: record the node (and block) for a possible future reorg.
		c.nodes[id] = node
	}

	c.connectOrphansLocked(id)
	return nil
}

// lowerHash reports whether a < b lexicographically (tie-break order).
func lowerHash(a, b [32]byte) bool { return bytes.Compare(a[:], b[:]) < 0 }

func (c *Chain) orphanCount() int { return len(c.orphanMeta) }

// bufferOrphanLocked stores a parent-unknown block, enforcing the count and byte
// bounds by evicting the oldest orphans (FIFO) until the new block fits. A body
// larger than MaxBlockBytes (or MaxOrphanBytes) is never bufferable and is
// dropped silently — it would be rejected on activation anyway.
func (c *Chain) bufferOrphanLocked(b *block.Block) {
	id := b.Header.ID()
	if _, dup := c.orphanMeta[id]; dup {
		return // already buffered
	}
	sz := len(b.Serialize())
	if sz > MaxOrphanBytes {
		return // a single body that cannot fit the whole budget — never buffer
	}
	// Evict oldest orphans (FIFO) until both bounds admit the newcomer.
	for len(c.orphanMeta) >= MaxOrphans || c.orphanBytes+sz > MaxOrphanBytes {
		if !c.evictOldestOrphanLocked() {
			return // nothing left to evict yet still over budget — drop the newcomer
		}
	}
	c.orphans[b.Header.PrevHash] = append(c.orphans[b.Header.PrevHash], b)
	c.orphanMeta[id] = orphanMeta{parent: b.Header.PrevHash, bytes: sz}
	c.orphanFIFO = append(c.orphanFIFO, id)
	c.orphanBytes += sz
	// Compact the FIFO when stale (connected/evicted) entries dominate, so the
	// queue itself cannot grow unbounded as orphans churn. Bounded by 2×MaxOrphans.
	if len(c.orphanFIFO) > 2*MaxOrphans {
		live := c.orphanFIFO[:0]
		for _, h := range c.orphanFIFO {
			if _, ok := c.orphanMeta[h]; ok {
				live = append(live, h)
			}
		}
		c.orphanFIFO = live
	}
}

// evictOldestOrphanLocked removes the oldest still-buffered orphan, freeing its
// bytes. Returns false if the FIFO is empty (nothing to evict).
func (c *Chain) evictOldestOrphanLocked() bool {
	for len(c.orphanFIFO) > 0 {
		id := c.orphanFIFO[0]
		c.orphanFIFO = c.orphanFIFO[1:]
		meta, ok := c.orphanMeta[id]
		if !ok {
			continue // already removed (connected to a parent) — skip its stale FIFO entry
		}
		c.removeOrphanLocked(id, meta)
		return true
	}
	return false
}

// removeOrphanLocked drops a single buffered orphan from the parent->children
// map and the byte accounting. The FIFO queue is compacted lazily (stale entries
// are skipped on eviction), so it is not touched here.
func (c *Chain) removeOrphanLocked(id [32]byte, meta orphanMeta) {
	siblings := c.orphans[meta.parent]
	for i, blk := range siblings {
		if blk.Header.ID() == id {
			siblings = append(siblings[:i], siblings[i+1:]...)
			break
		}
	}
	if len(siblings) == 0 {
		delete(c.orphans, meta.parent)
	} else {
		c.orphans[meta.parent] = siblings
	}
	delete(c.orphanMeta, id)
	c.orphanBytes -= meta.bytes
}

// connectOrphansLocked re-adds any orphans whose parent just arrived.
func (c *Chain) connectOrphansLocked(parentID [32]byte) {
	children := c.orphans[parentID]
	if len(children) == 0 {
		return
	}
	delete(c.orphans, parentID)
	for _, child := range children {
		// drop from bookkeeping (FIFO entry goes stale and is skipped on eviction)
		id := child.Header.ID()
		if meta, ok := c.orphanMeta[id]; ok {
			delete(c.orphanMeta, id)
			c.orphanBytes -= meta.bytes
		}
		_ = c.addBlockLocked(child)
	}
}

// branchToLocked returns the ordered block list genesis..node.
func (c *Chain) branchToLocked(node *chainNode) []*block.Block {
	var rev []*block.Block
	cur := node
	for cur != nil {
		rev = append(rev, c.bodyForNode(cur))
		if cur.height == 0 {
			break
		}
		cur = c.nodes[cur.prev]
	}
	// reverse
	out := make([]*block.Block, len(rev))
	for i := range rev {
		out[len(rev)-1-i] = rev[i]
	}
	return out
}

// reorgForkLocked returns how many active blocks would be rolled back to adopt
// the branch ending at node (depth = active tip height − fork height) and the
// height of the common ancestor (fork point). The fork height is what bounds a
// safe snapshot restore during the rebuild — see rebuildToBranchLocked.
func (c *Chain) reorgForkLocked(node *chainNode) (depth, forkHeight uint64) {
	// collect the candidate branch's hashes
	anc := make(map[[32]byte]bool)
	cur := node
	for cur != nil {
		anc[cur.hash] = true
		if cur.height == 0 {
			break
		}
		cur = c.nodes[cur.prev]
	}
	// walk active chain back until we hit a candidate ancestor = fork point
	best := c.nodes[c.bestHash]
	a := best
	for a != nil {
		if anc[a.hash] {
			return best.height - a.height, a.height
		}
		if a.height == 0 {
			break
		}
		a = c.nodes[a.prev]
	}
	return best.height, 0 // no common ancestor found (shouldn't happen past genesis)
}

// --- state reset + branch rebuild for reorg / restart ---

// resetState clears all in-memory consensus state to genesis-empty. Disk-backed
// sets only have their RAM count reset; the caller (rebuild/replay) truncates bolt.
func (c *Chain) resetState() {
	c.invalidateStateRoot()               // state-root memo: reset clears all residual state (#perf)
	c.acc = accumulator.NewValueOnly(c.G) // Track A: value-only (no member set)
	c.spent.resetCount()
	c.coinCount = 0
	c.tags.resetCount()
	c.swaps = make(map[string]*SwapEntry)
	c.swapNonces = make(map[string]bool)
	c.vaults = make(map[string]*VaultEntry)
	c.outPrimes.resetCount()
	c.accValues = make(map[string]bool)
	c.referral = make(map[string]uint64)
	c.headers = nil
	c.byHash = make(map[[32]byte]uint64)
	c.blocks = make(map[uint64]*block.Block)
	c.emitted = 0
	c.incentivePool = 0
	c.nullAcc = pqaccum.NewStreaming()
	c.pqAcc = pqaccum.New()
	c.pqUtxo = make(map[string]*tx.PQOutput)
	c.pqIndex = make(map[string]int)
	c.pqNull = make(map[string]bool)
	c.pqWots = make(map[string]bool)
	c.pqRoots = make(map[string]bool)
	c.cmTree = stark.NewEpochIMT(stark.ZKDepth)
	c.cmRoots = make(map[string]bool)
	c.cmFinal = make(map[string]bool)
	c.cmRootOrder = nil
	c.zkNull = make(map[string]bool)
	// the empty-set anchor is re-seeded by the genesis apply (or first PQ output);
	// see apply.go. Not seeded here, matching Finding-2 (no empty-root anchor).
}

// rebuildToBranchLocked makes `branch` the active state by a crude, obvious
// "restore snapshot → truncate disk sets → replay" sequence: restore the latest
// finalized snapshot at-or-below the fork point (or reset to genesis if none),
// truncate the disk-backed sets back to that point (this also cleans up any partial
// state from a prior failed attempt), then validate+apply the branch forward.
// Returns an error (leaving partial state) if any block is invalid — the caller
// recovers by rebuilding the previous branch.
func (c *Chain) rebuildToBranchLocked(branch []*block.Block, forkHeight uint64) error {
	if len(branch) == 0 {
		return fmt.Errorf("%w: empty branch", errValidation)
	}
	// The branch tip body must be present — it drives the positional height math below and is
	// always replayed. (Lower bodies may legitimately be nil/pruned; handled in the loop.)
	last := branch[len(branch)-1]
	if last == nil {
		return fmt.Errorf("%w: branch tip body missing (pruned) — cannot rebuild", errValidation)
	}
	tip := last.Header.Height
	var startH uint64
	fromSnapshot := false
	// The restored snapshot MUST be on the shared prefix (height ≤ the fork point),
	// or its state would carry blocks from the abandoned branch. Normal reorgs fork
	// within MaxReorgDepth, so tip−MaxReorgDepth is a safe, snapshot-retained ceiling.
	// A deeper PARTITION-RECOVERY reorg forks further back, so we cap the restore at
	// forkHeight instead — restoring older finalized state and replaying more blocks,
	// but never restoring state above the fork (which would corrupt the rebuild).
	if tip >= MaxReorgDepth {
		restoreCeil := tip - MaxReorgDepth
		if forkHeight < restoreCeil {
			restoreCeil = forkHeight
		}
		if sh, ok, err := c.restoreSnapshotAtMostLocked(restoreCeil); err == nil && ok {
			startH, fromSnapshot = sh, true
		}
	}
	if !fromSnapshot {
		c.resetState() // no usable snapshot → rebuild from genesis
		startH = 0
	}
	// reconcile the disk-backed sets to the restored counts: drop everything above
	// (truncate scans bolt, so partial writes from a failed attempt are cleaned up),
	// then the replay below re-appends.
	c.truncateCoinsLocked(c.coinCount)
	c.tags.truncate(c.tags.Count())
	c.outPrimes.truncate(c.outPrimes.Count())
	c.spent.truncate(c.spent.Count())

	// Persist each replayed block durably to bolt as it is applied (persist=true).
	// The reorg's changed suffix can be deeper than the RAM block cache (a
	// partition-recovery reorg replays up to PoWSeedLag blocks > blockCacheCap), so
	// relying on persistActiveChainLocked — which only flushes the bounded c.blocks
	// cache — would silently drop heights in [forkHeight+1, tip-blockCacheCap] from
	// disk even though they are inside the PoR retention window. Writing here keeps
	// the FULL replayed suffix on disk regardless of cache capacity. (persist is
	// idempotent: persistActiveChainLocked still runs afterward to delete any stale
	// heights above the new tip.)
	// branch is contiguous ascending (each node prev-links to height−1), so a block's height is
	// positional even when its body is nil (pruned). audit #1: a pruned body BELOW the restore
	// floor is already covered by the restored snapshot and MUST be skipped — only a nil at/above
	// the replay floor is unrecoverable. The previous code rejected the WHOLE branch on any nil,
	// which made reorg-failure recovery impossible on snapshot-bootstrapped / PoR-pruned nodes
	// (their pre-floor bodies are gone) and left the node live on corrupt state after a failed
	// forward attempt.
	for i, blk := range branch {
		h := tip - uint64(len(branch)-1-i)
		if fromSnapshot && h <= startH {
			continue // covered by the restored snapshot (body may be nil/pruned — fine)
		}
		if blk == nil {
			return fmt.Errorf("%w: missing block body at height %d (pruned) — cannot rebuild", errValidation, h)
		}
		if blk.Header.Height == 0 {
			if err := c.applyBlock(blk, true); err != nil {
				return err
			}
			continue
		}
		if err := c.validateBlockLocked(blk); err != nil {
			return err
		}
		if err := c.applyBlock(blk, true); err != nil {
			return err
		}
	}
	return nil
}

// reorgToLocked switches the active state to a new branch via rebuildToBranchLocked.
// If the new branch fails, it rebuilds the previous (known-valid) branch to recover,
// so a failed reorg never leaves the chain half-applied. No staging/buffering —
// writes go straight to bolt and rollback is just another rebuild (clarity over
// cleverness; the chain is test-only).
func (c *Chain) reorgToLocked(branch []*block.Block, forkHeight uint64) error {
	oldTip := c.bestHash // the fork tree (c.nodes) is not mutated by a rebuild
	if err := c.rebuildToBranchLocked(branch, forkHeight); err != nil {
		// recover: rebuild the previous (known-valid) branch onto the HIGHEST available
		// finalized snapshot of its own history. audit #1: passing forkHeight 0 forced a
		// genesis replay, which is UNSATISFIABLE on a snapshot-bootstrapped or PoR-pruned node
		// (its pre-floor bodies are gone) — recovery then failed *after* state was mutated
		// forward, leaving the node live on state matching neither chain. Passing the old tip
		// height makes rebuildToBranchLocked restore from tip−MaxReorgDepth and replay only the
		// retained suffix (all on the old branch's own state, so valid). Short chains still
		// fall back to genesis replay inside rebuildToBranchLocked when tip < MaxReorgDepth,
		// where genesis-era bodies are not pruned.
		oldBranch := c.branchToLocked(c.nodes[oldTip])
		var recoverFork uint64
		if n := len(oldBranch); n > 0 && oldBranch[n-1] != nil {
			recoverFork = oldBranch[n-1].Header.Height
		}
		if rerr := c.rebuildToBranchLocked(oldBranch, recoverFork); rerr != nil {
			return fmt.Errorf("%w: reorg failed (%v) AND recovery failed (%v)", errValidation, err, rerr)
		}
		// The failed forward attempt may have durably written its (invalid-branch)
		// bodies at heights above the recovered tip; flush the cache and prune those
		// stale heights so disk matches the recovered active chain.
		c.persistActiveChainLocked()
		return err
	}
	return nil
}

// persistActiveChainLocked rewrites the on-disk block index to the current
// active chain (only called after a reorg; the common fast path persists
// incrementally in applyBlock).
func (c *Chain) persistActiveChainLocked() {
	if c.db == nil {
		return
	}
	// A reorg only changes the suffix after the fork point; the shared prefix is
	// already correct in bolt. The changed suffix (≤ MaxReorgDepth blocks) is in the
	// RAM cache (cap > MaxReorgDepth), so we overwrite cached heights and delete any
	// stale heights above the new tip — WITHOUT wiping the whole bucket (which would
	// drop the finalized prefix bodies that are no longer held in RAM).
	tip := c.headers[len(c.headers)-1].Height
	_ = c.db.Update(func(dtx *bolt.Tx) error {
		b := dtx.Bucket(bucketBlocks)
		if b == nil {
			var err error
			if b, err = dtx.CreateBucket(bucketBlocks); err != nil {
				return err
			}
		}
		for h, blk := range c.blocks {
			if err := b.Put(heightKey(h), blk.Serialize()); err != nil {
				return err
			}
			// re-index the re-orged-in block's txs (additive query index; overwrites
			// any superseded txid->height mapping from the abandoned branch).
			if err := indexBlockTxs(dtx, blk); err != nil {
				return err
			}
		}
		// delete stale heights above the new tip (old, longer abandoned chain)
		cur := b.Cursor()
		for k, _ := cur.Last(); k != nil; k, _ = cur.Prev() {
			if heightFromKey(k) > tip {
				if err := b.Delete(k); err != nil {
					return err
				}
			} else {
				break
			}
		}
		return nil
	})
}

var errOrphanBlock = fmt.Errorf("%w: orphan (parent unknown)", errValidation)

// IsOrphanErr reports whether err indicates a buffered orphan (not a real
// rejection — the block is held until its parent arrives).
func IsOrphanErr(err error) bool { return err == errOrphanBlock }

// IsValidationErr reports whether err is a consensus-validation rejection (bad PoW,
// bad timestamp, wrong height, etc.). NOTE: orphans wrap errValidation too, so callers
// that treat orphans specially must check IsOrphanErr FIRST. A validation failure is
// NOT necessarily peer abuse — a peer on a different fork sends blocks that are valid on
// its chain but fail under ours (e.g. PoW-seed mismatch), so the p2p layer treats this
// as soft, connection-local misbehavior (drop, no persistent ban) rather than a ban.
func IsValidationErr(err error) bool { return errors.Is(err, errValidation) }
