package chain

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"os"
	"strconv"

	bolt "go.etcd.io/bbolt"

	"obscura/pkg/accumulator"
	"obscura/pkg/block"
	"obscura/pkg/config"
	"obscura/pkg/pqaccum"
	"obscura/pkg/stark"
	"obscura/pkg/tx"
)

func init() {
	// DEVNET ONLY: shrink the snapshot interval for fast snapshot-sync demos/tests. Gated to
	// non-mainnet (mainnet keeps 200, which exceeds MaxReorgDepth so a reorg always has a
	// snapshot at-or-below its fork point). On a single-miner devnet there are no deep reorgs,
	// so a small interval is safe there.
	if config.IsMainnet() {
		return
	}
	if v := os.Getenv("OBX_SNAPSHOT_INTERVAL"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			SnapshotInterval = n
		}
	}
}

// State snapshots let a node restore full consensus state at a height WITHOUT
// replaying (and re-verifying) every block from genesis — the keystone for fast
// restart and (next) block-body pruning + snapshot-based reorg. See
// docs/SCALING_100M.md (Track B). The bulk of state is gob-encoded (all struct
// fields are exported); the two accumulators carry their own MarshalState bytes.
//
// SnapshotInterval: take a snapshot every N blocks (height-triggered). A var so
// tests can lower it. Must exceed MaxReorgDepth (100) so the second-newest snapshot
// is always at-or-below any reorg's fork point.
//
// Restart cost is dominated by REPLAY: chain.New restores the newest snapshot's
// accumulator state directly (no class-group Exp) and then re-applies every block
// ABOVE it. Each replayed block costs real class-group exponentiations, so a large
// interval makes restart of a tall chain take minutes (e.g. replaying ~500 blocks
// from genesis took >4 min on a 1-core droplet). 200 bounds the worst-case crash
// replay to ~200 blocks; graceful shutdown additionally snapshots the exact tip
// (cmd/obscura-node) so a planned restart replays ~0 blocks.
var SnapshotInterval uint64 = 200

// chainSnapshot is the gob-encoded portion of a state snapshot.
type chainSnapshot struct {
	Height         uint64
	Emitted        uint64
	IncentivePool  uint64
	CoinCount      uint64 // anonymity-set coins are durable in bolt; only the count is snapshotted
	SpentCount     uint64 // spent-output set is disk-backed; only the count is snapshotted
	TagsCount      uint64 // disk-backed; only the count is snapshotted
	Swaps          map[string]*SwapEntry
	SwapNonces     map[string]bool // adaptor-nonce uniqueness set (audit #14)
	Vaults         map[string]*VaultEntry
	AccValues      map[string]bool
	OutPrimesCount uint64
	Referral       map[string]uint64
	PQUtxo         map[string]*tx.PQOutput
	PQIndex        map[string]int
	PQNull         map[string]bool
	PQWots         map[string]bool
	PQRoots        map[string]bool
	Headers        []block.Header
	ByHash         map[[32]byte]uint64
	// accumulators (their own compact encodings)
	Acc     []byte
	NullAcc []byte
	PQAcc   []byte
	// ZK commitment-tree accumulator (frontier+root+count) + anchors + nullifiers.
	CMTree      []byte
	CMRoots     map[string]bool
	CMFinal     map[string]bool
	CMRootOrder []string
	ZKNull      map[string]bool
}

// encodeSnapshotLocked serializes current consensus state. Caller holds the lock.
func (c *Chain) encodeSnapshotLocked() ([]byte, error) {
	s := chainSnapshot{
		Height: c.headers[len(c.headers)-1].Height, Emitted: c.emitted, IncentivePool: c.incentivePool,
		CoinCount: c.coinCount, SpentCount: c.spent.Count(), TagsCount: c.tags.Count(), Swaps: c.swaps, SwapNonces: c.swapNonces, Vaults: c.vaults,
		AccValues: c.accValues, OutPrimesCount: c.outPrimes.Count(), Referral: c.referral,
		PQUtxo: c.pqUtxo, PQIndex: c.pqIndex, PQNull: c.pqNull, PQWots: c.pqWots, PQRoots: c.pqRoots,
		Headers: c.headers, ByHash: c.byHash,
		// the accumulator value alone can't restore the member set, so store full state
		Acc: c.acc.MarshalState(), NullAcc: c.nullAcc.MarshalState(), PQAcc: c.pqAcc.MarshalState(),
		CMTree: c.cmTree.MarshalState(), CMRoots: c.cmRoots, CMFinal: c.cmFinal, CMRootOrder: c.cmRootOrder, ZKNull: c.zkNull,
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SaveSnapshot persists a state snapshot at the current tip to bolt (key "latest"
// + the height), so a restart can restore from it.
func (c *Chain) SaveSnapshot() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saveSnapshotLocked()
}

// snapshotsToKeep is how many recent snapshots to retain. The OLDEST kept snapshot must
// sit at least the DEEPEST acceptable reorg below the tip, so that any reorg can restore
// a snapshot at-or-below its fork point and replay forward. Normal reorgs are bounded by
// MaxReorgDepth (100), but a deep PARTITION-RECOVERY reorg is permitted up to
// config.PoWSeedLag (512) deep (forkchoice.go). Sizing for MaxReorgDepth alone (keep=2 at
// SnapshotInterval=200) leaves the oldest snapshot ~400 below the tip, so a >400-deep
// partition-recovery reorg on a pruned chain could not restore and would never heal (audit
// 2026-06-28). So the oldest snapshot must cover PoWSeedLag: with snapshots SnapshotInterval
// apart we need (keep-1)*SnapshotInterval >= PoWSeedLag, i.e. keep = ceil(PoWSeedLag /
// SnapshotInterval) + 1 (always >= 2). Bodies below the oldest kept snapshot are pruned.
func snapshotsToKeep() int {
	si := SnapshotInterval
	if si == 0 {
		si = 1
	}
	keep := int((config.PoWSeedLag+si-1)/si) + 1
	if keep < 2 {
		keep = 2
	}
	return keep
}

func (c *Chain) saveSnapshotLocked() error {
	if c.db == nil {
		return nil
	}
	data, err := c.encodeSnapshotLocked()
	if err != nil {
		return err
	}
	h := c.headers[len(c.headers)-1].Height
	return c.db.Update(func(dtx *bolt.Tx) error {
		b, err := dtx.CreateBucketIfNotExists(bucketSnapshot)
		if err != nil {
			return err
		}
		if err := b.Put(heightKey(h), data); err != nil {
			return err
		}
		// keep only the most recent `keep` snapshots (sized to cover PoWSeedLag, see above)
		keep := snapshotsToKeep()
		var heights []uint64
		cur := b.Cursor()
		for k, _ := cur.First(); k != nil; k, _ = cur.Next() {
			heights = append(heights, heightFromKey(k))
		}
		for i := 0; i+keep < len(heights); i++ {
			if err := b.Delete(heightKey(heights[i])); err != nil {
				return err
			}
		}
		// TIER-2 body pruning (INTRINSIC to the protocol — every node, miners
		// included, prunes; there is no archive mode). Bodies below the prune floor
		// can never be needed again for restart/reorg (restart restores the newest
		// snapshot; a reorg restores a snapshot ≥ the oldest kept and replays forward
		// from retained bodies).
		//
		// The floor is the LOWER of two retention requirements, so BOTH are honored:
		//   (a) the oldest kept snapshot — needed for restart/reorg replay; and
		//   (b) tip - config.PoRWindow — the protocol guarantee that the
		//       PoR-challengeable window (pkg/block/por.go) is still on disk, so this
		//       node can keep mining. PoR challenges never go below this floor, so the
		//       challengeable set ⊆ the retained set BY DESIGN.
		if len(heights) > keep {
			pruneBelow := heights[len(heights)-keep]
			tip := c.headers[len(c.headers)-1].Height
			var porFloor uint64
			if tip > config.PoRWindow {
				porFloor = tip - config.PoRWindow
			}
			if porFloor < pruneBelow {
				pruneBelow = porFloor // retain the larger (lower-floored) body set
			}
			bb := dtx.Bucket(bucketBlocks)
			if bb != nil {
				bc := bb.Cursor()
				for k, _ := bc.First(); k != nil && heightFromKey(k) < pruneBelow; k, _ = bc.First() {
					if err := bb.Delete(k); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

// loadSnapshotLocked restores the NEWEST snapshot (for restart). Returns its
// height and whether one was loaded.
func (c *Chain) loadSnapshotLocked() (uint64, bool, error) {
	return c.restoreSnapshotAtMostLocked(^uint64(0))
}

// restoreSnapshotAtMostLocked restores the highest snapshot whose height ≤ maxH.
func (c *Chain) restoreSnapshotAtMostLocked(maxH uint64) (uint64, bool, error) {
	if c.db == nil {
		return 0, false, nil
	}
	var data []byte
	var sh uint64
	_ = c.db.View(func(dtx *bolt.Tx) error {
		b := dtx.Bucket(bucketSnapshot)
		if b == nil {
			return nil
		}
		cur := b.Cursor()
		// seek to just past maxH, then step back to the highest ≤ maxH
		seekKey := heightKey(maxH)
		k, v := cur.Seek(seekKey)
		if k == nil {
			k, v = cur.Last()
		} else if heightFromKey(k) > maxH {
			k, v = cur.Prev()
		}
		if k != nil && heightFromKey(k) <= maxH {
			data = append([]byte(nil), v...)
			sh = heightFromKey(k)
		}
		return nil
	})
	if data == nil {
		return 0, false, nil
	}
	if err := c.restoreSnapshotLocked(data); err != nil {
		return 0, false, fmt.Errorf("snapshot restore: %w", err)
	}
	return sh, true, nil
}

// readSnapshotAtMostLocked returns the bytes of the highest saved snapshot whose height ≤ maxH,
// WITHOUT restoring it. Used by the network transfer producer (which serves a below-tip snapshot
// so the verifier has a child header for the pre-state StateRoot check). Caller holds the lock.
func (c *Chain) readSnapshotAtMostLocked(maxH uint64) ([]byte, uint64, bool) {
	if c.db == nil {
		return nil, 0, false
	}
	var data []byte
	var sh uint64
	_ = c.db.View(func(dtx *bolt.Tx) error {
		b := dtx.Bucket(bucketSnapshot)
		if b == nil {
			return nil
		}
		cur := b.Cursor()
		k, v := cur.Seek(heightKey(maxH))
		if k == nil {
			k, v = cur.Last()
		} else if heightFromKey(k) > maxH {
			k, v = cur.Prev()
		}
		if k != nil && heightFromKey(k) <= maxH {
			data = append([]byte(nil), v...)
			sh = heightFromKey(k)
		}
		return nil
	})
	if data == nil {
		return nil, 0, false
	}
	return data, sh, true
}

// restoreSnapshotLocked decodes a snapshot and replaces in-memory consensus state.
func (c *Chain) restoreSnapshotLocked(data []byte) error {
	c.invalidateStateRoot() // state-root memo: restore replaces all residual state (#perf)
	var s chainSnapshot
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&s); err != nil {
		return err
	}
	acc, err := accumulator.RestoreState(c.G, s.Acc)
	if err != nil {
		return err
	}
	nullAcc, err := pqaccum.RestoreState(s.NullAcc)
	if err != nil {
		return err
	}
	pqAcc, err := pqaccum.RestoreState(s.PQAcc)
	if err != nil {
		return err
	}
	c.acc = acc
	c.nullAcc = nullAcc
	c.pqAcc = pqAcc
	c.coinCount = s.CoinCount // disk coins are durable; replay/reorg reconcile bolt to this count
	c.spent.setCount(s.SpentCount)
	c.swaps, c.vaults = nzMap(s.Swaps), nzMap(s.Vaults)
	c.swapNonces = nzBool(s.SwapNonces)
	c.accValues, c.referral = nzBool(s.AccValues), nzU64(s.Referral)
	c.tags.setCount(s.TagsCount)
	c.outPrimes.setCount(s.OutPrimesCount)
	c.pqUtxo, c.pqIndex, c.pqNull, c.pqRoots = nzMap(s.PQUtxo), nzInt(s.PQIndex), nzBool(s.PQNull), nzBool(s.PQRoots)
	c.pqWots = nzBool(s.PQWots)
	if t, ok := stark.LoadEpochIMTState(s.CMTree); ok {
		c.cmTree = t
	} else {
		c.cmTree = stark.NewEpochIMT(stark.ZKDepth)
	}
	c.cmRoots, c.zkNull = nzBool(s.CMRoots), nzBool(s.ZKNull)
	c.cmFinal = nzBool(s.CMFinal)
	c.cmRootOrder = s.CMRootOrder
	c.headers = s.Headers
	c.byHash = s.ByHash
	if c.byHash == nil {
		c.byHash = make(map[[32]byte]uint64)
	}
	c.emitted, c.incentivePool = s.Emitted, s.IncentivePool
	c.blocks = make(map[uint64]*block.Block) // body cache rebuilds from bolt
	return nil
}

// verifySnapshotLocked checks restored state against the header-committed roots at
// the tip — so a corrupt/tampered snapshot cannot silently install bad state.
func (c *Chain) verifySnapshotLocked() error {
	tip := c.headers[len(c.headers)-1]
	if !bytes.Equal(c.G.Marshal(c.acc.Value()), tip.AccValue) {
		return fmt.Errorf("%w: snapshot accumulator != header AccValue", errValidation)
	}
	var nr [32]byte
	copy(nr[:], c.nullAcc.Root())
	if nr != tip.NullRoot {
		return fmt.Errorf("%w: snapshot nullifier root != header NullRoot", errValidation)
	}
	var pr [32]byte
	copy(pr[:], c.pqAcc.Root())
	if pr != tip.PQAccRoot {
		return fmt.Errorf("%w: snapshot pq root != header PQAccRoot", errValidation)
	}
	if cmRootBytes(c.cmTree.CurrentRoot()) != tip.CMRoot {
		return fmt.Errorf("%w: snapshot commitment-tree root != header CMRoot", errValidation)
	}
	return nil
}

// small nil-safe map helpers (gob decodes empty maps as nil)
func nz(m map[string]*UTXOEntry) map[string]*UTXOEntry {
	if m == nil {
		return make(map[string]*UTXOEntry)
	}
	return m
}
func nzBool(m map[string]bool) map[string]bool {
	if m == nil {
		return make(map[string]bool)
	}
	return m
}
func nzU64(m map[string]uint64) map[string]uint64 {
	if m == nil {
		return make(map[string]uint64)
	}
	return m
}
func nzInt(m map[string]int) map[string]int {
	if m == nil {
		return make(map[string]int)
	}
	return m
}
func nzMap[V any](m map[string]V) map[string]V {
	if m == nil {
		return make(map[string]V)
	}
	return m
}
