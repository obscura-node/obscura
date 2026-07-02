package chain

// Persisted txid -> height index (RPC /tx perf). This is an ADDITIVE, NON-CONSENSUS
// query index: it is never consulted during block validation, fork choice, or state
// roots. It maps every active-chain transaction id to the height of the block that
// contains it, so a client can resolve "where/whether did my tx confirm?" in O(1)
// instead of scanning the chain. It is maintained on block apply + reorg persistence
// and built once on open if a pre-existing database lacks it.
//
// Reorg safety: the index is a HINT. On a reorg, entries from abandoned blocks may
// linger pointing at a height now occupied by a different block; the RPC handler
// re-verifies the txid is actually present at the indexed height before trusting it,
// so a stale entry self-heals (falls back to "not found"). Re-orged-in blocks are
// re-indexed by persistActiveChainLocked, overwriting any superseded mapping.

import (
	"encoding/binary"
	"encoding/hex"

	bolt "go.etcd.io/bbolt"

	"obscura/pkg/block"
)

// indexBlockTxs records every txid in b -> b's height into the txindex bucket, using
// the caller's bolt write transaction (so it commits atomically with the block body
// write). A nil bucket (e.g. a database opened before this index existed and not yet
// built) is skipped without error.
func indexBlockTxs(dtx *bolt.Tx, b *block.Block) error {
	ti := dtx.Bucket(bucketTxIndex)
	if ti == nil {
		return nil
	}
	hk := heightKey(b.Header.Height)
	for _, t := range b.Txs {
		id := t.Hash()
		if err := ti.Put(id[:], hk); err != nil {
			return err
		}
	}
	return nil
}

// buildTxIndexIfAbsent populates the txid->height index from the persisted block
// bodies the first time it finds the index empty (a database created before the
// index existed). Once populated, the per-block apply/reorg hooks keep it current,
// so this is a no-op on every subsequent open. Single-threaded constructor context.
func (c *Chain) buildTxIndexIfAbsent() error {
	if c.db == nil {
		return nil
	}
	return c.db.Update(func(dtx *bolt.Tx) error {
		ti := dtx.Bucket(bucketTxIndex)
		if ti == nil {
			var err error
			if ti, err = dtx.CreateBucket(bucketTxIndex); err != nil {
				return err
			}
		}
		// Already populated (any key present)? Then the apply/reorg hooks own it.
		if k, _ := ti.Cursor().First(); k != nil {
			return nil
		}
		bb := dtx.Bucket(bucketBlocks)
		if bb == nil {
			return nil
		}
		return bb.ForEach(func(_, v []byte) error {
			blk, err := block.DeserializeBlock(v)
			if err != nil {
				return err
			}
			hk := heightKey(blk.Header.Height)
			for _, t := range blk.Txs {
				id := t.Hash()
				if err := ti.Put(id[:], hk); err != nil {
					return err
				}
			}
			return nil
		})
	})
}

// TxHeight returns the active-chain height of the block containing the transaction
// whose hex txid is given, using the persisted index (O(1)). ok is false when the
// txid is unknown to the index (not confirmed, or outside the indexed set). The
// caller should re-verify presence at the returned height to be robust to a stale
// post-reorg entry. Safe for concurrent use.
func (c *Chain) TxHeight(txidHex string) (height uint64, ok bool) {
	if c.db == nil {
		return 0, false
	}
	id, err := hex.DecodeString(txidHex)
	if err != nil || len(id) != 32 {
		return 0, false
	}
	_ = c.db.View(func(dtx *bolt.Tx) error {
		ti := dtx.Bucket(bucketTxIndex)
		if ti == nil {
			return nil
		}
		if v := ti.Get(id); len(v) == 8 {
			height = binary.BigEndian.Uint64(v)
			ok = true
		}
		return nil
	})
	return height, ok
}
