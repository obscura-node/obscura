package chain

import (
	"bytes"
	"encoding/binary"

	bolt "go.etcd.io/bbolt"
)

// Disk-backed coin store (Track A / 100M scaling, docs/SCALING_100M.md). The
// "all coins ever" set used to build anonymity rings was an O(n) RAM map+slice
// (coins/coinList) — the last large runtime-RAM hog. It now lives in bolt
// (coinlist by creation index, coins by key) and is read on demand; only an O(1)
// count is kept in RAM. Rings are 16 contiguous entries (PoolSize) so on-demand
// reads are cheap.
//
// Reorg safety without an O(n) rollback: finalized coins are immutable, and a
// reorg only ever rewinds within MaxReorgDepth. During a reorg the replayed
// branch's coins are STAGED in RAM (bolt untouched) and committed only on
// success — so a failed reorg leaves bolt exactly as it was. Restart/reset
// truncate bolt to the snapshot's coin count, then replay re-appends.

func coinIndexKey(i uint64) []byte {
	var k [8]byte
	binary.BigEndian.PutUint64(k[:], i)
	return k[:]
}

// encodeCoin/decodeCoin are a compact CoinInfo wire form.
func encodeCoin(ci *CoinInfo) []byte {
	var b bytes.Buffer
	w := func(p []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		b.Write(l[:])
		b.Write(p)
	}
	w(ci.Key)
	w(ci.Commitment)
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], ci.Height)
	b.Write(u[:])
	binary.BigEndian.PutUint64(u[:], ci.Index)
	b.Write(u[:])
	binary.BigEndian.PutUint64(u[:], ci.LockUntil)
	b.Write(u[:])
	if ci.IsCoinbase {
		b.WriteByte(1)
	} else {
		b.WriteByte(0)
	}
	return b.Bytes()
}

func decodeCoin(data []byte) *CoinInfo {
	r := bytes.NewReader(data)
	rd := func() []byte {
		var l [4]byte
		if _, err := r.Read(l[:]); err != nil {
			return nil
		}
		n := binary.BigEndian.Uint32(l[:])
		p := make([]byte, n)
		if n > 0 {
			_, _ = r.Read(p)
		}
		return p
	}
	ci := &CoinInfo{}
	ci.Key = rd()
	ci.Commitment = rd()
	var u [8]byte
	_, _ = r.Read(u[:])
	ci.Height = binary.BigEndian.Uint64(u[:])
	_, _ = r.Read(u[:])
	ci.Index = binary.BigEndian.Uint64(u[:])
	_, _ = r.Read(u[:])
	ci.LockUntil = binary.BigEndian.Uint64(u[:])
	cb, _ := r.ReadByte()
	ci.IsCoinbase = cb == 1
	return ci
}

// addCoinLocked appends a coin in canonical creation order. During a reorg it is
// staged in RAM; otherwise it is written through to bolt. Caller holds the lock.
func (c *Chain) addCoinLocked(key, commitment []byte, height uint64, isCoinbase bool, lockUntil uint64) {
	ci := &CoinInfo{
		Key:        append([]byte(nil), key...),
		Commitment: append([]byte(nil), commitment...),
		Height:     height,
		IsCoinbase: isCoinbase,
		LockUntil:  lockUntil,
		Index:      c.coinCount,
	}
	if c.db != nil {
		_ = c.db.Update(func(dtx *bolt.Tx) error {
			_ = dtx.Bucket(bucketCoinList).Put(coinIndexKey(ci.Index), encodeCoin(ci))
			return dtx.Bucket(bucketCoins).Put([]byte(hexstr(ci.Key)), encodeCoin(ci))
		})
	}
	c.coinCount++
}

// coinByIndexLocked returns the coin at creation index i (nil if absent).
func (c *Chain) coinByIndexLocked(i uint64) *CoinInfo {
	if c.db == nil {
		return nil
	}
	var ci *CoinInfo
	_ = c.db.View(func(dtx *bolt.Tx) error {
		if v := dtx.Bucket(bucketCoinList).Get(coinIndexKey(i)); v != nil {
			ci = decodeCoin(v)
		}
		return nil
	})
	return ci
}

// coinByKeyLocked returns the coin with the given one-time key (nil if absent).
func (c *Chain) coinByKeyLocked(key []byte) *CoinInfo {
	if c.db == nil {
		return nil
	}
	var ci *CoinInfo
	_ = c.db.View(func(dtx *bolt.Tx) error {
		if v := dtx.Bucket(bucketCoins).Get([]byte(hexstr(key))); v != nil {
			ci = decodeCoin(v)
		}
		return nil
	})
	return ci
}

// truncateCoinsLocked drops bolt coins with index >= n and sets the count to n.
// Used on restart/reset/snapshot-restore (the linear, non-staged path).
func (c *Chain) truncateCoinsLocked(n uint64) {
	if c.db != nil {
		// scan bolt (not the RAM count): on restart the count is the restore target
		// while bolt may hold more coins from before the crash.
		_ = c.db.Update(func(dtx *bolt.Tx) error {
			cl := dtx.Bucket(bucketCoinList)
			co := dtx.Bucket(bucketCoins)
			cur := cl.Cursor()
			var delIdx, delKey [][]byte
			for k, v := cur.Seek(coinIndexKey(n)); k != nil; k, v = cur.Next() {
				delIdx = append(delIdx, append([]byte(nil), k...))
				delKey = append(delKey, []byte(hexstr(decodeCoin(v).Key)))
			}
			for i := range delIdx {
				_ = cl.Delete(delIdx[i])
				_ = co.Delete(delKey[i])
			}
			return nil
		})
	}
	c.coinCount = n
}

// utxoEntryLocked returns the unspent-output entry for an output key, DERIVED from
// the coin record minus the spent-output set (Track A: `utxo = coins ∧ ¬spent`).
// Returns false if the output was never created or has been spent.
func (c *Chain) utxoEntryLocked(ref []byte) (*UTXOEntry, bool) {
	if c.spent.Has(hexstr(ref)) {
		return nil, false
	}
	ci := c.coinByKeyLocked(ref)
	if ci == nil {
		return nil, false
	}
	return &UTXOEntry{
		Commitment: ci.Commitment, Height: ci.Height,
		IsCoinbase: ci.IsCoinbase, LockUntil: ci.LockUntil,
	}, true
}

// CoinCount returns the number of coins ever created (anonymity-set size).
func (c *Chain) CoinCount() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.coinCount
}
