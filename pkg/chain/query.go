package chain

import (
	"math/big"

	"obscura/pkg/config"
	"obscura/pkg/fee"
)

// RecentFeeSamples summarizes the fee market of up to the last n blocks (tip
// first) for fee estimation: each block's per-tx fee-rates and how full it was.
// Coinbase transactions are excluded (they carry no fee). Computable by anyone
// with the recent blocks, so a light client can reproduce it.
func (c *Chain) RecentFeeSamples(n int) []fee.BlockFees {
	c.mu.RLock()
	defer c.mu.RUnlock()
	tip := c.headers[len(c.headers)-1].Height
	out := make([]fee.BlockFees, 0, n)
	for h := tip; ; h-- {
		if len(out) >= n {
			break
		}
		b, ok := c.bodyAtHeight(h)
		if !ok {
			break
		}
		var bf fee.BlockFees
		used := 0
		for _, t := range b.Txs {
			raw := t.Serialize()
			used += len(raw)
			if t.IsCoinbase {
				continue
			}
			sz := len(raw)
			if sz < 1 {
				sz = 1
			}
			bf.Rates = append(bf.Rates, t.Fee/uint64(sz))
		}
		bf.Fullness = float64(used) / float64(config.MaxBlockBytes)
		out = append(out, bf)
		if h == 0 {
			break
		}
	}
	return out
}

// WitnessFor returns the membership witness (serialized) for an output prime
// against the CURRENT accumulator value, so a wallet can build a spend proof.
//
// PRIVACY NOTE: asking a remote node for a specific output's witness reveals
// interest in that output to the node. Production wallets recompute witnesses
// client-side from public block data (the accumulator is add-only, so a witness
// is updated by exponentiating with the primes added since it was last current).
// The prototype exposes this convenience endpoint with that caveat.
func (c *Chain) WitnessFor(primeBytes []byte) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	p := new(big.Int).SetBytes(primeBytes)
	w, err := c.acc.MembershipWitness(p)
	if err != nil {
		return nil, false
	}
	return c.G.Marshal(w), true
}

// CurrentCheckpoint returns the current accumulator value bytes, which a wallet
// uses as the membership checkpoint when building a spend.
func (c *Chain) CurrentCheckpoint() []byte {
	return c.AccValue()
}

// PoolOf returns the anonymity pool id of a coin and its position within that
// pool (by canonical creation order), if the coin exists.
func (c *Chain) PoolOf(coinKey []byte) (poolID uint64, indexInPool int, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ci := c.coinByKeyLocked(coinKey)
	if ci == nil {
		return 0, 0, false
	}
	return ci.Index / config.PoolSize, int(ci.Index % config.PoolSize), true
}

// PoolMembers returns the canonical ring (keys + amount commitments, in creation
// order) for a complete, fully-mature anonymity pool. ok=false if the pool is
// not yet full or not all members are mature at `height`.
func (c *Chain) PoolMembers(poolID, height uint64) (keys [][]byte, commits [][]byte, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.poolMembersLocked(poolID, height)
}

func (c *Chain) poolMembersLocked(poolID, height uint64) (keys [][]byte, commits [][]byte, ok bool) {
	// guard against multiplication/addition overflow on an attacker-supplied poolID
	if config.PoolSize == 0 || poolID > (^uint64(0)-config.PoolSize)/config.PoolSize {
		return nil, nil, false
	}
	start := poolID * config.PoolSize
	end := start + config.PoolSize
	if end > c.coinCount {
		return nil, nil, false // pool not yet complete ("frozen")
	}
	keys = make([][]byte, 0, config.PoolSize)
	commits = make([][]byte, 0, config.PoolSize)
	for i := start; i < end; i++ {
		ci := c.coinByIndexLocked(i)
		if ci == nil {
			return nil, nil, false
		}
		if ci.IsCoinbase && height < ci.Height+config.CoinbaseMaturity {
			return nil, nil, false // a member is immature → pool not usable yet
		}
		keys = append(keys, ci.Key)
		commits = append(commits, ci.Commitment)
	}
	return keys, commits, true
}

// LatestCompletePool returns the highest pool id that is full and mature at the
// given height, or false if none exists yet.
func (c *Chain) LatestCompletePool(height uint64) (uint64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.coinCount < config.PoolSize {
		return 0, false
	}
	last := c.coinCount/config.PoolSize - 1
	for {
		if _, _, ok := c.poolMembersLocked(last, height); ok {
			return last, true
		}
		if last == 0 {
			return 0, false
		}
		last--
	}
}
