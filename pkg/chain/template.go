package chain

import (
	"math/big"

	"obscura/pkg/block"
	"obscura/pkg/consensus"
	"obscura/pkg/tx"
)

// BlockTemplate assembles an unmined block on top of the current tip from the
// given transactions (the first must be the coinbase). It fills in height,
// prev hash, difficulty, timestamp, merkle root, and the predicted accumulator
// checkpoint. The caller (miner) then grinds the nonce.
func (c *Chain) BlockTemplate(txs []*tx.Transaction) (*block.Block, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	tip := c.headers[len(c.headers)-1]
	ts, df := c.recentTimestampsAndDiffs()
	diff := consensus.NextDifficulty(ts, df)

	// predict accumulator after adding all output primes (add-only)
	prod := big.NewInt(1)
	added := 0
	seen := make(map[string]bool)
	for _, t := range txs {
		for _, o := range t.Outputs {
			pb, ok := accPrime(o.OneTimeKey, o.PrimeNonce)
			if !ok {
				continue
			}
			k := hexstr(pb)
			if seen[k] || c.outPrimes.Has(k) {
				continue
			}
			seen[k] = true
			prod.Mul(prod, new(big.Int).SetBytes(pb))
			added++
		}
	}
	predicted := c.G.Exp(c.acc.Value(), prod)

	// predict the post-block PQ anonymity-set root (in apply order).
	var pqKeys [][]byte
	for _, t := range txs {
		for i := range t.PQOutputs {
			pqKeys = append(pqKeys, t.PQOutputs[i].OneTimeKey)
		}
	}
	var pqRoot [32]byte
	copy(pqRoot[:], c.pqAcc.RootAfter(pqKeys))

	// predict the post-block nullifier-set root (spent key-images in apply order).
	var nullRoot [32]byte
	copy(nullRoot[:], c.nullAcc.RootAfter(blockTagsFromTxs(txs)))

	hdr := block.Header{
		Version:    1,
		Height:     tip.Height + 1,
		PrevHash:   tip.ID(),
		Timestamp:  CandidateTimestamp(tip.Timestamp),
		Difficulty: diff,
		Nonce:      0,
		AccValue:   c.G.Marshal(predicted),
		AccSize:    uint64(c.acc.Size()) + uint64(added),
		PQAccRoot:  pqRoot,
		NullRoot:   nullRoot,
		CMRoot:     c.predictCMRoot(txs), // post-block Poseidon commitment-tree root
		StateRoot:  c.stateRootLocked(),  // PRE-STATE root: commits the PARENT's residual state
	}
	b := &block.Block{Header: hdr, Txs: txs}
	b.Header.MerkleRoot = block.MerkleRoot(txs)
	b.Header.NumTxs = uint32(len(txs))
	// Proof-of-retrievability: build the challenge answers from historical bodies. A pruned
	// node fails here (cannot read the challenged bodies) and so cannot produce a block —
	// this is what makes "miners must be full nodes" consensus-enforced.
	por, err := c.buildPoRLocked(hdr.PrevHash, hdr.Height)
	if err != nil {
		return nil, err
	}
	b.PoR = por
	b.Header.PoRRoot = block.PoRRootOf(por)
	return b, nil
}

// CollectedFees sums fees for a set of non-coinbase transactions.
func CollectedFees(txs []*tx.Transaction) uint64 {
	var f uint64
	for _, t := range txs {
		if t.IsCoinbase {
			continue
		}
		// audit SECURITY_AUDIT_2026-07-01: PQ-tx fees live in the PQ value space and are
		// burned there via PQ conservation; consensus EXCLUDES them from the classical
		// coinbase fee total (validate.go ~144-149, "if hasPQ(t) { continue }"). Mirror that
		// exclusion EXACTLY here, else a template mixing a PQ tx with classical txs credits
		// the PQ fee to the coinbase and consensus rejects the block (miner self-orphans).
		if hasPQ(t) {
			continue
		}
		f += t.Fee
	}
	return f
}
