package chain

import (
	"fmt"

	"obscura/pkg/tx"
)

// SeedPQOutput injects a post-quantum output directly into the PQ anonymity
// set / UTXO map, mirroring the apply path (pqAcc.Add + pqIndex + pqUtxo +
// anchor whitelist). It exists because consensus has NO miner-controlled PQ
// minting path: coinbase PQ minting was removed (it was uncapped — an inflation
// hole), and a capped PQ emission / transparent-to-PQ wrap is still a documented
// TODO (docs/POST_QUANTUM_ROADMAP.md). Until that lands, the ONLY origin of a PQ
// output is this explicit, capped, consensus-fixed seed — analogous to
// pqtx.Ledger.AddOutput's "genesis / coinbase funding" role.
//
// This is a BOOTSTRAP/test-support primitive, not a miner-reachable path: a
// block can never carry it (validate.go forbids coinbase PQ legs and a PQ tx
// must spend an existing PQ output), so it cannot be used to forge value in a
// mined block. It only populates the live in-memory PQ set so the genuine PQ
// SPEND path (membership proof, hybrid signature, conservation, nullifier,
// double-spend, reorg, snapshot) can be exercised end-to-end. Seeded state is
// captured by SaveSnapshot like any other PQ output, so it survives restart via
// the snapshot path.
func (c *Chain) SeedPQOutput(o tx.PQOutput) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := hexstr(o.OneTimeKey)
	if len(o.OneTimeKey) != 32 {
		return fmt.Errorf("%w: bad pq seed key", errValidation)
	}
	if _, exists := c.pqUtxo[key]; exists {
		return fmt.Errorf("%w: duplicate pq seed key", errValidation)
	}
	idx := c.pqAcc.Add(o.OneTimeKey)
	c.pqIndex[key] = idx
	c.pqUtxo[key] = &tx.PQOutput{
		OneTimeKey: append([]byte(nil), o.OneTimeKey...),
		Amount:     o.Amount,
	}
	// Whitelist the new PQ root as a valid spend anchor (Zcash-style), exactly as
	// apply() does, so a witness built against it verifies.
	if c.pqAcc.Len() > 0 {
		c.pqRoots[hexstr(c.pqAcc.Root())] = true
	}
	return nil
}
