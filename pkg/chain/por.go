package chain

import (
	"fmt"

	"obscura/pkg/block"
	"obscura/pkg/config"
)

// Proof-of-retrievability glue (docs + design in pkg/block/por.go). Building the proofs
// requires reading historical BLOCK BODIES, so a pruned node cannot mine; verifying them
// needs only stored HEADERS, so pruned nodes can still validate.

// buildPoRLocked constructs the PoR entries for a block being mined at `height` with parent
// `prevHash`. Returns an error if any challenged body is unavailable — which is exactly how
// a pruned (non-full) node is prevented from mining. Caller holds c.mu.
func (c *Chain) buildPoRLocked(prevHash [32]byte, height uint64) ([]block.PoREntry, error) {
	if !block.PoRRequired(height) {
		return nil, nil
	}
	entries := make([]block.PoREntry, 0, config.PoRChallenges)
	for slot := 0; slot < config.PoRChallenges; slot++ {
		hc := block.PoRChallengeHeight(prevHash, slot, height)
		if hc >= uint64(len(c.headers)) {
			return nil, fmt.Errorf("por: challenge height %d out of range", hc)
		}
		idx := block.PoRChallengeIndex(prevHash, slot, c.headers[hc].NumTxs)
		blk, ok := c.bodyAtHeight(hc)
		if !ok {
			// The defining check: a pruned node has evicted this body and cannot answer.
			return nil, fmt.Errorf("por: missing body at height %d — node is not a full node, cannot mine", hc)
		}
		if int(idx) >= len(blk.Txs) {
			return nil, fmt.Errorf("por: index %d out of range (%d txs) at height %d", idx, len(blk.Txs), hc)
		}
		steps, ok := block.MerkleProof(blk.Txs, int(idx))
		if !ok {
			return nil, fmt.Errorf("por: merkle proof failed at height %d idx %d", hc, idx)
		}
		entries = append(entries, block.PoREntry{
			Height: hc, TxBytes: blk.Txs[idx].Serialize(), Steps: steps,
		})
	}
	return entries, nil
}

// validatePoRLocked verifies a block's PoR set using STORED HEADERS only (no body needed,
// so a pruned validator works). Caller holds c.mu (read).
func (c *Chain) validatePoRLocked(b *block.Block) error {
	height := b.Header.Height
	// NumTxs must commit the real tx count (the PoR index derivation depends on it).
	if uint64(b.Header.NumTxs) != uint64(len(b.Txs)) {
		return fmt.Errorf("%w: header NumTxs %d != %d", errValidation, b.Header.NumTxs, len(b.Txs))
	}
	if !block.PoRRequired(height) {
		if len(b.PoR) != 0 || b.Header.PoRRoot != ([32]byte{}) {
			return fmt.Errorf("%w: PoR present on exempt (genesis) block", errValidation)
		}
		return nil
	}
	if len(b.PoR) != config.PoRChallenges {
		return fmt.Errorf("%w: PoR entry count %d, want %d", errValidation, len(b.PoR), config.PoRChallenges)
	}
	// PoRRoot binds the proof set to the PoW (it is in the header preimage).
	if block.PoRRootOf(b.PoR) != b.Header.PoRRoot {
		return fmt.Errorf("%w: PoR root mismatch", errValidation)
	}
	prevHash := b.Header.PrevHash
	for slot := 0; slot < config.PoRChallenges; slot++ {
		hc := block.PoRChallengeHeight(prevHash, slot, height)
		if hc >= uint64(len(c.headers)) {
			return fmt.Errorf("%w: PoR challenge height %d out of range", errValidation, hc)
		}
		hdr := c.headers[hc]
		idx := block.PoRChallengeIndex(prevHash, slot, hdr.NumTxs)
		if !block.VerifyPoREntry(&b.PoR[slot], hc, idx, hdr.MerkleRoot) {
			return fmt.Errorf("%w: PoR proof slot %d invalid (height %d idx %d)", errValidation, slot, hc, idx)
		}
	}
	return nil
}
