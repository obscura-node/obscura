package chain

// Snapshot-sync robustness (additive; no validation/fork-choice semantics
// change). ResumeOrphans exists for exactly one hole: buffered orphans are
// normally connected when their PARENT arrives via AddBlock
// (connectOrphansLocked) — but a snapshot fast-sync import
// (VerifyAndImportSnapshot) makes parents known WITHOUT AddBlock ever running.
// A block that arrived moments before the import and was buffered as
// parent-unknown then wedges sync one block short of the network tip forever:
// re-sent copies are deduplicated against the orphan buffer ("already
// buffered") and never re-applied. Observed live in the p2p snapshot-sync
// two-node test (receiver stuck at H while the network is at H+1).

// ResumeOrphans triggers the EXISTING orphan-connect sweep from the current
// best tip, applying any buffered blocks that now extend it (recursively, via
// the same addBlockLocked path normal gossip uses). Call after an out-of-band
// state adoption such as a verified snapshot import. It validates every block
// it connects exactly as AddBlock would — this only fires the sweep, it does
// not relax anything.
func (c *Chain) ResumeOrphans() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if node, ok := c.nodes[c.bestHash]; ok && node != nil {
		c.connectOrphansLocked(node.hash)
	}
}
