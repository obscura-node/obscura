package chain

import (
	bolt "go.etcd.io/bbolt"
)

// Snapshot-import correctness on a NON-FRESH node (P2P sync robustness; found
// by the p2p snapshot fast-sync tests, reproduced in
// snapshot_import_nonfresh_internal_test.go).
//
// diskSet.importMembers documents a FRESH-set precondition, but
// VerifyAndImportSnapshot never enforced it. On a node that had already
// applied some blocks before adopting a heavier verified snapshot (a
// partially-synced or long-restarted node — the exact fast-sync audience),
// importing onto the non-empty set corrupts the per-count commit history:
// Add() is idempotent for the member and the running commit, but still bumps
// `count` for a duplicate, so every commit record after the duplicate is
// shifted by one. restoreSnapshotLocked's setCount(N) then restores the commit
// recorded at the WRONG position, the residual state-root diverges from the
// network, and every subsequent block fails "state-root mismatch" — the node
// wedges permanently one import behind the tip.
//
// resetForImport clears the set completely (bolt buckets + in-RAM count and
// commit) so importMembers really does rebuild from a fresh set. It is called
// ONLY on the fully-verified import path (after every PoW/root/state check has
// passed, immediately before importMembers), so a rejected/malicious snapshot
// can never wipe local state.

// resetForImport empties the set: all three bolt buckets are cleared and the
// in-RAM count/commit return to zero. The next Add sequence (importMembers)
// rebuilds membership, insertion order, and the per-count commit records
// exactly as on a fresh node.
func (s *diskSet) resetForImport() {
	if s.db != nil {
		_ = s.db.Update(func(tx *bolt.Tx) error {
			for _, b := range [][]byte{s.idxBucket, s.setBucket, s.commitBucket} {
				if b == nil || tx.Bucket(b) == nil {
					continue
				}
				if err := tx.DeleteBucket(b); err != nil {
					return err
				}
				if _, err := tx.CreateBucket(b); err != nil {
					return err
				}
			}
			return nil
		})
	}
	s.count = 0
	s.commit = [32]byte{}
}
