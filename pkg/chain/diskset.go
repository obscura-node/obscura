package chain

import (
	"encoding/binary"

	"golang.org/x/crypto/blake2b"
	bolt "go.etcd.io/bbolt"
)

// diskSet is a disk-backed, add-only membership set: keys live in bolt (so RAM is
// O(1)), indexed by insertion order so a reorg/restart can roll back by truncating
// to a recorded count and replaying. Used for the nullifier set, the output-prime
// uniqueness set, and the spent-output set — all add-only (entries removed only by
// a reorg rollback). See docs/SCALING_100M.md.
//
// Writes go straight to bolt; a reorg rolls back by truncate-then-replay (see
// rebuildToBranchLocked in forkchoice.go) — deliberately crude and obvious rather
// than buffered/staged, since the chain is test-only and clarity wins.
//
// SET COMMITMENT (state-root precursor): the set also maintains an order-independent
// cryptographic commitment `commit` = Σ blake2b(key) mod 2^256 over its members — an
// incremental multiset hash (AdHash-style). It is O(1) per add, commutative (so the
// value is independent of insertion order), and committed in the header StateRoot so a
// light/pruned/snapshot node can verify these otherwise-uncommitted consensus sets (the
// classical key-image double-spend set `tags`, the output-prime set, the spent set).
// Reorg/restart safety: every Add records the running commit at the post-add count in
// `commitBucket`, so truncate(n)/setCount(n) restore the EXACT commit for count n by an
// absolute lookup (no error-prone relative subtraction across the restore+truncate path).
//
// Three bolt buckets: idx (insertion-index → key, for ordered truncation), set
// (key → present, for O(1) membership), and commit (count → running commit).
type diskSet struct {
	db           *bolt.DB
	idxBucket    []byte
	setBucket    []byte
	commitBucket []byte
	count        uint64
	commit       [32]byte // Σ blake2b(key) mod 2^256 over current members
}

func newDiskSet(db *bolt.DB, idxBucket, setBucket, commitBucket []byte) *diskSet {
	s := &diskSet{db: db, idxBucket: idxBucket, setBucket: setBucket, commitBucket: commitBucket}
	return s
}

func setIdxKey(i uint64) []byte {
	var k [8]byte
	binary.BigEndian.PutUint64(k[:], i)
	return k[:]
}

// add256 returns (a+b) mod 2^256 over big-endian 256-bit integers. Commutative, so the
// resulting set commitment is independent of insertion order.
func add256(a, b [32]byte) [32]byte {
	var out [32]byte
	var carry uint16
	for i := 31; i >= 0; i-- {
		s := uint16(a[i]) + uint16(b[i]) + carry
		out[i] = byte(s)
		carry = s >> 8
	}
	return out
}

// Has reports membership.
func (s *diskSet) Has(key string) bool {
	if s.db == nil {
		return false
	}
	found := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		found = tx.Bucket(s.setBucket).Get([]byte(key)) != nil
		return nil
	})
	return found
}

// Add inserts a key (idempotent — a duplicate changes neither the insertion index nor the
// commitment). The running commit is recorded at the post-add count so a later truncate or
// restore can recover the exact commit for that count.
func (s *diskSet) Add(key string) {
	wasNew := true
	if s.db != nil {
		_ = s.db.Update(func(tx *bolt.Tx) error {
			if tx.Bucket(s.setBucket).Get([]byte(key)) != nil {
				wasNew = false
				return nil
			}
			if err := tx.Bucket(s.idxBucket).Put(setIdxKey(s.count), []byte(key)); err != nil {
				return err
			}
			return tx.Bucket(s.setBucket).Put([]byte(key), []byte{1})
		})
	}
	if wasNew {
		h := blake2b.Sum256([]byte(key))
		s.commit = add256(s.commit, h)
	}
	s.count++
	if s.db != nil && s.commitBucket != nil {
		c := s.commit
		_ = s.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(s.commitBucket).Put(setIdxKey(s.count), c[:])
		})
	}
}

// CommitAfter returns the set commitment AFTER adding the given keys (deduped against
// current membership and against earlier keys in the slice), WITHOUT mutating the set.
// Used by BlockTemplate/validate to predict the post-block commitment.
func (s *diskSet) CommitAfter(keys []string) [32]byte {
	c := s.commit
	var seen map[string]bool
	if len(keys) > 1 {
		seen = make(map[string]bool, len(keys))
	}
	for _, k := range keys {
		if (seen != nil && seen[k]) || s.Has(k) {
			continue
		}
		if seen != nil {
			seen[k] = true
		}
		h := blake2b.Sum256([]byte(k))
		c = add256(c, h)
	}
	return c
}

// Commit returns the current set commitment.
func (s *diskSet) Commit() [32]byte { return s.commit }

// members returns the first `upTo` members in insertion order (the members at the height whose
// recorded count is `upTo`). Used to serialize the set for a NETWORK transfer snapshot; the
// local restart path keeps members in bolt and never needs this.
func (s *diskSet) members(upTo uint64) [][]byte {
	out := make([][]byte, 0, upTo)
	if s.db == nil {
		return out
	}
	_ = s.db.View(func(tx *bolt.Tx) error {
		cur := tx.Bucket(s.idxBucket).Cursor()
		for k, v := cur.First(); k != nil; k, v = cur.Next() {
			if binary.BigEndian.Uint64(k) >= upTo {
				break
			}
			out = append(out, append([]byte(nil), v...))
		}
		return nil
	})
	return out
}

// importMembers rebuilds the set from a transferred member list on a FRESH set (Add recomputes
// the multiset commitment + records the per-count commit), so a snapshot-imported node has a
// complete, queryable set. Returns the resulting commitment.
func (s *diskSet) importMembers(members [][]byte) [32]byte {
	for _, m := range members {
		s.Add(string(m))
	}
	return s.commit
}

// commitOfMembers computes the multiset commitment a diskSet WOULD have for these members,
// WITHOUT touching bolt — used to verify a transferred member list against the StateRoot before
// committing anything. Mirrors diskSet.Add's incremental hash exactly (dedup included).
func commitOfMembers(members [][]byte) [32]byte {
	var c [32]byte
	seen := make(map[string]bool, len(members))
	for _, m := range members {
		k := string(m)
		if seen[k] {
			continue
		}
		seen[k] = true
		hh := blake2b.Sum256(m)
		c = add256(c, hh)
	}
	return c
}

// readCommit returns the running commit recorded at count n (zero for n==0). Absolute, so
// it is correct regardless of how many entries bolt currently holds (restart reconciliation).
func (s *diskSet) readCommit(n uint64) [32]byte {
	var out [32]byte
	if n == 0 || s.db == nil || s.commitBucket == nil {
		return out
	}
	_ = s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(s.commitBucket).Get(setIdxKey(n)); len(v) == 32 {
			copy(out[:], v)
		}
		return nil
	})
	return out
}

// truncate drops every key with insertion-index >= n. It scans bolt rather than
// trusting the RAM count — on restart the count is the restore TARGET while bolt
// may hold more entries from before the crash. The commit is restored absolutely
// from the recorded commit at count n.
func (s *diskSet) truncate(n uint64) {
	if s.db != nil {
		_ = s.db.Update(func(tx *bolt.Tx) error {
			ib := tx.Bucket(s.idxBucket)
			sb := tx.Bucket(s.setBucket)
			cur := ib.Cursor()
			var delIdx, delKey [][]byte
			for k, v := cur.Seek(setIdxKey(n)); k != nil; k, v = cur.Next() {
				delIdx = append(delIdx, append([]byte(nil), k...))
				delKey = append(delKey, append([]byte(nil), v...))
			}
			for i := range delIdx {
				_ = ib.Delete(delIdx[i])
				_ = sb.Delete(delKey[i])
			}
			// drop commit records strictly above n (they are stale post-truncation).
			if cb := tx.Bucket(s.commitBucket); cb != nil {
				cc := cb.Cursor()
				var delC [][]byte
				for k, _ := cc.Seek(setIdxKey(n + 1)); k != nil; k, _ = cc.Next() {
					delC = append(delC, append([]byte(nil), k...))
				}
				for _, k := range delC {
					_ = cb.Delete(k)
				}
			}
			return nil
		})
	}
	s.count = n
	s.commit = s.readCommit(n)
}

func (s *diskSet) Count() uint64 { return s.count }

// setCount restores the in-RAM count to a snapshot value (bolt reconciled by a
// following truncate in the rebuild path). The commit is restored from the recorded
// commit at that count.
func (s *diskSet) setCount(n uint64) {
	s.count = n
	s.commit = s.readCommit(n)
}

// resetCount clears the RAM count + commit (bolt left for the caller to truncate).
func (s *diskSet) resetCount() {
	s.count = 0
	s.commit = [32]byte{}
}

// rebindDB points the set at a (re)opened db.
func (s *diskSet) rebindDB(db *bolt.DB) { s.db = db }
