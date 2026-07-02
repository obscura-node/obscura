package stark

import (
	"bytes"
	"encoding/binary"
)

// PoseidonIMT is an append-only, fixed-depth Poseidon incremental Merkle tree —
// the commitment-tree accumulator for the anonymous spend (Zcash/Tornado style).
//
// A full node keeps only O(depth) state: the rightmost "frontier" (filled left
// subtrees) + the current root + the leaf count. Appending a coin commitment is
// O(depth). The header commits the root; a spend proves membership against a recent
// root (anchor) with the STARK in spend_air.go. This REPLACES the class-group
// accumulator + anonymity rings for the ZK spend: the tree's Poseidon hashing is
// STARK-friendly (the membership circuit re-verifies the exact Hash2), so the node
// is constant-size AND post-quantum.
//
// Empty positions hash with per-level "zero" subtree hashes. Spenders need their
// authentication path; PathFor recomputes it from the appended leaves (a node that
// only validates does not need PathFor — just Append + Root).
type PoseidonIMT struct {
	depth  int
	count  uint64
	filled []Felt // filled[k] = left-subtree hash pending at level k
	zeros  []Felt // zeros[k] = hash of an all-empty subtree of height k
	root   Felt
	leaves []Felt // appended leaves (for PathFor / wallets); node may drop these
}

// NewPoseidonIMT creates an empty tree of the given depth (≤ 50 in practice).
func NewPoseidonIMT(depth int) *PoseidonIMT {
	zeros := make([]Felt, depth+1)
	zeros[0] = 0 // empty leaf
	for k := 1; k <= depth; k++ {
		zeros[k] = PoseidonHash2(zeros[k-1], zeros[k-1])
	}
	filled := make([]Felt, depth)
	copy(filled, zeros[:depth])
	return &PoseidonIMT{depth: depth, zeros: zeros, filled: filled, root: zeros[depth]}
}

// Append adds a leaf, updating the frontier + root in O(depth). Returns the leaf's
// index.
func (t *PoseidonIMT) Append(leaf Felt) uint64 {
	idx := t.count
	t.leaves = append(t.leaves, leaf)
	cur := leaf
	at := idx
	for k := 0; k < t.depth; k++ {
		if at&1 == 0 {
			t.filled[k] = cur
			cur = PoseidonHash2(cur, t.zeros[k])
		} else {
			cur = PoseidonHash2(t.filled[k], cur)
		}
		at >>= 1
	}
	t.root = cur
	t.count++
	return idx
}

// Root returns the current commitment-tree root.
func (t *PoseidonIMT) Root() Felt { return t.root }

// RootAfter returns the root the tree WOULD have after appending the given leaves,
// without mutating the tree (used to predict a block's committed root). If leaves is
// empty it returns the current root.
func (t *PoseidonIMT) RootAfter(leaves []Felt) Felt {
	if len(leaves) == 0 {
		return t.root
	}
	filled := append([]Felt(nil), t.filled...)
	at := t.count
	root := t.root
	for _, leaf := range leaves {
		cur := leaf
		a := at
		for k := 0; k < t.depth; k++ {
			if a&1 == 0 {
				filled[k] = cur
				cur = PoseidonHash2(cur, t.zeros[k])
			} else {
				cur = PoseidonHash2(filled[k], cur)
			}
			a >>= 1
		}
		root = cur
		at++
	}
	return root
}

// Count returns the number of appended leaves.
func (t *PoseidonIMT) Count() uint64 { return t.count }

// Depth returns the tree depth.
func (t *PoseidonIMT) Depth() int { return t.depth }

// LeafAt returns the appended leaf at index i (requires retained leaves).
func (t *PoseidonIMT) LeafAt(i uint64) Felt {
	if i >= uint64(len(t.leaves)) {
		return 0
	}
	return t.leaves[i]
}

// subtreeHash returns the hash of the height-`level` subtree whose left edge is leaf
// index `base`, using stored leaves (zeros beyond the appended count).
func (t *PoseidonIMT) subtreeHash(level int, base uint64) Felt {
	if level == 0 {
		if base < t.count {
			return t.leaves[base]
		}
		return t.zeros[0]
	}
	span := uint64(1) << level
	if base >= t.count { // wholly empty subtree
		return t.zeros[level]
	}
	left := t.subtreeHash(level-1, base)
	right := t.subtreeHash(level-1, base+span/2)
	return PoseidonHash2(left, right)
}

// PathFor returns the authentication path for the leaf at index i against the
// CURRENT tree state. Requires the appended leaves (wallet/spender side).
func (t *PoseidonIMT) PathFor(i uint64) MerklePath {
	sibs := make([]Felt, t.depth)
	for k := 0; k < t.depth; k++ {
		sibIndex := (i >> uint(k)) ^ 1 // sibling position at level k
		base := sibIndex << uint(k)    // left edge of that sibling subtree
		sibs[k] = t.subtreeHash(k, base)
	}
	return MerklePath{Index: int(i), Siblings: sibs}
}

// MarshalState encodes the O(depth) node-side state (no leaves) for persistence.
func (t *PoseidonIMT) MarshalState() []byte {
	var buf bytes.Buffer
	var u [8]byte
	binary.BigEndian.PutUint32(u[:4], uint32(t.depth))
	buf.Write(u[:4])
	binary.BigEndian.PutUint64(u[:], t.count)
	buf.Write(u[:])
	binary.BigEndian.PutUint64(u[:], uint64(t.root))
	buf.Write(u[:])
	for _, f := range t.filled {
		binary.BigEndian.PutUint64(u[:], uint64(f))
		buf.Write(u[:])
	}
	return buf.Bytes()
}

// LoadIMTState restores node-side state (frontier + root + count). The leaves are
// not restored (a validating node does not need them).
func LoadIMTState(data []byte) (*PoseidonIMT, bool) {
	if len(data) < 4+8+8 {
		return nil, false
	}
	depth := int(binary.BigEndian.Uint32(data[:4]))
	if depth <= 0 || depth > 64 || len(data) != 4+8+8+depth*8 {
		return nil, false
	}
	t := NewPoseidonIMT(depth)
	t.count = binary.BigEndian.Uint64(data[4:12])
	t.root = Felt(binary.BigEndian.Uint64(data[12:20]))
	off := 20
	for k := 0; k < depth; k++ {
		t.filled[k] = Felt(binary.BigEndian.Uint64(data[off : off+8]))
		off += 8
	}
	return t, true
}
