package stark

import (
	"bytes"
	"encoding/binary"
)

// PoseidonIMT256 is the wide (256-bit-node) incremental commitment tree — the
// collision-fixed replacement for PoseidonIMT. Nodes are 4 Goldilocks elements,
// compressed with WideHash2 (~2¹²⁸ collision resistance). Same append-only,
// O(depth)-node-state design as the narrow tree.
type PoseidonIMT256 struct {
	depth  int
	count  uint64
	filled []Node256
	zeros  []Node256
	root   Node256
	leaves []Node256 // retained for PathFor (wallet/spender side)
}

// MerklePath256 is a 256-bit-node authentication path.
type MerklePath256 struct {
	Index    int
	Siblings []Node256
}

// NewPoseidonIMT256 creates an empty wide tree of the given depth.
func NewPoseidonIMT256(depth int) *PoseidonIMT256 {
	zeros := make([]Node256, depth+1)
	for k := 1; k <= depth; k++ {
		zeros[k] = WideHash2(zeros[k-1], zeros[k-1])
	}
	filled := make([]Node256, depth)
	copy(filled, zeros[:depth])
	return &PoseidonIMT256{depth: depth, zeros: zeros, filled: filled, root: zeros[depth]}
}

// Append adds a leaf node, updating the frontier + root in O(depth).
func (t *PoseidonIMT256) Append(leaf Node256) uint64 {
	idx := t.count
	t.leaves = append(t.leaves, leaf)
	cur := leaf
	at := idx
	for k := 0; k < t.depth; k++ {
		if at&1 == 0 {
			t.filled[k] = cur
			cur = WideHash2(cur, t.zeros[k])
		} else {
			cur = WideHash2(t.filled[k], cur)
		}
		at >>= 1
	}
	t.root = cur
	t.count++
	return idx
}

func (t *PoseidonIMT256) Root() Node256 { return t.root }
func (t *PoseidonIMT256) Count() uint64 { return t.count }
func (t *PoseidonIMT256) Depth() int    { return t.depth }
func (t *PoseidonIMT256) LeafAt(i uint64) Node256 {
	if i >= uint64(len(t.leaves)) {
		return Node256{}
	}
	return t.leaves[i]
}

// RootAfter returns the root after appending leaves, without mutating the tree.
func (t *PoseidonIMT256) RootAfter(leaves []Node256) Node256 {
	if len(leaves) == 0 {
		return t.root
	}
	filled := append([]Node256(nil), t.filled...)
	at := t.count
	root := t.root
	for _, leaf := range leaves {
		cur := leaf
		a := at
		for k := 0; k < t.depth; k++ {
			if a&1 == 0 {
				filled[k] = cur
				cur = WideHash2(cur, t.zeros[k])
			} else {
				cur = WideHash2(filled[k], cur)
			}
			a >>= 1
		}
		root = cur
		at++
	}
	return root
}

func (t *PoseidonIMT256) subtreeHash(level int, base uint64) Node256 {
	if level == 0 {
		if base < t.count {
			return t.leaves[base]
		}
		return t.zeros[0]
	}
	if base >= t.count {
		return t.zeros[level]
	}
	span := uint64(1) << level
	return WideHash2(t.subtreeHash(level-1, base), t.subtreeHash(level-1, base+span/2))
}

// PathFor returns the authentication path for the leaf at index i.
func (t *PoseidonIMT256) PathFor(i uint64) MerklePath256 {
	sibs := make([]Node256, t.depth)
	for k := 0; k < t.depth; k++ {
		sibIndex := (i >> uint(k)) ^ 1
		sibs[k] = t.subtreeHash(k, sibIndex<<uint(k))
	}
	return MerklePath256{Index: int(i), Siblings: sibs}
}

// VerifyPath256 recomputes the root from a leaf + path (clear-text check).
func VerifyPath256(root, leaf Node256, path MerklePath256) bool {
	h := leaf
	idx := path.Index
	for _, sib := range path.Siblings {
		if idx&1 == 0 {
			h = WideHash2(h, sib)
		} else {
			h = WideHash2(sib, h)
		}
		idx >>= 1
	}
	return h == root
}

// MarshalState encodes FULL tree state: depth, count, root(4), frontier, AND the
// retained leaves slice (length-prefixed leaf count + each Node256).
//
// audit: SECURITY_AUDIT_2026-07-01 — leaves are now persisted. Previously only the
// node-side frontier/root was serialized, so after a snapshot restore or P2P
// fast-sync the node could rebuild the root and keep appending but could NOT serve
// PathFor(i) membership witnesses for pre-snapshot coins (PathFor needs the full
// leaves slice). That made every ZK coin minted before a snapshot permanently
// unspendable on any non-genesis-replay node (HIGH: coin freeze). Persisting leaves
// makes LeafAt/PathFor exact after restore.
func (t *PoseidonIMT256) MarshalState() []byte {
	var buf bytes.Buffer
	var u [8]byte
	binary.BigEndian.PutUint32(u[:4], uint32(t.depth))
	buf.Write(u[:4])
	binary.BigEndian.PutUint64(u[:], t.count)
	buf.Write(u[:])
	writeNode := func(n Node256) {
		for i := 0; i < 4; i++ {
			binary.BigEndian.PutUint64(u[:], uint64(n[i]))
			buf.Write(u[:])
		}
	}
	writeNode(t.root)
	for _, f := range t.filled {
		writeNode(f)
	}
	// audit: SECURITY_AUDIT_2026-07-01 — length-prefixed leaf count, then each leaf.
	binary.BigEndian.PutUint64(u[:], uint64(len(t.leaves)))
	buf.Write(u[:])
	for _, lf := range t.leaves {
		writeNode(lf)
	}
	return buf.Bytes()
}

// LoadIMT256State restores FULL tree state (including leaves).
//
// audit: SECURITY_AUDIT_2026-07-01 — also decodes the persisted leaves slice so
// LeafAt/PathFor are exact after restore.
func LoadIMT256State(data []byte) (*PoseidonIMT256, bool) {
	if len(data) < 4+8 {
		return nil, false
	}
	depth := int(binary.BigEndian.Uint32(data[:4]))
	if depth <= 0 || depth > 64 {
		return nil, false
	}
	// Header (depth+count+root+frontier) followed by leafCount(8) + leaves.
	headLen := 4 + 8 + 32 + depth*32
	if len(data) < headLen+8 {
		return nil, false
	}
	t := NewPoseidonIMT256(depth)
	t.count = binary.BigEndian.Uint64(data[4:12])
	off := 12
	readNode := func() Node256 {
		var n Node256
		for i := 0; i < 4; i++ {
			n[i] = Felt(binary.BigEndian.Uint64(data[off : off+8]))
			off += 8
		}
		return n
	}
	t.root = readNode()
	for k := 0; k < depth; k++ {
		t.filled[k] = readNode()
	}
	// audit: SECURITY_AUDIT_2026-07-01 — decode leaves.
	leafCount := binary.BigEndian.Uint64(data[off : off+8])
	off += 8
	if uint64(len(data)-off) != leafCount*32 {
		return nil, false
	}
	t.leaves = make([]Node256, 0, leafCount)
	for i := uint64(0); i < leafCount; i++ {
		t.leaves = append(t.leaves, readNode())
	}
	return t, true
}

// NodeBytes encodes a node as 32 bytes (big-endian, 4×8).
func NodeBytes(n Node256) []byte {
	b := make([]byte, 32)
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint64(b[i*8:], uint64(n[i]))
	}
	return b
}

// NodeFromBytes decodes a 32-byte node.
func NodeFromBytes(b []byte) Node256 {
	var n Node256
	for i := 0; i < 4 && (i+1)*8 <= len(b); i++ {
		n[i] = NewFelt(binary.BigEndian.Uint64(b[i*8:]))
	}
	return n
}
