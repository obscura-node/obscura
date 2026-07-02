package stark

import (
	"bytes"
	"encoding/binary"
)

// EpochIMT scales the commitment-tree accumulator to UNLIMITED coins at CONSTANT
// per-proof cost — the answer to "deeper tree without losing efficiency".
//
// A Merkle membership proof costs ~depth compressions, and depth = log(capacity), so
// a single growing tree makes proofs more expensive as the coin set grows. Instead we
// keep the tree depth FIXED (a large but bounded anonymity set, 2^depth coins per
// epoch) and roll to a fresh tree when the current one fills. Total coins are
// unbounded; a spend proves membership in ITS epoch's tree, so the proof size/time
// never grow with total supply. Every epoch root (current + recent finalized) is a
// valid spend anchor. The spend circuit is unchanged — it already proves against a
// (root, path, depth), and depth is constant.
//
// Anonymity tradeoff: the set is one epoch's coins (e.g. 2^20 ≈ 1M), not literally
// every coin ever — the standard, sound tradeoff that real shielded systems make.
type EpochIMT struct {
	depth int
	cap   uint64 // 1<<depth, coins per epoch
	trees []*PoseidonIMT256
}

// NewEpochIMT creates an epoch-sharded tree of the given fixed depth.
func NewEpochIMT(depth int) *EpochIMT {
	return &EpochIMT{depth: depth, cap: uint64(1) << uint(depth), trees: []*PoseidonIMT256{NewPoseidonIMT256(depth)}}
}

// Append adds a leaf, rolling to a new epoch tree when the current one is full.
// Returns the (epoch, local index) locating the coin.
func (e *EpochIMT) Append(leaf Node256) (epoch int, index uint64) {
	cur := e.trees[len(e.trees)-1]
	if cur.Count() == e.cap {
		cur = NewPoseidonIMT256(e.depth)
		e.trees = append(e.trees, cur)
	}
	idx := cur.Append(leaf)
	return len(e.trees) - 1, idx
}

// Depth returns the fixed per-epoch tree depth (the spend circuit's path length).
func (e *EpochIMT) Depth() int { return e.depth }

// Epochs returns the number of epoch trees.
func (e *EpochIMT) Epochs() int { return len(e.trees) }

// TotalCount returns the total number of coins across all epochs.
func (e *EpochIMT) TotalCount() uint64 {
	var n uint64
	for _, t := range e.trees {
		n += t.Count()
	}
	return n
}

// CurrentRoot returns the root new coins are being appended under.
func (e *EpochIMT) CurrentRoot() Node256 { return e.trees[len(e.trees)-1].Root() }

// RootAfter returns the CURRENT epoch root the accumulator WOULD have after appending
// `leaves` (handling mid-batch epoch rollover), without mutating — for header CMRoot
// prediction.
//
// NOTE (review finding): the header commits only the CURRENT root per block, so a
// finalized epoch's TERMINAL root is not necessarily any block's committed root (a
// mid-block rollover skips past it). That is fine for full nodes — the entire epoch
// tree sequence is determined by the header-committed leaf stream, so every finalized
// root is reproduced exactly on replay. But it means a light client cannot verify a
// finalized-epoch anchor from the header chain alone, and the snapshot-restored anchor
// set (cmRoots/cmFinal) is trusted local data, not header-cross-checked (acceptable
// for local-only snapshots; a header commitment to the full epoch-root vector would be
// needed for trustless light-client anchor verification).
func (e *EpochIMT) RootAfter(leaves []Node256) Node256 {
	if len(leaves) == 0 {
		return e.CurrentRoot()
	}
	cur := e.trees[len(e.trees)-1]
	filled := append([]Node256(nil), cur.filled...)
	count := cur.count
	root := cur.root
	zeros := cur.zeros // read-only, shared
	for _, leaf := range leaves {
		if count == e.cap { // roll to a fresh epoch
			copy(filled, zeros[:e.depth])
			count = 0
			root = zeros[e.depth]
		}
		c := leaf
		at := count
		for k := 0; k < e.depth; k++ {
			if at&1 == 0 {
				filled[k] = c
				c = WideHash2(c, zeros[k])
			} else {
				c = WideHash2(filled[k], c)
			}
			at >>= 1
		}
		root = c
		count++
	}
	return root
}

// Roots returns every epoch root (current + finalized) — the valid spend anchors.
func (e *EpochIMT) Roots() []Node256 {
	rs := make([]Node256, len(e.trees))
	for i, t := range e.trees {
		rs[i] = t.Root()
	}
	return rs
}

// RootAt returns the root of a given epoch.
func (e *EpochIMT) RootAt(epoch int) (Node256, bool) {
	if epoch < 0 || epoch >= len(e.trees) {
		return Node256{}, false
	}
	return e.trees[epoch].Root(), true
}

// PathFor returns the authentication path for a coin at (epoch, index) against that
// epoch's root.
func (e *EpochIMT) PathFor(epoch int, index uint64) (MerklePath256, Node256, bool) {
	if epoch < 0 || epoch >= len(e.trees) {
		return MerklePath256{}, Node256{}, false
	}
	t := e.trees[epoch]
	return t.PathFor(index), t.Root(), true
}

// Find locates a leaf across all epochs (spender helper; needs retained leaves).
func (e *EpochIMT) Find(leaf Node256) (epoch int, index uint64, ok bool) {
	for ep, t := range e.trees {
		for i := uint64(0); i < t.Count(); i++ {
			if t.LeafAt(i) == leaf {
				return ep, i, true
			}
		}
	}
	return 0, 0, false
}

// MarshalState encodes the FULL state of every epoch tree (frontier+root+count AND
// each epoch's retained leaves), length-prefixed per tree.
//
// audit: SECURITY_AUDIT_2026-07-01 — each per-tree blob now carries that epoch's
// leaves (see PoseidonIMT256.MarshalState), so after a snapshot/fast-sync restore the
// node can serve PathFor witnesses for every coin in every epoch. The per-tree
// length prefix below is unchanged and self-describing, so this wrapper needed no
// format edit — only the inner PoseidonIMT256 layout grew. Size grows from
// O(epochs·depth) to O(total coins) (32 bytes/leaf), which is required to keep
// pre-snapshot ZK coins spendable.
func (e *EpochIMT) MarshalState() []byte {
	var buf bytes.Buffer
	var u [4]byte
	binary.BigEndian.PutUint32(u[:], uint32(len(e.trees)))
	buf.Write(u[:])
	for _, t := range e.trees {
		s := t.MarshalState()
		binary.BigEndian.PutUint32(u[:], uint32(len(s)))
		buf.Write(u[:])
		buf.Write(s)
	}
	return buf.Bytes()
}

// LoadEpochIMTState restores node-side state.
func LoadEpochIMTState(data []byte) (*EpochIMT, bool) {
	if len(data) < 4 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint32(data[:4]))
	if n <= 0 || n > 1<<20 {
		return nil, false
	}
	off := 4
	trees := make([]*PoseidonIMT256, 0, n)
	for i := 0; i < n; i++ {
		if off+4 > len(data) {
			return nil, false
		}
		l := int(binary.BigEndian.Uint32(data[off : off+4]))
		off += 4
		if off+l > len(data) {
			return nil, false
		}
		t, ok := LoadIMT256State(data[off : off+l])
		if !ok {
			return nil, false
		}
		trees = append(trees, t)
		off += l
	}
	depth := trees[0].Depth()
	return &EpochIMT{depth: depth, cap: uint64(1) << uint(depth), trees: trees}, true
}
