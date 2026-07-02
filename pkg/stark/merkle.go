package stark

import (
	"encoding/binary"

	"golang.org/x/crypto/blake2b"
)

// Merkle commitment over a vector of field elements — the transparent, post-quantum
// vector commitment FRI uses to bind each layer's evaluations. Security rests only
// on blake2b collision resistance (no trusted setup, no algebraic assumption).

func leafHash(f Felt) [32]byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(f))
	return blake2b.Sum256(buf[:])
}

func nodeHash(l, r [32]byte) [32]byte {
	var buf [64]byte
	copy(buf[:32], l[:])
	copy(buf[32:], r[:])
	return blake2b.Sum256(buf[:])
}

// MerkleTree is a full binary tree over a power-of-two number of leaves.
type MerkleTree struct {
	leaves []Felt
	// levels[0] = leaf hashes, levels[len-1] = {root}
	levels [][][32]byte
}

// BuildMerkle commits to leaves (length must be a power of two).
func BuildMerkle(leaves []Felt) *MerkleTree {
	n := len(leaves)
	if n == 0 || n&(n-1) != 0 {
		panic("stark: Merkle leaf count must be a power of two")
	}
	level := make([][32]byte, n)
	for i, f := range leaves {
		level[i] = leafHash(f)
	}
	levels := [][][32]byte{level}
	for len(level) > 1 {
		next := make([][32]byte, len(level)/2)
		for i := 0; i < len(next); i++ {
			next[i] = nodeHash(level[2*i], level[2*i+1])
		}
		levels = append(levels, next)
		level = next
	}
	return &MerkleTree{leaves: append([]Felt(nil), leaves...), levels: levels}
}

// Root returns the commitment.
func (t *MerkleTree) Root() [32]byte { return t.levels[len(t.levels)-1][0] }

// Open returns the leaf value at i and its authentication path (sibling hashes,
// bottom-up).
func (t *MerkleTree) Open(i int) (Felt, [][32]byte) {
	path := make([][32]byte, 0, len(t.levels)-1)
	idx := i
	for lvl := 0; lvl < len(t.levels)-1; lvl++ {
		path = append(path, t.levels[lvl][idx^1])
		idx >>= 1
	}
	return t.leaves[i], path
}

// leafHashRow hashes a whole row of field elements into one leaf — used to commit
// all trace columns + the composition value at a domain index under a SINGLE Merkle
// tree, so one authentication path opens the entire row (instead of one path per
// column). This is the dominant proof-size win for multi-column AIRs.
func leafHashRow(vals []Felt) [32]byte {
	buf := make([]byte, 8*len(vals))
	for i, f := range vals {
		binary.BigEndian.PutUint64(buf[i*8:], uint64(f))
	}
	return blake2b.Sum256(buf)
}

// RowMerkleTree commits one leaf per row, each leaf = leafHashRow(row).
type RowMerkleTree struct {
	rows   [][]Felt
	levels [][][32]byte
}

// BuildRowMerkle commits a matrix as rows (row count must be a power of two).
func BuildRowMerkle(rows [][]Felt) *RowMerkleTree {
	n := len(rows)
	if n == 0 || n&(n-1) != 0 {
		panic("stark: RowMerkle row count must be a power of two")
	}
	level := make([][32]byte, n)
	for i, row := range rows {
		level[i] = leafHashRow(row)
	}
	levels := [][][32]byte{level}
	for len(level) > 1 {
		next := make([][32]byte, len(level)/2)
		for i := range next {
			next[i] = nodeHash(level[2*i], level[2*i+1])
		}
		levels = append(levels, next)
		level = next
	}
	return &RowMerkleTree{rows: rows, levels: levels}
}

// Root returns the commitment.
func (t *RowMerkleTree) Root() [32]byte { return t.levels[len(t.levels)-1][0] }

// Open returns row i and its authentication path.
func (t *RowMerkleTree) Open(i int) ([]Felt, [][32]byte) {
	path := make([][32]byte, 0, len(t.levels)-1)
	idx := i
	for lvl := 0; lvl < len(t.levels)-1; lvl++ {
		path = append(path, t.levels[lvl][idx^1])
		idx >>= 1
	}
	return t.rows[i], path
}

// VerifyRowMerkle checks a row at index i with its path against root.
func VerifyRowMerkle(root [32]byte, n, i int, row []Felt, path [][32]byte) bool {
	if i < 0 || i >= n || !validPathLen(n, len(path)) {
		return false
	}
	h := leafHashRow(row)
	idx := i
	for _, sib := range path {
		if idx&1 == 0 {
			h = nodeHash(h, sib)
		} else {
			h = nodeHash(sib, h)
		}
		idx >>= 1
	}
	return h == root
}

// validPathLen reports whether a path of len p authenticates one of n leaves —
// exactly log2(n) sibling hashes. Guards against short/long-path shenanigans
// (defensive; a forged length would still need a hash collision to hit the root).
func validPathLen(n, p int) bool {
	want := 0
	for (1 << want) < n {
		want++
	}
	return p == want
}

// VerifyMerkle checks that leaf at index i with the given path hashes to root.
// n is the number of leaves (needed to interpret the index bits).
func VerifyMerkle(root [32]byte, n, i int, leaf Felt, path [][32]byte) bool {
	if i < 0 || i >= n || !validPathLen(n, len(path)) {
		return false
	}
	h := leafHash(leaf)
	idx := i
	for _, sib := range path {
		if idx&1 == 0 {
			h = nodeHash(h, sib)
		} else {
			h = nodeHash(sib, h)
		}
		idx >>= 1
	}
	return h == root
}
