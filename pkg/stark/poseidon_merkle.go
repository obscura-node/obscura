package stark

// Poseidon Merkle tree — the STARK-friendly membership structure for the ZK spend.
// A coin is a leaf; the accumulator "value" is the root; membership is an
// authentication path. Because every node is a Poseidon compression (low-degree),
// a path can be re-verified inside an AIR — which is exactly what the ZK
// membership proof does (hiding which leaf). This is the membership relation in the
// CLEAR; poseidon_air.go proves the same relation in zero knowledge.
//
// This converges with the PQ roadmap: a Poseidon (or any STARK-friendly hash)
// Merkle accumulator IS the post-quantum, STARK-provable replacement for the
// RSA/class-group accumulator (whose group ops are STARK-hostile).

// PoseidonMerkle is a fixed-depth Poseidon Merkle tree over Felt leaves.
type PoseidonMerkle struct {
	depth  int
	leaves []Felt
	levels [][]Felt // levels[0]=leaves, levels[depth]={root}
}

// BuildPoseidonMerkle builds a tree over 2^depth leaves (padded with 0 if short).
func BuildPoseidonMerkle(leaves []Felt, depth int) *PoseidonMerkle {
	n := 1 << depth
	padded := make([]Felt, n)
	copy(padded, leaves)
	levels := [][]Felt{padded}
	cur := padded
	for len(cur) > 1 {
		next := make([]Felt, len(cur)/2)
		for i := range next {
			next[i] = PoseidonHash2(cur[2*i], cur[2*i+1])
		}
		levels = append(levels, next)
		cur = next
	}
	return &PoseidonMerkle{depth: depth, leaves: padded, levels: levels}
}

// Root returns the tree root (the accumulator value).
func (m *PoseidonMerkle) Root() Felt { return m.levels[m.depth][0] }

// MerklePath is an authentication path: sibling at each level, bottom-up, plus the
// index (its bits select left/right at each level).
type MerklePath struct {
	Index    int
	Siblings []Felt
}

// PathFor returns the authentication path for leaf index i.
func (m *PoseidonMerkle) PathFor(i int) MerklePath {
	sibs := make([]Felt, m.depth)
	idx := i
	for lvl := 0; lvl < m.depth; lvl++ {
		sibs[lvl] = m.levels[lvl][idx^1]
		idx >>= 1
	}
	return MerklePath{Index: i, Siblings: sibs}
}

// VerifyPoseidonPath recomputes the root from a leaf + path and compares to root.
// At each level the index bit decides whether the running hash is the left or right
// input — the same logic the AIR enforces with a path-bit selector.
func VerifyPoseidonPath(root, leaf Felt, path MerklePath) bool {
	h := leaf
	idx := path.Index
	for _, sib := range path.Siblings {
		if idx&1 == 0 {
			h = PoseidonHash2(h, sib)
		} else {
			h = PoseidonHash2(sib, h)
		}
		idx >>= 1
	}
	return h == root
}

// Nullifier derives a coin's spend nullifier from its secret serial: N = H(s).
// Deterministic (one coin ⇒ one N) and one-way (N hides s).
func Nullifier(serial Felt) Felt { return PoseidonHash1(serial) }
