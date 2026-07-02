package stark

// Anonymous spend proof — membership + nullifier + value bound in ONE
// zero-knowledge STARK.
//
// A coin's commitment (tree leaf) is
//
//	L = Hash2( Hash2(S, amount), blind )
//
// where S is the coin serial, `amount` its value, and `blind` a secret. To spend,
// the owner REVEALS S (the nullifier) and `amount` (public, so value conservation
// is a trivial public sum at the tx layer) and proves in zero knowledge that L is a
// member of the commitment tree with public root R — while `blind` stays secret, so
// L itself is hidden and observers cannot tell which coin was spent.
//
//   - binding: S and amount are wired into the leaf as public boundaries, so a
//     spender cannot reveal a nullifier/amount unrelated to the coin proven a
//     member;
//   - no inflation: amount is public and bound into the spent leaf;
//   - double-spend: reusing S collides in the nullifier set;
//   - sender-anonymity: blind hides L, so the spent coin is unlinkable.
//
// (Amount privacy is intentionally traded for a trivially-sound public value sum on
// the test chain; a confidential-value leg can replace it later.)
//
// One trace computes Hash2(S,amount) (block 0), folds in `blind` (Hash2(·,blind),
// block 1) to get the leaf, then folds the leaf up D Merkle levels (blocks 2..D+1),
// reusing the membership constraints. The block-0 input is pinned by boundaries.

const spendPreBlocks = 2 // block 0 = Hash2(S,amount); block 1 = Hash2(·,blind)

// spendCircuit proves membership of L=Hash2(Hash2(S,amount),blind) under root.
type spendCircuit struct {
	depth  int
	serial Felt // public nullifier S
	amount Felt // public coin value
	root   Felt // public commitment-tree root
	bind   Felt // tx-binding domain (folded into the transcript so a proof can't be
	// lifted into a different transaction; 0 = unbound, for tests)
}

func (c spendCircuit) Name() string {
	if c.bind == 0 {
		return "anon-spend"
	}
	return "anon-spend:" + feltHex(c.bind)
}

// feltHex renders a Felt as 16 lowercase hex chars (transcript domain separator).
func feltHex(f Felt) string {
	const hexdig = "0123456789abcdef"
	v := uint64(f)
	var out [16]byte
	for i := 15; i >= 0; i-- {
		out[i] = hexdig[v&0xf]
		v >>= 4
	}
	return string(out[:])
}
func (spendCircuit) Cols() int       { return 5 }
func (spendCircuit) Periodic() int   { return 6 }
func (c spendCircuit) blocks() int   { return c.depth + spendPreBlocks }
func (c spendCircuit) TraceLen() int { return nextPow2(merkleBlock * c.blocks()) }

// rootRow holds the final root (last row of the last block).
func (c spendCircuit) rootRow() int { return merkleBlock*c.blocks() - 1 }

// PeriodicCol: 31-row blocks; rows m=0..29 are Poseidon rounds (round r=m); the
// transition at m=30 is an injection feeding the next block.
func (c spendCircuit) PeriodicCol(j int) []Felt {
	T := c.TraceLen()
	col := make([]Felt, T)
	for row := 0; row < c.rootRow(); row++ {
		m := row % merkleBlock
		if m == merkleBlock-1 { // injection
			if j == 5 {
				col[row] = 1
			}
			continue
		}
		r := m
		switch {
		case j < poseidonT:
			col[row] = poseidonRC[r][j]
		case j == 3:
			if fullRound(r) {
				col[row] = 1
			}
		case j == 4:
			col[row] = 1
		}
	}
	return col
}

func (c spendCircuit) Boundaries() []Boundary {
	return []Boundary{
		{Col: 0, Row: 0, Val: c.serial},               // block-0 input s0 = S (public)
		{Col: 1, Row: 0, Val: c.amount},               // block-0 input s1 = amount (public)
		{Col: 2, Row: 0, Val: Felt(poseidonMerkleIV)}, // block-0 input s2 = IV
		{Col: 0, Row: c.rootRow(), Val: c.root},       // folded result = root (public)
	}
}

func (spendCircuit) ConstraintsFelt(cur, next, per []Felt) []Felt {
	return merkleConstraints[Felt](feltEnv{}, cur, next, per)
}

func (spendCircuit) ConstraintsExt(cur, next, per []Felt2) []Felt2 {
	return merkleConstraints[Felt2](felt2Env{}, cur, next, per)
}
func (spendCircuit) ConstraintsPoly(cur, next, per []Poly) []Poly {
	return merkleConstraints[Poly](polyEnv{}, cur, next, per)
}

// spendTrace builds a constraint-satisfying spend trace.
func spendTrace(serial, amount, blind Felt, path MerklePath, depth int) [][]Felt {
	blocks := depth + spendPreBlocks
	T := nextPow2(merkleBlock * blocks)
	s0 := make([]Felt, T)
	s1 := make([]Felt, T)
	s2 := make([]Felt, T)
	sib := make([]Felt, T)
	bit := make([]Felt, T)

	s0[0], s1[0], s2[0] = serial, amount, Felt(poseidonMerkleIV)
	idx := path.Index
	last := merkleBlock*blocks - 1
	for i := 0; i < last; i++ {
		m := i % merkleBlock
		if m == merkleBlock-1 { // injection at end of a block
			blk := i / merkleBlock // which block just produced its output (0..blocks-2)
			var b, sv Felt
			if blk == 0 {
				// fold the secret blind in: L = Hash2(Hash2(S,amount), blind)
				b, sv = 0, blind
			} else {
				lvl := blk - 1 // path level
				b = Felt(idx & 1)
				sv = path.Siblings[lvl]
				idx >>= 1
			}
			sib[i] = sv
			bit[i] = b
			parent := s0[i]
			var in0, in1 Felt
			if b == 0 {
				in0, in1 = parent, sv
			} else {
				in0, in1 = sv, parent
			}
			s0[i+1], s1[i+1], s2[i+1] = in0, in1, Felt(poseidonMerkleIV)
			continue
		}
		r := m
		st := [poseidonT]Felt{s0[i], s1[i], s2[i]}
		for k := 0; k < poseidonT; k++ {
			st[k] = st[k].Add(poseidonRC[r][k])
		}
		if fullRound(r) {
			for k := 0; k < poseidonT; k++ {
				st[k] = sbox(st[k])
			}
		} else {
			st[0] = sbox(st[0])
		}
		st = mds(st)
		s0[i+1], s1[i+1], s2[i+1] = st[0], st[1], st[2]
	}
	return [][]Felt{s0, s1, s2, sib, bit}
}

// SpendLeaf computes the commitment-tree leaf for a coin:
// L = Hash2(Hash2(serial, amount), blind).
func SpendLeaf(serial, amount, blind Felt) Felt {
	return PoseidonHash2(PoseidonHash2(serial, amount), blind)
}

// ProveSpend produces an anonymous spend proof. It reveals only serial (the
// nullifier), amount, and root.
func ProveSpend(serial, amount, blind Felt, path MerklePath, depth int, root Felt, nQueries int) (*AIRProof, error) {
	return ProveSpendBound(serial, amount, blind, path, depth, root, 0, nQueries)
}

// ProveSpendBound is ProveSpend with a tx-binding domain: the proof is valid only
// when verified with the same `bind` (typically a digest of the spending tx), so a
// proof cannot be lifted into a different transaction.
func ProveSpendBound(serial, amount, blind Felt, path MerklePath, depth int, root, bind Felt, nQueries int) (*AIRProof, error) {
	c := spendCircuit{depth: depth, serial: serial, amount: amount, root: root, bind: bind}
	return ProveAIR(c, spendTrace(serial, amount, blind, path, depth), nQueries)
}

// VerifySpend checks an anonymous spend proof against the public nullifier
// (serial), amount, and commitment-tree root.
func VerifySpend(serial, amount, root Felt, depth int, pf *AIRProof, nQueries int) bool {
	return VerifySpendBound(serial, amount, root, 0, depth, pf, nQueries)
}

// VerifySpendBound checks a tx-bound anonymous spend proof.
func VerifySpendBound(serial, amount, root, bind Felt, depth int, pf *AIRProof, nQueries int) bool {
	return VerifyAIR(spendCircuit{depth: depth, serial: serial, amount: amount, root: root, bind: bind}, pf, nQueries)
}
