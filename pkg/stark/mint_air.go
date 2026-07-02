package stark

// SECURITY: NOT FOR CONSENSUS. Superseded spend/mint model (pre-#96, plain serial,
// no recipient-secret nullifier binding). The live path is
// nfmint_air.go / nfspend_air.go / cnfspend_air.go. Do NOT wire this into pkg/chain
// without a full re-audit — it lacks ownership binding.

// Mint (shield) proof — binds a Poseidon commitment leaf to its PUBLIC value
// without revealing the coin's secrets. It proves
//
//	leaf = Hash2( Hash2(serial, amount), blind )
//
// for a public (amount, leaf), hiding serial and blind. This is what lets a node
// account a freshly-minted ZK coin's value (publicOut += amount) while keeping the
// serial secret — so the later spend's revealed serial cannot be linked back to the
// mint, and a creator cannot mint a leaf worth more than they declare (anti-
// inflation). It is the spend circuit's leaf computation (blocks 0–1) standing
// alone, with serial as a witness instead of a public input.

// mintCircuit proves leaf = Hash2(Hash2(serial,amount),blind), amount+leaf public.
type mintCircuit struct {
	amount Felt
	leaf   Felt
	bind   Felt
}

func (c mintCircuit) Name() string {
	if c.bind == 0 {
		return "zk-mint"
	}
	return "zk-mint:" + feltHex(c.bind)
}
func (mintCircuit) Cols() int       { return 5 }
func (mintCircuit) Periodic() int   { return 6 }
func (mintCircuit) blocks() int     { return spendPreBlocks }
func (c mintCircuit) TraceLen() int { return nextPow2(merkleBlock * c.blocks()) }
func (c mintCircuit) rootRow() int  { return merkleBlock*c.blocks() - 1 }

func (c mintCircuit) PeriodicCol(j int) []Felt {
	T := c.TraceLen()
	col := make([]Felt, T)
	for row := 0; row < c.rootRow(); row++ {
		m := row % merkleBlock
		if m == merkleBlock-1 {
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

func (c mintCircuit) Boundaries() []Boundary {
	return []Boundary{
		{Col: 1, Row: 0, Val: c.amount},               // s1 input = amount (public)
		{Col: 2, Row: 0, Val: Felt(poseidonMerkleIV)}, // s2 input = IV
		{Col: 0, Row: c.rootRow(), Val: c.leaf},       // computed leaf = public Leaf
		// s0 input (serial) is a FREE witness — kept secret.
	}
}

func (mintCircuit) ConstraintsFelt(cur, next, per []Felt) []Felt {
	return merkleConstraints[Felt](feltEnv{}, cur, next, per)
}

func (mintCircuit) ConstraintsExt(cur, next, per []Felt2) []Felt2 {
	return merkleConstraints[Felt2](felt2Env{}, cur, next, per)
}
func (mintCircuit) ConstraintsPoly(cur, next, per []Poly) []Poly {
	return merkleConstraints[Poly](polyEnv{}, cur, next, per)
}

// ProveMint proves leaf = SpendLeaf(serial, amount, blind) for public amount+leaf,
// hiding serial and blind. bind ties the proof to a transaction.
func ProveMint(serial, amount, blind, bind Felt, nQueries int) (*AIRProof, error) {
	leaf := SpendLeaf(serial, amount, blind)
	c := mintCircuit{amount: amount, leaf: leaf, bind: bind}
	// depth 0 ⇒ spendTrace produces exactly the two leaf-compression blocks.
	return ProveAIR(c, spendTrace(serial, amount, blind, MerklePath{}, 0), nQueries)
}

// VerifyMint checks a mint proof binds leaf to amount.
func VerifyMint(leaf, amount, bind Felt, pf *AIRProof, nQueries int) bool {
	return VerifyAIR(mintCircuit{amount: amount, leaf: leaf, bind: bind}, pf, nQueries)
}
