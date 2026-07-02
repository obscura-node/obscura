package stark

// SECURITY: NOT FOR CONSENSUS. Superseded spend/mint model (pre-#96, plain serial,
// no recipient-secret nullifier binding). The live path is
// nfmint_air.go / nfspend_air.go / cnfspend_air.go. Do NOT wire this into pkg/chain
// without a full re-audit — it lacks ownership binding.

// Width-8 mint circuit — the 256-bit-node version of mint_air.go. Proves
// leaf = WideHash2(WideHash2(serial,amount), blind) for a PUBLIC (amount, leaf),
// hiding serial+blind. It is the wide spend circuit's leaf computation (blocks 0–1)
// standing alone, with serial a witness instead of public.

type mint256Circuit struct {
	amount Felt
	leaf   Node256
	bind   []byte
}

func (c mint256Circuit) Name() string {
	if len(c.bind) == 0 {
		return "zk-mint-256"
	}
	return "zk-mint-256:" + bytesHex(c.bind)
}
func (mint256Circuit) Cols() int       { return 17 } // 13 base + 4 fold
func (mint256Circuit) Periodic() int   { return 17 } // 11 base + row0 + outSel + 4 rootVal
func (mint256Circuit) blocks() int     { return spendPreBlocks }
func (c mint256Circuit) TraceLen() int { return nextPow2(merkleBlock * c.blocks()) }
func (c mint256Circuit) rootRow() int  { return merkleBlock*c.blocks() - 1 }

func (c mint256Circuit) PeriodicCol(j int) []Felt {
	col := make([]Felt, c.TraceLen())
	if j == 11 { // row0
		col[0] = 1
		return col
	}
	if j == 12 { // outSel: the Jive leaf-output row
		col[c.rootRow()] = 1
		return col
	}
	if j >= 13 && j <= 16 { // rootVal: public leaf at the output row
		col[c.rootRow()] = c.leaf[j-13]
		return col
	}
	for row := 0; row < c.rootRow(); row++ {
		m := row % merkleBlock
		if m == merkleBlock-1 {
			if j == 10 {
				col[row] = 1
			}
			continue
		}
		r := m
		switch {
		case j < poseidonWideT:
			col[row] = poseidonWideRC[r][j]
		case j == 8:
			if wideFullRound(r) {
				col[row] = 1
			}
		case j == 9:
			col[row] = 1
		}
	}
	return col
}

func (c mint256Circuit) Boundaries() []Boundary {
	b := []Boundary{{Col: 4, Row: 0, Val: c.amount}} // s4 input = amount (public)
	for _, col := range []int{1, 2, 3, 5, 6, 7} {    // serial/amount upper slots = 0
		b = append(b, Boundary{Col: col, Row: 0, Val: 0})
	}
	// computed leaf bound to the Jive output via periodic columns (outSel + rootVal).
	// s0 input (serial) is a FREE witness.
	return b
}

func (mint256Circuit) ConstraintsFelt(cur, next, per []Felt) []Felt {
	out := wideMerkleConstraints[Felt](feltEnv{}, cur[:13], next[:13], per[:11], cur[13:17], next[13:17], per[11])
	return append(out, jiveRootBind[Felt](feltEnv{}, cur[:8], cur[13:17], per[13:17], per[12])...)
}

func (mint256Circuit) ConstraintsExt(cur, next, per []Felt2) []Felt2 {
	out := wideMerkleConstraints[Felt2](felt2Env{}, cur[:13], next[:13], per[:11], cur[13:17], next[13:17], per[11])
	return append(out, jiveRootBind[Felt2](felt2Env{}, cur[:8], cur[13:17], per[13:17], per[12])...)
}
func (mint256Circuit) ConstraintsPoly(cur, next, per []Poly) []Poly {
	out := wideMerkleConstraints[Poly](polyEnv{}, cur[:13], next[:13], per[:11], cur[13:17], next[13:17], per[11])
	return append(out, jiveRootBind[Poly](polyEnv{}, cur[:8], cur[13:17], per[13:17], per[12])...)
}

// ProveMint256 proves leaf = SpendLeaf256(serial,amount,blind) for public amount+leaf.
func ProveMint256(serial, amount, blind Felt, bind []byte, nQueries int) (*AIRProof, error) {
	leaf := SpendLeaf256(serial, amount, blind)
	c := mint256Circuit{amount: amount, leaf: leaf, bind: bind}
	return ProveAIR(c, spend256Trace(serial, amount, blind, MerklePath256{}, 0), nQueries)
}

// VerifyMint256 checks a wide mint proof binds leaf to amount. bind is the full
// tx-binding domain.
func VerifyMint256(leaf Node256, amount Felt, bind []byte, pf *AIRProof, nQueries int) bool {
	return VerifyAIR(mint256Circuit{amount: amount, leaf: leaf, bind: bind}, pf, nQueries)
}
