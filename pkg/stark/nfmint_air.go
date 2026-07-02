package stark

// nf-note MINT circuit — shields a PUBLIC amount into an unlinkable note coin (the entry
// point for the confidential+unlinkable system, the analog of mint256 for nf notes). It
// proves cm = sponge(pk, amount, rho, blind) commits to the declared public `amount`
// (anti-inflation — a minter can't put more value in the note than it declares), hiding
// the recipient address pk and the nonces rho, blind. The note is later spent
// confidentially + unlinkably by cnfSpendCircuit, or membership-proven by nfSpendCircuit.
//
//   block 0      h1 = H(pk, N(amount))     input [pk(0..3), amount,0,0,0]
//   block 0 inj  fold rho  → 1: h2 = H(h1, N(rho))
//   block 1 inj  fold blind→ 2: cm = H(h2, N(blind))   → cm @ last row
//
// Columns (13): s0..s7, sib0..sib3, bit.  Periodic (11): the base wide schedule.

type nfMintCircuit struct {
	amount Felt    // public
	cm     Node256 // public note commitment
	bind   []byte
}

func (c nfMintCircuit) Name() string {
	if len(c.bind) == 0 {
		return "nf-mint"
	}
	return "nf-mint:" + bytesHex(c.bind)
}
func (nfMintCircuit) Cols() int       { return 17 } // 13 base + 4 fold
func (nfMintCircuit) Periodic() int   { return 17 } // 11 base + row0 + outSel + 4 rootVal
func (nfMintCircuit) blocks() int     { return 3 }  // h1, h2, cm
func (c nfMintCircuit) TraceLen() int { return nextPow2(merkleBlock * c.blocks()) }
func (c nfMintCircuit) cmRow() int    { return merkleBlock*c.blocks() - 1 }

func (c nfMintCircuit) PeriodicCol(j int) []Felt {
	col := make([]Felt, c.TraceLen())
	if j == 11 { // row0
		col[0] = 1
		return col
	}
	if j == 12 { // outSel: the Jive cm-output row
		col[c.cmRow()] = 1
		return col
	}
	if j >= 13 && j <= 16 { // rootVal: public cm at the output row
		col[c.cmRow()] = c.cm[j-13]
		return col
	}
	for row := 0; row < c.cmRow(); row++ {
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

func (c nfMintCircuit) Boundaries() []Boundary {
	// input row: [pk(0..3), amount, 0,0,0] — pk hidden, amount public, upper amount-node 0.
	b := []Boundary{{Col: 4, Row: 0, Val: c.amount}}
	for _, col := range []int{5, 6, 7} {
		b = append(b, Boundary{Col: col, Row: 0, Val: 0})
	}
	// rho / blind folds: sib = N(field), bit = 0, upper sib cells 0 (canonical node).
	for _, row := range []int{merkleBlock - 1, merkleBlock*2 - 1} {
		for _, col := range []int{9, 10, 11, 12} {
			b = append(b, Boundary{Col: col, Row: row, Val: 0})
		}
	}
	// public note commitment bound to the Jive output via periodic columns (outSel+rootVal).
	return b
}

func (nfMintCircuit) ConstraintsFelt(cur, next, per []Felt) []Felt {
	out := wideMerkleConstraints[Felt](feltEnv{}, cur[:13], next[:13], per[:11], cur[13:17], next[13:17], per[11])
	return append(out, jiveRootBind[Felt](feltEnv{}, cur[:8], cur[13:17], per[13:17], per[12])...)
}

func (nfMintCircuit) ConstraintsExt(cur, next, per []Felt2) []Felt2 {
	out := wideMerkleConstraints[Felt2](felt2Env{}, cur[:13], next[:13], per[:11], cur[13:17], next[13:17], per[11])
	return append(out, jiveRootBind[Felt2](felt2Env{}, cur[:8], cur[13:17], per[13:17], per[12])...)
}
func (nfMintCircuit) ConstraintsPoly(cur, next, per []Poly) []Poly {
	out := wideMerkleConstraints[Poly](polyEnv{}, cur[:13], next[:13], per[:11], cur[13:17], next[13:17], per[11])
	return append(out, jiveRootBind[Poly](polyEnv{}, cur[:8], cur[13:17], per[13:17], per[12])...)
}

func nfMintTrace(pk Node256, amount, rho, blind Felt) [][]Felt {
	blocks := 3
	T := nextPow2(merkleBlock * blocks)
	cmRow := merkleBlock*blocks - 1
	cols := make([][]Felt, 17)
	for i := range cols {
		cols[i] = make([]Felt, T)
	}
	// block-0 input = [pk(0..3), amount, 0,0,0].
	for k := 0; k < 4; k++ {
		cols[k][0] = pk[k]
	}
	cols[4][0] = amount
	for i := 0; i < cmRow; i++ {
		m := i % merkleBlock
		if m == merkleBlock-1 { // injection (fold rho then blind, bit=0)
			b := i / merkleBlock
			var sib Node256
			if b == 0 {
				sib = Node256FromFelts(rho)
			} else {
				sib = Node256FromFelts(blind)
			}
			parent := jiveParentAt(cols, i)
			for k := 0; k < 4; k++ {
				cols[8+k][i] = sib[k]
			}
			cols[12][i] = 0
			for k := 0; k < 4; k++ {
				cols[k][i+1] = parent[k]
				cols[4+k][i+1] = sib[k]
			}
			continue
		}
		var st [poseidonWideT]Felt
		for k := 0; k < poseidonWideT; k++ {
			st[k] = cols[k][i]
		}
		st = wideRoundStep(st, m)
		for k := 0; k < poseidonWideT; k++ {
			cols[k][i+1] = st[k]
		}
	}
	fillJiveFold(cols, blocks, cmRow)
	return cols
}

// ProveNfMint proves cm = sponge(pk, amount, rho, blind) for the public amount.
func ProveNfMint(pk Node256, amount, rho, blind Felt, cm Node256, bind []byte, nQueries int) (*AIRProof, error) {
	return ProveAIR(nfMintCircuit{amount: amount, cm: cm, bind: bind}, nfMintTrace(pk, amount, rho, blind), nQueries)
}

// VerifyNfMint checks an nf-note mint proof against the public amount + commitment.
func VerifyNfMint(amount Felt, cm Node256, bind []byte, pf *AIRProof, nQueries int) bool {
	return VerifyAIR(nfMintCircuit{amount: amount, cm: cm, bind: bind}, pf, nQueries)
}
