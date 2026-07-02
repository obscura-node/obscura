package stark

// CONFIDENTIAL + UNLINKABLE spend circuit — the endgame spend (#96 ⊕ #102 merged). ONE
// zk-STARK that is BOTH:
//   - confidential (cspend_full.go): hidden a_in, a_out; value-conserved a_in=a_out+fee;
//     both range-bound; reveals only the fee.
//   - sender↔spend unlinkable (nfspend_air.go): the input note uses a recipient-secret
//     nullifier nf=H(nk,rho) the sender cannot compute; the output note is paid to a
//     recipient ADDRESS pk_out the sender knows but whose nullifier it cannot derive.
//
// It proves, revealing only {nf, root, cm_out, fee} and hiding everything else:
//   INPUT  : pk_in = H(nk_in,0); cm_in = sponge(pk_in,a_in,rho_in,blind_in) ∈ tree(root);
//            nf = H(nk_in,rho_in).                         (authority + membership + nullifier)
//   OUTPUT : cm_out = sponge(pk_out,a_out,rho_out,blind_out).         (note paid to pk_out)
//   VALUE  : a_in = a_out + fee; a_in,a_out ∈ [0,2^vbits).            (conservation + range)
//
// Block schedule (blocks = depth+8; H = WideHash2):
//   0      pk_in = H([nk_in,0..])
//   0 inj  fold a_in   → 1: h1_in=H(pk_in,N(a_in))
//   1 inj  fold rho_in → 2: h2_in=H(h1_in,N(rho_in))
//   2 inj  fold blind_in→ 3: cm_in=H(h2_in,N(blind_in))
//   3..d+2 fold path siblings (membership)               → root @ rootRow (block d+3 end)
//   RESET-A @rootRow  seed nf input [nk_in,0,0,0,rho_in,0,0,0]
//   d+4    nf = H(nk_in,rho_in)                            → nf   @ nfRow (block d+4 end)
//   RESET-B @nfRow    seed output input [pk_out, a_out,0,0,0]
//   d+5    h1_out=H(pk_out,N(a_out))
//   d+5 inj fold rho_out → d+6: h2_out
//   d+6 inj fold blind_out→ d+7: cm_out                   → cm_out @ cmOutRow (last row)
//
// Columns (16+2·vbits): s0..s7,sib0..sib3,bit (13) | nkCol | rhoInCol | ainCol |
//   a_in bits[vbits] | a_out bits[vbits].
// Periodic (17): rc0..7,full,active,inject (11) | sel0 | selAmtIn | selRhoIn | resetA |
//   resetB | selOut.

type cnfSpendCircuit struct {
	depth int
	nf    Node256 // public nullifier
	root  Node256 // public anchor
	cmOut Node256 // public output commitment
	fee   Felt    // public
	bind  []byte
	vbits int
}

func (c cnfSpendCircuit) Name() string {
	if len(c.bind) == 0 {
		return "cnf-spend"
	}
	return "cnf-spend:" + bytesHex(c.bind)
}
func (c cnfSpendCircuit) Cols() int     { return 20 + 2*c.vbits } // +4 fold vs old 16
func (cnfSpendCircuit) Periodic() int   { return 23 }             // +6 (row0,outSel,4 rootVal) vs old 17
func (c cnfSpendCircuit) blocks() int   { return c.depth + 8 }
func (c cnfSpendCircuit) TraceLen() int { return nextPow2(merkleBlock * c.blocks()) }

func (c cnfSpendCircuit) rootRow() int     { return merkleBlock*(c.depth+4) - 1 }
func (c cnfSpendCircuit) nfRow() int       { return merkleBlock*(c.depth+5) - 1 }
func (c cnfSpendCircuit) outInputRow() int { return c.nfRow() + 1 }
func (c cnfSpendCircuit) cmOutRow() int    { return merkleBlock*c.blocks() - 1 }

const (
	cnfPerRow0     = 11
	cnfPerOutSel   = 12
	cnfPerRootV0   = 13 // rootVal columns 13..16
	cnfPerSel0     = 17
	cnfPerSelAmtIn = 18
	cnfPerSelRhoIn = 19
	cnfPerResetA   = 20
	cnfPerResetB   = 21
	cnfPerSelOut   = 22
)

func (c cnfSpendCircuit) PeriodicCol(j int) []Felt {
	col := make([]Felt, c.TraceLen())
	switch {
	case j == cnfPerRow0:
		col[0] = 1
		return col
	case j == cnfPerOutSel: // Jive output rows (root, nf, cm_out)
		col[c.rootRow()] = 1
		col[c.nfRow()] = 1
		col[c.cmOutRow()] = 1
		return col
	case j >= cnfPerRootV0 && j <= cnfPerRootV0+3: // rootVal: root @ rootRow, nf @ nfRow, cm_out @ cmOutRow
		k := j - cnfPerRootV0
		col[c.rootRow()] = c.root[k]
		col[c.nfRow()] = c.nf[k]
		col[c.cmOutRow()] = c.cmOut[k]
		return col
	case j == cnfPerSel0:
		col[0] = 1
		return col
	case j == cnfPerSelAmtIn:
		col[merkleBlock-1] = 1 // block-0 injection (folds a_in)
		return col
	case j == cnfPerSelRhoIn:
		col[merkleBlock*2-1] = 1 // block-1 injection (folds rho_in)
		return col
	case j == cnfPerResetA:
		col[c.rootRow()] = 1
		return col
	case j == cnfPerResetB:
		col[c.nfRow()] = 1
		return col
	case j == cnfPerSelOut:
		col[c.outInputRow()] = 1
		return col
	}
	// base schedule over all blocks, EXCEPT no injection at rootRow / nfRow (resets there).
	rRoot, rNf := c.rootRow(), c.nfRow()
	for row := 0; row < c.cmOutRow(); row++ {
		m := row % merkleBlock
		if m == merkleBlock-1 {
			if j == 10 && row != rRoot && row != rNf {
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

func (c cnfSpendCircuit) Boundaries() []Boundary {
	b := []Boundary{}
	// pk_in input row: [nk_in,0,0,0,0,0,0,0] — nk_in (col 0) hidden, rest zero.
	for _, col := range []int{1, 2, 3, 4, 5, 6, 7} {
		b = append(b, Boundary{Col: col, Row: 0, Val: 0})
	}
	// note folds: sib = N(field) = [field,0,0,0], bit = 0; field (col 8) stays hidden.
	// Pin the upper sib cells + bit to 0 so each note node is explicitly canonical.
	noteFolds := []int{
		merkleBlock - 1,             // a_in   (block 0)
		merkleBlock*2 - 1,           // rho_in (block 1)
		merkleBlock*3 - 1,           // blind_in (block 2)
		merkleBlock*(c.depth+6) - 1, // rho_out (block d+5)
		merkleBlock*(c.depth+7) - 1, // blind_out (block d+6)
	}
	for _, row := range noteFolds {
		for _, col := range []int{9, 10, 11, 12} {
			b = append(b, Boundary{Col: col, Row: row, Val: 0})
		}
	}
	// public anchor root, nullifier nf, output commitment cm_out are bound to their Jive
	// outputs via periodic columns (outSel + rootVal) — no boundary needed.
	return b
}

func cnfSpendConstraints[T any](e cenv[T], vbits int, fee Felt, cur, next, per []T) []T {
	out := wideMerkleConstraints[T](e, cur[:13], next[:13], per[:11], cur[13:17], next[13:17], per[cnfPerRow0])
	// Jive output binding for the three public outputs (root @ rootRow, nf @ nfRow,
	// cm_out @ cmOutRow); the periodic rootVal columns carry each public value at its row.
	out = append(out, jiveRootBind[T](e, cur[:8], cur[13:17], per[cnfPerRootV0:cnfPerRootV0+4], per[cnfPerOutSel])...)
	sel0, selAmtIn, selRhoIn := per[cnfPerSel0], per[cnfPerSelAmtIn], per[cnfPerSelRhoIn]
	resetA, resetB, selOut := per[cnfPerResetA], per[cnfPerResetB], per[cnfPerSelOut]
	// reseed the Jive fold at BOTH reset rows (nf block and output block are spliced by
	// resets, not injections, so the inject-reseed does not fire there).
	out = append(out, jiveReseed[T](e, next[:8], next[13:17], resetA)...)
	out = append(out, jiveReseed[T](e, next[:8], next[13:17], resetB)...)
	one := e.Const(1)
	nkCol, rhoInCol, ainCol := cur[17], cur[18], cur[19]
	// constant carries (ungated ⇒ constant over the whole trace).
	out = append(out, e.Sub(next[17], nkCol))
	out = append(out, e.Sub(next[18], rhoInCol))
	out = append(out, e.Sub(next[19], ainCol))
	// link the secrets: nk_in at the pk-input cell; rho_in at its fold sibling; a_in at
	// its fold sibling (so the SAME values drive the note, the nullifier and the balance).
	out = append(out, e.Mul(sel0, e.Sub(nkCol, cur[0])))
	out = append(out, e.Mul(selRhoIn, e.Sub(rhoInCol, cur[8])))
	out = append(out, e.Mul(selAmtIn, e.Sub(ainCol, cur[8])))
	// range-bind a_in at its fold row: a_in (= cur[8]) = Σ bitᵢ·2ⁱ, each boolean.
	sumIn := e.Const(0)
	pow := Felt(1)
	for i := 0; i < vbits; i++ {
		bc := cur[20+i]
		sumIn = e.Add(sumIn, e.Mul(e.Const(pow), bc))
		out = append(out, e.Mul(selAmtIn, e.Mul(bc, e.Sub(bc, one))))
		pow = pow.Mul(Felt(2))
	}
	out = append(out, e.Mul(selAmtIn, e.Sub(cur[8], sumIn)))
	// RESET-A: seed nf input [nk,0,0,0, rho,0,0,0].
	out = append(out, e.Mul(resetA, e.Sub(next[0], nkCol)))
	out = append(out, e.Mul(resetA, e.Sub(next[4], rhoInCol)))
	for _, k := range []int{1, 2, 3, 5, 6, 7} {
		out = append(out, e.Mul(resetA, next[k]))
	}
	// RESET-B: seed output input [pk_out(0..3), a_out, 0,0,0]. pk_out (next[0..3]) and
	// a_out (next[4]) are free witnesses; force the three zero slots.
	for _, k := range []int{5, 6, 7} {
		out = append(out, e.Mul(resetB, next[k]))
	}
	// range-bind a_out at the output-input row: a_out (= cur[4]) = Σ bitᵢ·2ⁱ, boolean.
	sumOut := e.Const(0)
	pow = Felt(1)
	for i := 0; i < vbits; i++ {
		bc := cur[20+vbits+i]
		sumOut = e.Add(sumOut, e.Mul(e.Const(pow), bc))
		out = append(out, e.Mul(selOut, e.Mul(bc, e.Sub(bc, one))))
		pow = pow.Mul(Felt(2))
	}
	out = append(out, e.Mul(selOut, e.Sub(cur[4], sumOut)))
	// value conservation at the output-input row: a_in = a_out + fee (a_in = ainCol carry).
	out = append(out, e.Mul(selOut, e.Sub(e.Sub(ainCol, cur[4]), e.Const(fee))))
	return out
}

func (c cnfSpendCircuit) ConstraintsFelt(cur, next, per []Felt) []Felt {
	return cnfSpendConstraints[Felt](feltEnv{}, c.vbits, c.fee, cur, next, per)
}

func (c cnfSpendCircuit) ConstraintsExt(cur, next, per []Felt2) []Felt2 {
	return cnfSpendConstraints[Felt2](felt2Env{}, c.vbits, c.fee, cur, next, per)
}
func (c cnfSpendCircuit) ConstraintsPoly(cur, next, per []Poly) []Poly {
	return cnfSpendConstraints[Poly](polyEnv{}, c.vbits, c.fee, cur, next, per)
}

// cnfSpendTrace builds a constraint-satisfying confidential+unlinkable spend trace.
func cnfSpendTrace(nkIn, aIn, rhoIn, blindIn Felt, path MerklePath256, depth int,
	pkOut Node256, aOut, rhoOut, blindOut Felt, vbits int) [][]Felt {
	blocks := depth + 8
	T := nextPow2(merkleBlock * blocks)
	rRoot := merkleBlock*(depth+4) - 1
	rNf := merkleBlock*(depth+5) - 1
	cmOutRow := merkleBlock*blocks - 1
	ncol := 20 + 2*vbits
	cols := make([][]Felt, ncol)
	for i := range cols {
		cols[i] = make([]Felt, T)
	}
	cols[0][0] = nkIn // block-0 input [nk_in,0,...]
	fold := func(i int, sib Node256, bit Felt) {
		parent := jiveParentAt(cols, i)
		for k := 0; k < 4; k++ {
			cols[8+k][i] = sib[k]
		}
		cols[12][i] = bit
		var in0, in1 Node256
		if bit == 0 {
			in0, in1 = parent, sib
		} else {
			in0, in1 = sib, parent
		}
		for k := 0; k < 4; k++ {
			cols[k][i+1] = in0[k]
			cols[4+k][i+1] = in1[k]
		}
	}
	for i := 0; i < cmOutRow; i++ {
		m := i % merkleBlock
		switch {
		case i == rRoot: // RESET-A: seed nf input
			cols[0][i+1] = nkIn
			cols[4][i+1] = rhoIn
			continue
		case i == rNf: // RESET-B: seed output input [pk_out, a_out,0,0,0]
			for k := 0; k < 4; k++ {
				cols[k][i+1] = pkOut[k]
			}
			cols[4][i+1] = aOut
			continue
		}
		if m == merkleBlock-1 { // injection
			b := i / merkleBlock
			switch {
			case b == 0:
				fold(i, Node256FromFelts(aIn), 0)
			case b == 1:
				fold(i, Node256FromFelts(rhoIn), 0)
			case b == 2:
				fold(i, Node256FromFelts(blindIn), 0)
			case b >= 3 && b <= depth+2: // membership level b-3
				lvl := b - 3
				var bit Felt
				if (path.Index>>uint(lvl))&1 == 1 {
					bit = 1
				}
				fold(i, path.Siblings[lvl], bit)
			case b == depth+5:
				fold(i, Node256FromFelts(rhoOut), 0)
			case b == depth+6:
				fold(i, Node256FromFelts(blindOut), 0)
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
	// constant carries.
	for i := 0; i < T; i++ {
		cols[17][i] = nkIn
		cols[18][i] = rhoIn
		cols[19][i] = aIn
	}
	// range bits: a_in at its fold row, a_out at the output-input row.
	vi, vo := uint64(aIn), uint64(aOut)
	for i := 0; i < vbits; i++ {
		cols[20+i][merkleBlock-1] = Felt(vi & 1)
		cols[20+vbits+i][rNf+1] = Felt(vo & 1)
		vi >>= 1
		vo >>= 1
	}
	fillJiveFold(cols, blocks, cmOutRow)
	return cols
}

// ProveCnfSpend proves a confidential + unlinkable spend. Reveals only nf, root, cm_out,
// fee; hides both amounts AND the sender↔spend link.
func ProveCnfSpend(nkIn, aIn, rhoIn, blindIn Felt, path MerklePath256, depth int,
	root Node256, pkOut Node256, aOut, rhoOut, blindOut Felt, nf, cmOut Node256, fee Felt,
	bind []byte, vbits, nQueries int) (*AIRProof, error) {
	if vbits <= 0 || vbits > MaxRangeBits {
		panic("stark: cnf vbits must be in (0, MaxRangeBits]")
	}
	c := cnfSpendCircuit{depth: depth, nf: nf, root: root, cmOut: cmOut, fee: fee, bind: bind, vbits: vbits}
	tr := cnfSpendTrace(nkIn, aIn, rhoIn, blindIn, path, depth, pkOut, aOut, rhoOut, blindOut, vbits)
	return ProveAIR(c, tr, nQueries)
}

// VerifyCnfSpend checks a confidential + unlinkable spend proof.
func VerifyCnfSpend(nf, root, cmOut Node256, fee Felt, bind []byte, depth, vbits int, pf *AIRProof, nQueries int) bool {
	c := cnfSpendCircuit{depth: depth, nf: nf, root: root, cmOut: cmOut, fee: fee, bind: bind, vbits: vbits}
	return VerifyAIR(c, pf, nQueries)
}
