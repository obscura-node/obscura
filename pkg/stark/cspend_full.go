package stark

// SECURITY: NOT FOR CONSENSUS. Superseded spend/mint model (pre-#96, plain serial,
// no recipient-secret nullifier binding). The live path is
// nfmint_air.go / nfspend_air.go / cnfspend_air.go. Do NOT wire this into pkg/chain
// without a full re-audit — it lacks ownership binding.

// Full confidential ZK→ZK spend circuit (Phase C integration, MONOLITH form). One
// proof that:
//   - proves the spent coin leaf_in = WideHash2(WideHash2(N(serial),N(a_in)),N(blind_in))
//     is a MEMBER of the commitment tree at a public `root` (the anchor),
//   - reveals the nullifier `serial` (double-spend guard) but HIDES a_in,
//   - computes a fresh output coin leaf_out = WideHash2(WideHash2(N(serial_out),
//     N(a_out)),N(blind_out)) and reveals only leaf_out (the new commitment), HIDING a_out,
//   - proves value conservation a_in = a_out + fee with only `fee` public, and
//   - range-binds a_in, a_out ∈ [0,2^vbits) (anti-inflation / no field wraparound).
//
// Everything is in-field (Goldilocks) — no ed25519/Pedersen cross-system binding. This
// is the input half (cspend_air.go) extended with an output leaf and the value gadget.
//
// Trace layout (blocks of merkleBlock rows each, blocks = depth+4):
//   block 0          : hash N(serial)‖N(a_in)            → commit_in
//   block 0 inject   : fold blind_in                     → leaf_in
//   blocks 1..depth  : fold path siblings[0..depth-1]    → climb to root
//   block depth+1    : last fold                          → root           (R_root)
//   R_root  RESET    : seed output input N(serial_out)‖N(a_out)
//   block depth+2    : hash N(serial_out)‖N(a_out)        → commit_out
//   block depth+2 inj: fold blind_out                     → (input to last)
//   block depth+3    : hash                                → leaf_out       (last row)
//
// Columns (14 + 2·vbits): s0..s7, sib0..sib3, bit (13, base) | ain (13, constant =a_in)
//   | bits_in[vbits] | bits_out[vbits].
// Periodic (14): rc0..rc7, full, active, inject (11, base) | sel0 | reset | selOut.

type cspendFullCircuit struct {
	depth   int
	serial  Felt    // input nullifier (public)
	root    Node256 // anchor (public)
	leafOut Node256 // new coin commitment (public)
	fee     Felt    // public
	bind    []byte  // tx-binding domain
	vbits   int
}

func (c cspendFullCircuit) Name() string {
	if len(c.bind) == 0 {
		return "cspend-full"
	}
	return "cspend-full:" + bytesHex(c.bind)
}
func (c cspendFullCircuit) Cols() int     { return 18 + 2*c.vbits }               // +4 fold vs old 14
func (cspendFullCircuit) Periodic() int   { return 20 }                           // 11 base+row0+outSel+4 rootVal+sel0+reset+selOut
func (c cspendFullCircuit) blocks() int   { return c.depth + spendPreBlocks + 2 } // +output(2)
func (c cspendFullCircuit) TraceLen() int { return nextPow2(merkleBlock * c.blocks()) }

// rootRowFull: the membership root sits at the end of block depth+1.
func (c cspendFullCircuit) rootRowFull() int { return merkleBlock*(c.depth+spendPreBlocks) - 1 }

// leafOutRow: the final output leaf sits at the very last meaningful row.
func (c cspendFullCircuit) leafOutRow() int { return merkleBlock*c.blocks() - 1 }

// outInputRow: the output leaf-input row (right after the reset).
func (c cspendFullCircuit) outInputRow() int { return c.rootRowFull() + 1 }

const (
	cspfPerRow0   = 11
	cspfPerOutSel = 12
	cspfPerRootV0 = 13 // rootVal columns 13..16
	cspfPerSel0   = 17
	cspfPerReset  = 18
	cspfPerSelOut = 19
)

func (c cspendFullCircuit) PeriodicCol(j int) []Felt {
	col := make([]Felt, c.TraceLen())
	switch {
	case j == cspfPerRow0: // block-0 init
		col[0] = 1
		return col
	case j == cspfPerOutSel: // Jive output rows (root and leafOut)
		col[c.rootRowFull()] = 1
		col[c.leafOutRow()] = 1
		return col
	case j >= cspfPerRootV0 && j <= cspfPerRootV0+3: // rootVal: root @ rootRow, leafOut @ leafOutRow
		k := j - cspfPerRootV0
		col[c.rootRowFull()] = c.root[k]
		col[c.leafOutRow()] = c.leafOut[k]
		return col
	case j == cspfPerSel0: // sel0: the input leaf row (row 0)
		col[0] = 1
		return col
	case j == cspfPerReset: // reset: the membership-root row (seed the output input next)
		col[c.rootRowFull()] = 1
		return col
	case j == cspfPerSelOut: // selOut: the output leaf-input row
		col[c.outInputRow()] = 1
		return col
	}
	// base spend schedule over all blocks, EXCEPT no membership injection at R_root.
	rRoot := c.rootRowFull()
	for row := 0; row < c.leafOutRow(); row++ {
		m := row % merkleBlock
		if m == merkleBlock-1 { // injection row
			if j == 10 && row != rRoot { // inject everywhere except the reset row
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
			col[row] = 1 // active
		}
	}
	return col
}

func (c cspendFullCircuit) Boundaries() []Boundary {
	// serial public (nullifier), zero capacity inputs, NO amount pin (hidden).
	b := []Boundary{{Col: 0, Row: 0, Val: c.serial}}
	for _, col := range []int{1, 2, 3, 5, 6, 7} {
		b = append(b, Boundary{Col: col, Row: 0, Val: 0})
	}
	// public anchor root + new-coin commitment leafOut are bound to their Jive outputs via
	// periodic columns (outSel + rootVal), so no boundary is needed for them.
	return b
}

func cspendFullConstraints[T any](e cenv[T], vbits int, fee Felt, cur, next, per []T) []T {
	out := wideMerkleConstraints[T](e, cur[:13], next[:13], per[:11], cur[13:17], next[13:17], per[cspfPerRow0])
	// Jive output binding for both public outputs (root @ rootRow, leafOut @ leafOutRow); the
	// periodic rootVal columns carry the correct public value at each output row.
	out = append(out, jiveRootBind[T](e, cur[:8], cur[13:17], per[cspfPerRootV0:cspfPerRootV0+4], per[cspfPerOutSel])...)
	sel0, reset, selOut := per[cspfPerSel0], per[cspfPerReset], per[cspfPerSelOut]
	// reseed the Jive fold at the reset row (output block spliced by a reset, not inject).
	out = append(out, jiveReseed[T](e, next[:8], next[13:17], reset)...)
	one := e.Const(1)
	ain := cur[17]
	// ain is a constant column carrying the hidden a_in across rows (ungated ⇒ enforced
	// on every transition row, so ain is constant over the whole trace).
	out = append(out, e.Sub(next[17], ain))
	// reset row: the seeded output input must be N(serial_out)‖N(a_out) =
	// [serial_out,0,0,0, a_out,0,0,0]. serial_out (next[0]) and a_out (next[4]) are free
	// witnesses; force the six zero slots so leaf_out commits exactly to (serial_out,a_out).
	for _, k := range []int{1, 2, 3, 5, 6, 7} {
		out = append(out, e.Mul(reset, next[k]))
	}
	// link ain = a_in at the input row (a_in = s4 = cur[4]).
	out = append(out, e.Mul(sel0, e.Sub(ain, cur[4])))
	// range-bind a_in at row 0: a_in = Σ bits_in·2ⁱ, each boolean.
	sumIn := e.Const(0)
	pow := Felt(1)
	for i := 0; i < vbits; i++ {
		bc := cur[18+i]
		sumIn = e.Add(sumIn, e.Mul(e.Const(pow), bc))
		out = append(out, e.Mul(sel0, e.Mul(bc, e.Sub(bc, one))))
		pow = pow.Mul(Felt(2))
	}
	out = append(out, e.Mul(sel0, e.Sub(cur[4], sumIn)))
	// range-bind a_out at the output-input row: a_out = Σ bits_out·2ⁱ, each boolean.
	sumOut := e.Const(0)
	pow = Felt(1)
	for i := 0; i < vbits; i++ {
		bc := cur[18+vbits+i]
		sumOut = e.Add(sumOut, e.Mul(e.Const(pow), bc))
		out = append(out, e.Mul(selOut, e.Mul(bc, e.Sub(bc, one))))
		pow = pow.Mul(Felt(2))
	}
	out = append(out, e.Mul(selOut, e.Sub(cur[4], sumOut)))
	// value conservation at the output-input row: a_in = a_out + fee  (a_out = cur[4]).
	out = append(out, e.Mul(selOut, e.Sub(e.Sub(ain, cur[4]), e.Const(fee))))
	return out
}

func (c cspendFullCircuit) ConstraintsFelt(cur, next, per []Felt) []Felt {
	return cspendFullConstraints[Felt](feltEnv{}, c.vbits, c.fee, cur, next, per)
}

func (c cspendFullCircuit) ConstraintsExt(cur, next, per []Felt2) []Felt2 {
	return cspendFullConstraints[Felt2](felt2Env{}, c.vbits, c.fee, cur, next, per)
}
func (c cspendFullCircuit) ConstraintsPoly(cur, next, per []Poly) []Poly {
	return cspendFullConstraints[Poly](polyEnv{}, c.vbits, c.fee, cur, next, per)
}

// cspendFullTrace builds a constraint-satisfying confidential-spend trace.
func cspendFullTrace(serial, aIn, blindIn Felt, path MerklePath256, depth int,
	serialOut, aOut, blindOut Felt, vbits int) [][]Felt {
	blocks := depth + spendPreBlocks + 2
	T := nextPow2(merkleBlock * blocks)
	rRoot := merkleBlock*(depth+spendPreBlocks) - 1
	leafRow := merkleBlock*blocks - 1
	ncol := 18 + 2*vbits
	cols := make([][]Felt, ncol)
	for i := range cols {
		cols[i] = make([]Felt, T)
	}
	// block-0 input = N(serial)‖N(a_in).
	cols[0][0] = serial
	cols[4][0] = aIn
	for i := 0; i < leafRow; i++ {
		m := i % merkleBlock
		if i == rRoot { // RESET: seed the output leaf input at i+1
			cols[0][i+1] = serialOut
			cols[4][i+1] = aOut
			continue
		}
		if m == merkleBlock-1 { // injection
			b := i / merkleBlock
			parent := jiveParentAt(cols, i)
			var bit Felt
			var sib Node256
			switch {
			case b == 0:
				bit, sib = 0, Node256{blindIn, 0, 0, 0}
			case b >= 1 && b <= depth:
				lvl := b - 1
				if (path.Index>>uint(lvl))&1 == 1 {
					bit = 1
				}
				sib = path.Siblings[lvl]
			case b == depth+spendPreBlocks: // output block: fold blind_out
				bit, sib = 0, Node256{blindOut, 0, 0, 0}
			}
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
			continue
		}
		// round r=m
		var st [poseidonWideT]Felt
		for k := 0; k < poseidonWideT; k++ {
			st[k] = cols[k][i]
		}
		st = wideRoundStep(st, m)
		for k := 0; k < poseidonWideT; k++ {
			cols[k][i+1] = st[k]
		}
	}
	// ain constant column = a_in.
	for i := 0; i < T; i++ {
		cols[17][i] = aIn
	}
	// range bits: a_in's bits at row 0, a_out's bits at the output-input row.
	vi := uint64(aIn)
	vo := uint64(aOut)
	outRow := rRoot + 1
	for i := 0; i < vbits; i++ {
		cols[18+i][0] = Felt(vi & 1)
		cols[18+vbits+i][outRow] = Felt(vo & 1)
		vi >>= 1
		vo >>= 1
	}
	fillJiveFold(cols, blocks, leafRow)
	return cols
}

// ProveCSpendFull proves a full confidential ZK→ZK spend. Reveals only serial
// (nullifier), root (anchor), leafOut (new commitment) and fee; a_in and a_out hidden.
func ProveCSpendFull(serial, aIn, blindIn Felt, path MerklePath256, depth int,
	root Node256, serialOut, aOut, blindOut Felt, leafOut Node256, fee Felt,
	bind []byte, vbits, nQueries int) (*AIRProof, error) {
	if vbits <= 0 || vbits > MaxRangeBits {
		panic("stark: cspend vbits must be in (0, MaxRangeBits]")
	}
	c := cspendFullCircuit{depth: depth, serial: serial, root: root, leafOut: leafOut,
		fee: fee, bind: bind, vbits: vbits}
	tr := cspendFullTrace(serial, aIn, blindIn, path, depth, serialOut, aOut, blindOut, vbits)
	return ProveAIR(c, tr, nQueries)
}

// VerifyCSpendFull checks a full confidential-spend proof.
func VerifyCSpendFull(serial Felt, root, leafOut Node256, fee Felt, bind []byte,
	depth, vbits int, pf *AIRProof, nQueries int) bool {
	c := cspendFullCircuit{depth: depth, serial: serial, root: root, leafOut: leafOut,
		fee: fee, bind: bind, vbits: vbits}
	return VerifyAIR(c, pf, nQueries)
}
