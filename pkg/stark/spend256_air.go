package stark

// SECURITY: NOT FOR CONSENSUS. Superseded spend/mint model (pre-#96, plain serial,
// no recipient-secret nullifier binding). The live path is
// nfmint_air.go / nfspend_air.go / cnfspend_air.go. Do NOT wire this into pkg/chain
// without a full re-audit — it lacks ownership binding.

// Width-8 anonymous spend circuit — the collision-fixed (256-bit-node) version of
// spend_air.go. Same construction, widened: the Poseidon state is 8 columns, tree
// nodes are 4 elements, and each compression is one width-8 permutation block whose
// output is truncated to 4 elements (WideHash2). The leaf is
// L = WideHash2( WideHash2(serialNode, amountNode), blindNode ), proven a member of
// the wide commitment tree against a public 4-element root, revealing serial + amount.
//
// Columns (13): s0..s7 (state), sib0..sib3 (sibling node), bit.
// Periodic (11): rc0..rc7, fullSel, active, inject.

// wideMerkleConstraints is the width-8 round + injection + booleanity + JIVE-fold
// constraint set. cur/next are the 13 base columns (s0..s7, sib0..sib3, bit) and per is
// the 11 base periodic columns (rc0..7, full, active, inject). curF/nextF are the 4
// Jive-fold columns f0..f3 carrying fld[i]=x[i]+x[i+4] (x = the current Merkle block's
// INPUT state, row-0 of the block); row0 is the periodic selector that is 1 ONLY at the
// very first trace row (block-0 init).
//
// The compression is Jive_2: the parent (compression output) folded into the next block
// is parent[i] = fld[i] + y[i] + y[4+i] (y = perm(x) = cur[0:8] at the inject row), which
// matches JiveCompress exactly. This replaces the old truncation parent = cur[0:4]
// (an invertible permutation → forgeable membership paths).
func wideMerkleConstraints[T any](e cenv[T], cur, next, per, curF, nextF []T, row0 T) []T {
	full, active, inject := per[8], per[9], per[10]
	one := e.Const(1)
	sb := func(x T) T {
		x2 := e.Mul(x, x)
		x4 := e.Mul(x2, x2)
		return e.Mul(e.Mul(x4, x2), x)
	}
	t := make([]T, poseidonWideT)
	for i := 0; i < poseidonWideT; i++ {
		t[i] = e.Add(cur[i], per[i])
	}
	s := make([]T, poseidonWideT)
	s[0] = sb(t[0])
	for i := 1; i < poseidonWideT; i++ {
		s[i] = e.Add(e.Mul(full, sb(t[i])), e.Mul(e.Sub(one, full), t[i]))
	}
	mix := make([]T, poseidonWideT)
	for i := 0; i < poseidonWideT; i++ {
		acc := e.Const(0)
		for j := 0; j < poseidonWideT; j++ {
			acc = e.Add(acc, e.Mul(e.Const(poseidonWideMDS[i][j]), s[j]))
		}
		mix[i] = acc
	}
	out := make([]T, 0, 4*poseidonWideT)
	// Round constraints (8), gated by active.
	for i := 0; i < poseidonWideT; i++ {
		out = append(out, e.Mul(active, e.Sub(next[i], mix[i])))
	}
	// Injection: parent = JIVE output = curF[i] + cur[i] + cur[4+i]; sib = cur[8:12],
	// bit = cur[12]. bit=0 ⇒ next = parent‖sib; bit=1 ⇒ sib‖parent.
	bit := cur[12]
	for i := 0; i < 4; i++ {
		parent := e.Add(curF[i], e.Add(cur[i], cur[4+i]))
		sib := cur[8+i]
		in0 := e.Add(e.Mul(e.Sub(one, bit), parent), e.Mul(bit, sib))
		in1 := e.Add(e.Mul(bit, parent), e.Mul(e.Sub(one, bit), sib))
		out = append(out, e.Mul(inject, e.Sub(next[i], in0)))
		out = append(out, e.Mul(inject, e.Sub(next[4+i], in1)))
	}
	// Booleanity of the path bit at injection rows.
	out = append(out, e.Mul(inject, e.Mul(bit, e.Sub(bit, one))))
	// JIVE fold carry/reseed/init:
	//  (1) carry on round rows: active*(nextF[i] - curF[i]) == 0.
	//  (2) reseed at injection: inject*(nextF[i] - (next[i]+next[4+i])) == 0.
	//  (3) block-0 init: row0*(curF[i] - (cur[i]+cur[4+i])) == 0.
	for i := 0; i < 4; i++ {
		out = append(out, e.Mul(active, e.Sub(nextF[i], curF[i])))
		out = append(out, e.Mul(inject, e.Sub(nextF[i], e.Add(next[i], next[4+i]))))
		out = append(out, e.Mul(row0, e.Sub(curF[i], e.Add(cur[i], cur[4+i]))))
	}
	return out
}

// jiveReseed reseeds the 4 Jive-fold columns at a RESET row (where the next block's input
// is seeded by a reset, not by an injection). At the selected row it forces
// nextF[i] = next[i] + next[4+i] — the same reseed the inject path does — so the fold
// columns stay bound through circuits that splice fresh blocks via resets
// (nfspend / cnfspend / cspend_full). sel is the reset selector (1 only at that row).
func jiveReseed[T any](e cenv[T], next, nextF []T, sel T) []T {
	out := make([]T, 0, 4)
	for i := 0; i < 4; i++ {
		out = append(out, e.Mul(sel, e.Sub(nextF[i], e.Add(next[i], next[4+i]))))
	}
	return out
}

// jiveRootBind binds the PUBLIC compression outputs (root / leaf / cm / nf …) to their
// Jive values WITHOUT any extra trace column (proof-size neutral). rootVal are 4 PERIODIC
// columns that carry the public output value at each output row (and 0 elsewhere); outSel
// is a PERIODIC selector that is 1 at every output row. At each output row the constraint
// forces the Jive output curF[i]+cur[i]+cur[4+i] to equal the public value rootVal[i].
// Periodic columns are verifier-reconstructed from the circuit's public outputs (never
// committed/opened), so the binding is sound and adds zero bytes to the proof.
func jiveRootBind[T any](e cenv[T], cur, curF, rootVal []T, outSel T) []T {
	out := make([]T, 0, 4)
	for i := 0; i < 4; i++ {
		jive := e.Add(curF[i], e.Add(cur[i], cur[4+i]))
		out = append(out, e.Mul(outSel, e.Sub(jive, rootVal[i])))
	}
	return out
}

type spend256Circuit struct {
	depth  int
	serial Felt
	amount Felt
	root   Node256
	bind   []byte // full tx-binding domain (e.g. the 32-byte tx CoreHash)
}

func (c spend256Circuit) Name() string {
	if len(c.bind) == 0 {
		return "anon-spend-256"
	}
	return "anon-spend-256:" + bytesHex(c.bind)
}

// bytesHex renders bytes as lowercase hex (transcript domain separator).
func bytesHex(b []byte) string {
	const hexdig = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdig[c>>4]
		out[i*2+1] = hexdig[c&0xf]
	}
	return string(out)
}
func (spend256Circuit) Cols() int       { return 17 } // 13 base + 4 fold
func (spend256Circuit) Periodic() int   { return 17 } // 11 base + row0 + outSel + 4 rootVal
func (c spend256Circuit) blocks() int   { return c.depth + spendPreBlocks }
func (c spend256Circuit) TraceLen() int { return nextPow2(merkleBlock * c.blocks()) }
func (c spend256Circuit) rootRow() int  { return merkleBlock*c.blocks() - 1 }

func (c spend256Circuit) PeriodicCol(j int) []Felt {
	col := make([]Felt, c.TraceLen())
	if j == 11 { // row0: block-0 init
		col[0] = 1
		return col
	}
	if j == 12 { // outSel: the Jive root-output row
		col[c.rootRow()] = 1
		return col
	}
	if j >= 13 && j <= 16 { // rootVal: public root at the output row
		col[c.rootRow()] = c.root[j-13]
		return col
	}
	for row := 0; row < c.rootRow(); row++ {
		m := row % merkleBlock
		if m == merkleBlock-1 { // injection
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
			col[row] = 1 // active
		}
	}
	return col
}

func (c spend256Circuit) Boundaries() []Boundary {
	b := []Boundary{
		{Col: 0, Row: 0, Val: c.serial}, // leaf-input s0 = serial
		{Col: 4, Row: 0, Val: c.amount}, // leaf-input s4 = amount
	}
	// the other 6 input slots are 0 (serialNode/amountNode upper elements)
	for _, col := range []int{1, 2, 3, 5, 6, 7} {
		b = append(b, Boundary{Col: col, Row: 0, Val: 0})
	}
	// the public root is bound to the Jive output via periodic columns (outSel + rootVal),
	// so no boundary is needed for it.
	return b
}

func (spend256Circuit) ConstraintsFelt(cur, next, per []Felt) []Felt {
	out := wideMerkleConstraints[Felt](feltEnv{}, cur[:13], next[:13], per[:11], cur[13:17], next[13:17], per[11])
	return append(out, jiveRootBind[Felt](feltEnv{}, cur[:8], cur[13:17], per[13:17], per[12])...)
}

func (spend256Circuit) ConstraintsExt(cur, next, per []Felt2) []Felt2 {
	out := wideMerkleConstraints[Felt2](felt2Env{}, cur[:13], next[:13], per[:11], cur[13:17], next[13:17], per[11])
	return append(out, jiveRootBind[Felt2](felt2Env{}, cur[:8], cur[13:17], per[13:17], per[12])...)
}
func (spend256Circuit) ConstraintsPoly(cur, next, per []Poly) []Poly {
	out := wideMerkleConstraints[Poly](polyEnv{}, cur[:13], next[:13], per[:11], cur[13:17], next[13:17], per[11])
	return append(out, jiveRootBind[Poly](polyEnv{}, cur[:8], cur[13:17], per[13:17], per[12])...)
}

// spend256Trace builds a constraint-satisfying wide spend trace.
func spend256Trace(serial, amount, blind Felt, path MerklePath256, depth int) [][]Felt {
	blocks := depth + spendPreBlocks
	T := nextPow2(merkleBlock * blocks)
	cols := make([][]Felt, 17)
	for i := range cols {
		cols[i] = make([]Felt, T)
	}
	// block-0 input = serialNode ‖ amountNode = [serial,0,0,0, amount,0,0,0]
	cols[0][0] = serial
	cols[4][0] = amount
	last := merkleBlock*blocks - 1
	for i := 0; i < last; i++ {
		m := i % merkleBlock
		if m == merkleBlock-1 { // injection
			blk := i / merkleBlock
			parent := jiveParentAt(cols, i)
			var bit Felt
			var sib Node256
			if blk == 0 {
				bit, sib = 0, Node256{blind, 0, 0, 0}
			} else {
				lvl := blk - 1
				if (path.Index>>uint(lvl))&1 == 1 {
					bit = 1
				}
				sib = path.Siblings[lvl]
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
	fillJiveFold(cols, blocks, merkleBlock*blocks-1)
	return cols
}

// jiveParentAt computes the Jive compression output (the parent folded into the tree) at
// an injection row i of a 31-row block: parent[k] = (x[k]+x[k+4]) + y[k] + y[k+4], where
// x = the block-input state (row i-(merkleBlock-1)) and y = cols[0:8][i] = perm(x). The
// trace builders MUST use this (not the truncation cols[0:4][i]) so the spliced next-block
// input matches the in-circuit Jive injection constraint.
func jiveParentAt(cols [][]Felt, i int) Node256 {
	in := i - (merkleBlock - 1)
	var p Node256
	for k := 0; k < 4; k++ {
		fld := cols[k][in].Add(cols[4+k][in])
		p[k] = fld.Add(cols[k][i]).Add(cols[4+k][i])
	}
	return p
}

// fillJiveFold populates the 4 Jive-fold columns (cols[13..16]) for a width-8 Merkle/
// sponge trace. The fold columns carry, constant over each 31-row block, that block's
// input fold fld[i]=x[i]+x[i+4] (x = the block-input state at row 31·b). The public Jive
// outputs are bound via periodic columns (no trace column), so there is nothing else to
// fill here.
//
// realRows is the number of populated trace rows (rows ≥ realRows are padding); blocks is
// the block count. Every block b's input row is 31·b for b in [0,blocks).
func fillJiveFold(cols [][]Felt, blocks, realRows int) {
	for b := 0; b < blocks; b++ {
		in := b * merkleBlock
		var fld [4]Felt
		for i := 0; i < 4; i++ {
			fld[i] = cols[0+i][in].Add(cols[4+i][in])
		}
		end := in + merkleBlock // rows [in, end) share this block's fold
		if end > realRows+1 {
			end = realRows + 1
		}
		for row := in; row < end && row < len(cols[0]); row++ {
			for i := 0; i < 4; i++ {
				cols[13+i][row] = fld[i]
			}
		}
	}
}

// SpendLeaf256 = WideHash2(WideHash2(N(serial),N(amount)), N(blind)).
func SpendLeaf256(serial, amount, blind Felt) Node256 {
	commit := WideHash2(Node256FromFelts(serial), Node256FromFelts(amount))
	return WideHash2(commit, Node256FromFelts(blind))
}

// ProveSpend256 proves Hash2(Hash2(serial,amount),blind) ∈ tree(root), revealing
// serial+amount, bound to bind.
func ProveSpend256(serial, amount, blind Felt, path MerklePath256, depth int, root Node256, bind []byte, nQueries int) (*AIRProof, error) {
	c := spend256Circuit{depth: depth, serial: serial, amount: amount, root: root, bind: bind}
	return ProveAIR(c, spend256Trace(serial, amount, blind, path, depth), nQueries)
}

// VerifySpend256 checks a wide spend proof. bind is the full tx-binding domain.
func VerifySpend256(serial, amount Felt, root Node256, bind []byte, depth int, pf *AIRProof, nQueries int) bool {
	return VerifyAIR(spend256Circuit{depth: depth, serial: serial, amount: amount, root: root, bind: bind}, pf, nQueries)
}
