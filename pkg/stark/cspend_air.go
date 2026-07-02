package stark

// Confidential-spend INPUT circuit (Phase C integration). Proves membership of a coin
// whose amount is HIDDEN but range-bound — the input half of a confidential ZK→ZK
// spend. It is the width-8 spend circuit with the `amount` boundary removed (so the
// amount is a witness, not revealed) and replaced by an in-circuit range proof: the
// amount (state column s4 at the leaf-input row) is bit-decomposed into vbits boolean
// witness columns and recomposed, proving amount ∈ [0, 2^vbits) without revealing it.
// Combined with a confidential output + the value-balance gadget (value_air.go), this
// gives confidential amounts entirely in-field (no cross-system binding).
//
// Columns: spend256's 13 (s0..s7,sib0..sib3,bit) + vbits range-bit columns.
// Periodic: spend256's 11 + sel0 (the leaf-input row, where the amount lives).

type cspendInputCircuit struct {
	depth  int
	serial Felt
	root   Node256
	bind   []byte
	vbits  int
}

func (c cspendInputCircuit) Name() string {
	if len(c.bind) == 0 {
		return "cspend-in"
	}
	return "cspend-in:" + bytesHex(c.bind)
}
func (c cspendInputCircuit) Cols() int     { return 17 + c.vbits } // 13 base+4 fold+vbits
func (cspendInputCircuit) Periodic() int   { return 18 }           // 11 base+row0+outSel+4 rootVal+sel0
func (c cspendInputCircuit) blocks() int   { return c.depth + spendPreBlocks }
func (c cspendInputCircuit) TraceLen() int { return nextPow2(merkleBlock * c.blocks()) }
func (c cspendInputCircuit) rootRow() int  { return merkleBlock*c.blocks() - 1 }

func (c cspendInputCircuit) PeriodicCol(j int) []Felt {
	col := make([]Felt, c.TraceLen())
	switch {
	case j == 11: // row0
		col[0] = 1
		return col
	case j == 12: // outSel
		col[c.rootRow()] = 1
		return col
	case j >= 13 && j <= 16: // rootVal: public root at the output row
		col[c.rootRow()] = c.root[j-13]
		return col
	case j == 17: // sel0: the leaf-input row (row 0), where amount = s4 lives
		col[0] = 1
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

func (c cspendInputCircuit) Boundaries() []Boundary {
	// serial public (nullifier), IV/zero capacity inputs, root public — but NOT the
	// amount (s4), which is hidden and bound only by the in-circuit range proof.
	b := []Boundary{{Col: 0, Row: 0, Val: c.serial}}
	for _, col := range []int{1, 2, 3, 5, 6, 7} {
		b = append(b, Boundary{Col: col, Row: 0, Val: 0})
	}
	// root bound to the Jive output via periodic columns (outSel + rootVal).
	return b
}

func cspendInputConstraints[T any](e cenv[T], vbits int, cur, next, per []T) []T {
	out := wideMerkleConstraints[T](e, cur[:13], next[:13], per[:11], cur[13:17], next[13:17], per[11])
	out = append(out, jiveRootBind[T](e, cur[:8], cur[13:17], per[13:17], per[12])...)
	sel0 := per[17]
	one := e.Const(1)
	// range-bind the hidden amount (s4 = cur[4]) at the leaf-input row: amount must
	// equal Σ bitᵢ·2ⁱ with each bit boolean ⇒ amount ∈ [0, 2^vbits).
	sum := e.Const(0)
	pow := Felt(1)
	for i := 0; i < vbits; i++ {
		bitc := cur[17+i]
		sum = e.Add(sum, e.Mul(e.Const(pow), bitc))
		out = append(out, e.Mul(sel0, e.Mul(bitc, e.Sub(bitc, one)))) // booleanity
		pow = pow.Mul(Felt(2))
	}
	out = append(out, e.Mul(sel0, e.Sub(cur[4], sum))) // amount = Σ bits
	return out
}

func (c cspendInputCircuit) ConstraintsFelt(cur, next, per []Felt) []Felt {
	return cspendInputConstraints[Felt](feltEnv{}, c.vbits, cur, next, per)
}

func (c cspendInputCircuit) ConstraintsExt(cur, next, per []Felt2) []Felt2 {
	return cspendInputConstraints[Felt2](felt2Env{}, c.vbits, cur, next, per)
}
func (c cspendInputCircuit) ConstraintsPoly(cur, next, per []Poly) []Poly {
	return cspendInputConstraints[Poly](polyEnv{}, c.vbits, cur, next, per)
}

func cspendInputTrace(serial, amount, blind Felt, path MerklePath256, depth, vbits int) [][]Felt {
	base := spend256Trace(serial, amount, blind, path, depth) // 17 cols (13 base + 4 fold)
	T := len(base[0])
	v := uint64(amount)
	for i := 0; i < vbits; i++ {
		bc := make([]Felt, T)
		bc[0] = Felt(v & 1) // amount's bits at the leaf-input row
		v >>= 1
		base = append(base, bc)
	}
	return base
}

// ProveCSpendInput proves membership of a coin with a HIDDEN, range-bound amount.
// Reveals only serial (nullifier) and root.
func ProveCSpendInput(serial, amount, blind Felt, path MerklePath256, depth int, root Node256, bind []byte, vbits, nQueries int) (*AIRProof, error) {
	if vbits <= 0 || vbits > MaxRangeBits {
		panic("stark: cspend vbits must be in (0, MaxRangeBits]")
	}
	c := cspendInputCircuit{depth: depth, serial: serial, root: root, bind: bind, vbits: vbits}
	return ProveAIR(c, cspendInputTrace(serial, amount, blind, path, depth, vbits), nQueries)
}

// VerifyCSpendInput checks a confidential-input proof.
func VerifyCSpendInput(serial Felt, root Node256, bind []byte, depth, vbits int, pf *AIRProof, nQueries int) bool {
	return VerifyAIR(cspendInputCircuit{depth: depth, serial: serial, root: root, bind: bind, vbits: vbits}, pf, nQueries)
}
