package stark

// Recipient-secret-nullifier spend circuit (#96 — sender↔spend UNLINKABILITY). Today a
// stealth sender knows the coin secret, hence the nullifier, and can detect when their
// sent coin is spent. This circuit removes that link with a Zcash-Sapling-style two-key
// note, all-Poseidon (no ECC, STARK-friendly):
//
//   pk = H(nk, 0)                         recipient address; sender knows pk, NOT nk
//   note cm = sponge(pk, amount, rho, blind):
//        h1 = H(pk,  N(amount))
//        h2 = H(h1,  N(rho))
//        cm = H(h2,  N(blind))
//   nf = H(nk, rho)                       nullifier — needs nk, which the sender lacks
//
// The spend proves: knowledge of nk with pk=H(nk,0) (spend AUTHORITY — a thief who only
// knows pk cannot spend); that cm = sponge(pk,amount,rho,blind) is a member of the tree
// at `root`; and that nf = H(nk,rho). It reveals only nf, amount (public in this variant)
// and root — NOT nk. Since nf depends on nk, the sender cannot precompute it, so cannot
// link the spend to the payment. (H = WideHash2; N(x)=Node256FromFelts(x).)
//
// Structure: the sponge folds reuse the width-8 injection machinery (parent‖N(field),
// bit=0) exactly as the Merkle path does. nk and rho are carried in constant columns
// (leak-free under the ZK-masked engine, zk_mask.go) and linked into the final nf block
// by a reset transition — the same device as cspend_full.go.
//
// Blocks: pk(0) | +amount(1) | +rho(2) | +blind(3) → cm | membership(depth) | nf(last).
// Columns (15): s0..s7, sib0..sib3, bit (13) | nkCol | rhoCol.
// Periodic (14): rc0..7, full, active, inject (11) | sel0 | selRho | reset.

const nfPreBlocks = 4 // pk, +amount, +rho, +blind(→cm)

// NfNote computes the note commitment cm and address pk in the clear (the tree leaf).
func NfNote(nk, amount, rho, blind Felt) (cm, pk Node256) {
	pk = WideHash2(Node256FromFelts(nk), Node256{})
	h1 := WideHash2(pk, Node256FromFelts(amount))
	h2 := WideHash2(h1, Node256FromFelts(rho))
	cm = WideHash2(h2, Node256FromFelts(blind))
	return cm, pk
}

// NfNoteFromPk computes a note commitment from a recipient ADDRESS pk (a Node256) — what
// a SENDER does when paying pk: cm = sponge(pk, amount, rho, blind). The sender knows pk
// (= H(nk,0)) but not nk, so cannot later compute the recipient's nullifier.
func NfNoteFromPk(pk Node256, amount, rho, blind Felt) Node256 {
	h1 := WideHash2(pk, Node256FromFelts(amount))
	h2 := WideHash2(h1, Node256FromFelts(rho))
	return WideHash2(h2, Node256FromFelts(blind))
}

// NfAddress derives the recipient address pk = H(nk, 0) from the secret nk.
func NfAddress(nk Felt) Node256 { return WideHash2(Node256FromFelts(nk), Node256{}) }

// NfNullifier computes nf = H(nk, rho) — the revealed nullifier (needs the secret nk).
func NfNullifier(nk, rho Felt) Node256 { return WideHash2(Node256FromFelts(nk), Node256FromFelts(rho)) }

type nfSpendCircuit struct {
	depth  int
	amount Felt    // public
	nf     Node256 // public nullifier
	root   Node256 // public anchor
	bind   []byte
}

func (c nfSpendCircuit) Name() string {
	if len(c.bind) == 0 {
		return "nf-spend"
	}
	return "nf-spend:" + bytesHex(c.bind)
}
func (nfSpendCircuit) Cols() int       { return 19 }                        // 13 base+4 fold+nkCol+rhoCol
func (nfSpendCircuit) Periodic() int   { return 20 }                        // 11 base+row0+outSel+4 rootVal+sel0+selRho+reset
func (c nfSpendCircuit) blocks() int   { return c.depth + nfPreBlocks + 1 } // +nf
func (c nfSpendCircuit) TraceLen() int { return nextPow2(merkleBlock * c.blocks()) }
func (c nfSpendCircuit) rootRow() int  { return merkleBlock*(c.depth+nfPreBlocks) - 1 }
func (c nfSpendCircuit) nfRow() int    { return merkleBlock*c.blocks() - 1 }
func (c nfSpendCircuit) rhoRow() int   { return merkleBlock*2 - 1 } // block1 injection (folds rho)

const (
	nfPerRow0   = 11
	nfPerOutSel = 12
	nfPerRootV0 = 13 // rootVal columns 13..16
	nfPerSel0   = 17
	nfPerSelRho = 18
	nfPerReset  = 19
)

func (c nfSpendCircuit) PeriodicCol(j int) []Felt {
	col := make([]Felt, c.TraceLen())
	switch {
	case j == nfPerRow0: // block-0 init
		col[0] = 1
		return col
	case j == nfPerOutSel: // Jive output rows (root and nf)
		col[c.rootRow()] = 1
		col[c.nfRow()] = 1
		return col
	case j >= nfPerRootV0 && j <= nfPerRootV0+3: // rootVal: root @ rootRow, nf @ nfRow
		k := j - nfPerRootV0
		col[c.rootRow()] = c.root[k]
		col[c.nfRow()] = c.nf[k]
		return col
	case j == nfPerSel0: // sel0: row 0 (pk input, where nk lives)
		col[0] = 1
		return col
	case j == nfPerSelRho: // selRho: the rho-fold injection row (link rhoCol)
		col[c.rhoRow()] = 1
		return col
	case j == nfPerReset: // reset: the membership-root row (seed the nf input)
		col[c.rootRow()] = 1
		return col
	}
	rRoot := c.rootRow()
	for row := 0; row < c.nfRow(); row++ {
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

func (c nfSpendCircuit) Boundaries() []Boundary {
	mb := merkleBlock - 1
	b := []Boundary{}
	// pk input row: [nk,0,0,0,0,0,0,0]; nk (col 0) is hidden, the rest are zero.
	for _, col := range []int{1, 2, 3, 4, 5, 6, 7} {
		b = append(b, Boundary{Col: col, Row: 0, Val: 0})
	}
	// amount fold (block 0 injection): sib = N(amount) public, bit = 0.
	b = append(b, Boundary{Col: 8, Row: mb, Val: c.amount})
	for _, col := range []int{9, 10, 11, 12} {
		b = append(b, Boundary{Col: col, Row: mb, Val: 0})
	}
	// rho / blind folds: the folded sib is N(field) = [field,0,0,0] with bit = 0. The
	// field (sib0=col 8) stays hidden, but pin the upper sib cells (9,10,11) and the bit
	// to 0 so the note node is explicitly canonical (defense-in-depth — review note; else
	// canonicality rests only on membership against the public root).
	for _, row := range []int{merkleBlock*2 - 1, merkleBlock*3 - 1} {
		for _, col := range []int{9, 10, 11, 12} {
			b = append(b, Boundary{Col: col, Row: row, Val: 0})
		}
	}
	// public anchor root + nullifier nf bound to their Jive outputs via periodic columns.
	return b
}

func nfSpendConstraints[T any](e cenv[T], cur, next, per []T) []T {
	out := wideMerkleConstraints[T](e, cur[:13], next[:13], per[:11], cur[13:17], next[13:17], per[nfPerRow0])
	// Jive output binding for both public outputs (root @ rootRow, nf @ nfRow); the periodic
	// rootVal columns carry the correct public value at each output row.
	out = append(out, jiveRootBind[T](e, cur[:8], cur[13:17], per[nfPerRootV0:nfPerRootV0+4], per[nfPerOutSel])...)
	sel0, selRho, reset := per[nfPerSel0], per[nfPerSelRho], per[nfPerReset]
	// reseed the Jive fold at the reset row (the nf block is spliced by a reset, not an
	// injection, so the inject-reseed does not fire there).
	out = append(out, jiveReseed[T](e, next[:8], next[13:17], reset)...)
	nkCol, rhoCol := cur[17], cur[18]
	// constant carries of the secrets nk, rho (ungated ⇒ constant over the whole trace).
	out = append(out, e.Sub(next[17], nkCol))
	out = append(out, e.Sub(next[18], rhoCol))
	// link nk to the pk-input cell (s0 at row 0) and rho to its fold sibling (sib0 at the
	// rho injection row), so the SAME secrets that build the note also build the nullifier.
	out = append(out, e.Mul(sel0, e.Sub(nkCol, cur[0])))
	out = append(out, e.Mul(selRho, e.Sub(rhoCol, cur[8])))
	// reset: seed the nf block input = [nk,0,0,0, rho,0,0,0] from the carried secrets.
	out = append(out, e.Mul(reset, e.Sub(next[0], nkCol)))
	out = append(out, e.Mul(reset, e.Sub(next[4], rhoCol)))
	for _, k := range []int{1, 2, 3, 5, 6, 7} {
		out = append(out, e.Mul(reset, next[k]))
	}
	return out
}

func (c nfSpendCircuit) ConstraintsFelt(cur, next, per []Felt) []Felt {
	return nfSpendConstraints[Felt](feltEnv{}, cur, next, per)
}

func (c nfSpendCircuit) ConstraintsExt(cur, next, per []Felt2) []Felt2 {
	return nfSpendConstraints[Felt2](felt2Env{}, cur, next, per)
}
func (c nfSpendCircuit) ConstraintsPoly(cur, next, per []Poly) []Poly {
	return nfSpendConstraints[Poly](polyEnv{}, cur, next, per)
}

// nfSpendTrace builds a constraint-satisfying recipient-secret-nullifier spend trace.
func nfSpendTrace(nk, amount, rho, blind Felt, path MerklePath256, depth int) [][]Felt {
	blocks := depth + nfPreBlocks + 1
	T := nextPow2(merkleBlock * blocks)
	rRoot := merkleBlock*(depth+nfPreBlocks) - 1
	nfRow := merkleBlock*blocks - 1
	cols := make([][]Felt, 19)
	for i := range cols {
		cols[i] = make([]Felt, T)
	}
	// block-0 input = [nk,0,0,0, 0,0,0,0] (pk = H(N(nk), 0)).
	cols[0][0] = nk
	fold := func(i int, sib Node256, bit Felt) { // emit an injection at row i
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
	for i := 0; i < nfRow; i++ {
		m := i % merkleBlock
		if i == rRoot { // RESET: seed the nf input [nk,0,0,0, rho,0,0,0]
			cols[0][i+1] = nk
			cols[4][i+1] = rho
			continue
		}
		if m == merkleBlock-1 { // injection
			b := i / merkleBlock
			switch {
			case b == 0:
				fold(i, Node256FromFelts(amount), 0)
			case b == 1:
				fold(i, Node256FromFelts(rho), 0)
			case b == 2:
				fold(i, Node256FromFelts(blind), 0)
			default: // membership: block 3 (cm's injection) folds sibling 0, so lvl = b-3
				lvl := b - 3
				var bit Felt
				if (path.Index>>uint(lvl))&1 == 1 {
					bit = 1
				}
				fold(i, path.Siblings[lvl], bit)
			}
			continue
		}
		// round
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
		cols[17][i] = nk
		cols[18][i] = rho
	}
	fillJiveFold(cols, blocks, nfRow)
	return cols
}

// ProveNfSpend proves a recipient-secret-nullifier spend. Reveals nf, amount, root.
func ProveNfSpend(nk, amount, rho, blind Felt, path MerklePath256, depth int,
	root, nf Node256, bind []byte, nQueries int) (*AIRProof, error) {
	c := nfSpendCircuit{depth: depth, amount: amount, nf: nf, root: root, bind: bind}
	return ProveAIR(c, nfSpendTrace(nk, amount, rho, blind, path, depth), nQueries)
}

// VerifyNfSpend checks a recipient-secret-nullifier spend proof.
func VerifyNfSpend(amount Felt, root, nf Node256, bind []byte, depth int, pf *AIRProof, nQueries int) bool {
	return VerifyAIR(nfSpendCircuit{depth: depth, amount: amount, nf: nf, root: root, bind: bind}, pf, nQueries)
}
