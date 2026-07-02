package stark

// Zero-knowledge Merkle-membership STARK — the heart of the anonymous spend. It
// proves "I know a leaf L and an authentication path (siblings + path bits) such
// that folding L up the tree yields the PUBLIC root R", revealing nothing about L,
// the path, or the leaf's position. This is membership against the Poseidon-Merkle
// commitment-tree accumulator, proven transparently (no trusted setup,
// post-quantum) on the general AIR engine.
//
// Trace layout (5 witness columns: s0,s1,s2 = Poseidon state, sib, bit):
//   row 0            : seed — s0 = leaf (witness)
//   rows 1+31k..30+31k: Poseidon permutation of compression k (30 rounds)
//   the transition at every row ≡ 0 (mod 31) is an INJECTION that builds the next
//     compression's input [in0,in1,IV] from the running hash and the level's
//     sibling, ordered by the level's path bit; the transition at rows ≡ 1..30 is
//     a Poseidon round. Row 31·D holds the final root.
//
// Constraint types (all gated by periodic selectors so exactly one is live per
// transition): Poseidon round (×3 state elements), injection swap (×3), and
// booleanity of the path bit. A bad path makes the boundary/zerofier division
// non-exact ⇒ the proof can't even be formed.

// merkleConstraints is the constraint set, written once over the generic env.
// per = [rc0, rc1, rc2, fullSel, active, inject]; cur/next = [s0,s1,s2,sib,bit].
func merkleConstraints[T any](e cenv[T], cur, next, per []T) []T {
	rc0, rc1, rc2, full, active, inject := per[0], per[1], per[2], per[3], per[4], per[5]
	one := e.Const(1)
	iv := e.Const(Felt(poseidonMerkleIV))
	sb := func(x T) T { // x⁷
		x2 := e.Mul(x, x)
		x4 := e.Mul(x2, x2)
		return e.Mul(e.Mul(x4, x2), x)
	}
	// Poseidon round on the current state.
	t0 := e.Add(cur[0], rc0)
	t1 := e.Add(cur[1], rc1)
	t2 := e.Add(cur[2], rc2)
	rs0 := sb(t0)
	rs1 := e.Add(e.Mul(full, sb(t1)), e.Mul(e.Sub(one, full), t1))
	rs2 := e.Add(e.Mul(full, sb(t2)), e.Mul(e.Sub(one, full), t2))
	rs := []T{rs0, rs1, rs2}
	mix := make([]T, poseidonT)
	for i := 0; i < poseidonT; i++ {
		acc := e.Const(0)
		for j := 0; j < poseidonT; j++ {
			acc = e.Add(acc, e.Mul(e.Const(poseidonMDS[i][j]), rs[j]))
		}
		mix[i] = acc
	}

	out := make([]T, 0, 7)
	// Round constraints (gated by active).
	for i := 0; i < poseidonT; i++ {
		out = append(out, e.Mul(active, e.Sub(next[i], mix[i])))
	}
	// Injection: parent=cur[0], sib=cur[3], bit=cur[4]. bit=0 ⇒ (parent,sib);
	// bit=1 ⇒ (sib,parent). next[2] forced to IV.
	parent, sib, bit := cur[0], cur[3], cur[4]
	in0 := e.Add(e.Mul(e.Sub(one, bit), parent), e.Mul(bit, sib))
	in1 := e.Add(e.Mul(bit, parent), e.Mul(e.Sub(one, bit), sib))
	out = append(out, e.Mul(inject, e.Sub(next[0], in0)))
	out = append(out, e.Mul(inject, e.Sub(next[1], in1)))
	out = append(out, e.Mul(inject, e.Sub(next[2], iv)))
	// Booleanity of the path bit at injection rows.
	out = append(out, e.Mul(inject, e.Mul(bit, e.Sub(bit, one))))
	return out
}

const merkleBlock = poseidonRounds + 1 // 31 rows consumed per compression level

// membershipCircuit proves membership of some leaf under root, for a tree of the
// given depth.
type membershipCircuit struct {
	depth int
	root  Felt
}

func (membershipCircuit) Name() string  { return "merkle-membership" }
func (membershipCircuit) Cols() int     { return 5 }
func (membershipCircuit) Periodic() int { return 6 }
func (c membershipCircuit) TraceLen() int {
	return nextPow2(merkleBlock*c.depth + 1)
}

// rootRow is the trace row holding the final root.
func (c membershipCircuit) rootRow() int { return merkleBlock * c.depth }

// PeriodicCol j: 0..2 round constants, 3 fullSel, 4 active, 5 inject.
func (c membershipCircuit) PeriodicCol(j int) []Felt {
	T := c.TraceLen()
	col := make([]Felt, T)
	lastCur := c.rootRow() // transitions with cur in [0, rootRow) are live
	for row := 0; row < lastCur; row++ {
		m := row % merkleBlock
		if m == 0 { // injection transition
			if j == 5 {
				col[row] = 1
			}
			continue
		}
		// round transition, round index r = m-1 ∈ [0,30)
		r := m - 1
		switch {
		case j < poseidonT:
			col[row] = poseidonRC[r][j]
		case j == 3:
			if fullRound(r) {
				col[row] = 1
			}
		case j == 4:
			col[row] = 1 // active
		}
	}
	return col
}

func (c membershipCircuit) Boundaries() []Boundary {
	return []Boundary{{Col: 0, Row: c.rootRow(), Val: c.root}}
}

func (membershipCircuit) ConstraintsFelt(cur, next, per []Felt) []Felt {
	return merkleConstraints[Felt](feltEnv{}, cur, next, per)
}

func (membershipCircuit) ConstraintsExt(cur, next, per []Felt2) []Felt2 {
	return merkleConstraints[Felt2](felt2Env{}, cur, next, per)
}
func (membershipCircuit) ConstraintsPoly(cur, next, per []Poly) []Poly {
	return merkleConstraints[Poly](polyEnv{}, cur, next, per)
}

// membershipTrace builds a constraint-satisfying trace from a leaf and its path.
func membershipTrace(leaf Felt, path MerklePath, depth int) [][]Felt {
	T := nextPow2(merkleBlock*depth + 1)
	s0 := make([]Felt, T)
	s1 := make([]Felt, T)
	s2 := make([]Felt, T)
	sib := make([]Felt, T)
	bit := make([]Felt, T)

	s0[0] = leaf
	idx := path.Index
	for i := 0; i < merkleBlock*depth; i++ {
		m := i % merkleBlock
		if m == 0 { // injection at row i, level lvl
			lvl := i / merkleBlock
			b := Felt(idx & 1)
			sv := path.Siblings[lvl]
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
			idx >>= 1
			continue
		}
		// round r = m-1
		r := m - 1
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

// ProveMembership proves that leaf is a member of the tree with the given root,
// using its authentication path. Reveals only the root.
func ProveMembership(leaf Felt, path MerklePath, depth int, root Felt, nQueries int) (*AIRProof, error) {
	c := membershipCircuit{depth: depth, root: root}
	return ProveAIR(c, membershipTrace(leaf, path, depth), nQueries)
}

// VerifyMembership checks a membership proof against the public root.
func VerifyMembership(root Felt, depth int, pf *AIRProof, nQueries int) bool {
	return VerifyAIR(membershipCircuit{depth: depth, root: root}, pf, nQueries)
}
