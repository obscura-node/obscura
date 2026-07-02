package stark

// Poseidon preimage AIR — a zero-knowledge proof of "I know s such that
// H(s) = y", with s the secret witness and y public. This is the nullifier
// sub-proof of the ZK spend (N = H(serial), revealed) and the atomic building
// block of Merkle-membership-in-ZK (a path is a chain of these compressions).
//
// The trace has 3 columns (the Poseidon state) and one row per round: row 0 is the
// preimage state (witness), row r+1 is round r applied to row r. The whole round
// function — add round constants, x⁷ S-box, MDS mix — is enforced as one uniform
// transition constraint per state element, with periodic columns supplying the
// per-round constants, the full-vs-partial S-box selector, and an "active"
// selector that switches the constraint off on padding rows.

// poseidonTraceLen is the padded power-of-two trace length (rounds + 1 → 31 → 32).
const poseidonTraceLen = 32

func init() {
	if poseidonRounds+1 > poseidonTraceLen {
		panic("stark: poseidonTraceLen too small for round count")
	}
}

// fullRound reports whether round r (0-indexed) is a full round.
func fullRound(r int) bool {
	half := poseidonRF / 2
	return r < half || r >= half+poseidonRP
}

// poseidonRoundConstraints is the round function as AIR constraints, written once
// over the generic environment so prover (Poly) and verifier (Felt) agree.
// per = [rc0, rc1, rc2, fullSel, active].
func poseidonRoundConstraints[T any](e cenv[T], cur, next, per []T) []T {
	rc0, rc1, rc2, full, active := per[0], per[1], per[2], per[3], per[4]
	one := e.Const(1)
	sb := func(x T) T { // x⁷
		x2 := e.Mul(x, x)
		x4 := e.Mul(x2, x2)
		return e.Mul(e.Mul(x4, x2), x)
	}
	t0 := e.Add(cur[0], rc0)
	t1 := e.Add(cur[1], rc1)
	t2 := e.Add(cur[2], rc2)
	// S-box: element 0 always; elements 1,2 only on full rounds (else identity).
	s0 := sb(t0)
	s1 := e.Add(e.Mul(full, sb(t1)), e.Mul(e.Sub(one, full), t1))
	s2 := e.Add(e.Mul(full, sb(t2)), e.Mul(e.Sub(one, full), t2))
	s := []T{s0, s1, s2}
	out := make([]T, poseidonT)
	for i := 0; i < poseidonT; i++ {
		acc := e.Const(0)
		for j := 0; j < poseidonT; j++ {
			acc = e.Add(acc, e.Mul(e.Const(poseidonMDS[i][j]), s[j]))
		}
		// active·(next − MDS(sbox(cur+rc))): zero (vacuous) on padding rows.
		out[i] = e.Mul(active, e.Sub(next[i], acc))
	}
	return out
}

// poseidonPreimageCircuit proves H1(s) = y (capacity inputs fixed to [_,0,IV]).
type poseidonPreimageCircuit struct {
	y Felt // public output H1(s)
}

func (poseidonPreimageCircuit) Name() string  { return "poseidon-preimage" }
func (poseidonPreimageCircuit) Cols() int     { return poseidonT }
func (poseidonPreimageCircuit) Periodic() int { return 5 }
func (poseidonPreimageCircuit) TraceLen() int { return poseidonTraceLen }

// PeriodicCol j: 0..2 = round constants, 3 = full-round selector, 4 = active.
func (poseidonPreimageCircuit) PeriodicCol(j int) []Felt {
	col := make([]Felt, poseidonTraceLen)
	for row := 0; row < poseidonTraceLen; row++ {
		if row >= poseidonRounds { // padding rows: inactive, zero constants
			continue
		}
		switch {
		case j < poseidonT:
			col[row] = poseidonRC[row][j]
		case j == 3:
			if fullRound(row) {
				col[row] = 1
			}
		case j == 4:
			col[row] = 1 // active
		}
	}
	return col
}

func (c poseidonPreimageCircuit) Boundaries() []Boundary {
	return []Boundary{
		{Col: 1, Row: 0, Val: 0},                    // capacity input s1 = 0
		{Col: 2, Row: 0, Val: Felt(poseidonNullIV)}, // capacity input s2 = IV
		{Col: 0, Row: poseidonRounds, Val: c.y},     // output element 0 = y
	}
}

func (poseidonPreimageCircuit) ConstraintsFelt(cur, next, per []Felt) []Felt {
	return poseidonRoundConstraints[Felt](feltEnv{}, cur, next, per)
}

func (poseidonPreimageCircuit) ConstraintsExt(cur, next, per []Felt2) []Felt2 {
	return poseidonRoundConstraints[Felt2](felt2Env{}, cur, next, per)
}
func (poseidonPreimageCircuit) ConstraintsPoly(cur, next, per []Poly) []Poly {
	return poseidonRoundConstraints[Poly](polyEnv{}, cur, next, per)
}

// poseidonPreimageTrace runs the permutation, recording the state after each round.
func poseidonPreimageTrace(s Felt) [][]Felt {
	cols := [poseidonT][]Felt{}
	for i := range cols {
		cols[i] = make([]Felt, poseidonTraceLen)
	}
	state := [poseidonT]Felt{s, 0, Felt(poseidonNullIV)}
	for i := 0; i < poseidonT; i++ {
		cols[i][0] = state[i]
	}
	for r := 0; r < poseidonRounds; r++ {
		for i := 0; i < poseidonT; i++ {
			state[i] = state[i].Add(poseidonRC[r][i])
		}
		if fullRound(r) {
			for i := 0; i < poseidonT; i++ {
				state[i] = sbox(state[i])
			}
		} else {
			state[0] = sbox(state[0])
		}
		state = mds(state)
		for i := 0; i < poseidonT; i++ {
			cols[i][r+1] = state[i]
		}
	}
	// Padding rows copy the final state (constraint is inactive there).
	for row := poseidonRounds + 1; row < poseidonTraceLen; row++ {
		for i := 0; i < poseidonT; i++ {
			cols[i][row] = cols[i][poseidonRounds]
		}
	}
	return [][]Felt{cols[0], cols[1], cols[2]}
}

// ProvePoseidonPreimage proves knowledge of s with H1(s) = y, revealing only y.
func ProvePoseidonPreimage(s Felt, nQueries int) (Felt, *AIRProof, error) {
	y := PoseidonHash1(s)
	c := poseidonPreimageCircuit{y: y}
	pf, err := ProveAIR(c, poseidonPreimageTrace(s), nQueries)
	return y, pf, err
}

// VerifyPoseidonPreimage checks a preimage proof for public output y.
func VerifyPoseidonPreimage(y Felt, pf *AIRProof, nQueries int) bool {
	return VerifyAIR(poseidonPreimageCircuit{y: y}, pf, nQueries)
}
