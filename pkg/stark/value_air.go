package stark

// Confidential value-conservation core (Phase C). Proves, over HIDDEN amounts:
//
//	a_in = a_out + fee   AND   a_in, a_out ∈ [0, 2^bits)
//
// with only `fee` public. This is value conservation done ENTIRELY in the Goldilocks
// field — no ed25519 Pedersen commitment, hence no cross-system binding problem. Both
// amounts are bit-peeled (range-checked) so neither can wrap/go negative, and balance
// is plain field subtraction. This is the building block a confidential ZK spend
// composes with membership: prove the spent coin's (hidden) amount equals the new
// coin's (hidden) amount plus fee, revealing nothing but the fee.
//
// Columns: vin (0), bin (1), vout (2), bout (3).  Periodic: active, sel0.

type valueBalanceCircuit struct {
	bits int
	fee  Felt
}

func (valueBalanceCircuit) Name() string    { return "value-balance" }
func (valueBalanceCircuit) Cols() int       { return 4 }
func (valueBalanceCircuit) Periodic() int   { return 2 }
func (c valueBalanceCircuit) TraceLen() int { return nextPow2(c.bits + 1) }

func (c valueBalanceCircuit) PeriodicCol(j int) []Felt {
	col := make([]Felt, c.TraceLen())
	if j == 1 { // sel0: row 0 only (the balance row)
		col[0] = 1
		return col
	}
	for row := 0; row < c.bits; row++ { // active: the peel rows
		col[row] = 1
	}
	return col
}

func (c valueBalanceCircuit) Boundaries() []Boundary {
	return []Boundary{
		{Col: 0, Row: c.bits, Val: 0}, // a_in peeled to 0 ⇒ in range
		{Col: 2, Row: c.bits, Val: 0}, // a_out peeled to 0 ⇒ in range
		// a_in (vin[0]) and a_out (vout[0]) are HIDDEN witnesses — pinned only by the
		// range peels + the balance constraint, never revealed.
	}
}

// valueConstraintsGen is the shared constraint set over the generic environment.
func valueConstraintsGen[T any](e cenv[T], fee Felt, cur, next, per []T) []T {
	active, sel0 := per[0], per[1]
	one := e.Const(1)
	two := e.Const(2)
	vin, bin, vinN := cur[0], cur[1], next[0]
	vout, bout, voutN := cur[2], cur[3], next[2]
	peel := func(v, b, vn T) (T, T) {
		rec := e.Sub(e.Sub(v, e.Mul(two, vn)), b) // v = 2·v_next + b
		boolc := e.Mul(b, e.Sub(b, one))          // b ∈ {0,1}
		return e.Mul(active, rec), e.Mul(active, boolc)
	}
	r1, b1 := peel(vin, bin, vinN)
	r2, b2 := peel(vout, bout, voutN)
	// balance: a_in = a_out + fee  (only at row 0)
	bal := e.Mul(sel0, e.Sub(e.Sub(vin, vout), e.Const(fee)))
	return []T{r1, b1, r2, b2, bal}
}

func (c valueBalanceCircuit) ConstraintsFelt(cur, next, per []Felt) []Felt {
	return valueConstraintsGen[Felt](feltEnv{}, c.fee, cur, next, per)
}

func (c valueBalanceCircuit) ConstraintsExt(cur, next, per []Felt2) []Felt2 {
	return valueConstraintsGen[Felt2](felt2Env{}, c.fee, cur, next, per)
}
func (c valueBalanceCircuit) ConstraintsPoly(cur, next, per []Poly) []Poly {
	return valueConstraintsGen[Poly](polyEnv{}, c.fee, cur, next, per)
}

// valueBalanceTrace builds the trace: bit-peel a_in and a_out (with a_in=a_out+fee).
func valueBalanceTrace(aIn, aOut Felt, bits int) [][]Felt {
	T := nextPow2(bits + 1)
	cols := [4][]Felt{}
	for i := range cols {
		cols[i] = make([]Felt, T)
	}
	vi, vo := uint64(aIn), uint64(aOut)
	for i := 0; i < bits; i++ {
		cols[0][i] = Felt(vi)
		cols[1][i] = Felt(vi & 1)
		cols[2][i] = Felt(vo)
		cols[3][i] = Felt(vo & 1)
		vi >>= 1
		vo >>= 1
	}
	cols[0][bits] = Felt(vi)
	cols[2][bits] = Felt(vo)
	return [][]Felt{cols[0], cols[1], cols[2], cols[3]}
}

// ProveValueBalance proves a_in = a_out + fee with a_in, a_out hidden and in range.
// bits must be ≤ MaxRangeBits so 2^bits < P (amounts encoded in this range, NOT the
// raw supply cap — review finding 3).
func ProveValueBalance(aIn, aOut, fee Felt, bits, nQueries int) (*AIRProof, error) {
	if bits <= 0 || bits > MaxRangeBits {
		panic("stark: value-balance bits must be in (0, MaxRangeBits] so 2^bits < P")
	}
	return ProveAIR(valueBalanceCircuit{bits: bits, fee: fee}, valueBalanceTrace(aIn, aOut, bits), nQueries)
}

// VerifyValueBalance checks the proof for the public fee.
func VerifyValueBalance(fee Felt, bits int, pf *AIRProof, nQueries int) bool {
	return VerifyAIR(valueBalanceCircuit{bits: bits, fee: fee}, pf, nQueries)
}
