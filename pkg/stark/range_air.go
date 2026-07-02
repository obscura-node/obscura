package stark

// In-circuit range proof — the core primitive for CONFIDENTIAL AMOUNTS (Phase C).
//
// To hide amounts we must check value conservation (Σ in = Σ out + fee) over HIDDEN
// amounts. Doing that with an ed25519 Pedersen commitment would require ed25519
// scalar-mult INSIDE a Goldilocks STARK (infeasible). So we keep amounts in the
// Goldilocks field and prove balance + range entirely in-circuit — no cross-system
// binding. Balance is then just field subtraction; the only subtlety is preventing
// wraparound (a "negative" amount aliasing to a huge field element), which is what
// this range proof rules out: it proves a value lies in [0, 2^n).
//
// Construction (transition-based, AIR-native): bit-peeling. Each row peels the low
// bit; the running value halves; after n rows it must be 0. Constraints per active
// row: val = 2·val_next + bit, and bit ∈ {0,1}. Boundary: val_0 = value, val_n = 0.
// Then value = Σ bitᵢ·2ⁱ < 2^n.
//
// Columns: val (0), bit (1).  Periodic: active (1 for the n peel rows).

// rangeCircuit proves a (here public, for testing — a witness in integration) value
// lies in [0, 2^bits).
type rangeCircuit struct {
	bits  int
	value Felt
}

func (rangeCircuit) Name() string    { return "range" }
func (rangeCircuit) Cols() int       { return 2 }
func (rangeCircuit) Periodic() int   { return 1 }
func (c rangeCircuit) TraceLen() int { return nextPow2(c.bits + 1) }

func (c rangeCircuit) PeriodicCol(j int) []Felt {
	col := make([]Felt, c.TraceLen())
	for row := 0; row < c.bits; row++ {
		col[row] = 1 // active on the n peel rows
	}
	return col
}

func (c rangeCircuit) Boundaries() []Boundary {
	return []Boundary{
		{Col: 0, Row: 0, Val: c.value}, // val_0 = value
		{Col: 0, Row: c.bits, Val: 0},  // val_n = 0 ⇒ value < 2^bits
	}
}

func rangeConstraints[T any](e cenv[T], cur, next, per []T) []T {
	active := per[0]
	one := e.Const(1)
	val, bit, valNext := cur[0], cur[1], next[0]
	// val = 2·val_next + bit  ⇒  active·(val − 2·val_next − bit) = 0
	rec := e.Sub(e.Sub(val, e.Mul(e.Const(2), valNext)), bit)
	// booleanity: bit·(bit−1) = 0
	boolc := e.Mul(bit, e.Sub(bit, one))
	return []T{e.Mul(active, rec), e.Mul(active, boolc)}
}

func (rangeCircuit) ConstraintsFelt(cur, next, per []Felt) []Felt {
	return rangeConstraints[Felt](feltEnv{}, cur, next, per)
}

func (rangeCircuit) ConstraintsExt(cur, next, per []Felt2) []Felt2 {
	return rangeConstraints[Felt2](felt2Env{}, cur, next, per)
}
func (rangeCircuit) ConstraintsPoly(cur, next, per []Poly) []Poly {
	return rangeConstraints[Poly](polyEnv{}, cur, next, per)
}

// rangeTrace builds the bit-peeling trace for value over `bits` rows.
func rangeTrace(value Felt, bits int) [][]Felt {
	T := nextPow2(bits + 1)
	valCol := make([]Felt, T)
	bitCol := make([]Felt, T)
	v := uint64(value)
	for i := 0; i < bits; i++ {
		valCol[i] = Felt(v)
		bitCol[i] = Felt(v & 1)
		v >>= 1
	}
	valCol[bits] = Felt(v) // must be 0 for an in-range value
	return [][]Felt{valCol, bitCol}
}

// MaxRangeBits is the largest safe bit-width for the in-field range/value gadgets.
// Soundness needs 2^bits < P (Goldilocks ≈ 2^64) so an in-range value is also a
// canonical field element. We cap well below 64 for margin (note 2·MoneySupplyCap > P,
// so confidential amounts must be encoded ≤ MaxRangeBits, not up to the raw cap).
// REVIEW FINDING 3.
const MaxRangeBits = 60

// ProveRange proves value ∈ [0, 2^bits).
func ProveRange(value Felt, bits, nQueries int) (*AIRProof, error) {
	if bits <= 0 || bits > MaxRangeBits {
		panic("stark: range bits must be in (0, MaxRangeBits] so 2^bits < P")
	}
	return ProveAIR(rangeCircuit{bits: bits, value: value}, rangeTrace(value, bits), nQueries)
}

// VerifyRange checks a range proof for the public value.
func VerifyRange(value Felt, bits int, pf *AIRProof, nQueries int) bool {
	return VerifyAIR(rangeCircuit{bits: bits, value: value}, pf, nQueries)
}
