package stark

import "errors"

// General multi-column AIR STARK over the FRI engine — the same DEEP-ALI
// construction proven for the single-column square-step (stark.go), generalized to
// W trace columns, K transition constraints, and public periodic columns (for
// round constants / selectors). This is the engine the Poseidon membership/nullifier
// circuit runs on (poseidon_air.go).
//
// Soundness is unchanged from the single-column case and rests on three
// transcript-bound checks: (1) FRI proves the DEEP polynomial g is low-degree;
// (2) at an out-of-domain z the algebraic relation CP(z)=Σ aᵢ·qᵢ(z) ties the
// trace's constraint satisfaction to the committed composition; (3) at each FRI
// query point g equals the DEEP combination of the committed columns and CP. A
// violated constraint makes a quotient non-polynomial (its division leaves a
// remainder), so no low-degree CP can satisfy both the z-relation and FRI.

// Boundary asserts trace[Col][Row] == Val (a public input).
type Boundary struct {
	Col, Row int
	Val      Felt
}

// Circuit defines an AIR. Transition constraints must hold on rows 0..T-2 (they
// relate consecutive rows); a circuit handles trailing/padding rows with a periodic
// "active" selector inside its constraints.
type Circuit interface {
	Name() string
	Cols() int
	Periodic() int
	TraceLen() int            // power of two ≥ 2
	PeriodicCol(j int) []Felt // public schedule, length TraceLen
	Boundaries() []Boundary   // public boundary constraints
	// ConstraintsFelt/Poly/Ext evaluate the SAME constraints over base scalars /
	// polynomials / extension scalars. ConstraintsExt is used by the verifier at the
	// F_{p^2} out-of-domain point; because it shares the generic constraint source with
	// the other two, its evaluation is exactly the embedded image of the base identity.
	ConstraintsFelt(cur, next, per []Felt) []Felt
	ConstraintsPoly(cur, next, per []Poly) []Poly
	ConstraintsExt(cur, next, per []Felt2) []Felt2
}

// rowOpen authenticates a domain position: all W trace columns under one path
// (combined row commitment) plus the composition value under its own path. (CP is
// committed after the columns — it depends on coefficients drawn from the column
// commitment — so it cannot share their tree.)
type rowOpen struct {
	Cols    []Felt // W column values at this position
	ColPath [][32]byte
	CP      Felt
	CPPath  [][32]byte
}

// AIRProof is a non-interactive proof for a Circuit. The W trace columns are
// committed under ONE Merkle tree (leaf = hash of the whole row), so each opened
// position carries a single column path instead of W.
//
// SOUNDNESS (Fiat-Shamir, extension field): the out-of-domain point z, the DEEP
// combination coefficients, and the FRI fold challenges are drawn from F_{p^2}, so the
// out-of-domain evaluations Fz/Fgz/CPz are EXTENSION elements and the algebraic error
// terms are floored at 1/p^2 (≈ 2^-128), not 1/p. Trace + composition commitments stay
// in the base field; only challenges and OOD evaluations are extension-valued.
type AIRProof struct {
	Degree   int        // FRI degree bound d (power of two)
	RootCols [32]byte   // combined commitment over all W trace columns
	RootCP   [32]byte   // commitment to the composition polynomial
	Fz, Fgz  []Felt2    // f_c(z) and f_c(gH·z) per column, at the F_{p^2} OOD point
	CPz      Felt2      // CP(z)
	Fri      *friProof2 // low-degree proof of the DEEP polynomial over F_{p^2}
	OpenP    []rowOpen  // [query] opening at position p
	OpenS    []rowOpen  // [query] opening at position p+half
}

func nextPow2(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// vanishOnAllButLast divides p(x) by ∏_{i=0}^{T-2}(x−gH^i) — the transition
// zerofier (every trace point except the last). Returns the quotient and whether
// the division was exact (constraint satisfied).
func vanishOnAllButLast(p []Felt, gH Felt, T int) (q []Felt, exact bool) {
	q = p
	for i := 0; i < T-1; i++ {
		var rem Felt
		q, rem = divLinear(q, gH.Exp(uint64(i)))
		if rem != 0 {
			return nil, false
		}
	}
	return q, true
}

var errAIRBadTrace = errors.New("stark: trace does not satisfy the circuit constraints")

// absorbCircuit binds the public circuit parameters + boundaries + degree into the
// transcript. Periodic columns are fixed by the circuit code (identical on both
// sides), so they need not be absorbed.
func absorbCircuit(tr *Transcript, c Circuit, d int) {
	tr.AbsorbFelt(Felt(uint64(c.TraceLen())))
	tr.AbsorbFelt(Felt(uint64(c.Cols())))
	tr.AbsorbFelt(Felt(uint64(c.Periodic())))
	tr.AbsorbFelt(Felt(uint64(d)))
	for _, b := range c.Boundaries() {
		tr.AbsorbFelt(Felt(uint64(b.Col)))
		tr.AbsorbFelt(Felt(uint64(b.Row)))
		tr.AbsorbFelt(b.Val)
	}
}

// ProveAIR builds a STARK proof that `trace` (W columns × T rows) satisfies the
// circuit. Returns errAIRBadTrace if any constraint is violated.
func ProveAIR(c Circuit, trace [][]Felt, nQueries int) (*AIRProof, error) {
	T := c.TraceLen()
	W := c.Cols()
	if T < 2 || T&(T-1) != 0 {
		return nil, errors.New("stark: trace length must be a power of two ≥ 2")
	}
	if len(trace) != W {
		return nil, errors.New("stark: trace column count mismatch")
	}
	logT := log2(T)
	gH := RootOfUnity(logT)

	// Trace and periodic polynomials. Each trace column is ZERO-KNOWLEDGE MASKED:
	// f[col] = INTT(trace) + Z_H·r (r fresh random). On H this equals the trace (Z_H
	// vanishes there) so every constraint/boundary still holds; off H (the coset LDE,
	// the OOD point, all query points) it is randomized so revealed evaluations leak
	// nothing about the witness. See zk_mask.go.
	f := make([]Poly, W)
	fNext := make([]Poly, W)
	for col := 0; col < W; col++ {
		if len(trace[col]) != T {
			return nil, errors.New("stark: trace row count mismatch")
		}
		f[col] = Poly(maskColumn(INTT(trace[col]), T, nQueries))
		fNext[col] = Poly(polyShiftArg(f[col], gH))
	}
	per := make([]Poly, c.Periodic())
	for j := range per {
		per[j] = Poly(INTT(c.PeriodicCol(j)))
	}

	// Transition quotients.
	cons := c.ConstraintsPoly(f, fNext, per)
	quots := make([][]Felt, 0, len(cons)+len(c.Boundaries()))
	for _, cp := range cons {
		q, exact := vanishOnAllButLast(cp, gH, T)
		if !exact {
			return nil, errAIRBadTrace
		}
		quots = append(quots, q)
	}
	// Boundary quotients: (f_col − val)/(x − gH^row).
	for _, b := range c.Boundaries() {
		num := polySub(f[b.Col], []Felt{b.Val})
		q, rem := divLinear(num, gH.Exp(uint64(b.Row)))
		if rem != 0 {
			return nil, errAIRBadTrace
		}
		quots = append(quots, q)
	}

	// Degree bound: large enough for honest quotients and the trace polys.
	maxDeg := T - 1
	for _, q := range quots {
		if len(q)-1 > maxDeg {
			maxDeg = len(q) - 1
		}
	}
	// The masked columns f' = f + Z_H·r have degree T + maskCoeffs − 1, so their DEEP
	// quotients (f'(x)−f'(z))/(x−z) reach degree T + maskCoeffs − 2. Bound d to cover
	// them EXPLICITLY (not just via the boundary/S-box quotients that happen to dominate
	// in every current circuit) so g stays within the degree-d FRI test for ANY future
	// circuit shape — otherwise an honest g could exceed d (completeness break). The
	// trace columns must also fit faithfully under the LDE: deg f' < N0 = friBlowup·d.
	if mc := T + maskCoeffs(nQueries) - 2; mc > maxDeg {
		maxDeg = mc
	}
	d := nextPow2(maxDeg + 1)
	if d < T {
		d = T
	}
	N0 := friBlowup * d

	// Commit all W trace columns over the COSET LDE domain airCoset·⟨ω_{N0}⟩ (disjoint
	// from H, so no opened position is ever a raw trace row) under ONE row-Merkle tree:
	// row i = [f_0LDE[i], …, f_{W-1}LDE[i]]. polyShiftArg(·, airCoset) evaluates on the
	// coset (coefficient k ↦ k·airCoset^k before the NTT).
	fLDE := make([][]Felt, W)
	for col := 0; col < W; col++ {
		fLDE[col] = NTT(pad(polyShiftArg(f[col], airCoset), N0))
	}
	rows := make([][]Felt, N0)
	for i := 0; i < N0; i++ {
		row := make([]Felt, W)
		for col := 0; col < W; col++ {
			row[col] = fLDE[col][i]
		}
		rows[i] = row
	}
	treeCols := BuildRowMerkle(rows)

	tr := NewTranscript("stark/air:" + c.Name())
	absorbCircuit(tr, c, d)
	tr.AbsorbRoot(treeCols.Root())

	// Composition CP = Σ a_k · quot_k. The batching coefficients a_k stay in the BASE
	// field so CP keeps base-field coefficients and is committed in the base field
	// (Merkle commitments stay base, per the design). The soundness-dominant challenges
	// (OOD point z, DEEP coefficients, FRI fold α) move to F_{p^2} below.
	coeffs := make([]Felt, len(quots))
	cp := []Felt{}
	for k := range quots {
		coeffs[k] = tr.ChallengeFelt()
		cp = polyAdd(cp, polyScale(quots[k], coeffs[k]))
	}
	treeCP := BuildMerkle(NTT(pad(polyShiftArg(cp, airCoset), N0))) // CP on the same coset
	tr.AbsorbRoot(treeCP.Root())

	// Out-of-domain point z ∈ F_{p^2} and claimed (extension) evaluations.
	z := drawOutOfDomain2(tr, N0, airCoset)
	gHz := z.MulBase(gH)
	fz := make([]Felt2, W)
	fgz := make([]Felt2, W)
	for col := 0; col < W; col++ {
		fz[col] = evalBaseAt2(f[col], z)
		fgz[col] = evalBaseAt2(f[col], gHz)
		tr.AbsorbFelt2(fz[col])
		tr.AbsorbFelt2(fgz[col])
	}
	cpz := evalBaseAt2(cp, z)
	tr.AbsorbFelt2(cpz)

	// DEEP polynomial g (column quotients at z and gH·z, plus CP at z), with EXTENSION
	// coefficients; its DEEP batching coefficients gcZ/gcGZ/gcCP are drawn from F_{p^2}.
	gcZ := make([]Felt2, W)
	gcGZ := make([]Felt2, W)
	for col := 0; col < W; col++ {
		gcZ[col] = tr.ChallengeFelt2()
		gcGZ[col] = tr.ChallengeFelt2()
	}
	gcCP := tr.ChallengeFelt2()
	var g []Felt2
	for col := 0; col < W; col++ {
		qz, _ := divLinear2(subExtConst2(f[col], fz[col]), z)
		qgz, _ := divLinear2(subExtConst2(f[col], fgz[col]), gHz)
		g = polyAdd2(g, polyScale2(qz, gcZ[col]))
		g = polyAdd2(g, polyScale2(qgz, gcGZ[col]))
	}
	qcp, _ := divLinear2(subExtConst2(cp, cpz), z)
	g = polyAdd2(g, polyScale2(qcp, gcCP))

	fri := friProveShared2(evalExtOnBaseDomain(g, N0, airCoset), d, nQueries, tr, airCoset)

	// Open the combined column row + CP at each FRI query's ± positions.
	half := N0 / 2
	openP := make([]rowOpen, nQueries)
	openS := make([]rowOpen, nQueries)
	openAt := func(p int) rowOpen {
		cols, cpath := treeCols.Open(p)
		cpv, cppath := treeCP.Open(p)
		return rowOpen{Cols: cols, ColPath: cpath, CP: cpv, CPPath: cppath}
	}
	for q := 0; q < nQueries; q++ {
		p := fri.Queries[q].Pos % half
		openP[q] = openAt(p)
		openS[q] = openAt(p + half)
	}

	return &AIRProof{
		Degree: d, RootCols: treeCols.Root(), RootCP: treeCP.Root(),
		Fz: fz, Fgz: fgz, CPz: cpz,
		Fri: fri, OpenP: openP, OpenS: openS,
	}, nil
}

// maxAIRDegree bounds the prover-chosen proof degree so the LDE domain
// N0 = friBlowup·d still fits the Goldilocks NTT (friBlowup = 4 = 2^2, so
// log2(N0) = 2 + log2(d) must stay <= twoAdicity). Without this a huge Degree makes
// RootOfUnity overflow the field 2-adicity and panic. See the consensus-DoS fix below.
const maxAIRDegree = 1 << (twoAdicity - 2)

// VerifyAIR checks an AIR proof against the circuit (which carries the public
// inputs as boundaries + periodic columns).
//
// ANTI-DoS (audit 2026-06-28, HIGH): a malformed or adversarial proof must NEVER panic
// a validating full node. The Degree field is prover-chosen; an out-of-range value used
// to be able to drive RootOfUnity past the field 2-adicity and crash every node that
// validated one cheap crafted transaction (network-wide halt). We now (1) hard-cap the
// degree to the NTT domain and (2) recover() any residual panic as a rejected proof, so
// a bad proof is always a `false`, never a crash.
func VerifyAIR(c Circuit, pf *AIRProof, nQueries int) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()
	T := c.TraceLen()
	W := c.Cols()
	if T < 2 || T&(T-1) != 0 || len(pf.Fz) != W || len(pf.Fgz) != W {
		return false
	}
	d := pf.Degree
	if d < T || d > maxAIRDegree || d&(d-1) != 0 {
		return false
	}
	logT := log2(T)
	gH := RootOfUnity(logT)
	hLast := gH.Exp(uint64(T - 1))
	N0 := friBlowup * d
	logN0 := log2(N0)
	wN := RootOfUnity(logN0)
	half := N0 / 2

	tr := NewTranscript("stark/air:" + c.Name())
	absorbCircuit(tr, c, d)
	tr.AbsorbRoot(pf.RootCols)

	// Periodic columns reconstructed by the verifier (public, circuit-fixed).
	perPolys := make([]Poly, c.Periodic())
	for j := range perPolys {
		perPolys[j] = Poly(INTT(c.PeriodicCol(j)))
	}

	// Re-draw composition coefficients (one per transition + boundary constraint). The
	// transition-constraint count is fixed by the circuit; count it from the BASE-field
	// constraint list (the extension list has the same length). Coefficients a_k stay in
	// the base field (CP is base-committed).
	nTrans := len(c.ConstraintsFelt(make([]Felt, W), make([]Felt, W), evalPerAt(perPolys, Felt(1))))
	nQuot := nTrans + len(c.Boundaries())
	coeffs := make([]Felt, nQuot)
	for k := 0; k < nQuot; k++ {
		coeffs[k] = tr.ChallengeFelt()
	}
	tr.AbsorbRoot(pf.RootCP)
	z := drawOutOfDomain2(tr, N0, airCoset)
	gHz := z.MulBase(gH)

	// Algebraic check at z ∈ F_{p^2}: CP(z) must equal Σ a_k·quot_k(z). The constraints
	// are evaluated over the EXTENSION field via felt2Env — the SAME constraint source
	// code as the prover, so the in-circuit (extension) evaluation EXACTLY matches the
	// native base-field polynomial identity (no drift, fully binding).
	perz := evalPerAt2(perPolys, z)
	consZ := c.ConstraintsExt(pf.Fz, pf.Fgz, perz)
	if len(consZ) != nTrans {
		return false
	}
	// Z_trans(z) = (z^T−1)/(z−h_{T-1}), in F_{p^2}.
	zTrans := z.Exp(uint64(T)).Sub(One2()).Mul(z.Sub(Felt2From(hLast)).Inv())
	zTransInv := zTrans.Inv()
	cpExpected := Zero2()
	k := 0
	for _, cv := range consZ {
		cpExpected = cpExpected.Add(cv.Mul(zTransInv).MulBase(coeffs[k]))
		k++
	}
	for _, b := range c.Boundaries() {
		qb := pf.Fz[b.Col].Sub(Felt2From(b.Val)).Mul(z.Sub(Felt2From(gH.Exp(uint64(b.Row)))).Inv())
		cpExpected = cpExpected.Add(qb.MulBase(coeffs[k]))
		k++
	}
	if !cpExpected.Equal(pf.CPz) {
		return false
	}

	for col := 0; col < W; col++ {
		tr.AbsorbFelt2(pf.Fz[col])
		tr.AbsorbFelt2(pf.Fgz[col])
	}
	tr.AbsorbFelt2(pf.CPz)

	gcZ := make([]Felt2, W)
	gcGZ := make([]Felt2, W)
	for col := 0; col < W; col++ {
		gcZ[col] = tr.ChallengeFelt2()
		gcGZ[col] = tr.ChallengeFelt2()
	}
	gcCP := tr.ChallengeFelt2()

	positions, ok := friVerifyShared2(pf.Fri, nQueries, tr, airCoset)
	if !ok {
		return false
	}
	if len(pf.OpenP) != nQueries || len(pf.OpenS) != nQueries {
		return false
	}

	// authRow authenticates a row opening (W columns under one path + CP under its
	// own) at position p, returning the column values and the CP value.
	authRow := func(o rowOpen, p int) ([]Felt, Felt, bool) {
		if len(o.Cols) != W {
			return nil, 0, false
		}
		if !VerifyRowMerkle(pf.RootCols, N0, p, o.Cols, o.ColPath) {
			return nil, 0, false
		}
		if !VerifyMerkle(pf.RootCP, N0, p, o.CP, o.CPPath) {
			return nil, 0, false
		}
		return o.Cols, o.CP, true
	}

	for q := 0; q < nQueries; q++ {
		pos := positions[q]
		p := pos % half
		// committed positions live on the coset airCoset·⟨ω_{N0}⟩.
		xP := airCoset.Mul(wN.Exp(uint64(p)))
		xS := airCoset.Mul(wN.Exp(uint64(p + half)))

		fP, cpP, okP := authRow(pf.OpenP[q], p)
		fS, cpS, okS := authRow(pf.OpenS[q], p+half)
		if !okP || !okS {
			return false
		}

		// DEEP cross-check at both ± points: g (an F_{p^2} value from FRI layer 0) equals
		// the extension-field combination of the base-committed columns and CP.
		gP, gS := pf.Fri.layer0(q)
		if !airDeep(gcZ, gcGZ, gcCP, fP, cpP, pf.Fz, pf.Fgz, pf.CPz, xP, z, gHz).Equal(gP) {
			return false
		}
		if !airDeep(gcZ, gcGZ, gcCP, fS, cpS, pf.Fz, pf.Fgz, pf.CPz, xS, z, gHz).Equal(gS) {
			return false
		}
	}
	return true
}

// airDeep recomputes g(x) ∈ F_{p^2} from opened BASE column values fx[col] and BASE CP
// value cpx at the BASE domain point x, using the extension OOD evaluations and the
// extension DEEP coefficients. x, fx, cpx are base elements lifted into F_{p^2}.
func airDeep(gcZ, gcGZ []Felt2, gcCP Felt2, fx []Felt, cpx Felt, fz, fgz []Felt2, cpz Felt2, x Felt, z, gHz Felt2) Felt2 {
	xe := Felt2From(x)
	invZ := xe.Sub(z).Inv()
	invGZ := xe.Sub(gHz).Inv()
	acc := Zero2()
	for col := range fx {
		fxe := Felt2From(fx[col])
		acc = acc.Add(gcZ[col].Mul(fxe.Sub(fz[col]).Mul(invZ)))
		acc = acc.Add(gcGZ[col].Mul(fxe.Sub(fgz[col]).Mul(invGZ)))
	}
	acc = acc.Add(gcCP.Mul(Felt2From(cpx).Sub(cpz).Mul(invZ)))
	return acc
}

// evalPerAt evaluates each periodic polynomial at a BASE point x.
func evalPerAt(perPolys []Poly, x Felt) []Felt {
	out := make([]Felt, len(perPolys))
	for j := range perPolys {
		out[j] = EvalPoly(perPolys[j], x)
	}
	return out
}

// evalPerAt2 evaluates each periodic polynomial at an EXTENSION point x ∈ F_{p^2}.
func evalPerAt2(perPolys []Poly, x Felt2) []Felt2 {
	out := make([]Felt2, len(perPolys))
	for j := range perPolys {
		out[j] = evalBaseAt2(perPolys[j], x)
	}
	return out
}
