package stark

import "errors"

// A complete transparent STARK over the FRI engine, for a concrete AIR: the
// "square-step" computation
//
//	a[0] = pubStart,  a[i+1] = a[i]² + K,  a[T-1] = pubEnd
//
// It proves knowledge of a full trace satisfying the transition + boundary
// constraints while revealing only the public inputs. This validates the whole
// stack (field → NTT → Merkle → FRI) composes into a sound STARK; the
// membership/nullifier AIR for the ZK spend is the same construction with a
// different constraint set (see docs/ZK_MEMBERSHIP_SPEND.md).
//
// Soundness rests on three checks, all bound by one Fiat-Shamir transcript:
//  1. FRI proves the DEEP polynomial g is low-degree.
//  2. At an out-of-domain z, the algebraic relation CP(z) = Σαᵢ·qᵢ(z) ties the
//     trace's constraint satisfaction to the committed composition CP.
//  3. At each FRI query point, g is checked to equal the DEEP combination of the
//     committed f and CP — binding the abstract low-degree object to the actual
//     trace and composition commitments (the DEEP step; without it a prover could
//     commit an unrelated low-degree g).

// deepOpen is one trace/composition opening at a layer-0 ± position pair.
type deepOpen struct {
	P, S         Felt
	PathP, PathS [][32]byte
}

// STARKProof is a non-interactive proof for the square-step AIR. The out-of-domain
// point z and the DEEP/FRI challenges live in F_{p^2}, so Fz/Fgz/CPz are extension
// elements (soundness floored at 1/p^2). Trace + composition commitments stay base.
type STARKProof struct {
	T                   int
	K, PubStart, PubEnd Felt
	RootF, RootCP       [32]byte
	Fz, Fgz, CPz        Felt2 // f(z), f(gH·z), CP(z) at the F_{p^2} out-of-domain point
	Fri                 *friProof2
	OpenF, OpenCP       []deepOpen // per query, indexed like Fri.Queries
}

var errBadTrace = errors.New("stark: trace does not satisfy the AIR constraints")

// drawOutOfDomain squeezes a challenge z that is nonzero and OUTSIDE the committed LDE
// domain. For the standard subgroup D = <ω_N0> the exclusion is z^N0 ≠ 1; for a coset
// c·<ω_N0> a domain point satisfies x^N0 = c^N0, so we also exclude z^N0 = c^N0 (pass
// coset=1 for the standard domain, where the two checks coincide). Excluding the coset
// keeps the DEEP quotient (f(x)−f(z))/(x−z) well-defined at every query point. Prover and
// verifier run the identical loop, staying in sync on the transcript.
func drawOutOfDomain(tr *Transcript, N0 int, coset Felt) Felt {
	cN0 := coset.Exp(uint64(N0))
	for {
		z := tr.ChallengeFelt()
		zN0 := z.Exp(uint64(N0))
		if z != 0 && zN0 != 1 && zN0 != cN0 {
			return z
		}
	}
}

// drawOutOfDomain2 squeezes an OOD point z ∈ F_{p^2} that is nonzero and OUTSIDE the
// committed LDE domain coset·⟨ω_{N0}⟩. A domain point x satisfies x^{N0} = coset^{N0}
// (a base value), so we reject z=0 and z^{N0} = coset^{N0} (embedded). Because z ranges
// over F_{p^2} (≈ 2^128) while the domain has only N0 ≤ 2^32 points, a uniform z lands
// outside w.h.p.; the loop matches prover/verifier and keeps the DEEP quotient
// (f(x)−f(z))/(x−z) well-defined at every base query point. Prover and verifier run the
// identical loop, staying in sync on the transcript.
func drawOutOfDomain2(tr *Transcript, N0 int, coset Felt) Felt2 {
	cN0 := Felt2From(coset.Exp(uint64(N0)))
	for {
		z := tr.ChallengeFelt2()
		if z.IsZero() {
			continue
		}
		zN0 := z.Exp(uint64(N0))
		if !zN0.Equal(cN0) {
			return z
		}
	}
}

// ProveSquareStep builds a STARK for the given trace (len must be a power of two
// ≥ 2). It returns errBadTrace if the trace violates the constraints.
func ProveSquareStep(trace []Felt, K Felt, nQueries int) (*STARKProof, error) {
	T := len(trace)
	if T < 2 || T&(T-1) != 0 {
		return nil, errors.New("stark: trace length must be a power of two ≥ 2")
	}
	logT := log2(T)
	gH := RootOfUnity(logT)        // generator of the trace domain H
	hLast := gH.Exp(uint64(T - 1)) // last trace point h_{T-1}
	N0 := friBlowup * T
	logN0 := log2(N0)
	wN := RootOfUnity(logN0) // generator of the LDE domain D

	pubStart, pubEnd := trace[0], trace[T-1]

	// Trace polynomial f with f(gH^i) = trace[i].
	f := INTT(trace)

	// Transition constraint C(x) = f(gH·x) − f(x)² − K, which must vanish on
	// h_0..h_{T-2}; divide those roots out to get the quotient qTrans.
	fNext := polyShiftArg(f, gH)
	fSq := polyMul(f, f)
	cTrans := polySub(polySub(fNext, fSq), []Felt{K})
	qTrans := cTrans
	for i := 0; i < T-1; i++ {
		var rem Felt
		qTrans, rem = divLinear(qTrans, gH.Exp(uint64(i)))
		if rem != 0 {
			return nil, errBadTrace
		}
	}

	// Boundary quotients.
	qB0, rem0 := divLinear(polySub(f, []Felt{pubStart}), Felt(1)) // f(1)=pubStart
	if rem0 != 0 {
		return nil, errBadTrace
	}
	qBe, remE := divLinear(polySub(f, []Felt{pubEnd}), hLast) // f(h_{T-1})=pubEnd
	if remE != 0 {
		return nil, errBadTrace
	}

	// Commit f over D.
	fLDE := NTT(pad(f, N0))
	treeF := BuildMerkle(fLDE)

	tr := NewTranscript("stark/square-step")
	absorbPublics(tr, T, K, pubStart, pubEnd)
	tr.AbsorbRoot(treeF.Root())

	// Composition CP = α1·qTrans + α2·qB0 + α3·qBe (degree < T).
	a1, a2, a3 := tr.ChallengeFelt(), tr.ChallengeFelt(), tr.ChallengeFelt()
	cp := polyAdd(polyAdd(polyScale(qTrans, a1), polyScale(qB0, a2)), polyScale(qBe, a3))
	cpLDE := NTT(pad(cp, N0))
	treeCP := BuildMerkle(cpLDE)
	tr.AbsorbRoot(treeCP.Root())

	// Out-of-domain point z ∈ F_{p^2} and the claimed (extension) evaluations.
	z := drawOutOfDomain2(tr, N0, Felt(1))
	gHz := z.MulBase(gH)
	fz := evalBaseAt2(f, z)
	fgz := evalBaseAt2(f, gHz)
	cpz := evalBaseAt2(cp, z)
	tr.AbsorbFelt2(fz)
	tr.AbsorbFelt2(fgz)
	tr.AbsorbFelt2(cpz)

	// DEEP polynomial g (extension coeffs), built so FRI's low-degreeness + the
	// per-query cross-check bind f and CP to their values at z.
	gc1, gc2, gc3 := tr.ChallengeFelt2(), tr.ChallengeFelt2(), tr.ChallengeFelt2()
	qCP, _ := divLinear2(subExtConst2(cp, cpz), z)
	qF, _ := divLinear2(subExtConst2(f, fz), z)
	qFn, _ := divLinear2(subExtConst2(f, fgz), gHz)
	g := polyAdd2(polyAdd2(polyScale2(qCP, gc1), polyScale2(qF, gc2)), polyScale2(qFn, gc3))

	fri := friProveShared2(evalExtOnBaseDomain(g, N0, Felt(1)), T, nQueries, tr, Felt(1))

	// Open f and CP at every FRI query's layer-0 ± positions.
	half := N0 / 2
	openF := make([]deepOpen, nQueries)
	openCP := make([]deepOpen, nQueries)
	for q := 0; q < nQueries; q++ {
		p := fri.Queries[q].Pos % half
		fp, pathFp := treeF.Open(p)
		fs, pathFs := treeF.Open(p + half)
		cpP, pathCPp := treeCP.Open(p)
		cpS, pathCPs := treeCP.Open(p + half)
		openF[q] = deepOpen{P: fp, S: fs, PathP: pathFp, PathS: pathFs}
		openCP[q] = deepOpen{P: cpP, S: cpS, PathP: pathCPp, PathS: pathCPs}
	}

	_ = wN // domain generator used implicitly via NTT; kept for clarity
	return &STARKProof{
		T: T, K: K, PubStart: pubStart, PubEnd: pubEnd,
		RootF: treeF.Root(), RootCP: treeCP.Root(),
		Fz: fz, Fgz: fgz, CPz: cpz,
		Fri: fri, OpenF: openF, OpenCP: openCP,
	}, nil
}

// VerifySquareStep checks a STARK proof against the public inputs embedded in it.
func VerifySquareStep(pf *STARKProof, nQueries int) bool {
	T := pf.T
	if T < 2 || T&(T-1) != 0 {
		return false
	}
	logT := log2(T)
	gH := RootOfUnity(logT)
	hLast := gH.Exp(uint64(T - 1))
	N0 := friBlowup * T
	logN0 := log2(N0)
	wN := RootOfUnity(logN0)
	half := N0 / 2

	tr := NewTranscript("stark/square-step")
	absorbPublics(tr, T, pf.K, pf.PubStart, pf.PubEnd)
	tr.AbsorbRoot(pf.RootF)
	a1, a2, a3 := tr.ChallengeFelt(), tr.ChallengeFelt(), tr.ChallengeFelt()
	tr.AbsorbRoot(pf.RootCP)
	z := drawOutOfDomain2(tr, N0, Felt(1))

	// Algebraic check at z ∈ F_{p^2}: CP(z) must equal the constraint combination
	// computed from the claimed f(z), f(gH·z). This is what ties the trace to CP. The
	// batching coefficients a1..a3 stay in the base field (CP is base-committed); z is
	// in F_{p^2} so the Schwartz-Zippel error is 1/p^2.
	zT := z.Exp(uint64(T))
	zTrans := zT.Sub(One2()).Mul(z.Sub(Felt2From(hLast)).Inv()) // Ztrans(z) = (z^T−1)/(z−h_{T-1})
	cTransZ := pf.Fgz.Sub(pf.Fz.Mul(pf.Fz)).Sub(Felt2From(pf.K))
	qTransZ := cTransZ.Mul(zTrans.Inv())
	qB0Z := pf.Fz.Sub(Felt2From(pf.PubStart)).Mul(z.Sub(One2()).Inv())
	qBeZ := pf.Fz.Sub(Felt2From(pf.PubEnd)).Mul(z.Sub(Felt2From(hLast)).Inv())
	cpExpected := qTransZ.MulBase(a1).Add(qB0Z.MulBase(a2)).Add(qBeZ.MulBase(a3))
	if !cpExpected.Equal(pf.CPz) {
		return false
	}

	tr.AbsorbFelt2(pf.Fz)
	tr.AbsorbFelt2(pf.Fgz)
	tr.AbsorbFelt2(pf.CPz)
	gc1, gc2, gc3 := tr.ChallengeFelt2(), tr.ChallengeFelt2(), tr.ChallengeFelt2()

	// FRI: g is low-degree, and we learn the query positions.
	positions, ok := friVerifyShared2(pf.Fri, nQueries, tr, Felt(1))
	if !ok {
		return false
	}
	if len(pf.OpenF) != nQueries || len(pf.OpenCP) != nQueries {
		return false
	}

	gHz := z.MulBase(gH)
	for q := 0; q < nQueries; q++ {
		pos := positions[q]
		p := pos % half
		of, ocp := pf.OpenF[q], pf.OpenCP[q]

		// Authenticate the f and CP openings at p and p+half.
		if !VerifyMerkle(pf.RootF, N0, p, of.P, of.PathP) ||
			!VerifyMerkle(pf.RootF, N0, p+half, of.S, of.PathS) ||
			!VerifyMerkle(pf.RootCP, N0, p, ocp.P, ocp.PathP) ||
			!VerifyMerkle(pf.RootCP, N0, p+half, ocp.S, ocp.PathS) {
			return false
		}

		// g's values at the same points come from the (already FRI-authenticated)
		// layer-0 openings. Cross-check the DEEP relation at both points (in F_{p^2}).
		gP, gS := pf.Fri.layer0(q)
		xP := wN.Exp(uint64(p))
		xS := wN.Exp(uint64(p + half))
		if !deepCombine(gc1, gc2, gc3, ocp.P, of.P, pf.CPz, pf.Fz, pf.Fgz, xP, z, gHz).Equal(gP) {
			return false
		}
		if !deepCombine(gc1, gc2, gc3, ocp.S, of.S, pf.CPz, pf.Fz, pf.Fgz, xS, z, gHz).Equal(gS) {
			return false
		}
	}
	return true
}

// deepCombine recomputes g(x) ∈ F_{p^2} = γ1·(CP(x)−CP(z))/(x−z) + γ2·(f(x)−f(z))/(x−z)
// + γ3·(f(x)−f(gH·z))/(x−gH·z) from BASE opened f(x), CP(x) at the BASE domain point x.
func deepCombine(g1, g2, g3 Felt2, cpx, fx Felt, cpz, fz, fgz Felt2, x Felt, z, gHz Felt2) Felt2 {
	xe := Felt2From(x)
	cpxe := Felt2From(cpx)
	fxe := Felt2From(fx)
	t1 := g1.Mul(cpxe.Sub(cpz).Mul(xe.Sub(z).Inv()))
	t2 := g2.Mul(fxe.Sub(fz).Mul(xe.Sub(z).Inv()))
	t3 := g3.Mul(fxe.Sub(fgz).Mul(xe.Sub(gHz).Inv()))
	return t1.Add(t2).Add(t3)
}

func absorbPublics(tr *Transcript, T int, K, pubStart, pubEnd Felt) {
	tr.AbsorbFelt(Felt(uint64(T)))
	tr.AbsorbFelt(K)
	tr.AbsorbFelt(pubStart)
	tr.AbsorbFelt(pubEnd)
}

// pad copies coeffs into a length-n slice (n ≥ len(coeffs)).
func pad(coeffs []Felt, n int) []Felt {
	out := make([]Felt, n)
	copy(out, coeffs)
	return out
}
