package stark

// FRI over the DEGREE-2 EXTENSION field F_{p^2} — the soundness-critical low-degree
// test for the DEEP polynomial g. This is a parallel engine to fri.go (which stays in
// the base field for the standalone low-degree tests); the AIR/STARK DEEP layer uses
// THIS one so that the fold challenge α, and hence every per-query soundness term, lives
// in F_{p^2} (error ~deg/p^2 ≈ 2^-128 instead of ~deg/p ≈ 2^-64).
//
// Layer values are F_{p^2} elements; the EVALUATION DOMAIN points stay in the base field
// (coset·⟨ω⟩), exactly as in Winterfell/Plonky2: only the committed values are extension
// elements. Each ± pair is committed as ONE row-Merkle leaf serialized as the four base
// coordinates {X.A, X.B, XSym.A, XSym.B}, so commitments remain pure base-field hashing.

// friLayerProof2 is one queried layer: the ± pair (both extension values) + one path.
type friLayerProof2 struct {
	X    Felt2
	XSym Felt2
	Path [][32]byte
}

// friQuery2 is the full top-to-bottom opening for one query position.
type friQuery2 struct {
	Pos    int
	Layers []friLayerProof2
}

// friProof2 is a non-interactive FRI proof over F_{p^2}.
type friProof2 struct {
	Degree     int
	Roots      [][32]byte
	FinalValue Felt2
	Grind      uint64
	Queries    []friQuery2
}

// fri2Leaf serializes an extension ± pair into a 4-element base row for RowMerkle.
func fri2Leaf(x, xsym Felt2) []Felt {
	return []Felt{x.A, x.B, xsym.A, xsym.B}
}

// fri2Pairs maps a layer's extension evaluations to paired leaves (one per ± pair).
func fri2Pairs(vals []Felt2) [][]Felt {
	half := len(vals) / 2
	out := make([][]Felt, half)
	for k := 0; k < half; k++ {
		out[k] = fri2Leaf(vals[k], vals[k+half])
	}
	return out
}

// fold2 maps a ± pair to the next layer over F_{p^2}, with x = coset·ω^pos a BASE domain
// point embedded into the extension and α ∈ F_{p^2}:
//
//	g(x²) = (f(x)+f(−x))/2 + α·(f(x)−f(−x))/(2x).
func fold2(fx, fsym Felt2, x Felt, alpha Felt2) Felt2 {
	twoInv := Felt(2).Inv()
	even := fx.Add(fsym).MulBase(twoInv)              // (f(x)+f(−x))/2
	odd := fx.Sub(fsym).MulBase(Felt(2).Mul(x).Inv()) // (f(x)−f(−x))/(2x)
	return even.Add(alpha.Mul(odd))
}

// friProveShared2 is the FRI prover over F_{p^2} on a caller-owned transcript. eval0 are
// the layer-0 extension evaluations of the DEEP polynomial over the coset domain
// coset·⟨ω_{N0}⟩ (coset a base element disjoint from the trace domain). Mirrors
// friProveShared exactly, lifted to Felt2.
func friProveShared2(eval0 []Felt2, d, nQueries int, tr *Transcript, coset Felt) *friProof2 {
	N0 := friBlowup * d
	if len(eval0) != N0 {
		panic("stark: eval0 length must equal blowup·d")
	}
	logN0 := log2(N0)

	layers := [][]Felt2{eval0}
	trees := []*RowMerkleTree{BuildRowMerkle(fri2Pairs(layers[0]))}
	tr.AbsorbRoot(trees[0].Root())

	L := int(log2(d))
	cur := layers[0]
	cosetPow := coset
	for j := 0; j < L; j++ {
		alpha := tr.ChallengeFelt2()
		half := len(cur) / 2
		wj := RootOfUnity(logN0 - uint(j))
		next := make([]Felt2, half)
		for i := 0; i < half; i++ {
			x := cosetPow.Mul(wj.Exp(uint64(i)))
			next[i] = fold2(cur[i], cur[i+half], x, alpha)
		}
		cur = next
		cosetPow = cosetPow.Mul(cosetPow)
		layers = append(layers, cur)
		if j < L-1 {
			t := BuildRowMerkle(fri2Pairs(cur))
			trees = append(trees, t)
			tr.AbsorbRoot(t.Root())
		}
	}
	finalVal := cur[0]
	tr.AbsorbFelt2(finalVal)

	grind := tr.Grind(friGrindBits)

	roots := make([][32]byte, len(trees))
	for i, t := range trees {
		roots[i] = t.Root()
	}

	queries := make([]friQuery2, nQueries)
	for q := 0; q < nQueries; q++ {
		pos := tr.ChallengeIndex(N0 / 2)
		queries[q] = friQuery2{Pos: pos}
		for j := 0; j < L; j++ {
			Nj := N0 >> j
			half := Nj / 2
			p := pos % half
			pair, path := trees[j].Open(p)
			queries[q].Layers = append(queries[q].Layers, friLayerProof2{
				X:    Felt2{A: pair[0], B: pair[1]},
				XSym: Felt2{A: pair[2], B: pair[3]},
				Path: path,
			})
		}
	}

	return &friProof2{Degree: d, Roots: roots, FinalValue: finalVal, Grind: grind, Queries: queries}
}

// friVerifyShared2 verifies a friProof2 against a caller-owned transcript and returns the
// layer-0 query positions. Mirrors friVerifyShared exactly, lifted to Felt2.
func friVerifyShared2(pf *friProof2, nQueries int, tr *Transcript, coset Felt) ([]int, bool) {
	d := pf.Degree
	if d == 0 || d&(d-1) != 0 {
		return nil, false
	}
	L := int(log2(d))
	if len(pf.Roots) != L {
		return nil, false
	}
	N0 := friBlowup * d
	logN0 := log2(N0)
	cosetPows := make([]Felt, L)
	cp := coset
	for j := 0; j < L; j++ {
		cosetPows[j] = cp
		cp = cp.Mul(cp)
	}

	tr.AbsorbRoot(pf.Roots[0])
	alphas := make([]Felt2, L)
	for j := 0; j < L; j++ {
		alphas[j] = tr.ChallengeFelt2()
		if j < L-1 {
			tr.AbsorbRoot(pf.Roots[j+1])
		}
	}
	tr.AbsorbFelt2(pf.FinalValue)

	if !tr.VerifyGrind(friGrindBits, pf.Grind) {
		return nil, false
	}

	if len(pf.Queries) != nQueries {
		return nil, false
	}
	positions := make([]int, nQueries)
	for q := 0; q < nQueries; q++ {
		pos := tr.ChallengeIndex(N0 / 2)
		positions[q] = pos
		query := pf.Queries[q]
		if query.Pos != pos || len(query.Layers) != L {
			return nil, false
		}
		var expected Felt2
		haveExpected := false
		for j := 0; j < L; j++ {
			Nj := N0 >> j
			half := Nj / 2
			p := pos % half
			lp := query.Layers[j]

			// Authenticate the ± pair as one paired leaf (four base coordinates).
			if !VerifyRowMerkle(pf.Roots[j], half, p, fri2Leaf(lp.X, lp.XSym), lp.Path) {
				return nil, false
			}

			if haveExpected {
				var atPrev Felt2
				if pos%Nj < half {
					atPrev = lp.X
				} else {
					atPrev = lp.XSym
				}
				if !expected.Equal(atPrev) {
					return nil, false
				}
			}

			wj := RootOfUnity(logN0 - uint(j))
			x := cosetPows[j].Mul(wj.Exp(uint64(p)))
			expected = fold2(lp.X, lp.XSym, x, alphas[j])
			haveExpected = true
		}
		if !expected.Equal(pf.FinalValue) {
			return nil, false
		}
	}
	return positions, true
}

// layer0 returns the opened layer-0 ± extension values for query q.
func (pf *friProof2) layer0(q int) (Felt2, Felt2) {
	return pf.Queries[q].Layers[0].X, pf.Queries[q].Layers[0].XSym
}
