package stark

// FRI (Fast Reed-Solomon Interactive Oracle Proof of Proximity) — the
// low-degree test at the heart of a STARK. Given Merkle-committed evaluations of a
// function over a domain, FRI convinces a verifier the function is (close to) a
// polynomial below a degree bound, in O(log n) work. It is transparent and
// post-quantum (only hashing + Reed-Solomon). This is the engine; an AIR layer on
// top reduces a computation's correctness to one such low-degree claim.
//
// Protocol (Fiat-Shamir / non-interactive):
//   Commit phase: evaluate the polynomial on a blowup·d domain; repeatedly FOLD
//     two ± points into one with a transcript challenge α, halving degree+domain,
//     Merkle-committing each layer, until the polynomial is a constant.
//   Query phase: at random positions, open each layer's ± pair and check it folds
//     consistently into the next layer, down to the constant.
// Soundness: a function far from low-degree survives a single query with
// probability ≤ ~(1+ρ)/2 per query (ρ = rate); nQueries makes this negligible.

const friBlowup = 4 // Reed-Solomon rate 1/4

// friGrindBits is the Fiat-Shamir grinding difficulty: before query positions are
// drawn, the prover must find a nonce whose transcript hash has this many leading
// zero bits, so a prover cannot cheaply re-roll the transcript to dodge queries.
//
// SOUNDNESS ACCOUNTING (be precise — audit-flagged): per-query soundness depends on
// the decoding radius assumed. The PROVABLE (unique-decoding) bound gives per-query
// rejection only ~(1−ρ)/2 of a violating function, i.e. per-query *pass* ≈ (1+ρ)/2 ≈
// 5/8 ⇒ ~0.7 bits/query ⇒ 48 queries ≈ 49 bits (+ friGrindBits). The widely-USED
// figure log2(1/ρ)=2 bits/query (⇒ ~2·nQueries + friGrindBits ≈ 112 bits here) relies
// on the FRI PROXIMITY-GAP / list-decoding results, which are partly CONJECTURED at
// the full Johnson radius. So "~112-bit" is the conjectured/industry figure (StarkWare
// et al.), NOT the proven bound. An external cryptographer must sign off on the level;
// raise nQueries to hit a target under the provable bound if the conjecture is rejected.
const friGrindBits = 16

// friLayerProof is one queried layer: the ± pair values + ONE Merkle path. The
// pair (i, i+half) is committed as a single leaf (hash of both values), so one
// authentication path opens both — halving FRI path bytes vs separate openings.
type friLayerProof struct {
	X    Felt // f(x) at the query position
	XSym Felt // f(−x) at the symmetric position
	Path [][32]byte
}

// friQuery is the full top-to-bottom opening for one query position.
type friQuery struct {
	Pos    int // position in [0, N0/2)
	Layers []friLayerProof
}

// FRIProof is a non-interactive proof that the committed polynomial has degree < d.
type FRIProof struct {
	Degree     int        // claimed degree bound d (power of two)
	Roots      [][32]byte // Merkle root of each folded layer (layers 0..L-1)
	FinalValue Felt       // the constant the polynomial folds down to
	Grind      uint64     // Fiat-Shamir grinding nonce (friGrindBits difficulty)
	Queries    []friQuery
}

// fold maps a ± pair to the next layer: with x=ω^pos, −x=ω^(pos+half),
//
//	g(x²) = (f(x)+f(−x))/2 + α·(f(x)−f(−x))/(2x).
func fold(fx, fsym, x, alpha Felt) Felt {
	two := Felt(2)
	even := fx.Add(fsym).Mul(two.Inv())       // (f(x)+f(−x))/2
	odd := fx.Sub(fsym).Mul(two.Mul(x).Inv()) // (f(x)−f(−x))/(2x)
	return even.Add(alpha.Mul(odd))
}

// log2 returns k for n=2^k (n must be a power of two).
func log2(n int) uint {
	k := uint(0)
	for 1<<k < n {
		k++
	}
	return k
}

// ProveFRI produces a low-degree proof for the polynomial given by coeffs
// (len(coeffs) == degree bound d, a power of two). nQueries sets the soundness.
func ProveFRI(coeffs []Felt, nQueries int) *FRIProof {
	d := len(coeffs)
	if d == 0 || d&(d-1) != 0 {
		panic("stark: FRI degree bound must be a power of two")
	}
	N0 := friBlowup * d
	// Layer 0 evaluations: pad coeffs to N0 and NTT.
	padded := make([]Felt, N0)
	copy(padded, coeffs)
	return proveFRIEvals(NTT(padded), d, nQueries)
}

// proveFRIEvals is the prover over explicit layer-0 evaluations (length N0 =
// blowup·d). Exposed (unexported) so soundness tests can feed a NON-low-degree
// function and confirm the verifier rejects it. Standard (non-coset) domain.
func proveFRIEvals(eval0 []Felt, d, nQueries int) *FRIProof {
	return friProveShared(eval0, d, nQueries, NewTranscript("fri"), Felt(1))
}

// friProveShared is the FRI prover over a CALLER-OWNED transcript. The AIR/STARK
// layer passes a transcript that has already absorbed the trace and composition
// commitments plus the out-of-domain point, so FRI's query positions are bound to
// those commitments (DEEP soundness). The query positions can be re-derived by the
// verifier from the same transcript.
// coset shifts the evaluation domain: layer-0 points are coset·ω^i (coset=1 ⇒ the
// standard subgroup). Squaring under folding maps coset to coset^(2^j) at layer j; the
// fold point is therefore coset^(2^j)·ω^p. AIR passes airCoset (a coset disjoint from the
// trace domain H) for zero-knowledge; standalone FRI passes 1.
func friProveShared(eval0 []Felt, d, nQueries int, tr *Transcript, coset Felt) *FRIProof {
	N0 := friBlowup * d
	if len(eval0) != N0 {
		panic("stark: eval0 length must equal blowup·d")
	}
	logN0 := log2(N0)

	layers := [][]Felt{eval0}

	trees := []*RowMerkleTree{BuildRowMerkle(friPairs(layers[0]))}
	tr.AbsorbRoot(trees[0].Root())

	// Commit phase: fold until the layer is a single coset of size friBlowup
	// (degree bound 1 → constant). L = log2(d) folds.
	L := int(log2(d))
	cur := layers[0]
	cosetPow := coset // coset^(2^j) at layer j
	for j := 0; j < L; j++ {
		alpha := tr.ChallengeFelt()
		half := len(cur) / 2
		wj := RootOfUnity(logN0 - uint(j)) // generator of layer-j domain
		next := make([]Felt, half)
		for i := 0; i < half; i++ {
			x := cosetPow.Mul(wj.Exp(uint64(i)))
			next[i] = fold(cur[i], cur[i+half], x, alpha)
		}
		cur = next
		cosetPow = cosetPow.Mul(cosetPow)
		layers = append(layers, cur)
		if j < L-1 {
			t := BuildRowMerkle(friPairs(cur))
			trees = append(trees, t)
			tr.AbsorbRoot(t.Root())
		}
	}
	// Final layer has size friBlowup and must be constant; absorb it.
	finalVal := cur[0]
	tr.AbsorbFelt(finalVal)

	// Grinding: bind a PoW nonce before drawing queries (Fiat-Shamir grinding
	// resistance).
	grind := tr.Grind(friGrindBits)

	roots := make([][32]byte, len(trees))
	for i, t := range trees {
		roots[i] = t.Root()
	}

	// Query phase. The ± pair (p, p+half) is one paired leaf at index p, so one path
	// opens both.
	queries := make([]friQuery, nQueries)
	for q := 0; q < nQueries; q++ {
		pos := tr.ChallengeIndex(N0 / 2)
		queries[q] = friQuery{Pos: pos}
		for j := 0; j < L; j++ {
			Nj := N0 >> j
			half := Nj / 2
			p := pos % half
			pair, path := trees[j].Open(p)
			queries[q].Layers = append(queries[q].Layers, friLayerProof{
				X: pair[0], XSym: pair[1], Path: path,
			})
		}
	}

	return &FRIProof{Degree: d, Roots: roots, FinalValue: finalVal, Grind: grind, Queries: queries}
}

// friPairs maps a layer's evaluations to paired leaves: leaf k = [vals[k],
// vals[k+half]] for k in [0, half). Each leaf commits a ± pair, so one Merkle path
// authenticates both points of a query.
func friPairs(vals []Felt) [][]Felt {
	half := len(vals) / 2
	out := make([][]Felt, half)
	for k := 0; k < half; k++ {
		out[k] = []Felt{vals[k], vals[k+half]}
	}
	return out
}

// VerifyFRI checks a low-degree proof against a fresh transcript.
func VerifyFRI(pf *FRIProof, nQueries int) bool {
	_, ok := friVerifyShared(pf, nQueries, NewTranscript("fri"), Felt(1))
	return ok
}

// friVerifyShared verifies a FRI proof against a CALLER-OWNED transcript and, on
// success, returns the layer-0 query positions so the AIR/STARK layer can open its
// trace/composition commitments at the same points and check the DEEP relation.
// It re-derives every challenge from the transcript (so the prover could not adapt
// to them) and, per query, walks the fold chain from layer 0 to the final constant.
func friVerifyShared(pf *FRIProof, nQueries int, tr *Transcript, coset Felt) ([]int, bool) {
	d := pf.Degree
	if d == 0 || d&(d-1) != 0 {
		return nil, false
	}
	L := int(log2(d))
	if len(pf.Roots) != L { // L-1 folded roots + layer 0 = L roots
		return nil, false
	}
	N0 := friBlowup * d
	logN0 := log2(N0)
	cosetPows := make([]Felt, L) // coset^(2^j) per layer
	cp := coset
	for j := 0; j < L; j++ {
		cosetPows[j] = cp
		cp = cp.Mul(cp)
	}

	// Re-derive the transcript: roots[0], then α_j before each fold, folded roots
	// for layers 1..L-1, then the final value.
	tr.AbsorbRoot(pf.Roots[0])
	alphas := make([]Felt, L)
	for j := 0; j < L; j++ {
		alphas[j] = tr.ChallengeFelt()
		if j < L-1 {
			tr.AbsorbRoot(pf.Roots[j+1])
		}
	}
	tr.AbsorbFelt(pf.FinalValue)

	// Verify the grinding nonce before drawing queries (must match the prover).
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
		var expected Felt
		haveExpected := false
		for j := 0; j < L; j++ {
			Nj := N0 >> j
			half := Nj / 2
			p := pos % half
			lp := query.Layers[j]

			// Authenticate the ± pair as one paired leaf (half leaves per layer).
			if !VerifyRowMerkle(pf.Roots[j], half, p, []Felt{lp.X, lp.XSym}, lp.Path) {
				return nil, false
			}

			// Consistency with the value folded in from the previous layer: it
			// sits at index (pos mod Nj) ∈ {p, p+half}.
			if haveExpected {
				var atPrev Felt
				if pos%Nj < half {
					atPrev = lp.X
				} else {
					atPrev = lp.XSym
				}
				if expected != atPrev {
					return nil, false
				}
			}

			// Fold this layer's pair into the next (coset-shifted domain point).
			wj := RootOfUnity(logN0 - uint(j))
			x := cosetPows[j].Mul(wj.Exp(uint64(p)))
			expected = fold(lp.X, lp.XSym, x, alphas[j])
			haveExpected = true
		}
		// The chain must bottom out at the committed constant.
		if expected != pf.FinalValue {
			return nil, false
		}
	}
	return positions, true
}

// Layer0 returns the opened layer-0 ± values for query q (positions p and p+N0/2),
// used by the AIR/STARK verifier to cross-check the DEEP relation.
func (pf *FRIProof) layer0(q int) (Felt, Felt) {
	return pf.Queries[q].Layers[0].X, pf.Queries[q].Layers[0].XSym
}
