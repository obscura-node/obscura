package stark

// Poseidon over Goldilocks — an arithmetization-friendly hash (low-degree round
// function), the hash the ZK spend's AIR needs: a Merkle path is a chain of
// Poseidon compressions, and the nullifier is a Poseidon image. Unlike blake2b
// (cheap to run, brutal to express as polynomial constraints), Poseidon's round is
// add-constants → x⁷ S-box → MDS mix, all low-degree, so it has a compact AIR.
//
// EXPERIMENTAL PARAMETERS. The round count + S-box (x⁷, a permutation since
// gcd(7,P−1)=1) follow the Hades design, but the round constants here are derived
// from blake2b and the MDS is a Cauchy matrix (guaranteed invertible) rather than
// values from the reference Poseidon parameter-generation script. That is fine for
// building/validating the AIR; real deployment must regenerate constants with the
// official generator and run the security (statistical/algebraic) analysis. This
// hash is NOT wired into consensus.

const (
	poseidonT  = 3  // state width: rate 2 + capacity 1 (2-to-1 compression)
	poseidonRF = 8  // full rounds (4 before + 4 after the partial rounds)
	poseidonRP = 22 // partial rounds
	poseidonA  = 7  // S-box exponent x⁷
)

const poseidonRounds = poseidonRF + poseidonRP

// poseidonRC[round][pos] are the round constants; poseidonMDS is the mix matrix.
var (
	poseidonRC  [poseidonRounds][poseidonT]Felt
	poseidonMDS [poseidonT][poseidonT]Felt
)

func init() {
	// Round constants from the canonical Grain LFSR generator (poseidon_grain.go),
	// the reference Poseidon derivation — replaces the previous ad-hoc blake2b
	// constants.
	rc := grainRoundConstants(poseidonT, poseidonRF, poseidonRP)
	for r := 0; r < poseidonRounds; r++ {
		for i := 0; i < poseidonT; i++ {
			poseidonRC[r][i] = rc[r][i]
		}
	}
	// Cauchy MDS: M[i][j] = 1/(x_i − y_j) with x_i=i, y_j=t+j (the reference
	// Cauchy construction); every square submatrix of a Cauchy matrix is invertible
	// ⇒ MDS.
	xs := []Felt{0, 1, 2}
	ys := []Felt{3, 4, 5}
	for i := 0; i < poseidonT; i++ {
		for j := 0; j < poseidonT; j++ {
			poseidonMDS[i][j] = xs[i].Sub(ys[j]).Inv()
		}
	}
}

// sbox returns x⁷.
func sbox(x Felt) Felt {
	x2 := x.Mul(x)
	x4 := x2.Mul(x2)
	return x4.Mul(x2).Mul(x) // x⁴·x²·x = x⁷
}

// mds applies the MDS matrix to the state.
func mds(s [poseidonT]Felt) [poseidonT]Felt {
	var out [poseidonT]Felt
	for i := 0; i < poseidonT; i++ {
		acc := Felt(0)
		for j := 0; j < poseidonT; j++ {
			acc = acc.Add(poseidonMDS[i][j].Mul(s[j]))
		}
		out[i] = acc
	}
	return out
}

// PoseidonPermute applies the full Poseidon permutation to a width-3 state. Full
// rounds apply the S-box to every element; partial rounds only to element 0.
func PoseidonPermute(state [poseidonT]Felt) [poseidonT]Felt {
	s := state
	half := poseidonRF / 2
	round := 0
	apply := func(full bool) {
		for i := 0; i < poseidonT; i++ {
			s[i] = s[i].Add(poseidonRC[round][i])
		}
		if full {
			for i := 0; i < poseidonT; i++ {
				s[i] = sbox(s[i])
			}
		} else {
			s[0] = sbox(s[0])
		}
		s = mds(s)
		round++
	}
	for i := 0; i < half; i++ {
		apply(true)
	}
	for i := 0; i < poseidonRP; i++ {
		apply(false)
	}
	for i := 0; i < half; i++ {
		apply(true)
	}
	return s
}

// Domain-separation capacity IVs (reused by the AIR circuits so the in-circuit
// hash matches these exactly).
const (
	poseidonMerkleIV = 0x4f42585f6d726b6c % P // "OBX_mrkl"
	poseidonNullIV   = 0x4f42585f6e756c6c % P // "OBX_null"
)

// PoseidonHash2 compresses two field elements to one (2-to-1, for Merkle nodes):
// permute [a, b, IV] and take the first output element.
func PoseidonHash2(a, b Felt) Felt {
	out := PoseidonPermute([poseidonT]Felt{a, b, Felt(poseidonMerkleIV)})
	return out[0]
}

// PoseidonHash1 maps a single element to one (for the nullifier N = H(s)): permute
// [s, 0, IV] and take the first element.
func PoseidonHash1(s Felt) Felt {
	out := PoseidonPermute([poseidonT]Felt{s, 0, Felt(poseidonNullIV)})
	return out[0]
}
