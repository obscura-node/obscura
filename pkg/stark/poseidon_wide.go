package stark

// Width-8 Poseidon + Jive compression — the cryptographic core of the fix for the
// 64-bit commitment-hash collision weakness (docs/ZK_MEMBERSHIP_SPEND.md). The
// width-3 PoseidonHash2 outputs a single 64-bit element → Merkle nodes have only
// ~2³² collision resistance. This wider instance produces 4-element (256-bit) nodes
// via the Jive compression mode, giving ~2¹²⁸ collision resistance.
//
// This is implemented as SEPARATE code (it does not touch the working width-3
// system). Migrating the commitment tree + the membership/spend/mint AIR circuits +
// the chain leaf encoding onto 4-element nodes is the remaining (large) step,
// designed in docs/ZK_MEMBERSHIP_SPEND.md. Round constants come from the same Grain
// generator (parameterized by width); the MDS is the reference Cauchy matrix. Round
// counts (R_F, R_P) still need the official security analysis for t=8 — flagged.

const (
	poseidonWideT  = 8 // state width: 4-element rate + 4-element capacity (256-bit)
	poseidonWideRF = 8
	poseidonWideRP = 22
)

const poseidonWideRounds = poseidonWideRF + poseidonWideRP

var (
	poseidonWideRC  [poseidonWideRounds][poseidonWideT]Felt
	poseidonWideMDS [poseidonWideT][poseidonWideT]Felt
)

func init() {
	rc := grainRoundConstants(poseidonWideT, poseidonWideRF, poseidonWideRP)
	for r := 0; r < poseidonWideRounds; r++ {
		copy(poseidonWideRC[r][:], rc[r])
	}
	// Cauchy MDS: M[i][j] = 1/(x_i − y_j), x_i=i, y_j=t+j (disjoint ⇒ invertible).
	for i := 0; i < poseidonWideT; i++ {
		for j := 0; j < poseidonWideT; j++ {
			poseidonWideMDS[i][j] = NewFelt(uint64(i)).Sub(NewFelt(uint64(poseidonWideT + j))).Inv()
		}
	}
}

func wideFullRound(r int) bool {
	half := poseidonWideRF / 2
	return r < half || r >= half+poseidonWideRP
}

// poseidonWidePermute applies the width-8 Poseidon permutation.
func poseidonWidePermute(state [poseidonWideT]Felt) [poseidonWideT]Felt {
	s := state
	for r := 0; r < poseidonWideRounds; r++ {
		for i := 0; i < poseidonWideT; i++ {
			s[i] = s[i].Add(poseidonWideRC[r][i])
		}
		if wideFullRound(r) {
			for i := 0; i < poseidonWideT; i++ {
				s[i] = sbox(s[i])
			}
		} else {
			s[0] = sbox(s[0])
		}
		// MDS mix
		var out [poseidonWideT]Felt
		for i := 0; i < poseidonWideT; i++ {
			acc := Felt(0)
			for j := 0; j < poseidonWideT; j++ {
				acc = acc.Add(poseidonWideMDS[i][j].Mul(s[j]))
			}
			out[i] = acc
		}
		s = out
	}
	return s
}

// wideRoundStep applies ONE width-8 Poseidon round (used by the AIR trace builder so
// it matches poseidonWidePermute exactly).
func wideRoundStep(s [poseidonWideT]Felt, r int) [poseidonWideT]Felt {
	for i := 0; i < poseidonWideT; i++ {
		s[i] = s[i].Add(poseidonWideRC[r][i])
	}
	if wideFullRound(r) {
		for i := 0; i < poseidonWideT; i++ {
			s[i] = sbox(s[i])
		}
	} else {
		s[0] = sbox(s[0])
	}
	var out [poseidonWideT]Felt
	for i := 0; i < poseidonWideT; i++ {
		acc := Felt(0)
		for j := 0; j < poseidonWideT; j++ {
			acc = acc.Add(poseidonWideMDS[i][j].Mul(s[j]))
		}
		out[i] = acc
	}
	return out
}

// Node256 is a 256-bit commitment-tree node (4 Goldilocks elements).
type Node256 [4]Felt

// JiveCompress is the Jive_2 compression: two 4-element nodes → one 4-element node,
// with a feed-forward (Davies-Meyer-style) that makes it collision-resistant rather
// than a permutation. out[i] = x[i] + x[i+4] + perm(x)[i] + perm(x)[i+4].
func JiveCompress(left, right Node256) Node256 {
	var x [poseidonWideT]Felt
	copy(x[:4], left[:])
	copy(x[4:], right[:])
	y := poseidonWidePermute(x)
	var out Node256
	for i := 0; i < 4; i++ {
		out[i] = x[i].Add(x[i+4]).Add(y[i]).Add(y[i+4])
	}
	return out
}

// Node256FromFelts packs up to 4 field elements into a node (the rest zero) — e.g.
// a leaf commitment hashed into 256 bits.
func Node256FromFelts(fs ...Felt) Node256 {
	var n Node256
	for i := 0; i < len(fs) && i < 4; i++ {
		n[i] = fs[i]
	}
	return n
}

// WideHash2 is the 2-to-1 commitment-tree compression used BOTH in the clear (here)
// and inside the AIR. It is the collision-resistant Jive_2 compression (feed-forward):
// out[i] = (left‖right)[i] + (left‖right)[i+4] + perm8(left‖right)[i] +
// perm8(left‖right)[i+4]. The earlier truncation form out = perm8(left‖right)[0:4] was
// an INVERTIBLE permutation with no capacity / feed-forward, so it admitted Merkle
// collisions and forged membership paths (crypto audit, reproduced O(1)). The Jive
// feed-forward (Davies-Meyer-style) closes that: the input is folded into the output,
// destroying invertibility, giving a true ~2¹²⁸ collision-resistant compression. All
// native callers (imt256.go, the AIR leaf/sponge helpers, SpendLeaf256, mint256, …)
// pick up the safe version with no rename; the AIRs circuitise the SAME fold via the
// f-columns + root-output binding (see wideMerkleConstraints).
func WideHash2(left, right Node256) Node256 {
	return JiveCompress(left, right)
}
