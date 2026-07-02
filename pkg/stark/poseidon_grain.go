package stark

// Grain LFSR round-constant generation — the CANONICAL Poseidon round-constant
// derivation from the reference `generate_parameters_grain.sage`, replacing the
// previous ad-hoc blake2b constants. An 80-bit LFSR is seeded from the parameter
// set (field, S-box, field-bit-size, width, round counts), clocked 160 times to
// warm up, then read with the Grain self-shrinking rule (two bits clocked per
// output bit) and rejection sampling to produce uniform field elements.
//
// IMPORTANT: this follows the widely-published algorithm (taps {0,13,23,38,51,62};
// init field=1/sbox=0/n=64/t/R_F/R_P then thirty 1-bits). It SHOULD be cross-checked
// against the reference sage script's known-answer constants before any production
// use — see docs/ZK_MEMBERSHIP_SPEND.md. It is deterministic and auditable, which is
// the point: standard-derived constants, not hand-rolled ones.

type grainLFSR struct {
	state [80]int
}

func newGrain(fieldFlag, sboxFlag, nBits, t, rf, rp int) *grainLFSR {
	bits := make([]int, 0, 80)
	push := func(v, width int) {
		for i := width - 1; i >= 0; i-- {
			bits = append(bits, (v>>uint(i))&1)
		}
	}
	push(fieldFlag, 2) // 1 = prime field GF(p)
	push(sboxFlag, 4)  // 0 = x^alpha
	push(nBits, 12)    // field size in bits
	push(t, 12)        // state width
	push(rf, 10)       // full rounds
	push(rp, 10)       // partial rounds
	for i := 0; i < 30; i++ {
		bits = append(bits, 1)
	}
	g := &grainLFSR{}
	copy(g.state[:], bits) // exactly 80 bits
	for i := 0; i < 160; i++ {
		g.clock() // warm-up
	}
	return g
}

// clock advances the LFSR and returns the fed-back bit (taps at 0,13,23,38,51,62).
func (g *grainLFSR) clock() int {
	nb := g.state[0] ^ g.state[13] ^ g.state[23] ^ g.state[38] ^ g.state[51] ^ g.state[62]
	copy(g.state[:79], g.state[1:])
	g.state[79] = nb
	return nb
}

// bit applies the Grain self-shrinking rule: clock two bits; the first decides
// whether the second is emitted.
func (g *grainLFSR) bit() int {
	for {
		b1 := g.clock()
		b2 := g.clock()
		if b1 == 1 {
			return b2
		}
	}
}

// fieldElement samples a uniform element of GF(P) by reading nBits at a time and
// rejecting values ≥ P.
func (g *grainLFSR) fieldElement(nBits int) Felt {
	for {
		var v uint64
		for i := 0; i < nBits; i++ {
			v = (v << 1) | uint64(g.bit())
		}
		if v < P {
			return Felt(v)
		}
	}
}

// grainRoundConstants generates rounds×t canonical round constants in order.
func grainRoundConstants(t, rf, rp int) [][]Felt {
	g := newGrain(1 /*GF(p)*/, 0 /*x^alpha*/, 64 /*Goldilocks bit size*/, t, rf, rp)
	out := make([][]Felt, rf+rp)
	for r := range out {
		row := make([]Felt, t)
		for i := 0; i < t; i++ {
			row[i] = g.fieldElement(64)
		}
		out[r] = row
	}
	return out
}
