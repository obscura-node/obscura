// Package pqcommit provides a POST-QUANTUM, additively-homomorphic commitment
// for Obscura amounts (Phase 2 of the PQ roadmap).
//
// Obscura's confidential transactions rely on Pedersen commitments whose
// HOMOMORPHISM lets a verifier check value conservation (Σ inputs = Σ outputs)
// without learning amounts. Pedersen binding rests on the discrete log, which
// Shor breaks — a quantum attacker could open a commitment to a different value
// and mint coins. This package replaces it with a lattice (BDLOP-style)
// commitment whose binding rests on the Short Integer Solution problem (no known
// quantum attack better than generic lattice reduction) and which is STILL
// additively homomorphic, so the existing conservation-proof shape carries over.
//
// Structure (BDLOP): pick public random matrices A1 (n1×m) and A2 (1×m) over
// Z_q and commit to amount v with a SHORT randomness vector r ∈ [-B,B]^m:
//
//	c1 = A1 · r            (mod q)     — the binding part
//	c2 = A2 · r + v        (mod q)     — the message part
//
// Binding: two short openings (v,r) ≠ (v',r') of the same c force A1(r−r') = 0
// with r−r' short → a SIS solution; if r = r' then c2 fixes v = v'. Hiding:
// A1·r and A2·r are pseudorandom for short r (leftover-hash / LWE), so c reveals
// nothing about v. The matrices come from a fixed public seed via a BLAKE2b XOF —
// nothing-up-my-sleeve, NO trusted setup.
//
// Homomorphism (this is the point): adding componentwise,
//
//	Commit(v1;r1) + Commit(v2;r2) = Commit(v1+v2; r1+r2)   (mod q)
//
// exactly. The randomness sums, so its coefficients grow with the number of
// terms; binding holds as long as the summed randomness stays under the SIS
// bound — fine for the bounded input/output count of a transaction (documented
// in the roadmap).
//
// PARAMETERS HERE ARE ILLUSTRATIVE for the research track and amounts must be
// < Q (single message limb). Production use needs formal Module-SIS parameter
// selection over a polynomial ring (multi-limb amounts), and an independent
// review. This lives off the default consensus path, so the shipping coin's
// speed is unaffected.
package pqcommit

import (
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/blake2b"
)

// Illustrative parameters.
const (
	Q       = (1 << 32) - 5 // 32-bit prime modulus (4294967291)
	N1      = 128           // binding dimension (rows of A1)
	RandLen = 512           // randomness dimension m
	RandB   = 4096          // |r_i| <= RandB (short)
)

// Commitment holds the binding part c1 (N1 coeffs) and message part c2 (1 coeff).
type Commitment struct {
	C1 [N1]uint32
	C2 uint32
}

type params struct {
	a1 []uint32 // N1*RandLen
	a2 []uint32 // RandLen
}

var pp = genParams("Obscura/pq/bdlop/v1")

func genParams(seed string) *params {
	xof, _ := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	xof.Write([]byte(seed))
	buf := make([]byte, 4)
	read := func(count int) []uint32 {
		out := make([]uint32, count)
		for i := range out {
			for { // rejection sampling for uniform mod Q
				xof.Read(buf)
				v := uint64(binary.LittleEndian.Uint32(buf))
				if v < Q {
					out[i] = uint32(v)
					break
				}
			}
		}
		return out
	}
	return &params{a1: read(N1 * RandLen), a2: read(RandLen)}
}

func canon(ri int32) uint64 { return uint64(((int64(ri) % Q) + Q) % Q) }

// linearMap computes (A1·r, A2·r + v) mod Q without bound checks.
func linearMap(v uint64, r []int32) *Commitment {
	var c Commitment
	for row := 0; row < N1; row++ {
		var acc uint64
		base := row * RandLen
		for k := 0; k < RandLen; k++ {
			acc = (acc + uint64(pp.a1[base+k])*canon(r[k])) % Q
		}
		c.C1[row] = uint32(acc)
	}
	var acc uint64 = v % Q
	for k := 0; k < RandLen; k++ {
		acc = (acc + uint64(pp.a2[k])*canon(r[k])) % Q
	}
	c.C2 = uint32(acc)
	return &c
}

// Commit computes the commitment to amount v (must be < Q) with short randomness
// r (length RandLen, |r_i| <= RandB).
func Commit(v uint64, r []int32) (*Commitment, error) {
	if len(r) != RandLen {
		return nil, errors.New("pqcommit: randomness must have length RandLen")
	}
	if v >= Q {
		return nil, errors.New("pqcommit: amount must be < Q (single-limb demo)")
	}
	for _, ri := range r {
		if ri > RandB || ri < -RandB {
			return nil, errors.New("pqcommit: randomness coefficient out of bound")
		}
	}
	return linearMap(v, r), nil
}

// CommitNoBound applies the commitment map WITHOUT the short-randomness bound
// check. It is for AGGREGATE / conservation arithmetic — e.g. forming
// Commit(0; Σr_in − Σr_out) to verify value balance — where the summed
// randomness legitimately exceeds the per-commitment bound RandB. Do NOT use it
// to create a stand-alone commitment (binding needs the bound); use Commit.
func CommitNoBound(v uint64, r []int32) (*Commitment, error) {
	if len(r) != RandLen {
		return nil, errors.New("pqcommit: randomness must have length RandLen")
	}
	return linearMap(v%Q, r), nil
}

// Add returns the homomorphic sum (mod Q) of two commitments.
func (c *Commitment) Add(d *Commitment) *Commitment {
	var out Commitment
	for i := 0; i < N1; i++ {
		out.C1[i] = uint32((uint64(c.C1[i]) + uint64(d.C1[i])) % Q)
	}
	out.C2 = uint32((uint64(c.C2) + uint64(d.C2)) % Q)
	return &out
}

// Sub returns c − d (mod Q).
func (c *Commitment) Sub(d *Commitment) *Commitment {
	var out Commitment
	for i := 0; i < N1; i++ {
		out.C1[i] = uint32((uint64(c.C1[i]) + Q - uint64(d.C1[i])) % Q)
	}
	out.C2 = uint32((uint64(c.C2) + Q - uint64(d.C2)) % Q)
	return &out
}

// Equal reports whether two commitments are identical.
func (c *Commitment) Equal(d *Commitment) bool {
	if c.C2 != d.C2 {
		return false
	}
	for i := 0; i < N1; i++ {
		if c.C1[i] != d.C1[i] {
			return false
		}
	}
	return true
}

// Open verifies that (v, r) is a valid opening of c (with r within bound).
func Open(c *Commitment, v uint64, r []int32) bool {
	got, err := Commit(v, r)
	if err != nil {
		return false
	}
	return got.Equal(c)
}

// Bytes serializes a commitment ((N1+1) little-endian uint32).
func (c *Commitment) Bytes() []byte {
	out := make([]byte, (N1+1)*4)
	for i := 0; i < N1; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], c.C1[i])
	}
	binary.LittleEndian.PutUint32(out[N1*4:], c.C2)
	return out
}
