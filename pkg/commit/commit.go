// Package commit implements Pedersen commitments, confidential-amount
// conservation proofs, and bit-decomposition range proofs over the
// edwards25519 prime-order group. These hide transaction amounts while letting
// the network verify that no coins are created out of thin air.
//
// A Pedersen commitment to value v with blinding r is C = v·H + r·G, where G is
// the edwards25519 base point and H is a second generator whose discrete log
// w.r.t. G is unknown (derived by hash-to-point). Commitments are additively
// homomorphic: C(v1,r1) + C(v2,r2) = C(v1+v2, r1+r2), which is what makes
// confidential conservation checks possible.
package commit

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"

	"filippo.io/edwards25519"

	"obscura/pkg/config"
)

// netDom is the network/instance domain-separation prefix (config.NetID) mixed
// into every PROOF/SIGNATURE Fiat-Shamir challenge in this package so a Schnorr,
// DLEQ, adaptor, range, anon-spend or one-of-many proof produced on one chain
// instance cannot replay verbatim on a sibling instance that re-minted the same
// coins (SECURITY_AUDIT: cross-instance replay). It is length-prefixed (a fixed
// 32 bytes) ahead of the rest of the transcript so it is unambiguous. NOTE: this
// binds proofs/signatures only — stealth one-time-key DERIVATIONS (Obscura/stealth,
// sub-view/sub-spend) are wallet key material, not replayable proofs, and are
// intentionally left unchanged so existing addresses/keys are unaffected.
func netDom() []byte {
	id := config.NetID()
	out := make([]byte, len(netDomTag)+32)
	copy(out, netDomTag)
	copy(out[len(netDomTag):], id[:])
	return out
}

var netDomTag = []byte("OBX/commit/netID/v1")

// G is the standard edwards25519 base point.
func G() *edwards25519.Point {
	return edwards25519.NewGeneratorPoint()
}

// H is the second Pedersen generator with unknown dlog w.r.t. G.
var hPoint = mustHashToPoint([]byte("Obscura/Pedersen/H/v1"))

// H returns the value-generator H.
func H() *edwards25519.Point { return new(edwards25519.Point).Set(hPoint) }

// RandomScalar returns a uniformly random scalar.
func RandomScalar() *edwards25519.Scalar {
	var b [64]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("commit: rng failure")
	}
	s, err := edwards25519.NewScalar().SetUniformBytes(b[:])
	if err != nil {
		panic(err)
	}
	return s
}

// ScalarFromUint64 returns a scalar equal to n.
func ScalarFromUint64(n uint64) *edwards25519.Scalar {
	var b [64]byte
	b[0] = byte(n)
	b[1] = byte(n >> 8)
	b[2] = byte(n >> 16)
	b[3] = byte(n >> 24)
	b[4] = byte(n >> 32)
	b[5] = byte(n >> 40)
	b[6] = byte(n >> 48)
	b[7] = byte(n >> 56)
	s, _ := edwards25519.NewScalar().SetUniformBytes(b[:])
	return s
}

// HashToScalar maps arbitrary data to a scalar (for Fiat-Shamir challenges).
func HashToScalar(data ...[]byte) *edwards25519.Scalar {
	h := sha512.New()
	for _, d := range data {
		h.Write(d)
	}
	sum := h.Sum(nil)
	s, _ := edwards25519.NewScalar().SetUniformBytes(sum[:64])
	return s
}

// Commit returns C = v·H + r·G.
func Commit(v uint64, r *edwards25519.Scalar) *edwards25519.Point {
	vH := new(edwards25519.Point).ScalarMult(ScalarFromUint64(v), hPoint)
	rG := new(edwards25519.Point).ScalarBaseMult(r)
	return new(edwards25519.Point).Add(vH, rG)
}

// CommitScalar returns C = v·H + r·G for an arbitrary scalar value (used in
// proofs where the value is not a small uint).
func CommitScalar(v, r *edwards25519.Scalar) *edwards25519.Point {
	vH := new(edwards25519.Point).ScalarMult(v, hPoint)
	rG := new(edwards25519.Point).ScalarBaseMult(r)
	return new(edwards25519.Point).Add(vH, rG)
}

// mustHashToPoint deterministically derives a curve point from a seed (NUMS).
// Try-and-increment: hash, attempt to decode as a compressed point, then clear
// the cofactor so the result lands in the prime-order subgroup.
func mustHashToPoint(seed []byte) *edwards25519.Point {
	ctr := byte(0)
	for {
		h := sha512.Sum512(append(append([]byte("Obscura/H2C"), seed...), ctr))
		var enc [32]byte
		copy(enc[:], h[:32])
		p, err := new(edwards25519.Point).SetBytes(enc[:])
		if err == nil {
			// clear cofactor (×8) to ensure prime-order subgroup membership
			p.MultByCofactor(p)
			if p.Equal(edwards25519.NewIdentityPoint()) != 1 {
				return p
			}
		}
		ctr++
		if ctr == 0 {
			panic("commit: hash-to-point exhausted")
		}
	}
}

var errBadProof = errors.New("commit: proof verification failed")
