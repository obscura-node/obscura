package commit

import (
	"errors"

	"filippo.io/edwards25519"
)

// Chaum-Pedersen DLEQ: a non-interactive proof of knowledge of a scalar x such
// that P1 = x·G1 AND P2 = x·G2 — i.e. P1 and P2 share the same discrete log
// across two (possibly different) bases — WITHOUT revealing x. Used by payment
// proofs (Block 27) to prove that two curve points were produced with the same
// secret (e.g. a view key, or a transaction key) without disclosing that secret.

// scalarOne returns the scalar 1.
func scalarOne() *edwards25519.Scalar {
	b := make([]byte, 32)
	b[0] = 1
	s, _ := new(edwards25519.Scalar).SetCanonicalBytes(b)
	return s
}

// BasePoint is the ed25519 base point G as an explicit Point (so DLEQ can treat
// G as just another base alongside arbitrary points).
var BasePoint = new(edwards25519.Point).ScalarBaseMult(scalarOne())

// DLEQProof is a Fiat-Shamir Chaum-Pedersen proof (challenge, response).
type DLEQProof struct {
	C *edwards25519.Scalar
	S *edwards25519.Scalar
}

// ProveDLEQ proves knowledge of x with P1 = x·G1 and P2 = x·G2. The caller passes
// x and the two bases; the points P1,P2 are derived here and returned so the
// verifier and caller agree on them. dom is a domain-separation label.
// aad (additional authenticated data) is bound into the Fiat-Shamir challenge, so
// anything passed (e.g. an output's encrypted amount) is authenticated by the
// proof and cannot be altered without invalidating it. Each element is
// length-prefixed to keep the transcript unambiguous.
func dleqChallenge(dom string, g1, g2, p1, p2, t1, t2 *edwards25519.Point, aad [][]byte) *edwards25519.Scalar {
	parts := [][]byte{netDom(), []byte(dom), g1.Bytes(), g2.Bytes(), p1.Bytes(), p2.Bytes(), t1.Bytes(), t2.Bytes()}
	for _, a := range aad {
		var l [4]byte
		l[0], l[1], l[2], l[3] = byte(len(a)>>24), byte(len(a)>>16), byte(len(a)>>8), byte(len(a))
		parts = append(parts, l[:], a)
	}
	return HashToScalar(parts...)
}

func ProveDLEQ(x *edwards25519.Scalar, g1, g2 *edwards25519.Point, dom string, aad ...[]byte) (p1, p2 *edwards25519.Point, proof DLEQProof) {
	p1 = new(edwards25519.Point).ScalarMult(x, g1)
	p2 = new(edwards25519.Point).ScalarMult(x, g2)
	k := RandomScalar()
	t1 := new(edwards25519.Point).ScalarMult(k, g1)
	t2 := new(edwards25519.Point).ScalarMult(k, g2)
	c := dleqChallenge(dom, g1, g2, p1, p2, t1, t2, aad)
	// s = k + c·x
	s := new(edwards25519.Scalar).MultiplyAdd(c, x, k)
	return p1, p2, DLEQProof{C: c, S: s}
}

// VerifyDLEQ checks a Chaum-Pedersen proof that P1 = x·G1 and P2 = x·G2 for some
// shared x, using the same dom label and authenticated data. Rejects identity
// points (a degenerate statement) as a defensive measure.
func VerifyDLEQ(g1, p1, g2, p2 *edwards25519.Point, proof DLEQProof, dom string, aad ...[]byte) bool {
	if proof.C == nil || proof.S == nil {
		return false
	}
	idt := edwards25519.NewIdentityPoint()
	if g1.Equal(idt) == 1 || g2.Equal(idt) == 1 || p1.Equal(idt) == 1 || p2.Equal(idt) == 1 {
		return false
	}
	// T1 = s·G1 − c·P1 ; T2 = s·G2 − c·P2
	t1 := new(edwards25519.Point).Subtract(
		new(edwards25519.Point).ScalarMult(proof.S, g1),
		new(edwards25519.Point).ScalarMult(proof.C, p1))
	t2 := new(edwards25519.Point).Subtract(
		new(edwards25519.Point).ScalarMult(proof.S, g2),
		new(edwards25519.Point).ScalarMult(proof.C, p2))
	c := dleqChallenge(dom, g1, g2, p1, p2, t1, t2, aad)
	return c.Equal(proof.C) == 1
}

// SerializeDLEQ encodes a proof as 64 bytes (C||S).
func (p DLEQProof) Serialize() []byte {
	out := make([]byte, 0, 64)
	out = append(out, p.C.Bytes()...)
	out = append(out, p.S.Bytes()...)
	return out
}

// ParseDLEQ decodes a 64-byte proof.
func ParseDLEQ(b []byte) (DLEQProof, error) {
	if len(b) != 64 {
		return DLEQProof{}, errors.New("dleq: proof must be 64 bytes")
	}
	c, err := new(edwards25519.Scalar).SetCanonicalBytes(b[:32])
	if err != nil {
		return DLEQProof{}, err
	}
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(b[32:])
	if err != nil {
		return DLEQProof{}, err
	}
	return DLEQProof{C: c, S: s}, nil
}
