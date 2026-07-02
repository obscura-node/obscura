package commit

import (
	"errors"

	"filippo.io/edwards25519"
)

// Schnorr adaptor signatures over edwards25519 — the cryptographic cornerstone
// of trustless cross-chain atomic swaps (see docs/INVENTION_SWAPS.md).
//
// An adaptor signature is a "pre-signature" bound to a secret t (with adaptor
// point T = t·G). It can be VERIFIED without knowing t; the holder of t can
// ADAPT it into a full, valid Schnorr signature; and from the pre-signature plus
// the published full signature, ANYONE can EXTRACT t. This "publishing the
// signature reveals the secret" property is what makes a swap atomic: completing
// one chain's spend reveals the secret the counterparty needs to complete the
// other chain — with no scripts required on either side.
//
// Construction (per-output one-time key P = x·G):
//   pre-sign:  R = r·G ; e = H(R+T, P, m) ; s' = r + e·x ; presig = (R, s')
//   pre-verify: s'·G == R + e·P   with e = H(R+T, P, m)
//   adapt:     full = (R+T, s' + t)   — a normal Schnorr sig with nonce R+T
//   extract:   t = s_full − s'

// AdaptorSig is a Schnorr pre-signature bound to an adaptor point T.
type AdaptorSig struct {
	R []byte // nonce commitment r·G
	S []byte // pre-response s' = r + e·x
}

// FullSig is a completed Schnorr signature (nonce point R+T, response s'+t).
type FullSig struct {
	R []byte
	S []byte
}

func adaptorChallenge(noncePlusT *edwards25519.Point, P *edwards25519.Point, m []byte) *edwards25519.Scalar {
	return HashToScalar(netDom(), []byte("Obscura/adaptor"), noncePlusT.Bytes(), P.Bytes(), m)
}

// AdaptorChallenge is the exported challenge used by adaptor signatures, so the
// 2-of-2 swap co-signing layer can build a matching aggregate pre-signature.
func AdaptorChallenge(noncePlusT, pub *edwards25519.Point, m []byte) *edwards25519.Scalar {
	return adaptorChallenge(noncePlusT, pub, m)
}

// PreSign creates an adaptor pre-signature on message m under secret key x
// (P = x·G), bound to adaptor point T.
func PreSign(x *edwards25519.Scalar, m []byte, T *edwards25519.Point) *AdaptorSig {
	if T == nil || T.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil // degenerate adaptor point: pre-sig would equal a plain sig (no atomicity)
	}
	r := RandomScalar()
	R := new(edwards25519.Point).ScalarBaseMult(r)
	e := adaptorChallenge(new(edwards25519.Point).Add(R, T), pubOf(x), m)
	sPrime := new(edwards25519.Scalar).Add(r, new(edwards25519.Scalar).Multiply(e, x))
	return &AdaptorSig{R: R.Bytes(), S: sPrime.Bytes()}
}

// PreVerify checks an adaptor pre-signature against public key P and adaptor T
// (without knowing t).
func PreVerify(P []byte, m []byte, T *edwards25519.Point, pre *AdaptorSig) bool {
	if pre == nil || T == nil || T.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false // reject identity adaptor point: a plain sig would pass, breaking atomicity
	}
	Pp, err := parsePoint(P)
	if err != nil {
		return false
	}
	R, err := new(edwards25519.Point).SetBytes(pre.R)
	if err != nil {
		return false
	}
	sPrime, err := new(edwards25519.Scalar).SetCanonicalBytes(pre.S)
	if err != nil {
		return false
	}
	e := adaptorChallenge(new(edwards25519.Point).Add(R, T), Pp, m)
	lhs := new(edwards25519.Point).ScalarBaseMult(sPrime)
	rhs := new(edwards25519.Point).Add(R, new(edwards25519.Point).ScalarMult(e, Pp))
	return lhs.Equal(rhs) == 1
}

// Adapt completes a pre-signature into a full signature using the secret t.
func Adapt(pre *AdaptorSig, t *edwards25519.Scalar, T *edwards25519.Point) (*FullSig, error) {
	R, err := new(edwards25519.Point).SetBytes(pre.R)
	if err != nil {
		return nil, err
	}
	sPrime, err := new(edwards25519.Scalar).SetCanonicalBytes(pre.S)
	if err != nil {
		return nil, err
	}
	full := new(edwards25519.Point).Add(R, T) // nonce becomes R+T
	s := new(edwards25519.Scalar).Add(sPrime, t)
	return &FullSig{R: full.Bytes(), S: s.Bytes()}, nil
}

// Sign produces a plain Schnorr signature under key x (verifiable by VerifyFull),
// used for the swap refund path.
func Sign(x *edwards25519.Scalar, m []byte) *FullSig {
	r := RandomScalar()
	R := new(edwards25519.Point).ScalarBaseMult(r)
	e := adaptorChallenge(R, pubOf(x), m)
	s := new(edwards25519.Scalar).Add(r, new(edwards25519.Scalar).Multiply(e, x))
	return &FullSig{R: R.Bytes(), S: s.Bytes()}
}

// VerifyFull checks a completed Schnorr signature against public key P.
func VerifyFull(P []byte, m []byte, sig *FullSig) bool {
	Pp, err := parsePoint(P)
	if err != nil {
		return false
	}
	if Pp.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false // identity public key: anyone can forge a signature
	}
	R, err := new(edwards25519.Point).SetBytes(sig.R)
	if err != nil {
		return false
	}
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(sig.S)
	if err != nil {
		return false
	}
	e := adaptorChallenge(R, Pp, m) // R here is already R+T
	lhs := new(edwards25519.Point).ScalarBaseMult(s)
	rhs := new(edwards25519.Point).Add(R, new(edwards25519.Point).ScalarMult(e, Pp))
	return lhs.Equal(rhs) == 1
}

// Extract recovers the adaptor secret t from a pre-signature and the published
// full signature: t = s_full − s'. This is the atomicity hinge.
func Extract(pre *AdaptorSig, full *FullSig) (*edwards25519.Scalar, error) {
	sPrime, err := new(edwards25519.Scalar).SetCanonicalBytes(pre.S)
	if err != nil {
		return nil, err
	}
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(full.S)
	if err != nil {
		return nil, err
	}
	return new(edwards25519.Scalar).Subtract(s, sPrime), nil
}

// pubOf returns x·G.
func pubOf(x *edwards25519.Scalar) *edwards25519.Point {
	return new(edwards25519.Point).ScalarBaseMult(x)
}

// Serialize encodes a full signature as R(32) || S(32).
func (sig *FullSig) Serialize() []byte {
	out := make([]byte, 0, 64)
	out = append(out, sig.R...)
	out = append(out, sig.S...)
	return out
}

// ParseFullSig decodes a 64-byte full signature.
func ParseFullSig(b []byte) (*FullSig, error) {
	if len(b) != 64 {
		return nil, errors.New("commit: bad full-signature length")
	}
	return &FullSig{R: append([]byte(nil), b[:32]...), S: append([]byte(nil), b[32:]...)}, nil
}

var errAdaptor = errors.New("commit: adaptor signature invalid")
