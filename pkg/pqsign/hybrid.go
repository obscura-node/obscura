package pqsign

import (
	"crypto/rand"
	"errors"

	"filippo.io/edwards25519"
)

// Hybrid spend authorization = classical Schnorr (edwards25519) AND WOTS+.
//
// The one-time key committed on-chain is HybridKey = BLAKE2b(P || R), binding
// BOTH a classical public point P = x·G and a WOTS+ root R. A valid spend must
// present a valid Schnorr proof for P AND a valid WOTS+ signature for R over the
// same message (the tx CoreHash). To forge a spend an attacker must defeat BOTH
// primitives, so the output stays secure as long as EITHER holds:
//
//   - Today: edwards25519 ECDLP is hard → secure even though WOTS+ is new code.
//   - After a cryptographically-relevant quantum computer: Shor breaks the
//     Schnorr half, but WOTS+ (hash-based) still stands → funds remain safe.
//
// This is the standard "hybrid / belt-and-suspenders" migration posture and is
// the conservative way to introduce PQ crypto without betting everything on the
// newer assumption. It lives off the default consensus path; see
// docs/POST_QUANTUM_ROADMAP.md for the integration plan.

// HybridPriv is a hybrid secret key: a classical scalar plus a WOTS+ seed.
type HybridPriv struct {
	x     *edwards25519.Scalar // classical secret, P = x·G
	wSeed []byte               // WOTS+ seed (32 bytes), one-time
}

// HybridPub is the public material: classical point P, WOTS+ root R, and the
// committed one-time key Key = H(P || R).
type HybridPub struct {
	P   []byte // 32-byte compressed edwards25519 point
	R   []byte // 32-byte WOTS+ root
	Key []byte // 32-byte BLAKE2b(P || R) — the on-chain one-time key
}

// HybridSig carries both halves: the Schnorr signature (over the classical key)
// and the WOTS+ signature (over the same message).
type HybridSig struct {
	Schnorr []byte // 64 bytes: R_point(32) || s(32)
	Wots    []byte // SigSize bytes
}

// HybridKeyOf computes the committed one-time key from P and R.
func HybridKeyOf(P, R []byte) []byte { return h(P, []byte("Obscura/pq/hybrid/v1"), R) }

// GenerateHybrid creates a fresh hybrid keypair.
func GenerateHybrid() (*HybridPriv, *HybridPub, error) {
	var sb [64]byte
	if _, err := rand.Read(sb[:]); err != nil {
		return nil, nil, err
	}
	x, err := edwards25519.NewScalar().SetUniformBytes(sb[:])
	if err != nil {
		return nil, nil, err
	}
	wSeed := make([]byte, SeedSize)
	if _, err := rand.Read(wSeed); err != nil {
		return nil, nil, err
	}
	return newHybrid(x, wSeed)
}

func newHybrid(x *edwards25519.Scalar, wSeed []byte) (*HybridPriv, *HybridPub, error) {
	P := new(edwards25519.Point).ScalarBaseMult(x)
	R, err := KeyGen(wSeed)
	if err != nil {
		return nil, nil, err
	}
	pb := P.Bytes()
	pub := &HybridPub{P: pb, R: R, Key: HybridKeyOf(pb, R)}
	return &HybridPriv{x: x, wSeed: wSeed}, pub, nil
}

// schnorrChallenge binds the commitment, public key and message.
func schnorrChallenge(Rpt, P, msg []byte) *edwards25519.Scalar {
	c := h([]byte("Obscura/pq/hybrid/schnorr/v1"), Rpt, P, msg)
	var buf [64]byte
	copy(buf[:32], c)
	s, _ := edwards25519.NewScalar().SetUniformBytes(buf[:])
	return s
}

// HybridSign produces both signatures over msg.
func HybridSign(priv *HybridPriv, pub *HybridPub, msg []byte) (*HybridSig, error) {
	if priv == nil || pub == nil {
		return nil, errors.New("pqsign: nil key")
	}
	// Schnorr: pick nonce k, Rpt = k·G, s = k + c·x.
	var kb [64]byte
	if _, err := rand.Read(kb[:]); err != nil {
		return nil, err
	}
	k, err := edwards25519.NewScalar().SetUniformBytes(kb[:])
	if err != nil {
		return nil, err
	}
	Rpt := new(edwards25519.Point).ScalarBaseMult(k).Bytes()
	c := schnorrChallenge(Rpt, pub.P, msg)
	s := edwards25519.NewScalar().Multiply(c, priv.x)
	s = edwards25519.NewScalar().Add(k, s)
	schnorr := append(append([]byte(nil), Rpt...), s.Bytes()...)

	wsig, err := Sign(priv.wSeed, msg)
	if err != nil {
		return nil, err
	}
	return &HybridSig{Schnorr: schnorr, Wots: wsig}, nil
}

// inv8 is 8^{-1} mod L (the edwards25519 group order), used for the prime-order
// subgroup test.
var inv8 = func() *edwards25519.Scalar {
	var b [32]byte
	b[0] = 8
	eight, _ := edwards25519.NewScalar().SetCanonicalBytes(b[:])
	return edwards25519.NewScalar().Invert(eight)
}()

// inPrimeOrder reports whether Q lies in the prime-order subgroup (no torsion
// component). Multiplying by the cofactor 8 kills any torsion part; multiplying
// back by 8^{-1} returns Q only if Q had none to begin with.
func inPrimeOrder(Q *edwards25519.Point) bool {
	t := new(edwards25519.Point).MultByCofactor(Q)
	t = new(edwards25519.Point).ScalarMult(inv8, t)
	return t.Equal(Q) == 1
}

// HybridVerify checks that the signature is valid under BOTH primitives and that
// P and R match the committed one-time key.
func HybridVerify(key []byte, P, R []byte, msg []byte, sig *HybridSig) bool {
	if sig == nil || len(P) != 32 || len(R) != PubKeySize || len(sig.Schnorr) != 64 {
		return false
	}
	// 1) the revealed P, R must reconstruct the committed key
	if !subtleEqual(HybridKeyOf(P, R), key) {
		return false
	}
	// 2) Schnorr: s·G == Rpt + c·P. Reject the identity and any point carrying a
	// torsion component (not in the prime-order subgroup) on BOTH P and Rpt, so
	// the signature is unique (no cofactor malleability). [audit Finding F1]
	Pp, err := new(edwards25519.Point).SetBytes(P)
	if err != nil || Pp.Equal(edwards25519.NewIdentityPoint()) == 1 || !inPrimeOrder(Pp) {
		return false
	}
	Rpt := sig.Schnorr[:32]
	Rptp, err := new(edwards25519.Point).SetBytes(Rpt)
	if err != nil || Rptp.Equal(edwards25519.NewIdentityPoint()) == 1 || !inPrimeOrder(Rptp) {
		return false
	}
	s, err := edwards25519.NewScalar().SetCanonicalBytes(sig.Schnorr[32:])
	if err != nil {
		return false
	}
	c := schnorrChallenge(Rpt, P, msg)
	lhs := new(edwards25519.Point).ScalarBaseMult(s)
	rhs := new(edwards25519.Point).ScalarMult(c, Pp)
	rhs = rhs.Add(Rptp, rhs)
	if lhs.Equal(rhs) != 1 {
		return false
	}
	// 3) WOTS+ (the post-quantum half)
	return Verify(R, msg, sig.Wots)
}
