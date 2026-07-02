// Package nanocrypto holds the PURE, NETWORK-FREE Nano (XNO) cryptographic
// primitives shared by the node and the browser (WASM) wallet: the nano_ address
// codec, the state-block hash preimage, and the ed25519-blake2b signature scheme.
//
// It is a deliberate, verbatim extraction of the primitives proven in
// pkg/swapd/nanorpc.go (which are cross-checked against the reference
// nanocurrency-web library before any real funds move). swapd is intentionally
// NOT refactored to depend on this package — the working node code is left
// untouched. Instead this package exists so the SAME math can run client-side in
// WebAssembly for the non-custodial swap path, where the browser signs its own
// XNO blocks and the node only relays them.
//
// IMPORTANT: nanocrypto imports ONLY filippo.io/edwards25519 and blake2b — no
// net/http, no os, no bolt — so it compiles cleanly to GOOS=js GOARCH=wasm. A
// guard test in package swapd asserts nanocrypto's output is byte-identical to
// swapd's in-tree implementation, so the two can never silently diverge.
package nanocrypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/blake2b"
)

// DefaultRep is a well-known online Nano representative used when opening an
// account (matches the XNO reference template's DEFAULT_REP).
const DefaultRep = "nano_3arg3asgtigae3xckabaaewkx3bzsh7nwz7jkmjos79ihyaxwphhm6qgjps4"

// Nano v2 work thresholds: a send/change needs the HIGHER difficulty, a
// receive/open the LOWER one. (Confirmed against the XNO reference template.)
const (
	SendDifficulty    = "fffffff800000000"
	ReceiveDifficulty = "fffffe0000000000"
)

// ---- Nano state-block hashing + ed25519-blake2b signature ------------------

// statePreamble is the 32-byte domain separator Nano prepends to every state
// block hash.
var statePreamble = func() []byte { b := make([]byte, 32); b[31] = 0x06; return b }()

// StateHash computes the 32-byte blake2b hash that a Nano state block is
// identified and signed by:
//
//	blake2b256(preamble || account || previous || representative || balance16 || link).
func StateHash(account, previous, representative []byte, balance *big.Int, link []byte) []byte {
	h, _ := blake2b.New256(nil)
	h.Write(statePreamble)
	h.Write(account)
	h.Write(previous)
	h.Write(representative)
	// clamp the big-endian balance to its low 16 bytes so 16-len(bal) can never go
	// negative and panic in make(). A 128-bit raw value fits in 16 bytes; callers
	// must reject anything wider before hashing (this keeps the primitive total).
	bal := balance.Bytes()
	if len(bal) > 16 {
		bal = bal[len(bal)-16:]
	}
	pad := make([]byte, 16-len(bal)) // 128-bit big-endian balance
	h.Write(pad)
	h.Write(bal)
	h.Write(link)
	return h.Sum(nil)
}

// Sign produces a Nano ed25519-blake2b signature over msg (the 32-byte block
// hash) with a RAW scalar private key. Verifiable by Verify and by Nano nodes,
// which use blake2b as the EdDSA hash. R = r·G; k = blake2b512(R||A||msg) mod L;
// s = r + k·secret. The nonce is hedged-deterministic (secret || msg || fresh
// randomness) so two signatures over distinct blocks can never reuse a nonce.
func Sign(secret *edwards25519.Scalar, msg []byte) []byte {
	A := new(edwards25519.Point).ScalarBaseMult(secret)
	var rnd [32]byte
	_, _ = rand.Read(rnd[:])
	nh, _ := blake2b.New512(nil)
	nh.Write([]byte("obscura/nano-sweep/nonce"))
	nh.Write(secret.Bytes())
	nh.Write(msg)
	nh.Write(rnd[:])
	r, _ := new(edwards25519.Scalar).SetUniformBytes(nh.Sum(nil))
	R := new(edwards25519.Point).ScalarBaseMult(r)

	k := challenge(R.Bytes(), A.Bytes(), msg)
	s := new(edwards25519.Scalar).Add(r, new(edwards25519.Scalar).Multiply(k, secret))

	out := make([]byte, 64)
	copy(out[:32], R.Bytes())
	copy(out[32:], s.Bytes())
	return out
}

// challenge = blake2b512(R || A || msg) reduced mod L — Nano's EdDSA hash.
func challenge(R, A, msg []byte) *edwards25519.Scalar {
	h, _ := blake2b.New512(nil)
	h.Write(R)
	h.Write(A)
	h.Write(msg)
	k, _ := new(edwards25519.Scalar).SetUniformBytes(h.Sum(nil))
	return k
}

// Verify checks a signature as a Nano node would: s·G == R + k·A.
func Verify(pub, msg, sig []byte) bool {
	if len(sig) != 64 || len(pub) != 32 {
		return false
	}
	R, err := new(edwards25519.Point).SetBytes(sig[:32])
	if err != nil {
		return false
	}
	A, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return false
	}
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}
	k := challenge(sig[:32], pub, msg)
	negK := new(edwards25519.Scalar).Negate(k)
	lhs := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(negK, A, s)
	return lhs.Equal(R) == 1
}

// PubFromSecret returns the 32-byte ed25519 public key for a raw scalar secret —
// the account public key whose nano_ address EncodeAddress renders.
func PubFromSecret(secret *edwards25519.Scalar) []byte {
	return new(edwards25519.Point).ScalarBaseMult(secret).Bytes()
}

// ---- Nano address codec ----------------------------------------------------

const alphabet = "13456789abcdefghijkmnopqrstuwxyz"

func decodeRune(r byte) (int, bool) {
	i := strings.IndexByte(alphabet, r)
	return i, i >= 0
}

// EncodeAddress turns a 32-byte ed25519 public key into a nano_ address (account
// + 5-byte blake2b checksum), the canonical Nano account encoding.
func EncodeAddress(pub []byte) (string, error) {
	if len(pub) != 32 {
		return "", errors.New("nanocrypto: nano pubkey must be 32 bytes")
	}
	// account: 256 bits padded to 260 (4 leading zero bits) → 52 base32 chars.
	acct := encodeBase32Bits(pub, 52)
	// checksum: blake2b(pub, 5) reversed → 40 bits → 8 base32 chars.
	ck, _ := blake2b.New(5, nil)
	ck.Write(pub)
	cs := ck.Sum(nil)
	for i, j := 0, len(cs)-1; i < j; i, j = i+1, j-1 {
		cs[i], cs[j] = cs[j], cs[i]
	}
	check := encodeBase32Bits(cs, 8)
	return "nano_" + acct + check, nil
}

// DecodeAddress parses a nano_/xrb_ address back to its 32-byte public key,
// verifying the checksum.
func DecodeAddress(addr string) ([]byte, error) {
	a := addr
	switch {
	case strings.HasPrefix(a, "nano_"):
		a = a[5:]
	case strings.HasPrefix(a, "xrb_"):
		a = a[4:]
	default:
		return nil, errors.New("nanocrypto: address must start with nano_ or xrb_")
	}
	if len(a) != 60 {
		return nil, errors.New("nanocrypto: bad nano address length")
	}
	pub, err := decodeBase32Bits(a[:52], 32)
	if err != nil {
		return nil, err
	}
	csBytes, err := decodeBase32Bits(a[52:], 5)
	if err != nil {
		return nil, err
	}
	ck, _ := blake2b.New(5, nil)
	ck.Write(pub)
	want := ck.Sum(nil)
	for i, j := 0, len(want)-1; i < j; i, j = i+1, j-1 {
		want[i], want[j] = want[j], want[i]
	}
	if !bytes.Equal(csBytes, want) {
		return nil, errors.New("nanocrypto: nano address checksum mismatch")
	}
	return pub, nil
}

// encodeBase32Bits encodes data as `chars` Nano-base32 characters, MSB-first,
// left-padding with zero bits to fill the leading characters (Nano pads the
// 256-bit account to 260 bits).
func encodeBase32Bits(data []byte, chars int) string {
	v := new(big.Int).SetBytes(data)
	out := make([]byte, chars)
	mask := big.NewInt(31)
	for i := chars - 1; i >= 0; i-- {
		idx := new(big.Int).And(v, mask).Int64()
		out[i] = alphabet[idx]
		v.Rsh(v, 5)
	}
	return string(out)
}

// decodeBase32Bits reverses encodeBase32Bits into a big-endian byte slice of
// length `byteLen`.
func decodeBase32Bits(s string, byteLen int) ([]byte, error) {
	v := new(big.Int)
	for i := 0; i < len(s); i++ {
		d, ok := decodeRune(s[i])
		if !ok {
			return nil, fmt.Errorf("nanocrypto: invalid base32 char %q", s[i])
		}
		v.Lsh(v, 5)
		v.Or(v, big.NewInt(int64(d)))
	}
	b := v.Bytes()
	if len(b) > byteLen {
		b = b[len(b)-byteLen:] // drop the leading pad bits
	}
	out := make([]byte, byteLen)
	copy(out[byteLen-len(b):], b)
	return out, nil
}
