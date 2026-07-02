// Package pqsign provides POST-QUANTUM spend-authorization signatures for Obscura
// (Phase 1 of the PQ roadmap — see docs/POST_QUANTUM_ROADMAP.md).
//
// It implements WOTS+ (Winternitz One-Time Signature, hash-based). The choice is
// driven by Obscura's model: every output has a ONE-TIME public key spent exactly
// once, so a one-time signature is a perfect fit — none of the state/index
// management that makes XMSS/SPHINCS+ awkward applies here. Security rests ONLY on
// BLAKE2b (second-preimage / collision resistance), which a quantum computer only
// weakens quadratically (Grover) — i.e. this is post-quantum under the most
// conservative assumption, with no trusted setup.
//
// Sizes (n=32, w=16): public key 32 bytes (fits the existing one-time-key slot),
// signature ~2 KB, verification ~1000 BLAKE2b calls (microseconds). It is a
// SEPARATE package off the default consensus path, so the classical coin's speed
// is unaffected; PQ spends opt in (see the hybrid helper and the roadmap).
//
// NOTE: this is a clean, self-contained WOTS+ for the research track. It follows
// the WOTS+ construction (per-(chain,position) keyed hashing as the one-way
// function, so each chain step is a distinct OWF instance — no single global
// collision shortcut) but is NOT byte-compatible with RFC 8391 XMSS-WOTS. It
// wants an independent review before any mainnet use.
package pqsign

import (
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/blake2b"
)

// Parameters: n = 32-byte hash, Winternitz w = 16 (4 bits per chain).
const (
	n    = 32             // hash output bytes
	w    = 16             // Winternitz parameter
	logW = 4              // log2(w)
	len1 = (8 * n) / logW // 64 message chains
	len2 = 3              // checksum chains (ceil for max checksum 64*15=960)
	wlen = len1 + len2    // 67 total chains

	// SigSize is the serialized signature length: pubSeed(32) + wlen*32.
	SigSize = n + wlen*n
	// PubKeySize is the WOTS+ public-key (root) length.
	PubKeySize = n
	// SeedSize is the secret seed length.
	SeedSize = n
)

func h(parts ...[]byte) []byte {
	d, _ := blake2b.New256(nil)
	for _, p := range parts {
		d.Write(p)
	}
	return d.Sum(nil)
}

func le32(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}

// chain applies `steps` one-way iterations to x starting at position `start` in
// chain j, keyed by pubSeed. Each step is a distinct keyed hash (acts as the
// WOTS+ bitmask/address), so no global collision lets an attacker skip ahead.
func chain(x, pubSeed []byte, j, start, steps int) []byte {
	out := append([]byte(nil), x...)
	for k := start; k < start+steps; k++ {
		out = h(pubSeed, le32(uint32(j)), le32(uint32(k)), out)
	}
	return out
}

// digits decodes a 32-byte message into wlen base-w digits (message + checksum).
func digits(msg []byte) []int {
	d := make([]int, 0, wlen)
	for _, b := range msg { // logW=4 → two nibbles per byte
		d = append(d, int(b>>4), int(b&0x0f))
	}
	// checksum = Σ (w-1 - d_i), encoded big-endian into len2 base-w digits.
	csum := 0
	for _, di := range d {
		csum += (w - 1) - di
	}
	for i := len2 - 1; i >= 0; i-- {
		d = append(d, (csum>>(uint(i)*logW))&(w-1))
	}
	return d
}

// pubSeedOf and skOf derive the public seed and per-chain secret starts from the
// secret seed (so the secret key is just 32 bytes).
func pubSeedOf(seed []byte) []byte { return h(seed, []byte("Obscura/pq/wots/pubseed/v1")) }
func skChain(seed []byte, j int) []byte {
	return h(seed, []byte("Obscura/pq/wots/sk/v1"), le32(uint32(j)))
}

// rootOf computes the public key (root) from the chain tops under pubSeed.
func rootOf(pubSeed []byte, tops [][]byte) []byte {
	parts := make([][]byte, 0, 1+len(tops))
	parts = append(parts, pubSeed)
	parts = append(parts, tops...)
	return h(parts...)
}

// KeyGen derives a WOTS+ keypair from a 32-byte secret seed. The public key
// (32-byte root) is deterministic from the seed.
func KeyGen(seed []byte) (pub []byte, err error) {
	if len(seed) != SeedSize {
		return nil, errors.New("pqsign: seed must be 32 bytes")
	}
	pubSeed := pubSeedOf(seed)
	tops := make([][]byte, wlen)
	for j := 0; j < wlen; j++ {
		tops[j] = chain(skChain(seed, j), pubSeed, j, 0, w-1)
	}
	return rootOf(pubSeed, tops), nil
}

// Sign produces a WOTS+ signature of msg (any length; hashed to 32 bytes) under
// the seed. The seed MUST be used for exactly one message (one-time signature) —
// which is exactly Obscura's one-time-key model.
func Sign(seed, msg []byte) ([]byte, error) {
	if len(seed) != SeedSize {
		return nil, errors.New("pqsign: seed must be 32 bytes")
	}
	m := h(msg)
	pubSeed := pubSeedOf(seed)
	d := digits(m)
	sig := make([]byte, 0, SigSize)
	sig = append(sig, pubSeed...)
	for j := 0; j < wlen; j++ {
		sig = append(sig, chain(skChain(seed, j), pubSeed, j, 0, d[j])...)
	}
	return sig, nil
}

// Verify checks a WOTS+ signature of msg against the public key (root).
func Verify(pub, msg, sig []byte) bool {
	if len(pub) != PubKeySize || len(sig) != SigSize {
		return false
	}
	pubSeed := sig[:n]
	m := h(msg)
	d := digits(m)
	tops := make([][]byte, wlen)
	for j := 0; j < wlen; j++ {
		sj := sig[n+j*n : n+(j+1)*n]
		// from position d[j], advance to the chain top (w-1)
		tops[j] = chain(sj, pubSeed, j, d[j], (w-1)-d[j])
	}
	got := rootOf(pubSeed, tops)
	return subtleEqual(got, pub)
}

func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
