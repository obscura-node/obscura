package swapsession

import (
	"filippo.io/edwards25519"

	"obscura/pkg/commit"
)

// nonceDomain separates deterministic swap-nonce derivation from every other
// hash-to-scalar use in the system (domain separation).
var nonceDomain = []byte("Obscura/swapsession/nonce/v1")

// DeriveNonce derives the per-claim Schnorr nonce r DETERMINISTICALLY from the
// signer's OWN secret share and the swap's core hash (RFC6979-style), instead of
// drawing a fresh random scalar each attempt (audit fix #13).
//
// WHY: the 2-of-2 claim is an adaptor co-signature ŝ = (ra+e·a)+(rb+e·b). If a
// party ever reuses a nonce r across two DIFFERENT challenges e≠e' (e.g. a retry
// after the coreHash changed because amount/timelock/peer-pubkeys were
// renegotiated), the two responses s = r+e·x and s' = r+e'·x solve for the
// secret share x = (s−s')/(e−e') — leaking a or b, hence the joint XNO key.
// Binding r to a hash of (own_secret || coreHash) makes r a deterministic
// function of the exact context being signed: a different coreHash yields a
// different, independent r, so a retry over new terms can NEVER reuse a nonce,
// and an identical re-derivation over the same context is harmless (same sig).
//
// The own secret is folded in so the nonce is unpredictable to the counterparty
// (who knows coreHash) — only the share holder can compute it. This mirrors
// RFC6979: nonce = H(secret, message).
func DeriveNonce(ownSecret *edwards25519.Scalar, coreHash []byte) *edwards25519.Scalar {
	return commit.HashToScalar(nonceDomain, ownSecret.Bytes(), coreHash)
}
