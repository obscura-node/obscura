package commit

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"filippo.io/edwards25519"

	"obscura/pkg/stark"
)

// deriveNfSecret derives the recipient-only nullifier secret nsk (a field element)
// from the spend secret b. Because only the holder of b can recompute nsk, ONLY the
// recipient can produce the nullifier nf=H(nsk,rho) and prove the spend authority
// pk=H(nsk,0). The sender, who knows a coin's (rho,amount,blind) via the stealth
// shared secret, still cannot derive nsk and therefore cannot spend or link the coin.
func deriveNfSecret(b *edwards25519.Scalar) stark.Felt {
	h := sha512.Sum512(append([]byte("Obscura/nf-nsk"), b.Bytes()...))
	return stark.FeltFromBytes(h[:8])
}

// nfPkBytes returns the 32-byte recipient nf-address pk = H(nsk,0).
func nfPkBytes(nsk stark.Felt) []byte { return stark.NodeBytes(stark.NfAddress(nsk)) }

// Stealth (one-time) addresses give every output a fresh, unlinkable public
// key, so a recipient's long-term address never appears on chain. This is the
// dual-key scheme used by Monero:
//
//   - Recipient keys: view key (a, A=a·G) and spend key (b, B=b·G).
//   - Public address is (A, B).
//   - Sender picks random r, publishes R=r·G, and creates the one-time output
//     key P = Hs(r·A)·G + B.
//   - Recipient detects the output by recomputing Hs(a·R)·G + B == P (needs
//     only the view key) and spends with one-time secret x = Hs(a·R) + b.

// StealthAddress is a recipient's public dual-key address. NfPk is the recipient's
// 32-byte nf-address pk=H(nsk,0): a sender pays a ZK coin to this pk, but only the
// recipient (who holds nsk) can later derive the spending nullifier.
type StealthAddress struct {
	A    *edwards25519.Point // view public key
	B    *edwards25519.Point // spend public key
	NfPk []byte              // 32B recipient nf-address pk = H(nsk,0)
}

// StealthKeys is a recipient's full keypair.
type StealthKeys struct {
	a, b *edwards25519.Scalar // view secret, spend secret
	nsk  stark.Felt           // recipient-only nullifier secret (nf spend authority)
	Addr StealthAddress
}

// NfSecret returns the recipient-only nullifier secret nsk (zero for view-only keys),
// used to derive the spending nullifier nf=H(nsk,rho) for received ZK coins.
func (k *StealthKeys) NfSecret() stark.Felt { return k.nsk }

// NewStealthKeys generates a fresh recipient keypair.
func NewStealthKeys() *StealthKeys {
	a := RandomScalar()
	b := RandomScalar()
	nsk := deriveNfSecret(b)
	return &StealthKeys{
		a: a, b: b, nsk: nsk,
		Addr: StealthAddress{
			A:    new(edwards25519.Point).ScalarBaseMult(a),
			B:    new(edwards25519.Point).ScalarBaseMult(b),
			NfPk: nfPkBytes(nsk),
		},
	}
}

// IsViewOnly reports whether this is a watch-only keypair (view secret present,
// spend secret absent). Such a keypair can detect incoming outputs and decrypt
// amounts but cannot spend.
func (k *StealthKeys) IsViewOnly() bool { return k.b == nil }

// ViewKey exports the 64-byte view key (view secret a ‖ spend PUBLIC B). Sharing
// it lets another party scan/detect this wallet's incoming outputs and read their
// amounts WITHOUT being able to spend. Handle with care: it deanonymizes incoming
// funds to whoever holds it.
func (k *StealthKeys) ViewKey() []byte {
	out := make([]byte, 0, 96)
	out = append(out, k.a.Bytes()...)
	out = append(out, k.Addr.B.Bytes()...)
	out = append(out, k.nfPkOrZero()...) // 32B NfPk so a watch-only wallet can scan ZK coins
	return out
}

// nfPkOrZero returns the address's 32-byte NfPk, or 32 zero bytes if unset.
func (k *StealthKeys) nfPkOrZero() []byte {
	if len(k.Addr.NfPk) == 32 {
		return k.Addr.NfPk
	}
	return make([]byte, 32)
}

// StealthKeysFromViewKey builds a WATCH-ONLY keypair from a view key (a ‖ B ‖ NfPk,
// 96 bytes; a legacy 64-byte a‖B is also accepted but cannot scan ZK coins). It can
// scan and read amounts but not spend (no spend secret, no nsk).
func StealthKeysFromViewKey(vk []byte) (*StealthKeys, error) {
	if len(vk) != 64 && len(vk) != 96 {
		return nil, errors.New("stealth: view key must be 64 or 96 bytes")
	}
	a, err := new(edwards25519.Scalar).SetCanonicalBytes(vk[:32])
	if err != nil {
		return nil, err
	}
	B, err := new(edwards25519.Point).SetBytes(vk[32:64])
	if err != nil {
		return nil, err
	}
	addr := StealthAddress{A: new(edwards25519.Point).ScalarBaseMult(a), B: B}
	if len(vk) == 96 {
		addr.NfPk = append([]byte(nil), vk[64:96]...)
	}
	return &StealthKeys{a: a, b: nil, Addr: addr}, nil
}

// StealthKeysFromSeed deterministically derives keys from a 32-byte seed (for
// wallet recovery from a mnemonic/seed).
func StealthKeysFromSeed(seed []byte) *StealthKeys {
	ha := sha512.Sum512(append([]byte("Obscura/view"), seed...))
	hb := sha512.Sum512(append([]byte("Obscura/spend"), seed...))
	a, _ := edwards25519.NewScalar().SetUniformBytes(ha[:64])
	b, _ := edwards25519.NewScalar().SetUniformBytes(hb[:64])
	nsk := deriveNfSecret(b)
	return &StealthKeys{
		a: a, b: b, nsk: nsk,
		Addr: StealthAddress{
			A:    new(edwards25519.Point).ScalarBaseMult(a),
			B:    new(edwards25519.Point).ScalarBaseMult(b),
			NfPk: nfPkBytes(nsk),
		},
	}
}

// ErrWatchOnlySubaddress signals that a watch-only (view-only) keypair was asked
// for a subaddress it cannot derive. Because a subaddress's spend key depends on
// the master SPEND secret, a watch-only wallet (view secret only) cannot
// reconstruct subaddress public keys and therefore cannot detect payments sent to
// any subaddress — those funds are real but invisible to it. Callers should
// surface this rather than silently understating the balance.
//
// audit: SECURITY_AUDIT_2026-07-01 — previously Subaddress silently returned the
// main keypair for watch-only callers, so subaddress payments went undetected
// with no warning. Use SubaddressChecked to detect and report this case.
var ErrWatchOnlySubaddress = errors.New("stealth: watch-only wallet cannot detect subaddress payments")

// SubaddressChecked is Subaddress with an explicit signal for the watch-only
// limitation. It returns ErrWatchOnlySubaddress (along with the unchanged main
// keypair) when a watch-only keypair is asked for a non-zero subaddress, so the
// caller can warn the user instead of silently missing those payments.
func (k *StealthKeys) SubaddressChecked(index uint32) (*StealthKeys, error) {
	if index != 0 && k.b == nil {
		return k, ErrWatchOnlySubaddress
	}
	return k.Subaddress(index), nil
}

// Subaddress derives the keypair for sub-account `index` (index 0 is the main
// account, returned unchanged). Each subaddress is an INDEPENDENT keypair derived
// from the master secrets, so distinct subaddresses share no on-chain link and
// cannot be tied to the main address without the master keys. Payments to a
// subaddress use the ordinary output format (R = r·G), so senders and consensus
// need no changes — the wallet simply scans against all its subaddress keys.
//
// NOTE: a watch-only (view-only) keypair cannot derive subaddress spend keys and
// so CANNOT detect subaddress payments; this returns the main keypair unchanged
// in that case. Callers that need to warn the user should use SubaddressChecked.
func (k *StealthKeys) Subaddress(index uint32) *StealthKeys {
	if index == 0 || k.b == nil {
		// view-only keypairs can't derive subaddress spend keys; return self.
		return k
	}
	var ib [4]byte
	binary.BigEndian.PutUint32(ib[:], index)
	a := HashToScalar([]byte("Obscura/sub-view"), k.a.Bytes(), ib[:])
	b := HashToScalar([]byte("Obscura/sub-spend"), k.b.Bytes(), ib[:])
	nsk := deriveNfSecret(b)
	return &StealthKeys{
		a: a, b: b, nsk: nsk,
		Addr: StealthAddress{
			A:    new(edwards25519.Point).ScalarBaseMult(a),
			B:    new(edwards25519.Point).ScalarBaseMult(b),
			NfPk: nfPkBytes(nsk),
		},
	}
}

// StealthOutput is the on-chain data for a stealth output.
type StealthOutput struct {
	P *edwards25519.Point // one-time output public key
	R *edwards25519.Point // transaction public key r·G
}

// CreateOutput generates a one-time output to addr, returning the output and
// the shared secret scalar Hs(r·A) (the sender keeps nothing secret long-term).
func CreateOutput(addr StealthAddress) *StealthOutput {
	r := RandomScalar()
	R := new(edwards25519.Point).ScalarBaseMult(r)
	// shared secret = Hs(r·A)
	rA := new(edwards25519.Point).ScalarMult(r, addr.A)
	hs := HashToScalar([]byte("Obscura/stealth"), rA.Bytes())
	// P = hs·G + B
	P := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(hs), addr.B)
	return &StealthOutput{P: P, R: R}
}

// CreateOutputDeterministic is like CreateOutput but uses a supplied r (for
// testing and for deterministic re-derivation).
func CreateOutputDeterministic(addr StealthAddress, r *edwards25519.Scalar) *StealthOutput {
	R := new(edwards25519.Point).ScalarBaseMult(r)
	rA := new(edwards25519.Point).ScalarMult(r, addr.A)
	hs := HashToScalar([]byte("Obscura/stealth"), rA.Bytes())
	P := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(hs), addr.B)
	return &StealthOutput{P: P, R: R}
}

// ViewTag derives the 1-byte view tag from an ECDH shared secret. It uses a
// DISTINCT domain separation from the stealth one-time-key derivation
// ("Obscura/stealth"), so it leaks nothing beyond the 1 byte and cannot be
// related back to the spend key.
func ViewTag(shared []byte) byte {
	h := sha512.Sum512(append([]byte("Obscura/view-tag"), shared...))
	return h[0]
}

// ScanMatch is the fast wallet-scan path: it computes the shared secret once,
// rejects immediately on a view-tag mismatch (skipping the second scalar
// multiplication for ~255/256 of non-owned outputs), and only does the full
// ownership check on a tag hit.
func (k *StealthKeys) ScanMatch(out *StealthOutput, viewTag byte) bool {
	aR := new(edwards25519.Point).ScalarMult(k.a, out.R)
	shared := aR.Bytes()
	if ViewTag(shared) != viewTag {
		return false // cheap reject — the common case
	}
	hs := HashToScalar([]byte("Obscura/stealth"), shared)
	expected := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(hs), k.Addr.B)
	return expected.Equal(out.P) == 1
}

// Owns reports whether this keypair owns the given output (view-key scan).
func (k *StealthKeys) Owns(out *StealthOutput) bool {
	aR := new(edwards25519.Point).ScalarMult(k.a, out.R)
	hs := HashToScalar([]byte("Obscura/stealth"), aR.Bytes())
	expected := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(hs), k.Addr.B)
	return expected.Equal(out.P) == 1
}

// OneTimeSecret returns the one-time spend secret x for an owned output, with
// x·G == P. Errors if the output is not owned.
func (k *StealthKeys) OneTimeSecret(out *StealthOutput) (*edwards25519.Scalar, error) {
	if k.b == nil {
		return nil, errors.New("stealth: view-only wallet cannot derive spend secrets")
	}
	if !k.Owns(out) {
		return nil, errors.New("stealth: output not owned")
	}
	aR := new(edwards25519.Point).ScalarMult(k.a, out.R)
	hs := HashToScalar([]byte("Obscura/stealth"), aR.Bytes())
	return new(edwards25519.Scalar).Add(hs, k.b), nil
}

// SharedSecretSender returns the ECDH shared secret bytes r·A for the sender.
func SharedSecretSender(addr StealthAddress, r *edwards25519.Scalar) []byte {
	rA := new(edwards25519.Point).ScalarMult(r, addr.A)
	return rA.Bytes()
}

// SharedSecret returns the ECDH shared secret bytes a·R for the recipient.
func (k *StealthKeys) SharedSecret(out *StealthOutput) []byte {
	aR := new(edwards25519.Point).ScalarMult(k.a, out.R)
	return aR.Bytes()
}

// keystream derives a deterministic keystream of length n from a shared secret.
func keystream(shared []byte, label string, n int) []byte {
	out := make([]byte, 0, n)
	ctr := byte(0)
	for len(out) < n {
		h := sha512.Sum512(append(append([]byte("Obscura/ks/"+label), shared...), ctr))
		out = append(out, h[:]...)
		ctr++
	}
	return out[:n]
}

// EncryptBytes XORs plaintext with a shared-secret keystream (symmetric).
func EncryptBytes(shared []byte, label string, plaintext []byte) []byte {
	ks := keystream(shared, label, len(plaintext))
	out := make([]byte, len(plaintext))
	for i := range plaintext {
		out[i] = plaintext[i] ^ ks[i]
	}
	return out
}

// EncryptAmount encrypts an 8-byte amount with the shared secret.
func EncryptAmount(shared []byte, amount uint64) []byte {
	pt := []byte{
		byte(amount), byte(amount >> 8), byte(amount >> 16), byte(amount >> 24),
		byte(amount >> 32), byte(amount >> 40), byte(amount >> 48), byte(amount >> 56),
	}
	return EncryptBytes(shared, "amount", pt)
}

// DecryptAmount recovers an amount encrypted with EncryptAmount.
func DecryptAmount(shared, enc []byte) uint64 {
	if len(enc) != 8 {
		return 0
	}
	pt := EncryptBytes(shared, "amount", enc)
	return uint64(pt[0]) | uint64(pt[1])<<8 | uint64(pt[2])<<16 | uint64(pt[3])<<24 |
		uint64(pt[4])<<32 | uint64(pt[5])<<40 | uint64(pt[6])<<48 | uint64(pt[7])<<56
}

// EncryptScalar encrypts a 32-byte scalar (e.g. a blinding mask).
func EncryptScalar(shared []byte, s *edwards25519.Scalar) []byte {
	return EncryptBytes(shared, "mask", s.Bytes())
}

// DecryptScalar recovers a scalar encrypted with EncryptScalar.
func DecryptScalar(shared, enc []byte) (*edwards25519.Scalar, error) {
	pt := EncryptBytes(shared, "mask", enc)
	return new(edwards25519.Scalar).SetCanonicalBytes(pt)
}

// EncodeAddress serializes a stealth address as 96 bytes (A||B||NfPk).
func (a StealthAddress) Encode() []byte {
	out := make([]byte, 0, 96)
	out = append(out, a.A.Bytes()...)
	out = append(out, a.B.Bytes()...)
	pk := a.NfPk
	if len(pk) != 32 {
		pk = make([]byte, 32) // defensive: tolerate an unset NfPk (encodes as zero)
	}
	out = append(out, pk...)
	return out
}

// DecodeAddress parses a 96-byte stealth address (A||B||NfPk).
func DecodeAddress(b []byte) (StealthAddress, error) {
	if len(b) != 96 {
		return StealthAddress{}, errors.New("stealth: address must be 96 bytes")
	}
	A, err := new(edwards25519.Point).SetBytes(b[:32])
	if err != nil {
		return StealthAddress{}, err
	}
	B, err := new(edwards25519.Point).SetBytes(b[32:64])
	if err != nil {
		return StealthAddress{}, err
	}
	return StealthAddress{A: A, B: B, NfPk: append([]byte(nil), b[64:96]...)}, nil
}

// Seed returns the wallet's master seed scalars as bytes (view||spend) for
// backup. Handle with care.
func (k *StealthKeys) PrivateBytes() []byte {
	out := make([]byte, 0, 64)
	out = append(out, k.a.Bytes()...)
	if k.b != nil {
		out = append(out, k.b.Bytes()...)
	}
	return out
}

// randScalarForTest is exported indirectly for deterministic tests.
func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
