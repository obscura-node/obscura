// Package keystore encrypts a wallet seed at rest with a passphrase (Block 24 —
// see docs/INVENTION_KEYSTORE.md). Until now the seed lived on disk as plaintext
// hex: anyone who read the file owned the funds. A real wallet protects the seed
// behind a passphrase.
//
// Design (best practice, no novel crypto):
//   - Derive a 256-bit key from the passphrase with Argon2id — a memory-hard KDF,
//     so a stolen file resists GPU/ASIC brute force. The salt and the Argon2
//     parameters are stored IN the blob, so we can raise the cost over time
//     without breaking old files.
//   - Encrypt the seed with XChaCha20-Poly1305 (AEAD): a random 24-byte nonce
//     (XChaCha's large nonce makes random nonces safe) and a 16-byte auth tag.
//     The tag means a wrong passphrase or any tampering is DETECTED, not silently
//     decrypted to garbage.
package keystore

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// magic identifies an encrypted keystore blob (distinguishes it from a legacy
// plaintext-hex seed file).
var magic = []byte("OBXKS")

const (
	version = 1
	saltLen = 16
	keyLen  = 32
)

// Argon2id default cost. Stored per-blob so these can be raised later.
var (
	DefaultTime    uint32 = 3
	DefaultMemKiB  uint32 = 64 * 1024 // 64 MiB
	DefaultThreads uint8  = 4
)

// Upper bounds on the per-blob KDF parameters. A blob carries its own params so
// the cost can be raised over time, but an attacker could otherwise craft a blob
// with astronomical params to force a victim into a multi-hour KDF (a denial of
// service) — the AEAD tag is only checked AFTER the key is derived. So we reject
// out-of-range params BEFORE running Argon2.
//
// audit: SECURITY_AUDIT_2026-07-01 — the previous ceilings (64 iters × 4 GiB)
// still let a hostile blob force a multi-second KDF and, on a memory-constrained
// or WASM client, an allocation that hangs or OOMs the wallet before the AEAD
// tag can reject it. Tightened to sane maxima that keep generous headroom over
// the encryption-time defaults (time 3, 64 MiB) — so every legitimately produced
// file still passes — while capping the worst case at 1 GiB.
const (
	maxTime    uint32 = 16
	minMemKiB  uint32 = 8
	maxMemKiB  uint32 = 1024 * 1024 // 1 GiB
	maxThreads uint8  = 64
)

// IsEncrypted reports whether data is an encrypted keystore blob (vs a legacy
// plaintext seed file).
func IsEncrypted(data []byte) bool {
	return len(data) >= len(magic) && string(data[:len(magic)]) == string(magic)
}

// Encrypt seals seed under passphrase and returns a self-describing blob.
//
// Layout: magic(5) | version(1) | salt(16) | time(4) | memKiB(4) | threads(1) |
// nonce(24) | ciphertext+tag.
func Encrypt(seed, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("keystore: empty passphrase")
	}
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key := argon2.IDKey(passphrase, salt, DefaultTime, DefaultMemKiB, DefaultThreads, keyLen)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	var b []byte
	b = append(b, magic...)
	b = append(b, version)
	b = append(b, salt...)
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], DefaultTime)
	b = append(b, u32[:]...)
	binary.BigEndian.PutUint32(u32[:], DefaultMemKiB)
	b = append(b, u32[:]...)
	b = append(b, DefaultThreads)
	b = append(b, nonce...)
	// authenticate the header (magic..threads) as associated data so params can't
	// be tampered with to weaken decryption.
	ad := b[:len(magic)+1+saltLen+9]
	b = aead.Seal(b, nonce, seed, ad)
	return b, nil
}

// Decrypt opens a keystore blob with passphrase. A wrong passphrase or any
// tampering returns an error (never wrong-but-plausible bytes).
func Decrypt(blob, passphrase []byte) ([]byte, error) {
	const headLen = 5 + 1 + saltLen + 4 + 4 + 1 // magic+ver+salt+time+mem+threads = 31
	if !IsEncrypted(blob) {
		return nil, errors.New("keystore: not an encrypted keystore")
	}
	if len(blob) < headLen+chacha20poly1305.NonceSizeX {
		return nil, errors.New("keystore: blob too short")
	}
	if blob[len(magic)] != version {
		return nil, errors.New("keystore: unsupported version")
	}
	pos := len(magic) + 1
	salt := blob[pos : pos+saltLen]
	pos += saltLen
	t := binary.BigEndian.Uint32(blob[pos:])
	pos += 4
	mem := binary.BigEndian.Uint32(blob[pos:])
	pos += 4
	threads := blob[pos]
	pos++
	// Reject hostile/corrupt KDF params before doing any expensive work.
	if t == 0 || t > maxTime || mem < minMemKiB || mem > maxMemKiB || threads == 0 || threads > maxThreads {
		return nil, errors.New("keystore: KDF parameters out of range")
	}
	ad := blob[:pos]
	nonce := blob[pos : pos+chacha20poly1305.NonceSizeX]
	pos += chacha20poly1305.NonceSizeX
	ct := blob[pos:]

	key := argon2.IDKey(passphrase, salt, t, mem, threads, keyLen)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	seed, err := aead.Open(nil, nonce, ct, ad)
	if err != nil {
		return nil, errors.New("keystore: wrong passphrase or corrupt file")
	}
	return seed, nil
}
