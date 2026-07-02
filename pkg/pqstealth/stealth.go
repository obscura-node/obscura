// Package pqstealth provides POST-QUANTUM payment detection and amount
// confidentiality for Obscura (Phase 2 of the PQ roadmap).
//
// It uses ML-KEM-768 (Kyber) from the Go 1.25 standard library (crypto/mlkem) —
// pure-Go, NIST-standardized (FIPS 203), no external dependency and no trusted
// setup. A recipient publishes an ML-KEM encapsulation key as their PQ view key.
// To pay them, the sender encapsulates to obtain a shared secret, attaches the
// KEM ciphertext to the transaction, and uses the shared secret to (a) tag the
// output so the recipient can detect it and (b) encrypt the amount. A quantum
// adversary who records the chain cannot recover the shared secret (ML-KEM is
// PQ-IND-CCA2), so amounts and recipient-linkage stay private even under
// harvest-now-decrypt-later — unlike the classical X25519 ECDH stealth path,
// which Shor breaks.
//
// SCOPE (honest): this layer makes payment DETECTION and AMOUNT CONFIDENTIALITY
// post-quantum. Non-interactive PQ *spend-authority* one-time keys (the hash/
// lattice analogue of Monero's P = Hs(ss)·G + B, where the sender derives the
// output key from public data without being able to spend) is an open research
// problem — hash- and lattice-based signatures lack the key-homomorphism that
// makes classical stealth spend keys work. Obscura's practical answer is the
// HYBRID one-time key (pkg/pqsign): the classical half provides the
// non-interactive one-time spend key today, and the WOTS+ half adds PQ spend
// protection. See docs/POST_QUANTUM_ROADMAP.md.
//
// Cost: one ML-KEM ciphertext (1088 bytes) per recipient per transaction — the
// price of PQ recipient privacy. It is off the default consensus path, so the
// classical coin's size and speed are unchanged.
package pqstealth

import (
	"crypto/mlkem"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/blake2b"
)

const (
	// TagSize identifies an output as belonging to a recipient.
	TagSize = 16
	// MACSize authenticates the encrypted amount.
	MACSize = 16
	// EncAmountSize is the ciphertext length for a uint64 amount.
	EncAmountSize = 8
)

func kdf(label string, ss []byte, extra ...[]byte) []byte {
	d, _ := blake2b.New256(nil)
	d.Write([]byte("Obscura/pq/stealth/v1/"))
	d.Write([]byte(label))
	d.Write(ss)
	for _, e := range extra {
		d.Write(e)
	}
	return d.Sum(nil)
}

// ViewKey is a recipient's PQ detection key (the ML-KEM decapsulation key plus
// its public encapsulation key).
type ViewKey struct {
	dk *mlkem.DecapsulationKey768
}

// GenerateViewKey creates a fresh PQ view key.
func GenerateViewKey() (*ViewKey, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &ViewKey{dk: dk}, nil
}

// ViewKeyFromSeed deterministically derives a view key from a 64-byte seed
// (e.g. derived from the wallet mnemonic), so the PQ view key need not be stored
// separately.
func ViewKeyFromSeed(seed []byte) (*ViewKey, error) {
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, err
	}
	return &ViewKey{dk: dk}, nil
}

// PublicKey returns the encapsulation-key bytes to publish as the PQ view key.
func (v *ViewKey) PublicKey() []byte { return v.dk.EncapsulationKey().Bytes() }

// Seed returns the 64-byte decapsulation seed (secret — back this up).
func (v *ViewKey) Seed() []byte { return v.dk.Bytes() }

// Announcement is the on-chain PQ stealth material for one output.
type Announcement struct {
	KEMCiphertext []byte // 1088 bytes (ML-KEM-768)
	Tag           []byte // TagSize — lets the recipient detect the output
	EncAmount     []byte // EncAmountSize — amount XOR keystream
	MAC           []byte // MACSize — authenticates EncAmount under the shared secret
}

// Send creates an announcement paying `amount` to the recipient identified by
// their encapsulation-key bytes. It also returns the shared secret, which the
// caller can mix into the hybrid one-time spend key derivation.
func Send(recipientPub []byte, amount uint64) (*Announcement, []byte, error) {
	ek, err := mlkem.NewEncapsulationKey768(recipientPub)
	if err != nil {
		return nil, nil, errors.New("pqstealth: bad recipient key")
	}
	ss, ct := ek.Encapsulate()
	ann := seal(ss, ct, amount)
	return ann, ss, nil
}

func seal(ss, ct []byte, amount uint64) *Announcement {
	var amt [8]byte
	binary.LittleEndian.PutUint64(amt[:], amount)
	ks := kdf("enc", ss)
	enc := make([]byte, EncAmountSize)
	subtle.XORBytes(enc, amt[:], ks[:EncAmountSize])
	tag := kdf("tag", ss)[:TagSize]
	mac := kdf("mac", ss, enc)[:MACSize]
	return &Announcement{KEMCiphertext: ct, Tag: tag, EncAmount: enc, MAC: mac}
}

// DetectTag recognizes an output by its KEM ciphertext and detection tag alone
// (used when the amount is carried in the clear on-chain — the consensus PQ path
// pending the confidential range proof). Returns the shared secret on a match.
func (v *ViewKey) DetectTag(kemCiphertext, tag []byte) (ss []byte, ok bool) {
	if len(kemCiphertext) != mlkem.CiphertextSize768 || len(tag) != TagSize {
		return nil, false
	}
	ss, err := v.dk.Decapsulate(kemCiphertext)
	if err != nil {
		return nil, false
	}
	if subtle.ConstantTimeCompare(kdf("tag", ss)[:TagSize], tag) != 1 {
		return nil, false
	}
	return ss, true
}

// Scan tries to recognize and decrypt an announcement. ok is true only if the
// announcement was addressed to this view key. It returns the amount and the
// shared secret (for spend-key derivation).
func (v *ViewKey) Scan(ann *Announcement) (amount uint64, ss []byte, ok bool) {
	if ann == nil || len(ann.KEMCiphertext) != mlkem.CiphertextSize768 ||
		len(ann.Tag) != TagSize || len(ann.EncAmount) != EncAmountSize || len(ann.MAC) != MACSize {
		return 0, nil, false
	}
	ss, err := v.dk.Decapsulate(ann.KEMCiphertext)
	if err != nil {
		return 0, nil, false
	}
	// ML-KEM implicit rejection: a ciphertext not meant for us yields a
	// pseudo-random ss, so the tag/MAC simply won't match.
	wantTag := kdf("tag", ss)[:TagSize]
	if subtle.ConstantTimeCompare(wantTag, ann.Tag) != 1 {
		return 0, nil, false
	}
	wantMAC := kdf("mac", ss, ann.EncAmount)[:MACSize]
	if subtle.ConstantTimeCompare(wantMAC, ann.MAC) != 1 {
		return 0, nil, false
	}
	ks := kdf("enc", ss)
	var amt [8]byte
	subtle.XORBytes(amt[:], ann.EncAmount, ks[:EncAmountSize])
	return binary.LittleEndian.Uint64(amt[:]), ss, true
}
