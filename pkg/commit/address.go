package commit

import (
	"bytes"
	"errors"

	"golang.org/x/crypto/blake2b"

	"obscura/pkg/base58"
)

// Human-facing address format (Block 28 — see docs/INVENTION_ADDRESS.md). The
// raw wire address is 96 bytes (A||B||NfPk), which as hex is 192 error-prone
// characters. The human format adds a version byte (network/format tag) and a
// 4-byte checksum, then Base58-encodes the whole thing — so a mistyped address is
// almost always rejected instead of silently sending funds into the void.

// AddressVersion tags the network/format. Changing it changes the leading
// characters of every address and makes addresses from other networks fail to
// parse here.
// 0x2A: nf-note format — the address now carries the 32-byte nf-address NfPk
// (recipient-secret nullifier), so the payload widened from A||B to A||B||NfPk.
const AddressVersion byte = 0x2A

const addrPayloadLen = 1 + 96 // version + A||B||NfPk
const addrChecksumLen = 4

// String returns the human-facing Base58 checksummed address.
func (a StealthAddress) String() string {
	payload := make([]byte, 0, addrPayloadLen)
	payload = append(payload, AddressVersion)
	payload = append(payload, a.Encode()...)
	sum := blake2b.Sum256(payload)
	full := append(payload, sum[:addrChecksumLen]...)
	return base58.Encode(full)
}

// ParseHumanAddress decodes and verifies a Base58 checksummed address.
func ParseHumanAddress(s string) (StealthAddress, error) {
	raw, err := base58.Decode(s)
	if err != nil {
		return StealthAddress{}, err
	}
	if len(raw) != addrPayloadLen+addrChecksumLen {
		return StealthAddress{}, errors.New("address: wrong length")
	}
	if raw[0] != AddressVersion {
		return StealthAddress{}, errors.New("address: wrong network/version")
	}
	payload := raw[:addrPayloadLen]
	sum := blake2b.Sum256(payload)
	if !bytes.Equal(sum[:addrChecksumLen], raw[addrPayloadLen:]) {
		return StealthAddress{}, errors.New("address: checksum mismatch (likely a typo)")
	}
	return DecodeAddress(payload[1:])
}
