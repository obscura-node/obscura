package stark

import "encoding/binary"

// Canonical parameters for the on-chain anonymous spend. The commitment-tree depth
// caps the anonymity set at 2^ZKDepth coins; ZKQueries sets the STARK soundness
// (~2 bits per query at rate 1/4 ⇒ ~80-bit). These are consensus constants.
// ZKDepth is the FIXED per-epoch commitment-tree depth = the anonymity-set size
// (2^ZKDepth coins per epoch). It is a var (not const) so tests can lower it to force
// epoch rollover and so deployments can raise it (e.g. 20 → ~1M, 22 → ~4M). Total
// coins are UNLIMITED regardless of depth via epoch sharding (EpochIMT) — depth only
// sets the anonymity set, not the capacity, and the per-proof cost is constant in it.
var ZKDepth = 16

// ZKQueries × 2 bits/query + friGrindBits ≈ 112-bit (conjectured) soundness.
const ZKQueries = 48

// FeltBytes is the canonical 8-byte big-endian encoding of a Felt (for tx fields
// and header roots).
func FeltBytes(f Felt) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(f))
	return b[:]
}

// FeltFromBytes decodes an 8-byte big-endian Felt, silently REDUCING mod P if the
// raw value is ≥ P.
//
// DANGER: silent reduction means a non-canonical encoding aliases to a canonical
// field element. This is fine ONLY for TRUSTED, already-canonical input (e.g. a
// wallet encoding its own Felt). For UNTRUSTED CONSENSUS input use ParseFelt, which
// rejects non-canonical bytes — otherwise the raw bytes (used for dedup/accounting)
// and the reduced felt (used in the proof) disagree, which has twice been a
// consensus-breaking bug (inflation + double-spend; see docs/SECURITY_AUDIT.md).
func FeltFromBytes(b []byte) Felt {
	if len(b) < 8 {
		var p [8]byte
		copy(p[8-len(b):], b)
		return NewFelt(binary.BigEndian.Uint64(p[:]))
	}
	return NewFelt(binary.BigEndian.Uint64(b[:8]))
}

// PModulus is the Goldilocks field modulus, exported so consensus can assert its
// economic bounds stay below it (no amount can alias).
const PModulus = P

// ParseFelt STRICTLY decodes a canonical 8-byte field element: ok=false unless the
// input is exactly 8 bytes AND encodes a value < P. This is the decoder for
// untrusted consensus input — a non-canonical encoding cannot pass, so the raw bytes
// and the field element are always the same value (no aliasing).
func ParseFelt(b []byte) (Felt, bool) {
	if len(b) != 8 {
		return 0, false
	}
	v := binary.BigEndian.Uint64(b)
	if v >= P {
		return 0, false
	}
	return Felt(v), true
}

// ParseNode STRICTLY decodes a canonical 32-byte node (4 canonical felts).
func ParseNode(b []byte) (Node256, bool) {
	if len(b) != 32 {
		return Node256{}, false
	}
	var n Node256
	for i := 0; i < 4; i++ {
		f, ok := ParseFelt(b[i*8 : i*8+8])
		if !ok {
			return Node256{}, false
		}
		n[i] = f
	}
	return n, true
}
