package stark

import (
	"encoding/binary"

	"golang.org/x/crypto/blake2b"

	"obscura/pkg/config"
)

// Transcript is a Fiat-Shamir transcript: the prover and verifier both absorb the
// same public values (Merkle roots, the final layer) and squeeze the same
// challenges, making the interactive FRI protocol non-interactive. Soundness
// depends on the verifier deriving challenges ONLY from already-committed data —
// never letting the prover choose a challenge after seeing it.
type Transcript struct {
	state [32]byte
}

// NewTranscript starts a transcript bound to a domain-separation label AND to the
// network/instance id (config.NetID). Binding netID makes every STARK challenge
// (FRI query positions, grinding, AIR composition) depend on which chain instance
// the proof targets, so an anon-spend/mint/cspend proof produced on one instance
// cannot replay verbatim on a sibling instance that re-minted the same coins
// (SECURITY_AUDIT: cross-instance replay). Every proof regenerates under the new
// transcript seed.
func NewTranscript(label string) *Transcript {
	t := &Transcript{}
	t.state = blake2b.Sum256([]byte("OBX/stark/transcript/" + config.NetIDHex() + "/" + label))
	return t
}

// AbsorbRoot mixes a Merkle root into the transcript.
func (t *Transcript) AbsorbRoot(root [32]byte) {
	var buf [64]byte
	copy(buf[:32], t.state[:])
	copy(buf[32:], root[:])
	t.state = blake2b.Sum256(buf[:])
}

// AbsorbFelt mixes a field element into the transcript.
func (t *Transcript) AbsorbFelt(f Felt) {
	var buf [40]byte
	copy(buf[:32], t.state[:])
	binary.BigEndian.PutUint64(buf[32:], uint64(f))
	t.state = blake2b.Sum256(buf[:])
}

// challengeBytes squeezes 32 fresh bytes and ratchets the state so successive
// challenges differ.
func (t *Transcript) challengeBytes() [32]byte {
	var buf [40]byte
	copy(buf[:32], t.state[:])
	binary.BigEndian.PutUint64(buf[32:], 0x9E3779B97F4A7C15) // ratchet constant
	out := blake2b.Sum256(buf[:])
	t.state = blake2b.Sum256(out[:]) // advance
	return out
}

// ChallengeFelt squeezes a field element challenge.
func (t *Transcript) ChallengeFelt() Felt {
	b := t.challengeBytes()
	return Felt(reduce128(binary.BigEndian.Uint64(b[8:16]), binary.BigEndian.Uint64(b[:8])))
}

// ChallengeFelt2 squeezes a uniform element of the degree-2 extension field
// F_{p^2}: one squeeze yields 32 bytes, from which we derive BOTH base coordinates
// (A from bytes[0:16], B from bytes[16:32], each reduced from 128→64 bits) so the
// resulting challenge ranges over all p^2 ≈ 2^128 elements. Used for every
// soundness-critical challenge (FRI fold α, OOD point z, composition + DEEP
// coefficients) so the Schwartz-Zippel / FRI error terms are floored at 1/p^2, not 1/p.
func (t *Transcript) ChallengeFelt2() Felt2 {
	b := t.challengeBytes()
	a := reduce128(binary.BigEndian.Uint64(b[8:16]), binary.BigEndian.Uint64(b[:8]))
	c := reduce128(binary.BigEndian.Uint64(b[24:32]), binary.BigEndian.Uint64(b[16:24]))
	return Felt2{A: Felt(a), B: Felt(c)}
}

// AbsorbFelt2 mixes an extension-field element into the transcript (both coordinates).
func (t *Transcript) AbsorbFelt2(f Felt2) {
	t.AbsorbFelt(f.A)
	t.AbsorbFelt(f.B)
}

// ChallengeIndex squeezes a uniform integer in [0, n) (n a power of two).
func (t *Transcript) ChallengeIndex(n int) int {
	b := t.challengeBytes()
	v := binary.BigEndian.Uint64(b[:8])
	return int(v & uint64(n-1))
}

// powHash binds the current transcript state to a grinding nonce.
func (t *Transcript) powHash(nonce uint64) [32]byte {
	var buf [48]byte
	copy(buf[:32], t.state[:])
	copy(buf[32:36], []byte("grnd"))
	binary.BigEndian.PutUint64(buf[40:], nonce)
	return blake2b.Sum256(buf[:])
}

func leadingZeroBits(h [32]byte) int {
	n := 0
	for _, b := range h {
		if b == 0 {
			n += 8
			continue
		}
		for bit := 7; bit >= 0; bit-- {
			if b&(1<<uint(bit)) == 0 {
				n++
			} else {
				return n
			}
		}
	}
	return n
}

// Grind finds a nonce whose powHash has ≥ bits leading zero bits, absorbs it into
// the transcript, and returns it. This raises the cost of a prover re-rolling the
// transcript to bias the query positions (Fiat-Shamir grinding resistance) by 2^bits.
func (t *Transcript) Grind(bits int) uint64 {
	for nonce := uint64(0); ; nonce++ {
		if leadingZeroBits(t.powHash(nonce)) >= bits {
			t.AbsorbFelt(Felt(nonce))
			return nonce
		}
	}
}

// VerifyGrind checks a grinding nonce meets the difficulty and absorbs it (keeping
// the verifier transcript in lock-step with the prover).
func (t *Transcript) VerifyGrind(bits int, nonce uint64) bool {
	if leadingZeroBits(t.powHash(nonce)) < bits {
		return false
	}
	t.AbsorbFelt(Felt(nonce))
	return true
}
