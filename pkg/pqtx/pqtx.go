//go:build pq

// Package pqtx wires Obscura's post-quantum primitives into an end-to-end
// OUTPUT + SPEND variant, gated behind the `pq` build tag AND a version byte so
// the default consensus path is untouched (it does not compile into the shipping
// binary; the classical coin's speed and wire size are unchanged). Build/test it
// with `-tags pq`.
//
// It is the concrete realization of docs/POST_QUANTUM_ROADMAP.md's "next step":
// a PQ output whose one-time key is the HYBRID key (classical Schnorr ⊕ WOTS+),
// spent by revealing (P, R) and a HybridSig that pqsign.HybridVerify checks
// against the spend's CoreHash — so the spend is authorized only if BOTH the
// classical and the post-quantum half verify (secure while either assumption
// holds). It mirrors the classical model (pkg/tx, pkg/chain, pkg/wallet):
//
//   - PQOutput mirrors tx.Output: OneTimeKey + amount commitment + stealth data.
//   - PQSpend mirrors tx.Input + tx.Transaction: it references an output, reveals
//     (P, R), carries a nullifier (bound pre-CoreHash, like KeyImage), and a
//     HybridSig (computed post-CoreHash, like the classical proofs).
//   - Ledger mirrors pkg/chain: a global Merkle anonymity set (pqaccum), a shared
//     nullifier set, and a UTXO map; ValidateSpend/ApplySpend mirror
//     validateTxLocked/applyBlock.
//
// PQ building blocks used:
//   - pqsign   — WOTS+ + hybrid one-time key / signature (spend authority).
//   - pqstealth— ML-KEM-768 payment detection + amount confidentiality.
//   - pqcommit — BDLOP/SIS homomorphic amount commitment (value conservation).
//   - pqaccum  — BLAKE2b Merkle accumulator (global anonymity set membership).
//
// Honest scope (see roadmap): membership here is transparent (it reveals the
// output ref, like the classical transparent path) — full ZK-private membership
// needs the zk-STARK that remains future work. The nullifier is bound to the
// WOTS+ root R, which is itself bound into the output's hybrid key, so it is
// post-quantum sound. The conservation check reveals only the aggregate blinding
// difference (not amounts); a PQ proof-of-knowledge / range proof is future work.
package pqtx

import (
	"bytes"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/blake2b"

	"obscura/pkg/pqcommit"
	"obscura/pkg/pqsign"
	"obscura/pkg/pqstealth"
)

// Version is the output/spend variant discriminator (classical tx uses Version
// 1; the PQ variant uses 2). A node selects this validation path by version.
const Version uint16 = 2

// PQOutput is the post-quantum analogue of tx.Output.
type PQOutput struct {
	Version    uint16 // == Version
	OneTimeKey []byte // 32B hybrid one-time key = BLAKE2b(P‖R) (pqsign.HybridPub.Key)
	Commitment []byte // serialized pqcommit.Commitment (PQ amount commitment)
	// Stealth (pqstealth.Announcement) — PQ payment detection + amount encryption:
	KEMCiphertext []byte // ML-KEM-768 ciphertext (1088B)
	ViewTag       []byte // detection tag
	EncAmount     []byte // encrypted amount
	MAC           []byte // amount authenticator
}

// PQSpend is the post-quantum analogue of tx.Input fused with tx.Transaction:
// it authorizes spending one output and creates new outputs.
type PQSpend struct {
	Version   uint16     // == Version
	OutputRef []byte     // spent output's OneTimeKey (its hybrid key)
	P         []byte     // 32B classical point P = x·G, revealed at spend
	WotsRoot  []byte     // 32B WOTS+ root R, revealed at spend
	Nullifier []byte     // 32B = BLAKE2b("null"‖R); bound pre-CoreHash (like KeyImage)
	HybridSig []byte     // serialized pqsign.HybridSig; computed post-CoreHash
	Outputs   []PQOutput // newly created outputs
	Fee       uint64     // public fee
	BlindDiff []int32    // aggregate blinding difference for conservation (see roadmap)
}

var (
	errVersion   = errors.New("pqtx: wrong version")
	errMalformed = errors.New("pqtx: malformed")
)

const nullDom = "Obscura/pq/nullifier/v1"

// NullifierOf derives the nullifier deterministically from the WOTS+ root R.
// Because R is bound into the output's hybrid key (Key = H(P‖R)) and
// HybridVerify enforces that binding, a spender cannot present a different R —
// hence cannot forge a different nullifier — and spending the same output twice
// reproduces the same nullifier. PQ-sound (BLAKE2b collision resistance).
func NullifierOf(wotsRoot []byte) []byte {
	d, _ := blake2b.New256(nil)
	d.Write([]byte(nullDom))
	d.Write(wotsRoot)
	return d.Sum(nil)
}

// --- length-prefixed serialization helpers (mirror pkg/tx wB/rB/wU64) ---

func wB(buf *bytes.Buffer, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	buf.Write(l[:])
	buf.Write(b)
}

func wU64(buf *bytes.Buffer, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	buf.Write(b[:])
}

func wU16(buf *bytes.Buffer, v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	buf.Write(b[:])
}

func serializeOutput(buf *bytes.Buffer, o *PQOutput) {
	wU16(buf, o.Version)
	wB(buf, o.OneTimeKey)
	wB(buf, o.Commitment)
	wB(buf, o.KEMCiphertext)
	wB(buf, o.ViewTag)
	wB(buf, o.EncAmount)
	wB(buf, o.MAC)
}

// CoreHash binds the spend's content EXCLUDING the HybridSig (which signs it),
// mirroring tx.CoreHash excluding the proof fields. The nullifier IS included
// (its value is bound), like the classical KeyImage.
func (s *PQSpend) CoreHash() []byte {
	var buf bytes.Buffer
	wU16(&buf, s.Version)
	wB(&buf, s.OutputRef)
	wB(&buf, s.P)
	wB(&buf, s.WotsRoot)
	wB(&buf, s.Nullifier)
	wU64(&buf, s.Fee)
	wU64(&buf, uint64(len(s.Outputs)))
	for i := range s.Outputs {
		serializeOutput(&buf, &s.Outputs[i])
	}
	// BlindDiff and HybridSig are deliberately excluded from the signed core.
	h := blake2b.Sum256(buf.Bytes())
	return h[:]
}

// Serialize encodes the full spend (including HybridSig and BlindDiff) for wire.
func (s *PQSpend) Serialize() []byte {
	var buf bytes.Buffer
	core := s.CoreHash() // not stored; just ensures determinism path exists
	_ = core
	wU16(&buf, s.Version)
	wB(&buf, s.OutputRef)
	wB(&buf, s.P)
	wB(&buf, s.WotsRoot)
	wB(&buf, s.Nullifier)
	wB(&buf, s.HybridSig)
	wU64(&buf, s.Fee)
	wU64(&buf, uint64(len(s.Outputs)))
	for i := range s.Outputs {
		serializeOutput(&buf, &s.Outputs[i])
	}
	wU64(&buf, uint64(len(s.BlindDiff)))
	for _, d := range s.BlindDiff {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(d))
		buf.Write(b[:])
	}
	return buf.Bytes()
}

func parseHybridSig(b []byte) (*pqsign.HybridSig, error) {
	// HybridSig wire = wB(Schnorr)‖wB(Wots)
	r := bytes.NewReader(b)
	schnorr, err := readB(r)
	if err != nil {
		return nil, err
	}
	wots, err := readB(r)
	if err != nil {
		return nil, err
	}
	return &pqsign.HybridSig{Schnorr: schnorr, Wots: wots}, nil
}

func serializeHybridSig(sig *pqsign.HybridSig) []byte {
	var buf bytes.Buffer
	wB(&buf, sig.Schnorr)
	wB(&buf, sig.Wots)
	return buf.Bytes()
}

func readB(r *bytes.Reader) ([]byte, error) {
	var l [4]byte
	if _, err := r.Read(l[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(l[:])
	if n > 1<<20 {
		return nil, errMalformed
	}
	out := make([]byte, n)
	if n > 0 {
		if _, err := r.Read(out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// parseCommitment rebuilds a pqcommit.Commitment from its serialized bytes.
func parseCommitment(b []byte) (*pqcommit.Commitment, error) {
	want := (pqcommit.N1 + 1) * 4
	if len(b) != want {
		return nil, errMalformed
	}
	var c pqcommit.Commitment
	for i := 0; i < pqcommit.N1; i++ {
		c.C1[i] = binary.LittleEndian.Uint32(b[i*4:])
	}
	c.C2 = binary.LittleEndian.Uint32(b[pqcommit.N1*4:])
	return &c, nil
}

// outputAnnouncement reconstructs the stealth announcement embedded in an output.
func (o *PQOutput) announcement() *pqstealth.Announcement {
	return &pqstealth.Announcement{
		KEMCiphertext: o.KEMCiphertext,
		Tag:           o.ViewTag,
		EncAmount:     o.EncAmount,
		MAC:           o.MAC,
	}
}
