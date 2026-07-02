package block

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/blake2b"

	"obscura/pkg/config"
	"obscura/pkg/tx"
)

// Proof-of-Retrievability (PoR): a consensus rule that forces MINERS to be full nodes.
//
// The RSA accumulator makes chain state succinct, so a pruned node (headers + O(1) state,
// no block bodies) can otherwise produce valid blocks. PoR closes that: to mine block H a
// miner must answer `config.PoRChallenges` pseudo-random challenges, each asking for a
// specific transaction in a pseudo-random earlier block H_c ∈ [0,H). The challenge is
// derived from the PARENT hash (fixed when mining starts, unpredictable in advance), so
// the miner must hold those bodies to build the inclusion proofs. VERIFIERS only need the
// stored header of H_c (its MerkleRoot + NumTxs) — so PRUNED nodes can still validate; only
// the block PRODUCER needs full bodies. A pruned miner cannot read the challenged body, so
// it cannot mine.
//
// HONEST SCOPE: this is proof-of-ACCESS. It makes pruning-while-mining costly (every block
// you must retrieve the challenged bodies) and breaks if the data is unavailable — but a
// well-resourced miner could fetch challenged bodies on demand rather than store them.
// Preventing outsourced storage entirely (true proof-of-custody) is a known harder problem
// (entangling the data with each PoW attempt); documented as a follow-up.

// PoREntry is one answered challenge: the full bytes of the challenged transaction plus its
// merkle inclusion branch in the challenged block. Carrying full TxBytes (not just the
// txid) forces the miner to retain block BODIES, not merely the txid list.
type PoREntry struct {
	Height  uint64       // the challenged block height H_c
	TxBytes []byte       // full serialized challenged transaction
	Steps   []MerkleStep // its merkle branch up to header[H_c].MerkleRoot
}

func (e *PoREntry) serialize() []byte {
	var buf bytes.Buffer
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], e.Height)
	buf.Write(u[:])
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(e.TxBytes)))
	buf.Write(l[:])
	buf.Write(e.TxBytes)
	binary.BigEndian.PutUint32(l[:], uint32(len(e.Steps)))
	buf.Write(l[:])
	for _, s := range e.Steps {
		buf.Write(s.Hash[:])
		if s.Right {
			buf.WriteByte(1)
		} else {
			buf.WriteByte(0)
		}
	}
	return buf.Bytes()
}

func parsePoREntry(data []byte) (*PoREntry, error) {
	r := bytes.NewReader(data)
	e := &PoREntry{}
	var u [8]byte
	if _, err := io.ReadFull(r, u[:]); err != nil {
		return nil, err
	}
	e.Height = binary.BigEndian.Uint64(u[:])
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	tl := binary.BigEndian.Uint32(l[:])
	if int(tl) > r.Len() || int(tl) > tx.MaxTxBytes {
		return nil, errors.New("block: PoR tx too large")
	}
	e.TxBytes = make([]byte, tl)
	if _, err := io.ReadFull(r, e.TxBytes); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	ns := binary.BigEndian.Uint32(l[:])
	if int(ns) > 64 || int(ns)*33 > r.Len() {
		return nil, errors.New("block: PoR branch too long")
	}
	for i := uint32(0); i < ns; i++ {
		var s MerkleStep
		if _, err := io.ReadFull(r, s.Hash[:]); err != nil {
			return nil, err
		}
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		s.Right = b == 1
		e.Steps = append(e.Steps, s)
	}
	return e, nil
}

// PoRRootOf hashes a PoR entry set into the value committed in Header.PoRRoot (binding the
// proofs to the PoW). Empty set → zero root (genesis).
func PoRRootOf(entries []PoREntry) [32]byte {
	if len(entries) == 0 {
		return [32]byte{}
	}
	h, _ := blake2b.New256(nil)
	h.Write([]byte("OBX/por-root/v1"))
	for i := range entries {
		eb := entries[i].serialize()
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(eb)))
		h.Write(l[:])
		h.Write(eb)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// porSeed derives the per-slot challenge randomness from the parent hash. Using the PARENT
// hash means the challenge is fixed once mining starts (so the miner knows which bodies it
// needs) yet was unpredictable before the parent's PoW was solved.
func porSeed(prevHash [32]byte, slot int) [32]byte {
	h, _ := blake2b.New256(nil)
	h.Write([]byte("OBX/por-chal/v1"))
	h.Write(prevHash[:])
	var s [4]byte
	binary.BigEndian.PutUint32(s[:], uint32(slot))
	h.Write(s[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// porWindowLow returns the lowest challengeable height for a block at blockHeight:
// blockHeight - config.PoRWindow, clamped at genesis (0). This is exactly the floor
// the protocol body-pruner guarantees is still retained (see config.PoRWindow), so
// challenges and retained bodies coincide BY DESIGN.
func porWindowLow(blockHeight uint64) uint64 {
	if blockHeight <= config.PoRWindow {
		return 0
	}
	return blockHeight - config.PoRWindow
}

// PoRChallengeHeight returns the challenged block height for a slot when mining at
// blockHeight (≥1; genesis is exempt). Uniform over the PROTOCOL-RETAINED window
// [blockHeight-config.PoRWindow, blockHeight) (clamped to [0, blockHeight) near
// genesis). Bounding to the retained window is what makes pruning + PoR consistent:
// every challengeable body is one the protocol guarantees every node still holds.
func PoRChallengeHeight(prevHash [32]byte, slot int, blockHeight uint64) uint64 {
	lo := porWindowLow(blockHeight)
	span := blockHeight - lo // ≥ 1 since blockHeight ≥ 1 and lo < blockHeight
	s := porSeed(prevHash, slot)
	return lo + binary.BigEndian.Uint64(s[0:8])%span
}

// PoRChallengeIndex returns the challenged leaf (transaction) index within the challenged
// block, uniform over [0, numTxs). numTxs comes from the challenged block's stored header.
func PoRChallengeIndex(prevHash [32]byte, slot int, numTxs uint32) uint32 {
	if numTxs == 0 {
		return 0
	}
	s := porSeed(prevHash, slot)
	return uint32(binary.BigEndian.Uint64(s[8:16]) % uint64(numTxs))
}

// indexFromSteps reconstructs the leaf index a merkle branch addresses. MerkleStep.Right
// is true when the sibling is the RIGHT child (current node is the LEFT child → bit 0);
// false means the current node is the right child → bit 1. So the index is the little-
// endian bitstring of (NOT Right) across levels.
func indexFromSteps(steps []MerkleStep) uint64 {
	var idx uint64
	for i, s := range steps {
		if !s.Right {
			idx |= 1 << uint(i)
		}
	}
	return idx
}

// VerifyPoREntry checks a single answered challenge against the (stored) header data of the
// challenged block: the entry targets the expected height + leaf index, and its tx is
// genuinely included under merkleRoot. Verifiable with headers ALONE — no body needed.
func VerifyPoREntry(e *PoREntry, expectHeight uint64, expectIdx uint32, merkleRoot [32]byte) bool {
	if e.Height != expectHeight {
		return false
	}
	if indexFromSteps(e.Steps) != uint64(expectIdx) {
		return false
	}
	// txid = blake2b(TxBytes). The builder set TxBytes = tx.Serialize(), and
	// tx.Hash() == blake2b(Serialize()), so this equals the merkle leaf txid EXACTLY —
	// without a deserialize→reserialize round-trip (not guaranteed byte-identical for
	// every tx shape). 2nd-preimage resistance still forces the miner to hold the real
	// tx bytes: only the genuine serialization hashes to the committed leaf.
	txid := blake2b.Sum256(e.TxBytes)
	return VerifyMerkleProof(txid, e.Steps, merkleRoot)
}

// PoRRequired reports whether a block at this height must carry PoR (every block past
// genesis, once challenges fit). Genesis (height 0) and height where no prior block exists
// are exempt.
func PoRRequired(height uint64) bool { return height >= 1 && config.PoRChallenges > 0 }
