// Package block defines Obscura blocks and headers. Each header commits to the
// accumulator value after applying the block, so light clients can verify
// membership proofs against header checkpoints.
package block

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/blake2b"

	"obscura/pkg/config"
	"obscura/pkg/pow"
	"obscura/pkg/tx"
)

// Header is the block header.
type Header struct {
	Version    uint16
	Height     uint64
	PrevHash   [32]byte
	Timestamp  int64
	Difficulty uint64
	Nonce      uint64
	MerkleRoot [32]byte // root over transaction ids
	AccValue   []byte   // accumulator value after this block (checkpoint)
	AccSize    uint64   // number of accumulated outputs after this block
	PQAccRoot  [32]byte // post-quantum anonymity-set Merkle root after this block (Version-2 path)
	NullRoot   [32]byte // nullifier-set (key-image) Merkle root after this block — commits the
	// SPENT set so it is part of the trustlessly-verifiable state (enables
	// pruning / state-snapshot sync of the spent set). See docs/PRUNING_DESIGN.md
	CMRoot [32]byte // Poseidon commitment-tree root after this block — the ZK anonymous-spend
	// accumulator (docs/ZK_MEMBERSHIP_SPEND.md). A spend proves membership of a
	// coin against a recent CMRoot anchor with a transparent STARK.
	NumTxs uint32 // number of transactions in this block. Committed in the header so a PRUNED
	// node (which keeps headers, not bodies) can derive the proof-of-retrievability
	// challenge leaf index for this block without holding its body. See por.go.
	PoRRoot [32]byte // proof-of-retrievability root: hash of the block's PoR entries (Block.PoR).
	// Binds the PoR set to the PoW so a miner MUST hold full historical bodies to
	// produce a valid block (else it cannot build the proofs). See por.go.
	StateRoot [32]byte // PRE-STATE commitment over consensus state NOT bound by the roots above
	// (emitted/incentivePool, the disk-set commitments, and the in-RAM maps incl.
	// pqUtxo amounts). A block commits its PARENT's state; see chain/stateroot.go.
}

// Block is a header plus its transactions (the first is the coinbase).
type Block struct {
	Header Header
	Txs    []*tx.Transaction
	// PoR carries the proof-of-retrievability entries that prove the miner held the
	// challenged historical block bodies. Body data (prunable); its hash is committed
	// in Header.PoRRoot (PoW-bound). Empty for the genesis block. See por.go.
	PoR []PoREntry
}

// PreimageForPoW returns the bytes hashed by the PoW (everything except the
// nonce is fixed; the nonce is appended so miners vary it).
func (h *Header) powPreimage() []byte {
	var buf bytes.Buffer
	var v [2]byte
	binary.BigEndian.PutUint16(v[:], h.Version)
	buf.Write(v[:])
	wu64(&buf, h.Height)
	buf.Write(h.PrevHash[:])
	wi64(&buf, h.Timestamp)
	wu64(&buf, h.Difficulty)
	buf.Write(h.MerkleRoot[:])
	// length-prefix the variable-length AccValue so field boundaries cannot be
	// confused (two different (MerkleRoot, AccValue) splits hashing the same).
	var al [4]byte
	binary.BigEndian.PutUint32(al[:], uint32(len(h.AccValue)))
	buf.Write(al[:])
	buf.Write(h.AccValue)
	wu64(&buf, h.AccSize)
	buf.Write(h.PQAccRoot[:])
	buf.Write(h.NullRoot[:])
	buf.Write(h.CMRoot[:])
	var nt [4]byte
	binary.BigEndian.PutUint32(nt[:], h.NumTxs)
	buf.Write(nt[:])
	buf.Write(h.PoRRoot[:])
	buf.Write(h.StateRoot[:])
	return buf.Bytes()
}

// PoWHash computes the proof-of-work hash for the header at its current nonce
// under the epoch-0 seed. Consensus uses PoWHashSeed with the per-epoch seed;
// this keyless form (epoch-0 constant) is kept for early blocks and tooling.
func (h *Header) PoWHash() [32]byte {
	return h.PoWHashSeed(config.PoWGenesisSeed)
}

// PoWHashSeed computes the PoW hash under an explicit per-epoch cache seed.
func (h *Header) PoWHashSeed(seed []byte) [32]byte {
	pre := h.powPreimage()
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], h.Nonce)
	return pow.HashSeed(seed, append(pre, nb[:]...))
}

// ID returns the block id (hash of the full serialized header including nonce).
func (h *Header) ID() [32]byte {
	return blake2b.Sum256(h.Serialize())
}

// Serialize encodes the header canonically.
func (h *Header) Serialize() []byte {
	var buf bytes.Buffer
	var v [2]byte
	binary.BigEndian.PutUint16(v[:], h.Version)
	buf.Write(v[:])
	wu64(&buf, h.Height)
	buf.Write(h.PrevHash[:])
	wi64(&buf, h.Timestamp)
	wu64(&buf, h.Difficulty)
	wu64(&buf, h.Nonce)
	buf.Write(h.MerkleRoot[:])
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(h.AccValue)))
	buf.Write(l[:])
	buf.Write(h.AccValue)
	wu64(&buf, h.AccSize)
	buf.Write(h.PQAccRoot[:])
	buf.Write(h.NullRoot[:])
	buf.Write(h.CMRoot[:])
	var nt [4]byte
	binary.BigEndian.PutUint32(nt[:], h.NumTxs)
	buf.Write(nt[:])
	buf.Write(h.PoRRoot[:])
	buf.Write(h.StateRoot[:])
	return buf.Bytes()
}

// ParseHeader decodes a header.
func ParseHeader(r *bytes.Reader) (*Header, error) {
	h := &Header{}
	var v [2]byte
	if _, err := io.ReadFull(r, v[:]); err != nil {
		return nil, err
	}
	h.Version = binary.BigEndian.Uint16(v[:])
	var err error
	if h.Height, err = ru64(r); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(r, h.PrevHash[:]); err != nil {
		return nil, err
	}
	if h.Timestamp, err = ri64(r); err != nil {
		return nil, err
	}
	if h.Difficulty, err = ru64(r); err != nil {
		return nil, err
	}
	if h.Nonce, err = ru64(r); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(r, h.MerkleRoot[:]); err != nil {
		return nil, err
	}
	var l [4]byte
	if _, err = io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(l[:])
	if n > 1<<16 || int(n) > r.Len() {
		return nil, errors.New("block: acc value too large")
	}
	h.AccValue = make([]byte, n)
	if _, err = io.ReadFull(r, h.AccValue); err != nil {
		return nil, err
	}
	if h.AccSize, err = ru64(r); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(r, h.PQAccRoot[:]); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(r, h.NullRoot[:]); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(r, h.CMRoot[:]); err != nil {
		return nil, err
	}
	var nt [4]byte
	if _, err = io.ReadFull(r, nt[:]); err != nil {
		return nil, err
	}
	h.NumTxs = binary.BigEndian.Uint32(nt[:])
	if _, err = io.ReadFull(r, h.PoRRoot[:]); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(r, h.StateRoot[:]); err != nil {
		return nil, err
	}
	return h, nil
}

// Serialize encodes a full block.
func (b *Block) Serialize() []byte {
	var buf bytes.Buffer
	hb := b.Header.Serialize()
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(hb)))
	buf.Write(l[:])
	buf.Write(hb)
	wu64(&buf, uint64(len(b.Txs)))
	for _, t := range b.Txs {
		tb := t.Serialize()
		binary.BigEndian.PutUint32(l[:], uint32(len(tb)))
		buf.Write(l[:])
		buf.Write(tb)
	}
	// proof-of-retrievability entries (appended last; older fields' layout unchanged).
	wu64(&buf, uint64(len(b.PoR)))
	for i := range b.PoR {
		eb := b.PoR[i].serialize()
		binary.BigEndian.PutUint32(l[:], uint32(len(eb)))
		buf.Write(l[:])
		buf.Write(eb)
	}
	return buf.Bytes()
}

// DeserializeBlock decodes a full block with strict size bounds (anti-DoS).
func DeserializeBlock(data []byte) (*Block, error) {
	if len(data) > config.MaxBlockBytes {
		return nil, errors.New("block: serialized block too large")
	}
	r := bytes.NewReader(data)
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	hl := binary.BigEndian.Uint32(l[:])
	if int(hl) > r.Len() {
		return nil, errors.New("block: header length exceeds input")
	}
	hb := make([]byte, hl)
	if _, err := io.ReadFull(r, hb); err != nil {
		return nil, err
	}
	hdr, err := ParseHeader(bytes.NewReader(hb))
	if err != nil {
		return nil, err
	}
	b := &Block{Header: *hdr}
	ntx, err := ru64(r)
	if err != nil {
		return nil, err
	}
	// each tx is at least a few bytes; cap by remaining input to avoid a huge
	// pre-allocation from a tiny crafted message.
	if ntx > uint64(r.Len()) {
		return nil, errors.New("block: too many txs for input size")
	}
	for i := uint64(0); i < ntx; i++ {
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return nil, err
		}
		tl := binary.BigEndian.Uint32(l[:])
		if int(tl) > r.Len() || int(tl) > tx.MaxTxBytes {
			return nil, errors.New("block: tx length exceeds input")
		}
		tb := make([]byte, tl)
		if _, err := io.ReadFull(r, tb); err != nil {
			return nil, err
		}
		t, err := tx.Deserialize(tb)
		if err != nil {
			return nil, err
		}
		b.Txs = append(b.Txs, t)
	}
	// proof-of-retrievability entries.
	npor, err := ru64(r)
	if err != nil {
		return nil, err
	}
	if npor > uint64(r.Len()) {
		return nil, errors.New("block: too many PoR entries for input size")
	}
	for i := uint64(0); i < npor; i++ {
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return nil, err
		}
		el := binary.BigEndian.Uint32(l[:])
		if int(el) > r.Len() {
			return nil, errors.New("block: PoR entry length exceeds input")
		}
		eb := make([]byte, el)
		if _, err := io.ReadFull(r, eb); err != nil {
			return nil, err
		}
		e, err := parsePoREntry(eb)
		if err != nil {
			return nil, err
		}
		b.PoR = append(b.PoR, *e)
	}
	// Audit fix: reject trailing bytes after the block structure. Without this a
	// peer can append arbitrary padding to a valid block; the decoded Block is the
	// same but relays that re-broadcast the raw received payload would propagate the
	// padded (non-canonical) bytes — a 1-hop malleability/amplification vector. By
	// requiring the reader fully consumed we force a single canonical wire encoding
	// (Serialize() is the only valid form).
	if r.Len() != 0 {
		return nil, errors.New("block: trailing bytes after block")
	}
	return b, nil
}

// MerkleRoot computes the merkle root over a list of transactions, with
// domain-separated leaf (0x00) and internal (0x01) hashing to resist
// second-preimage attacks. Duplicate-leaf malleability (CVE-2012-2459) is
// additionally prevented by rejecting blocks with duplicate txids in consensus
// validation.
func MerkleRoot(txs []*tx.Transaction) [32]byte {
	if len(txs) == 0 {
		return [32]byte{}
	}
	layer := make([][32]byte, len(txs))
	for i, t := range txs {
		layer[i] = leafHash(t.Hash())
	}
	for len(layer) > 1 {
		var next [][32]byte
		for i := 0; i < len(layer); i += 2 {
			r := layer[i] // odd node duplicated (txid dups rejected elsewhere)
			if i+1 < len(layer) {
				r = layer[i+1]
			}
			next = append(next, internalHash(layer[i], r))
		}
		layer = next
	}
	return layer[0]
}

func wu64(buf *bytes.Buffer, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	buf.Write(b[:])
}
func wi64(buf *bytes.Buffer, v int64) { wu64(buf, uint64(v)) }
func ru64(r *bytes.Reader) (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}
func ri64(r *bytes.Reader) (int64, error) {
	u, err := ru64(r)
	return int64(u), err
}
