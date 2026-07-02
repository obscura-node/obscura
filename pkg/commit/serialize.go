package commit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// Canonical binary serialization for range proofs and Schnorr proofs.

func wBytes(buf *bytes.Buffer, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	buf.Write(l[:])
	buf.Write(b)
}

func rBytes(r *bytes.Reader) ([]byte, error) {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(l[:])
	if n > 1<<16 || int(n) > r.Len() {
		return nil, errors.New("commit: field too large")
	}
	b := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// Serialize encodes a RangeProof.
func (p *RangeProof) Serialize() []byte {
	var buf bytes.Buffer
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(p.BitComms)))
	buf.Write(n[:])
	for i := range p.BitComms {
		wBytes(&buf, p.BitComms[i])
		o := p.OrProofs[i]
		wBytes(&buf, o.E0)
		wBytes(&buf, o.E1)
		wBytes(&buf, o.S0)
		wBytes(&buf, o.S1)
	}
	return buf.Bytes()
}

// ParseRangeProof decodes a RangeProof.
func ParseRangeProof(data []byte) (*RangeProof, error) {
	r := bytes.NewReader(data)
	var n [4]byte
	if _, err := r.Read(n[:]); err != nil {
		return nil, err
	}
	count := int(binary.BigEndian.Uint32(n[:]))
	if count != RangeBits {
		return nil, errors.New("commit: bad range proof bit count")
	}
	p := &RangeProof{BitComms: make([][]byte, count), OrProofs: make([]orProof, count)}
	for i := 0; i < count; i++ {
		var err error
		if p.BitComms[i], err = rBytes(r); err != nil {
			return nil, err
		}
		var o orProof
		if o.E0, err = rBytes(r); err != nil {
			return nil, err
		}
		if o.E1, err = rBytes(r); err != nil {
			return nil, err
		}
		if o.S0, err = rBytes(r); err != nil {
			return nil, err
		}
		if o.S1, err = rBytes(r); err != nil {
			return nil, err
		}
		p.OrProofs[i] = o
	}
	// audit: ROUND2 [93] reject trailing bytes — Serialize() consumes the whole
	// buffer, so any leftover is attacker-appended garbage that would change the
	// txid (Transaction.Hash() covers full wire bytes) without affecting validity.
	if r.Len() != 0 {
		return nil, errors.New("commit: trailing bytes after range proof")
	}
	return p, nil
}

// Serialize encodes a SchnorrProof.
func (p *SchnorrProof) Serialize() []byte {
	var buf bytes.Buffer
	wBytes(&buf, p.R)
	wBytes(&buf, p.S)
	return buf.Bytes()
}

// ParseSchnorrProof decodes a SchnorrProof.
func ParseSchnorrProof(data []byte) (*SchnorrProof, error) {
	r := bytes.NewReader(data)
	R, err := rBytes(r)
	if err != nil {
		return nil, err
	}
	S, err := rBytes(r)
	if err != nil {
		return nil, err
	}
	// audit: ROUND2 [93] reject trailing bytes (txid malleability — see above).
	if r.Len() != 0 {
		return nil, errors.New("commit: trailing bytes after schnorr proof")
	}
	return &SchnorrProof{R: R, S: S}, nil
}
