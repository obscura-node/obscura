package accumulator

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"obscura/pkg/group"
)

// Canonical length-prefixed serialization for accumulator proofs, so they can
// be embedded in transactions and hashed deterministically.

func putBytes(buf *bytes.Buffer, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	buf.Write(l[:])
	buf.Write(b)
}

func getBytes(r *bytes.Reader) ([]byte, error) {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(l[:])
	if n > 1<<16 || int(n) > r.Len() {
		return nil, errors.New("accumulator: field too large")
	}
	b := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
	}
	return b, nil
}

func putInt(buf *bytes.Buffer, x *big.Int) {
	neg := byte(0)
	if x.Sign() < 0 {
		neg = 1
	}
	buf.WriteByte(neg)
	putBytes(buf, new(big.Int).Abs(x).Bytes())
}

func getInt(r *bytes.Reader) (*big.Int, error) {
	neg, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	b, err := getBytes(r)
	if err != nil {
		return nil, err
	}
	x := new(big.Int).SetBytes(b)
	if neg == 1 {
		x.Neg(x)
	}
	return x, nil
}

func putElem(buf *bytes.Buffer, G group.Group, e group.Element) {
	putBytes(buf, G.Marshal(e))
}

func getElem(r *bytes.Reader, G group.Group) (group.Element, error) {
	b, err := getBytes(r)
	if err != nil {
		return nil, err
	}
	return G.Unmarshal(b)
}

// Serialize encodes a MultiPoKE.
func (p *MultiPoKE) Serialize(G group.Group) []byte {
	var buf bytes.Buffer
	putElem(&buf, G, p.Z1)
	putElem(&buf, G, p.Z2)
	putElem(&buf, G, p.Q)
	putInt(&buf, p.R1)
	putInt(&buf, p.R2)
	return buf.Bytes()
}

// ParseMultiPoKE decodes a MultiPoKE.
func ParseMultiPoKE(G group.Group, data []byte) (*MultiPoKE, error) {
	r := bytes.NewReader(data)
	z1, err := getElem(r, G)
	if err != nil {
		return nil, err
	}
	z2, err := getElem(r, G)
	if err != nil {
		return nil, err
	}
	q, err := getElem(r, G)
	if err != nil {
		return nil, err
	}
	r1, err := getInt(r)
	if err != nil {
		return nil, err
	}
	r2, err := getInt(r)
	if err != nil {
		return nil, err
	}
	return &MultiPoKE{Z1: z1, Z2: z2, Q: q, R1: r1, R2: r2}, nil
}

// Serialize encodes a ZKMembership proof.
func (m *ZKMembership) Serialize(G group.Group) []byte {
	var buf bytes.Buffer
	putElem(&buf, G, m.C)
	putBytes(&buf, m.Proof.Serialize(G))
	return buf.Bytes()
}

// ParseZKMembership decodes a ZKMembership proof.
func ParseZKMembership(G group.Group, data []byte) (*ZKMembership, error) {
	r := bytes.NewReader(data)
	c, err := getElem(r, G)
	if err != nil {
		return nil, err
	}
	pb, err := getBytes(r)
	if err != nil {
		return nil, err
	}
	pf, err := ParseMultiPoKE(G, pb)
	if err != nil {
		return nil, err
	}
	return &ZKMembership{C: c, Proof: pf}, nil
}
