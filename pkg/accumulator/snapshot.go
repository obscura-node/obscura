package accumulator

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"obscura/pkg/group"
)

// MarshalState serializes the accumulator for a node state SNAPSHOT: the value
// element, then either a size counter (value-only mode) or the member-prime set.
// Restore sets the value directly (no O(n) re-exponentiation). Layout:
// mode(1) ‖ len(val)‖val ‖ (value-only: count(8)) | (member: n(4) ‖ [len‖prime]…).
func (a *Accumulator) MarshalState() []byte {
	var buf bytes.Buffer
	if a.valueOnly {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	val := a.G.Marshal(a.acc)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(val)))
	buf.Write(l[:])
	buf.Write(val)
	if a.valueOnly {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], uint64(a.count))
		buf.Write(c[:])
		return buf.Bytes()
	}
	binary.BigEndian.PutUint32(l[:], uint32(len(a.members)))
	buf.Write(l[:])
	for _, p := range a.members {
		pb := p.Bytes()
		binary.BigEndian.PutUint32(l[:], uint32(len(pb)))
		buf.Write(l[:])
		buf.Write(pb)
	}
	return buf.Bytes()
}

// RestoreState reconstructs an accumulator from MarshalState bytes under group G.
// The value is taken as-authoritative (snapshots are verified against the
// header-committed AccValue), so no O(n) re-exponentiation is performed.
func RestoreState(G group.Group, data []byte) (*Accumulator, error) {
	r := bytes.NewReader(data)
	mode, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	// audit:SECURITY_AUDIT_2026-07-01 — use io.ReadFull so a short read is an error
	// rather than silent truncation (bytes.Reader.Read may return fewer bytes than
	// requested). Backstopped by the post-restore root check; defense-in-depth.
	readBlob := func() ([]byte, error) {
		var l [4]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint32(l[:])
		if int(n) > r.Len() {
			return nil, errors.New("accumulator: corrupt snapshot")
		}
		b := make([]byte, n)
		if n > 0 {
			if _, err := io.ReadFull(r, b); err != nil {
				return nil, err
			}
		}
		return b, nil
	}
	val, err := readBlob()
	if err != nil {
		return nil, err
	}
	acc, err := G.Unmarshal(val)
	if err != nil {
		return nil, err
	}
	if mode == 1 { // value-only
		var c [8]byte
		if _, err := io.ReadFull(r, c[:]); err != nil {
			return nil, err
		}
		return &Accumulator{G: G, acc: acc, valueOnly: true, count: int(binary.BigEndian.Uint64(c[:]))}, nil
	}
	var cnt [4]byte
	if _, err := io.ReadFull(r, cnt[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(cnt[:])
	members := make(map[string]*big.Int, n)
	for i := uint32(0); i < n; i++ {
		pb, err := readBlob()
		if err != nil {
			return nil, err
		}
		p := new(big.Int).SetBytes(pb)
		members[p.Text(16)] = p
	}
	return &Accumulator{G: G, acc: acc, members: members}, nil
}
