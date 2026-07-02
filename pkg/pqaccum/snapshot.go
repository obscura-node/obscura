package pqaccum

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// MarshalState serializes the accumulator (either mode) for a node state snapshot.
// Layout: mode(1) ‖ ... ; leaf mode stores all leaf hashes, streaming mode stores
// count + the O(log n) peaks (size ‖ hash each).
func (a *Accumulator) MarshalState() []byte {
	var buf bytes.Buffer
	var u [8]byte
	if a.streaming {
		buf.WriteByte(1)
		binary.BigEndian.PutUint64(u[:], uint64(a.count))
		buf.Write(u[:])
		binary.BigEndian.PutUint64(u[:], uint64(len(a.peaks)))
		buf.Write(u[:])
		for _, p := range a.peaks {
			binary.BigEndian.PutUint64(u[:], p.size)
			buf.Write(u[:])
			buf.Write(p.hash) // always HashSize
		}
		return buf.Bytes()
	}
	buf.WriteByte(0)
	binary.BigEndian.PutUint64(u[:], uint64(len(a.leaves)))
	buf.Write(u[:])
	for _, l := range a.leaves {
		buf.Write(l) // always HashSize
	}
	return buf.Bytes()
}

// RestoreState reconstructs an accumulator from MarshalState bytes.
func RestoreState(data []byte) (*Accumulator, error) {
	r := bytes.NewReader(data)
	mode, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	readU64 := func() (uint64, error) {
		var u [8]byte
		if _, err := r.Read(u[:]); err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint64(u[:]), nil
	}
	readHash := func() ([]byte, error) {
		h := make([]byte, HashSize)
		if _, err := r.Read(h); err != nil {
			return nil, err
		}
		return h, nil
	}
	if mode == 1 {
		count, err := readU64()
		if err != nil {
			return nil, err
		}
		np, err := readU64()
		if err != nil {
			return nil, err
		}
		// audit: np is read off the (peer-controlled) wire — do NOT pre-allocate `np`
		// elements (a huge value OOM-crashes the process). Append grows as real data is
		// read; a short/lying length makes readHash below fail fast. The snapshot
		// transport additionally size-caps the whole payload.
		a := &Accumulator{streaming: true, count: int(count), peaks: make([]peak, 0)}
		for i := uint64(0); i < np; i++ {
			size, err := readU64()
			if err != nil {
				return nil, err
			}
			h, err := readHash()
			if err != nil {
				return nil, err
			}
			a.peaks = append(a.peaks, peak{hash: h, size: size})
		}
		return a, nil
	}
	if mode != 0 {
		return nil, errors.New("pqaccum: bad snapshot mode")
	}
	n, err := readU64()
	if err != nil {
		return nil, err
	}
	// audit: n is peer-controlled — don't pre-allocate `n` elements (OOM). Append grows
	// with real data; readHash fails fast on a lying/short length.
	a := &Accumulator{leaves: make([][]byte, 0)}
	for i := uint64(0); i < n; i++ {
		h, err := readHash()
		if err != nil {
			return nil, err
		}
		a.leaves = append(a.leaves, h)
	}
	return a, nil
}
