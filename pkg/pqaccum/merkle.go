// Package pqaccum provides a POST-QUANTUM accumulator for Obscura's global
// anonymity set (Phase 2 of the PQ roadmap).
//
// Obscura's headline feature is a trustless accumulator that gives every spend a
// GLOBAL anonymity set. The shipping implementation uses a group of unknown
// order (RSA-2048 / class group); BOTH are broken by a quantum computer (Shor
// factors RSA; a Hallgren-type algorithm computes class-group structure), which
// would let an attacker forge membership witnesses. This package replaces the
// data structure with an append-only Merkle accumulator whose security rests
// ONLY on the collision resistance of BLAKE2b — post-quantum (Grover only
// halves the bit-security) and with no trusted setup.
//
// It follows RFC 6962 domain separation (leaf prefix 0x00, node prefix 0x01) so
// it is immune to the CVE-2012-2459 second-preimage ambiguity. Add returns the
// leaf index; Prove returns an O(log n) authentication path; Verify checks a
// path against a root.
//
// HONEST SCOPE — the privacy gap: a raw Merkle membership proof is PQ-SOUND but
// NOT zero-knowledge — it reveals the leaf (and its position), which would
// deanonymize the spend. The class-group accumulator's value was witness-HIDING
// membership. To recover ZK membership post-quantum, the Merkle path must be
// proven inside a transparent PQ zero-knowledge proof — a zk-STARK or a
// lattice/MPC-in-the-head proof of "I know a leaf and a path to the published
// root, and its nullifier is N" — without revealing which leaf. That STARK
// circuit is the larger remaining research effort (transparent and PQ, so it
// keeps Obscura's no-ceremony ethos); this package is the accumulator it would
// prove over. See docs/POST_QUANTUM_ROADMAP.md.
//
// Off the default consensus path — the shipping coin's speed is unaffected.
package pqaccum

import (
	"encoding/binary"
	"errors"
	"math/bits"

	"golang.org/x/crypto/blake2b"
)

const HashSize = 32

func leafHash(data []byte) []byte {
	d, _ := blake2b.New256(nil)
	d.Write([]byte{0x00})
	d.Write(data)
	return d.Sum(nil)
}

func nodeHash(l, r []byte) []byte {
	d, _ := blake2b.New256(nil)
	d.Write([]byte{0x01})
	d.Write(l)
	d.Write(r)
	return d.Sum(nil)
}

// Accumulator is an append-only Merkle accumulator over arbitrary leaf data
// (e.g. output commitments). It is safe for sequential use.
//
// Two modes:
//   - default (New): retains every leaf hash — supports Prove (membership paths).
//   - streaming (NewStreaming): retains only the O(log n) perfect-subtree "peaks"
//     instead of all leaves, so RAM is O(log n) not O(n). It supports Add / Root /
//     RootAfter / Len / Clone with BYTE-IDENTICAL roots to the leaf mode, but NOT
//     Prove (a prover keeps its own witness). Used for the nullifier set, which a
//     node only ever needs to root-commit, never to prove membership of.
type Accumulator struct {
	leaves [][]byte // (default mode) leaf hashes in insertion order

	streaming bool   // streaming mode: keep peaks, not leaves
	peaks     []peak // perfect-subtree roots, largest (oldest) first
	count     int    // number of elements added (streaming mode)
}

// peak is a perfect binary subtree root covering `size` consecutive leaves.
type peak struct {
	hash []byte
	size uint64
}

// New creates an empty leaf-retaining accumulator (supports Prove).
func New() *Accumulator { return &Accumulator{} }

// NewStreaming creates an empty O(log n)-memory accumulator (no Prove). Its roots
// are byte-identical to New's for the same insertion sequence.
func NewStreaming() *Accumulator { return &Accumulator{streaming: true} }

// pushPeak appends a leaf hash to the peak stack, merging equal-size peaks
// (RFC 6962: the new leaf is the right child of any equal-size left peak).
func (a *Accumulator) pushPeak(h []byte) {
	p := peak{hash: h, size: 1}
	for len(a.peaks) > 0 && a.peaks[len(a.peaks)-1].size == p.size {
		left := a.peaks[len(a.peaks)-1]
		a.peaks = a.peaks[:len(a.peaks)-1]
		p = peak{hash: nodeHash(left.hash, p.hash), size: p.size * 2}
	}
	a.peaks = append(a.peaks, p)
}

// rootFromPeaks folds peaks right-to-left into the RFC 6962 root (identical to
// levels()): root = node(P0, node(P1, … node(P_{k-1}, P_k))).
func rootFromPeaks(peaks []peak) []byte {
	if len(peaks) == 0 {
		return make([]byte, HashSize)
	}
	acc := append([]byte(nil), peaks[len(peaks)-1].hash...)
	for i := len(peaks) - 2; i >= 0; i-- {
		acc = nodeHash(peaks[i].hash, acc)
	}
	return acc
}

// Add appends data and returns its leaf index.
func (a *Accumulator) Add(data []byte) int {
	if a.streaming {
		a.pushPeak(leafHash(data))
		a.count++
		return a.count - 1
	}
	a.leaves = append(a.leaves, leafHash(data))
	return len(a.leaves) - 1
}

// Len returns the number of accumulated elements.
func (a *Accumulator) Len() int {
	if a.streaming {
		return a.count
	}
	return len(a.leaves)
}

// levels builds every tree level bottom-up (RFC 6962 promotion of odd nodes).
func (a *Accumulator) levels() [][][]byte {
	if len(a.leaves) == 0 {
		return nil
	}
	cur := make([][]byte, len(a.leaves))
	copy(cur, a.leaves)
	out := [][][]byte{cur}
	for len(cur) > 1 {
		next := make([][]byte, 0, (len(cur)+1)/2)
		for i := 0; i < len(cur); i += 2 {
			if i+1 < len(cur) {
				next = append(next, nodeHash(cur[i], cur[i+1]))
			} else {
				next = append(next, cur[i]) // lone node promoted as-is
			}
		}
		out = append(out, next)
		cur = next
	}
	return out
}

// Root returns the current Merkle root. The root of an empty accumulator is the
// all-zero hash.
func (a *Accumulator) Root() []byte {
	if a.streaming {
		return rootFromPeaks(a.peaks)
	}
	lv := a.levels()
	if lv == nil {
		return make([]byte, HashSize)
	}
	top := lv[len(lv)-1]
	return append([]byte(nil), top[0]...)
}

// RootAfter computes the root the accumulator WOULD have if the given extra
// data items were appended (in order), without mutating it. Used to predict and
// verify the post-block PQ root committed in the header.
func (a *Accumulator) RootAfter(extra [][]byte) []byte {
	if len(extra) == 0 {
		return a.Root()
	}
	if a.streaming {
		tmp := &Accumulator{streaming: true, count: a.count, peaks: make([]peak, len(a.peaks))}
		copy(tmp.peaks, a.peaks)
		for _, d := range extra {
			tmp.pushPeak(leafHash(d))
			tmp.count++
		}
		return rootFromPeaks(tmp.peaks)
	}
	tmp := &Accumulator{leaves: make([][]byte, len(a.leaves), len(a.leaves)+len(extra))}
	copy(tmp.leaves, a.leaves)
	for _, d := range extra {
		tmp.leaves = append(tmp.leaves, leafHash(d))
	}
	return tmp.Root()
}

// PathStep is one authentication-path element.
type PathStep struct {
	Hash    []byte
	IsRight bool // sibling is on the right of the running hash
}

// Proof is a membership proof: the leaf index, the tree size at proof time, and
// the authentication path. Index AND Size are required so Verify can derive the
// path directions itself (RFC 6962) rather than trusting attacker-supplied
// direction flags — otherwise the claimed position is unauthenticated.
type Proof struct {
	Index int
	Size  int
	Path  []PathStep
}

// maxProofSize bounds Size/Index parsing (anti-DoS / negative-cast guard).
const maxProofSize = 1 << 40

// Prove returns a membership proof for the leaf at index.
func (a *Accumulator) Prove(index int) (*Proof, error) {
	if a.streaming {
		return nil, errors.New("pqaccum: streaming accumulator cannot prove (no leaves retained)")
	}
	if index < 0 || index >= len(a.leaves) {
		return nil, errors.New("pqaccum: index out of range")
	}
	lv := a.levels()
	path := make([]PathStep, 0, len(lv))
	idx := index
	for level := 0; level < len(lv)-1; level++ {
		nodes := lv[level]
		if idx%2 == 0 {
			if idx+1 < len(nodes) { // right sibling exists
				path = append(path, PathStep{Hash: clone(nodes[idx+1]), IsRight: true})
			}
			// else: lone node promoted, no sibling at this level
		} else {
			path = append(path, PathStep{Hash: clone(nodes[idx-1]), IsRight: false})
		}
		idx /= 2
	}
	return &Proof{Index: index, Size: len(a.leaves), Path: path}, nil
}

// Verify checks that data is the leaf at proof.Index in a tree of proof.Size
// under root, using the RFC 6962 inclusion-proof algorithm. Directions are
// derived from (Index, Size) — the per-step IsRight flags are NOT trusted — and
// the path length must exactly match the structure implied by (Index, Size), so
// a tampered index, size, or path is rejected.
func Verify(root, data []byte, proof *Proof) bool {
	if proof == nil || len(root) != HashSize {
		return false
	}
	if proof.Index < 0 || proof.Size <= 0 || proof.Index >= proof.Size || proof.Size > maxProofSize {
		return false
	}
	index, size := uint64(proof.Index), uint64(proof.Size)
	inner := bits.Len64(index ^ (size - 1)) // levels with an "inner" sibling
	border := bits.OnesCount64(index >> uint(inner))
	if len(proof.Path) != inner+border {
		return false
	}
	for _, s := range proof.Path {
		if len(s.Hash) != HashSize {
			return false
		}
	}
	res := leafHash(data)
	for i := 0; i < inner; i++ {
		if (index>>uint(i))&1 == 0 {
			res = nodeHash(res, proof.Path[i].Hash)
		} else {
			res = nodeHash(proof.Path[i].Hash, res)
		}
	}
	for i := inner; i < inner+border; i++ {
		res = nodeHash(proof.Path[i].Hash, res)
	}
	return constEq(res, root)
}

// Marshal serializes a proof: index(8) ‖ size(8) ‖ count(8) ‖ [isRight(1) ‖ hash(32)]…
func (p *Proof) Marshal() []byte {
	out := make([]byte, 0, 24+len(p.Path)*(1+HashSize))
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], uint64(p.Index))
	out = append(out, u[:]...)
	binary.BigEndian.PutUint64(u[:], uint64(p.Size))
	out = append(out, u[:]...)
	binary.BigEndian.PutUint64(u[:], uint64(len(p.Path)))
	out = append(out, u[:]...)
	for _, s := range p.Path {
		if s.IsRight {
			out = append(out, 1)
		} else {
			out = append(out, 0)
		}
		out = append(out, s.Hash...)
	}
	return out
}

// ParseProof is the inverse of Marshal, with strict bounds (Index/Size are
// range-checked so a hostile value cannot become a negative int downstream).
func ParseProof(b []byte) (*Proof, error) {
	if len(b) < 24 {
		return nil, errors.New("pqaccum: short proof")
	}
	idx := binary.BigEndian.Uint64(b[:8])
	size := binary.BigEndian.Uint64(b[8:16])
	n := binary.BigEndian.Uint64(b[16:24])
	if size == 0 || size > maxProofSize || idx >= size || n > 64 || len(b) != 24+int(n)*(1+HashSize) {
		return nil, errors.New("pqaccum: malformed proof")
	}
	p := &Proof{Index: int(idx), Size: int(size), Path: make([]PathStep, 0, n)}
	off := 24
	for i := uint64(0); i < n; i++ {
		isRight := b[off] == 1
		off++
		p.Path = append(p.Path, PathStep{Hash: append([]byte(nil), b[off:off+HashSize]...), IsRight: isRight})
		off += HashSize
	}
	return p, nil
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }

func constEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
