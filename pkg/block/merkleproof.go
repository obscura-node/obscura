package block

import (
	"golang.org/x/crypto/blake2b"

	"obscura/pkg/tx"
)

// Merkle inclusion proofs let a light client verify that a transaction is in a
// block using only the block header's MerkleRoot and an O(log n) branch — no
// full block download. Hashing matches MerkleRoot exactly (domain-separated
// leaf 0x00 / internal 0x01, odd nodes duplicated).

// leafHash hashes a transaction id into a merkle leaf.
func leafHash(txid [32]byte) [32]byte {
	return blake2b.Sum256(append([]byte{0x00}, txid[:]...))
}

// internalHash hashes two child nodes into a parent.
func internalHash(l, r [32]byte) [32]byte {
	buf := make([]byte, 0, 65)
	buf = append(buf, 0x01)
	buf = append(buf, l[:]...)
	buf = append(buf, r[:]...)
	return blake2b.Sum256(buf)
}

// MerkleStep is one sibling on the path from a leaf to the root.
type MerkleStep struct {
	Hash  [32]byte
	Right bool // true if the sibling is the RIGHT child (current node is left)
}

// MerkleProof returns the inclusion branch for txs[idx].
func MerkleProof(txs []*tx.Transaction, idx int) ([]MerkleStep, bool) {
	if idx < 0 || idx >= len(txs) {
		return nil, false
	}
	layer := make([][32]byte, len(txs))
	for i, t := range txs {
		layer[i] = leafHash(t.Hash())
	}
	var steps []MerkleStep
	pos := idx
	for len(layer) > 1 {
		var next [][32]byte
		for i := 0; i < len(layer); i += 2 {
			l := layer[i]
			r := l
			if i+1 < len(layer) {
				r = layer[i+1]
			}
			if i == pos {
				steps = append(steps, MerkleStep{Hash: r, Right: true})
			} else if i+1 == pos {
				steps = append(steps, MerkleStep{Hash: l, Right: false})
			}
			next = append(next, internalHash(l, r))
		}
		pos /= 2
		layer = next
	}
	return steps, true
}

// VerifyMerkleProof recomputes the root from a leaf txid and its branch and
// checks it equals the expected root.
func VerifyMerkleProof(txid [32]byte, steps []MerkleStep, root [32]byte) bool {
	h := leafHash(txid)
	for _, s := range steps {
		if s.Right {
			h = internalHash(h, s.Hash)
		} else {
			h = internalHash(s.Hash, h)
		}
	}
	return h == root
}
