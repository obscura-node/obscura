package chain

import "errors"

// CanonicalGenesisID returns the ID (header hash) of the genesis block exactly as
// a node constructs it at startup. It builds a throwaway, fully in-memory chain —
// the genesis is derived deterministically from the compiled-in config and class
// group (NewConfiguredGroup), NOT from anything a remote node supplies — and
// returns the height-0 block's header ID.
//
// This is the SPV trust root. A light client pins this value and refuses any
// header chain whose genesis differs, so a malicious or compromised node cannot
// substitute a fabricated chain. Because it is computed from the same code path
// initGenesis() uses, it is byte-for-byte identical to a live node's genesis.
//
// audit: SECURITY_AUDIT_2026-07-01 #4
func CanonicalGenesisID() ([32]byte, error) {
	var zero [32]byte
	// New("") builds a fully in-memory chain: a nil db skips replay/persistence and
	// initGenesis() runs because no headers are present.
	c, err := New("")
	if err != nil {
		return zero, err
	}
	defer c.Close()
	b, ok := c.BlockByHeight(0)
	if !ok {
		return zero, errors.New("chain: genesis block missing")
	}
	return b.Header.ID(), nil
}
