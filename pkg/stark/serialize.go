package stark

import (
	"bytes"
	"encoding/gob"
)

// Wire encoding for AIRProof so proofs can be carried inside transactions. gob is
// fine here: all proof fields are exported and made of fixed scalars, [32]byte
// hashes, and slices thereof. A proof is self-describing (it carries its own
// degree, roots, openings); the verifier supplies the circuit + public inputs.

// MarshalProof encodes an AIR proof to bytes.
func MarshalProof(pf *AIRProof) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(pf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalProof decodes an AIR proof from bytes.
func UnmarshalProof(data []byte) (*AIRProof, error) {
	pf := &AIRProof{}
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(pf); err != nil {
		return nil, err
	}
	return pf, nil
}
