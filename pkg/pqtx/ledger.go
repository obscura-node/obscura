//go:build pq

package pqtx

import (
	"errors"
	"fmt"

	"obscura/pkg/pqaccum"
	"obscura/pkg/pqcommit"
	"obscura/pkg/pqsign"
)

// Ledger is a minimal PQ chainstate mirroring pkg/chain: a global Merkle
// anonymity set of output keys, a shared nullifier set, and a UTXO map. It is
// the end-to-end harness proving the PQ output+spend variant validates with
// HybridVerify, prevents double-spends, and conserves value — entirely off the
// default consensus path.
type Ledger struct {
	acc        *pqaccum.Accumulator
	utxo       map[string]*PQOutput // by OneTimeKey
	index      map[string]int       // OneTimeKey -> accumulator leaf index
	nullifiers map[string]bool      // shared nullifier set (double-spend guard)
}

// NewLedger creates an empty PQ ledger.
func NewLedger() *Ledger {
	return &Ledger{
		acc:        pqaccum.New(),
		utxo:       map[string]*PQOutput{},
		index:      map[string]int{},
		nullifiers: map[string]bool{},
	}
}

var errLedger = errors.New("pqtx: validation failed")

// AddOutput inserts an output into the anonymity set and UTXO map (used for
// genesis / coinbase funding; spend outputs are added by ApplySpend).
func (l *Ledger) AddOutput(o *PQOutput) error {
	if o.Version != Version || len(o.OneTimeKey) != 32 {
		return fmt.Errorf("%w: bad output", errLedger)
	}
	key := hexKey(o.OneTimeKey)
	if _, exists := l.utxo[key]; exists {
		return fmt.Errorf("%w: duplicate output key", errLedger)
	}
	if _, err := parseCommitment(o.Commitment); err != nil {
		return fmt.Errorf("%w: bad commitment", errLedger)
	}
	idx := l.acc.Add(o.OneTimeKey)
	l.index[key] = idx
	cp := *o
	l.utxo[key] = &cp
	return nil
}

// Root is the current anonymity-set Merkle root.
func (l *Ledger) Root() []byte { return l.acc.Root() }

// Prove returns a membership proof for an output (the spender attaches it).
func (l *Ledger) Prove(oneTimeKey []byte) (*pqaccum.Proof, error) {
	idx, ok := l.index[hexKey(oneTimeKey)]
	if !ok {
		return nil, fmt.Errorf("%w: unknown output", errLedger)
	}
	return l.acc.Prove(idx)
}

// ValidateSpend checks a PQ spend against the current ledger WITHOUT mutating
// it, mirroring chain.validateTxLocked. Order of checks:
//  1. version + structural sanity
//  2. the referenced output exists, and the membership proof verifies it is in
//     the global anonymity set under `root`
//  3. the nullifier is well-formed (= H(R)) and unseen (double-spend guard)
//  4. HybridVerify: the spend is authorized by BOTH the classical and the WOTS+
//     half over the spend's CoreHash (this also binds R↔OutputRef via the key)
//  5. value conservation: Σ in − Σ out − fee == commitment to zero under BlindDiff
func (l *Ledger) ValidateSpend(s *PQSpend, root []byte, member *pqaccum.Proof) error {
	if s == nil || s.Version != Version {
		return fmt.Errorf("%w: %v", errLedger, errVersion)
	}
	if len(s.OutputRef) != 32 || len(s.P) != 32 || len(s.WotsRoot) != 32 || len(s.Nullifier) != 32 {
		return fmt.Errorf("%w: malformed spend", errLedger)
	}
	// (2) output exists + global-set membership
	ref := hexKey(s.OutputRef)
	spent, ok := l.utxo[ref]
	if !ok {
		return fmt.Errorf("%w: spends nonexistent or already-spent output", errLedger)
	}
	if member == nil || !pqaccum.Verify(root, s.OutputRef, member) {
		return fmt.Errorf("%w: invalid anonymity-set membership proof", errLedger)
	}
	// (3) nullifier well-formed + unseen
	if !equalBytes(s.Nullifier, NullifierOf(s.WotsRoot)) {
		return fmt.Errorf("%w: nullifier not bound to root", errLedger)
	}
	if l.nullifiers[hexKey(s.Nullifier)] {
		return fmt.Errorf("%w: double-spend (nullifier already seen)", errLedger)
	}
	// (4) hybrid spend authorization over CoreHash
	sig, err := parseHybridSig(s.HybridSig)
	if err != nil {
		return fmt.Errorf("%w: malformed signature", errLedger)
	}
	if !pqsign.HybridVerify(s.OutputRef, s.P, s.WotsRoot, s.CoreHash(), sig) {
		return fmt.Errorf("%w: hybrid spend authorization failed", errLedger)
	}
	// (5) value conservation over the PQ homomorphic commitments
	if err := l.checkConservation(spent, s); err != nil {
		return err
	}
	// new outputs must be well-formed and not collide with existing keys
	seen := map[string]bool{}
	for i := range s.Outputs {
		o := &s.Outputs[i]
		if o.Version != Version || len(o.OneTimeKey) != 32 {
			return fmt.Errorf("%w: malformed new output", errLedger)
		}
		k := hexKey(o.OneTimeKey)
		if seen[k] || l.utxo[k] != nil {
			return fmt.Errorf("%w: duplicate new output key", errLedger)
		}
		if _, err := parseCommitment(o.Commitment); err != nil {
			return fmt.Errorf("%w: bad new output commitment", errLedger)
		}
		seen[k] = true
	}
	return nil
}

// checkConservation verifies Σ in − Σ out − Commit(fee;0) == Commit(0; BlindDiff)
// using the homomorphism of the PQ commitment. Reveals only the aggregate
// blinding difference, not amounts.
func (l *Ledger) checkConservation(spent *PQOutput, s *PQSpend) error {
	cIn, err := parseCommitment(spent.Commitment)
	if err != nil {
		return fmt.Errorf("%w: bad input commitment", errLedger)
	}
	acc := cIn
	for i := range s.Outputs {
		cOut, err := parseCommitment(s.Outputs[i].Commitment)
		if err != nil {
			return fmt.Errorf("%w: bad output commitment", errLedger)
		}
		acc = acc.Sub(cOut)
	}
	feeC, err := pqcommit.CommitNoBound(s.Fee, make([]int32, pqcommit.RandLen))
	if err != nil {
		return err
	}
	acc = acc.Sub(feeC)
	if len(s.BlindDiff) != pqcommit.RandLen {
		return fmt.Errorf("%w: bad blinding witness", errLedger)
	}
	// AUDIT FIX (HIGH, inflation): BlindDiff must be SHORT, not prover-chosen at
	// will. The conservation test acc == Commit(0; BlindDiff) only enforces value
	// balance when BlindDiff is bounded. The commitment map r ↦ (A1·r, A2·r) is
	// massively underdetermined (RandLen=512 unknowns vs N1+1=129 constraints), so
	// with an UNBOUNDED BlindDiff an attacker can solve A1·e=0, A2·e=Δv to absorb a
	// nonzero value mismatch Δv into the randomness — minting coins while passing
	// the check. Requiring BlindDiff to stay within the legitimate aggregate bound
	// makes finding such an e a hard SIS instance (the very basis of this scheme's
	// binding), so the value coordinate can no longer be forged. A genuine spend's
	// witness is r_in − Σ r_out over (1 input + len(Outputs)) terms, each |·|<=RandB,
	// so |BlindDiff_i| <= (1 + len(Outputs)) * RandB; reject anything larger.
	maxAbs := int64(1+len(s.Outputs)) * int64(pqcommit.RandB)
	for _, di := range s.BlindDiff {
		if int64(di) > maxAbs || int64(di) < -maxAbs {
			return fmt.Errorf("%w: blinding witness out of bound (inflation)", errLedger)
		}
	}
	zero, err := pqcommit.CommitNoBound(0, s.BlindDiff)
	if err != nil {
		return err
	}
	if !acc.Equal(zero) {
		return fmt.Errorf("%w: value not conserved (inflation)", errLedger)
	}
	return nil
}

// ApplySpend mutates the ledger after a successful ValidateSpend, mirroring
// chain.applyBlock: record the nullifier, delete the spent UTXO, and add the new
// outputs to the anonymity set and UTXO map.
func (l *Ledger) ApplySpend(s *PQSpend, root []byte, member *pqaccum.Proof) error {
	if err := l.ValidateSpend(s, root, member); err != nil {
		return err
	}
	l.nullifiers[hexKey(s.Nullifier)] = true
	delete(l.utxo, hexKey(s.OutputRef))
	delete(l.index, hexKey(s.OutputRef))
	for i := range s.Outputs {
		if err := l.AddOutput(&s.Outputs[i]); err != nil {
			return err
		}
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
