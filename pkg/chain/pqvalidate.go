package chain

import (
	"encoding/binary"
	"fmt"

	"obscura/pkg/config"
	"obscura/pkg/pqaccum"
	"obscura/pkg/pqsign"
	"obscura/pkg/pqstealth"
	"obscura/pkg/tx"

	"golang.org/x/crypto/blake2b"
)

// Post-quantum (Version-2) transaction validation. This is the experimental PQ
// path promoted from pkg/pqtx into the real consensus engine, gated by the
// presence of PQ fields and tx.Version == 2. Classical transactions never enter
// these functions, so the classical path's speed is unchanged.
//
// VALUE MODEL (honest): the consensus PQ value layer uses PUBLIC amounts. This is
// SOUND — there is no hidden value, so the wraparound/inflation attack that a
// confidential commitment without a range proof would allow is impossible, and
// the per-output supply-cap check bounds amounts directly. Recipient privacy
// (ML-KEM stealth) and post-quantum spend authority (hybrid Schnorr ⊕ WOTS+) are
// still fully in force; only the AMOUNT is public. Restoring confidential PQ
// amounts requires a compact PQ range proof (Ligero / zk-STARK over the bit
// decomposition — same research tier as the ZK-membership STARK), at which point
// the reserved tx.PQOutput.{Commitment,EncAmount,MAC} fields carry it. See
// docs/POST_QUANTUM_ROADMAP.md.
//
// Other honest limitations (prototype): PQ fees are BURNED (not yet credited to
// miners — clean to do once a PQ emission/wrap policy exists); coinbase PQ
// minting is FORBIDDEN (validate.go rejects all PQ fields on the coinbase — the
// old uncapped coinbase-PQ-mint route was removed as an inflation hole, so a PQ
// output can only be created by SPENDING an existing PQ output); ZK-private
// membership still needs the STARK (membership here is transparent, like the
// classical transparent path). None of this affects the classical chain.

const pqNullDom = "Obscura/pq/nullifier/v1"

// pqNullifierOf: nullifier = BLAKE2b(dom ‖ OutputRef). It is bound to the FULL
// output identity (OutputRef = BLAKE2b(P‖R)), not just R — otherwise two distinct
// outputs sharing a WOTS root R would collide on one nullifier, letting a spend
// of one permanently freeze the other (audit Finding 1).
func pqNullifierOf(outputRef []byte) []byte {
	d, _ := blake2b.New256(nil)
	d.Write([]byte(pqNullDom))
	d.Write(outputRef)
	return d.Sum(nil)
}

func pqHybridKey(p, r []byte) []byte {
	d, _ := blake2b.New256(nil)
	d.Write(p)
	d.Write([]byte("Obscura/pq/hybrid/v1"))
	d.Write(r)
	return d.Sum(nil)
}

// hasPQ reports whether a transaction uses the PQ path.
func hasPQ(t *tx.Transaction) bool {
	return len(t.PQInputs) > 0 || len(t.PQOutputs) > 0
}

// checkPQOutput validates a PQ output structurally, enforces the amount range
// (< supply cap — the public-amount analogue of a range proof), and enforces
// block-wide and confirmed-set OneTimeKey uniqueness (namespaced in seenPrime).
//
// NOTE (WOTS+ root dedup): the complementary anti-reuse defense — no two outputs
// may share a WOTS+ root R — CANNOT be enforced here because an output commits R
// only inside OneTimeKey = BLAKE2b(P‖R) and never exposes R on its own. R becomes
// visible only when the output is SPENT, so that dedup lives in the spend path
// (validatePQTxLocked, backed by the persistent c.pqWots set). See the comment
// there for the one-time-signature rationale.
func (c *Chain) checkPQOutput(o *tx.PQOutput, seenPrime map[string]bool) error {
	if len(o.OneTimeKey) != 32 || len(o.KEMCiphertext) != 1088 {
		return fmt.Errorf("%w: malformed pq output", errValidation)
	}
	if len(o.ViewTag) != pqstealth.TagSize {
		return fmt.Errorf("%w: bad pq view tag", errValidation)
	}
	// reserved confidential-amount fields must be empty until the PQ range proof
	// lands (else they are unvalidated chain-bloat space — audit Finding 2).
	if len(o.Commitment) != 0 || len(o.EncAmount) != 0 || len(o.MAC) != 0 {
		return fmt.Errorf("%w: reserved pq fields must be empty", errValidation)
	}
	if o.Amount == 0 || o.Amount > config.MoneySupplyCap {
		return fmt.Errorf("%w: pq output amount out of range", errValidation)
	}
	kk := "pqkey:" + hexstr(o.OneTimeKey)
	if seenPrime[kk] {
		return fmt.Errorf("%w: duplicate pq output key in block", errValidation)
	}
	// dedup against EVERY key ever created (pqIndex persists past spend), so a
	// one-time key can never be reused even after the output is spent.
	if _, exists := c.pqIndex[hexstr(o.OneTimeKey)]; exists {
		return fmt.Errorf("%w: duplicate pq output key", errValidation)
	}
	seenPrime[kk] = true
	return nil
}

// validatePQTxLocked validates a pure-PQ Version-2 transaction.
func (c *Chain) validatePQTxLocked(t *tx.Transaction, seenSpent, seenPrime map[string]bool) error {
	if t.Version != 2 {
		return fmt.Errorf("%w: pq tx must be version 2", errValidation)
	}
	// A PQ tx lives ENTIRELY in the PQ value space: it must carry ONLY PQ fields. Any
	// classical/ZK/CZK/swap/vault leg here is APPLIED by apply.go but NEVER validated on
	// this path (no proof, conservation, or anchor check), so allowing them lets a
	// PQ-routed tx mint forged ZK/CZK value, drain vaults, or forge swap outputs
	// (audit CRITICAL: PQ-routing bypass of all ZK/CZK/vault validation). Forbid all.
	if len(t.Inputs) != 0 || len(t.AnonInputs) != 0 || len(t.SwapInputs) != 0 ||
		len(t.SwapOutputs) != 0 || len(t.Outputs) != 0 || len(t.Conservation) != 0 ||
		len(t.ZKInputs) != 0 || len(t.ZKOutputs) != 0 || len(t.CZKSpends) != 0 ||
		len(t.VaultInputs) != 0 || len(t.VaultOutputs) != 0 {
		return fmt.Errorf("%w: pq tx must carry only pq fields", errValidation)
	}
	// PQBlindDiff is vestigial under public amounts; it is excluded from CoreHash,
	// so allowing arbitrary bytes there is a txid-malleability vector (audit). It
	// must be empty.
	if len(t.PQBlindDiff) != 0 {
		return fmt.Errorf("%w: pq blind-diff must be empty", errValidation)
	}
	if t.Height != 0 || t.Minted != 0 || len(t.ReferrerTag) != 0 || t.ExtraNonce != 0 {
		return fmt.Errorf("%w: coinbase-only fields set on pq tx", errValidation)
	}
	if len(t.PQInputs) == 0 || len(t.PQOutputs) == 0 {
		return fmt.Errorf("%w: pq tx needs inputs and outputs", errValidation)
	}
	if len(t.PQInputs) > tx.MaxInputs || len(t.PQOutputs) > tx.MaxOutputs {
		return fmt.Errorf("%w: too many pq inputs/outputs", errValidation)
	}
	// minimum fee (anti-spam), same rate as the classical path
	minFee, ovf := mulU64(uint64(len(t.Serialize())), config.MinFeePerByte)
	if ovf {
		return fmt.Errorf("%w: pq fee computation overflow", errValidation)
	}
	if t.Fee < minFee {
		return fmt.Errorf("%w: pq fee below minimum", errValidation)
	}

	ctx := t.CoreHash()

	var inSum uint64
	for i := range t.PQInputs {
		in := &t.PQInputs[i]
		if len(in.OutputRef) != 32 || len(in.P) != 32 || len(in.WotsRoot) != 32 ||
			len(in.Nullifier) != 32 || len(in.Anchor) != 32 {
			return fmt.Errorf("%w: malformed pq input", errValidation)
		}
		ref := hexstr(in.OutputRef)
		if seenSpent[ref] {
			return fmt.Errorf("%w: double-spend within block (pq ref)", errValidation)
		}
		spent, ok := c.pqUtxo[ref]
		if !ok {
			return fmt.Errorf("%w: spends nonexistent or already-spent pq output", errValidation)
		}
		// the output's one-time key must equal BLAKE2b(P‖R)
		if hexstr(pqHybridKey(in.P, in.WotsRoot)) != ref {
			return fmt.Errorf("%w: pq input keys do not match output", errValidation)
		}
		// nullifier bound to the full output, unseen in block and confirmed set
		if hexstr(pqNullifierOf(in.OutputRef)) != hexstr(in.Nullifier) {
			return fmt.Errorf("%w: pq nullifier not bound to output", errValidation)
		}
		nk := hexstr(in.Nullifier)
		if seenSpent[nk] {
			return fmt.Errorf("%w: duplicate pq nullifier in block", errValidation)
		}
		if c.pqNull[nk] {
			return fmt.Errorf("%w: double-spend (pq nullifier already seen)", errValidation)
		}
		// WOTS+ one-time-root reuse defense (defense-in-depth, dual of the
		// OneTimeKey dedup in checkPQOutput). POST-QUANTUM the Schnorr half of the
		// hybrid key is Shor-broken, so the WOTS+ root R is the SOLE spend defense
		// — and WOTS+ is a ONE-TIME signature: producing two signatures under one
		// root leaks enough key material to forge a third. A PQ output commits R
		// only INSIDE OneTimeKey = BLAKE2b(P‖R), so two outputs may share R while
		// differing in P (distinct OneTimeKey, both pass the OneTimeKey dedup). R is
		// revealed only HERE, at spend, so this is the only point at which reuse is
		// observable — reject a spend revealing an already-seen root (in-block or in
		// the persistent confirmed set c.pqWots).
		wk := "pqwots:" + hexstr(in.WotsRoot)
		if seenSpent[wk] {
			return fmt.Errorf("%w: duplicate pq wots root in block", errValidation)
		}
		if c.pqWots[hexstr(in.WotsRoot)] {
			return fmt.Errorf("%w: reused pq wots root (one-time signature)", errValidation)
		}
		// global-set membership against a known historical anchor (so a witness
		// built against any past PQ root stays valid across intervening blocks).
		if !c.pqRoots[hexstr(in.Anchor)] {
			return fmt.Errorf("%w: unknown pq anchor", errValidation)
		}
		mp, err := pqaccum.ParseProof(in.Membership)
		if err != nil {
			return fmt.Errorf("%w: malformed pq membership proof", errValidation)
		}
		if !pqaccum.Verify(in.Anchor, in.OutputRef, mp) {
			return fmt.Errorf("%w: invalid pq membership proof", errValidation)
		}
		// hybrid spend authorization (classical ⊕ WOTS+) over the CoreHash
		sig, err := parseHybridSig(in.HybridSig)
		if err != nil {
			return fmt.Errorf("%w: malformed pq signature", errValidation)
		}
		if !pqsign.HybridVerify(in.OutputRef, in.P, in.WotsRoot, ctx[:], sig) {
			return fmt.Errorf("%w: pq spend authorization failed", errValidation)
		}
		inSum, ovf = addU64(inSum, spent.Amount)
		if ovf {
			return fmt.Errorf("%w: pq input sum overflow", errValidation)
		}
		seenSpent[ref] = true
		seenSpent[nk] = true
		seenSpent[wk] = true
	}

	var outSum uint64
	for i := range t.PQOutputs {
		if err := c.checkPQOutput(&t.PQOutputs[i], seenPrime); err != nil {
			return err
		}
		outSum, ovf = addU64(outSum, t.PQOutputs[i].Amount)
		if ovf {
			return fmt.Errorf("%w: pq output sum overflow", errValidation)
		}
	}

	// value conservation (public amounts): Σ in == Σ out + fee. Fee is burned.
	spentTotal, ovf := addU64(outSum, t.Fee)
	if ovf {
		return fmt.Errorf("%w: pq value overflow", errValidation)
	}
	if inSum != spentTotal {
		return fmt.Errorf("%w: pq value not conserved", errValidation)
	}
	return nil
}

// PQProve returns a serialized membership proof for a PQ output.
func (c *Chain) PQProve(oneTimeKey []byte) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	idx, ok := c.pqIndex[hexstr(oneTimeKey)]
	if !ok {
		return nil, fmt.Errorf("%w: unknown pq output", errValidation)
	}
	p, err := c.pqAcc.Prove(idx)
	if err != nil {
		return nil, err
	}
	return p.Marshal(), nil
}

// PQRoot returns the current PQ anonymity-set root (the anchor a fresh spend
// should reference).
func (c *Chain) PQRoot() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pqAcc.Root()
}

// parseHybridSig decodes wire = u32 len ‖ Schnorr ‖ u32 len ‖ Wots.
func parseHybridSig(b []byte) (*pqsign.HybridSig, error) {
	if len(b) < 8 {
		return nil, errValidation
	}
	sl := binary.BigEndian.Uint32(b[:4])
	if 4+int(sl)+4 > len(b) {
		return nil, errValidation
	}
	schnorr := b[4 : 4+sl]
	off := 4 + int(sl)
	wl := binary.BigEndian.Uint32(b[off : off+4])
	off += 4
	if off+int(wl) != len(b) {
		return nil, errValidation
	}
	return &pqsign.HybridSig{
		Schnorr: append([]byte(nil), schnorr...),
		Wots:    append([]byte(nil), b[off:off+int(wl)]...),
	}, nil
}
