package chain

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"filippo.io/edwards25519"

	"obscura/pkg/accumulator"
	"obscura/pkg/block"
	"obscura/pkg/commit"
	"obscura/pkg/config"
	"obscura/pkg/consensus"
	"obscura/pkg/pow"
	"obscura/pkg/swap"
	"obscura/pkg/tx"
)

// ExpectedDifficulty returns the difficulty required for the next block.
func (c *Chain) ExpectedDifficulty() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ts, df := c.recentTimestampsAndDiffs()
	return consensus.NextDifficulty(ts, df)
}

// ValidateBlock checks a candidate block against the current tip WITHOUT
// mutating state.
func (c *Chain) ValidateBlock(b *block.Block) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.validateBlockLocked(b)
}

func (c *Chain) validateBlockLocked(b *block.Block) error {
	tip := c.headers[len(c.headers)-1]
	h := &b.Header

	// --- block weight (anti-DoS): reject oversized blocks early ---
	if sz := len(b.Serialize()); sz > config.MaxBlockBytes {
		return fmt.Errorf("%w: block too large (%d > %d)", errValidation, sz, config.MaxBlockBytes)
	}

	// --- header checks ---
	if h.Height != tip.Height+1 {
		return fmt.Errorf("%w: height %d, expected %d", errValidation, h.Height, tip.Height+1)
	}
	if h.PrevHash != tip.ID() {
		return fmt.Errorf("%w: prevhash mismatch", errValidation)
	}
	if h.Difficulty == 0 {
		return fmt.Errorf("%w: zero difficulty", errValidation)
	}
	// Future-time bound (standard practice; a too-future block is only
	// temporarily rejected and re-evaluated as wall-clock advances).
	if h.Timestamp > time.Now().Unix()+config.MaxFutureDriftSeconds {
		return fmt.Errorf("%w: timestamp too far in future", errValidation)
	}
	// Lower bound = median-time-past (deterministic, manipulation-resistant).
	if h.Timestamp <= c.medianTimePastLocked() {
		return fmt.Errorf("%w: timestamp <= median-time-past", errValidation)
	}
	ts, df := c.recentTimestampsAndDiffs()
	expDiff := consensus.NextDifficulty(ts, df)
	if h.Difficulty != expDiff {
		return fmt.Errorf("%w: difficulty %d, expected %d", errValidation, h.Difficulty, expDiff)
	}
	seed, known := c.powSeedLocked(h.Height)
	if !known {
		return fmt.Errorf("%w: missing PoW epoch seed for height %d", errValidation, h.Height)
	}
	if !pow.Meets(h.PoWHashSeed(seed), h.Difficulty) {
		return fmt.Errorf("%w: insufficient proof of work", errValidation)
	}

	// --- transaction structure ---
	if len(b.Txs) == 0 || !b.Txs[0].IsCoinbase {
		return fmt.Errorf("%w: missing coinbase", errValidation)
	}
	seenTxid := make(map[[32]byte]bool)
	for i := 0; i < len(b.Txs); i++ {
		if i > 0 && b.Txs[i].IsCoinbase {
			return fmt.Errorf("%w: multiple coinbases", errValidation)
		}
		id := b.Txs[i].Hash()
		if seenTxid[id] {
			return fmt.Errorf("%w: duplicate transaction in block", errValidation)
		}
		seenTxid[id] = true
	}

	height := h.Height
	seenSpent := make(map[string]bool)
	seenPrime := make(map[string]bool)
	var fees uint64
	newPrimes := make([]*big.Int, 0)

	// coinbase outputs (added to accumulator + UTXO on apply)
	cb := b.Txs[0]
	for i := range cb.Outputs {
		p, err := c.checkOutput(&cb.Outputs[i], seenPrime, false)
		if err != nil {
			return err
		}
		newPrimes = append(newPrimes, p)
	}
	// A coinbase may carry ONLY transparent Outputs (validated above), plus its
	// conservation proof and the coinbase-economics fields. It must NOT carry any spend or
	// alternative-value-space leg: NONE of those are validated on the coinbase path, so
	// apply() would record forged ZK/CZK/PQ/swap/vault value that a miner simply inserted
	// (audit CRITICAL: unvalidated coinbase value legs). PQ coinbase minting is disabled
	// outright until a real, capped PQ emission schedule exists — previously it minted PQ
	// outputs with no aggregate cap (audit CRITICAL: uncapped coinbase PQ minting).
	if len(cb.Inputs) != 0 || len(cb.AnonInputs) != 0 ||
		len(cb.SwapInputs) != 0 || len(cb.SwapOutputs) != 0 ||
		len(cb.ZKInputs) != 0 || len(cb.ZKOutputs) != 0 || len(cb.CZKSpends) != 0 ||
		len(cb.VaultInputs) != 0 || len(cb.VaultOutputs) != 0 ||
		len(cb.PQInputs) != 0 || len(cb.PQOutputs) != 0 || len(cb.PQBlindDiff) != 0 {
		return fmt.Errorf("%w: coinbase may carry only transparent outputs", errValidation)
	}

	// Best-effort PARALLEL pre-verification of per-tx proofs before the authoritative
	// sequential pass. The expensive crypto (range/ownership/value/key-image/anon/STARK)
	// is independent per tx, so we verify it across cores and cache the results; the loop
	// below then skips re-verifying them and only does the cheap, order-dependent state
	// checks (in-block double-spend, UTXO availability). Pure optimization — see
	// prewarmProofCacheLocked. Mainly speeds initial sync and blocks carrying txs we never
	// saw in our mempool (steady-state txs are already cached from admission).
	c.prewarmProofCacheLocked(b.Txs[1:], height)

	for i := 1; i < len(b.Txs); i++ {
		t := b.Txs[i]
		ps, err := c.validateTxLocked(t, height, seenSpent, seenPrime)
		if err != nil {
			return fmt.Errorf("tx %s: %w", t.HashHex(), err)
		}
		newPrimes = append(newPrimes, ps...)
		// PQ-tx fees live in the PQ value space and are burned there via PQ conservation;
		// crediting them to the CLASSICAL coinbase would create the same value twice
		// (audit CRITICAL: PQ fee leakage into the classical coinbase). Skip them.
		if hasPQ(t) {
			continue
		}
		nf, ovf := addU64(fees, t.Fee)
		if ovf {
			return fmt.Errorf("%w: fee sum overflow", errValidation)
		}
		fees = nf
	}

	// --- vault affordability: the total yield released by all claims in this block
	// must be covered by the incentive pool (yield is paid from it; principal is
	// backed by the locked deposits). This is the only thing tying vault payouts to
	// a real, already-emitted, supply-capped source — so it guarantees no inflation.
	var totalVaultYield uint64
	for _, t := range b.Txs {
		for _, in := range t.VaultInputs {
			v, ok := c.vaults[hexstr(in.VaultKey)]
			if !ok {
				return fmt.Errorf("%w: vault claim references unknown vault", errValidation)
			}
			// Affordability sums the STATED yields (each capped to entitlement in
			// validateTxLocked). cap recomputed only to surface an overflow early.
			if _, ok := vaultYieldAt(v, b.Header.Height); !ok {
				return fmt.Errorf("%w: vault yield computation overflow", errValidation)
			}
			var ovf bool
			if totalVaultYield, ovf = addU64(totalVaultYield, in.Yield); ovf {
				return fmt.Errorf("%w: vault yield sum overflow", errValidation)
			}
		}
	}
	if totalVaultYield > c.incentivePool {
		return fmt.Errorf("%w: vault yield exceeds incentive pool", errValidation)
	}

	// --- coinbase economics (overflow-checked) ---
	expMinted, err := c.expectedCoinbaseMintedChecked(fees, cb.ReferrerTag)
	if err != nil {
		return err
	}
	if cb.Minted != expMinted {
		return fmt.Errorf("%w: coinbase minted %d, expected %d", errValidation, cb.Minted, expMinted)
	}
	if cb.Minted > config.MoneySupplyCap {
		return fmt.Errorf("%w: coinbase minted exceeds supply cap", errValidation)
	}
	if cb.Height != h.Height {
		return fmt.Errorf("%w: coinbase height mismatch", errValidation)
	}
	if len(cb.Inputs) != 0 {
		return fmt.Errorf("%w: coinbase must have no inputs", errValidation)
	}
	cbOuts := commitmentList(cb.Outputs)
	// The coinbase conservation proof binds the CLASSICAL coinbase only; any PQ
	// outputs it mints are tamper-protected by the block merkle root, so they are
	// excluded from this context (and were empty when the proof was built).
	cbForCtx := *cb
	cbForCtx.PQInputs, cbForCtx.PQOutputs, cbForCtx.PQBlindDiff = nil, nil, nil
	cbCtx := cbForCtx.CoreHash()
	if !commit.VerifyCoinbaseConservation(cb.Minted, cbOuts, cb.Conservation, cbCtx[:]) {
		return fmt.Errorf("%w: coinbase conservation invalid", errValidation)
	}

	// --- merkle root ---
	if block.MerkleRoot(b.Txs) != h.MerkleRoot {
		return fmt.Errorf("%w: merkle root mismatch", errValidation)
	}

	// --- proof-of-retrievability: the miner must hold the challenged historical bodies
	// (so a pruned node cannot mine). Verified against stored headers — pruned validators
	// still work. See por.go / pkg/block/por.go.
	if err := c.validatePoRLocked(b); err != nil {
		return err
	}

	// --- accumulator checkpoint: newAcc = acc^(∏ newPrimes) (add-only) ---
	prod := big.NewInt(1)
	for _, p := range newPrimes {
		prod.Mul(prod, p)
	}
	predicted := c.G.Exp(c.acc.Value(), prod)
	if !bytes.Equal(c.G.Marshal(predicted), h.AccValue) {
		return fmt.Errorf("%w: accumulator checkpoint mismatch", errValidation)
	}
	if h.AccSize != uint64(c.acc.Size())+uint64(len(newPrimes)) {
		return fmt.Errorf("%w: accumulator size mismatch", errValidation)
	}

	// --- post-quantum accumulator checkpoint: header commits the PQ root AFTER
	// this block's PQ outputs (added in apply order: coinbase, then txs). ---
	var pqKeys [][]byte
	for _, t := range b.Txs {
		for i := range t.PQOutputs {
			pqKeys = append(pqKeys, t.PQOutputs[i].OneTimeKey)
		}
	}
	var predictedPQ [32]byte
	copy(predictedPQ[:], c.pqAcc.RootAfter(pqKeys))
	if predictedPQ != h.PQAccRoot {
		return fmt.Errorf("%w: pq accumulator root mismatch", errValidation)
	}

	// --- nullifier-set checkpoint: header commits the spent-set Merkle root
	// AFTER this block's key-images are added (in applyBlock order). ---
	var predictedNull [32]byte
	copy(predictedNull[:], c.nullAcc.RootAfter(blockTagsFromTxs(b.Txs)))
	if predictedNull != h.NullRoot {
		return fmt.Errorf("%w: nullifier root mismatch", errValidation)
	}

	// --- ZK commitment-tree checkpoint: header commits the Poseidon tree root
	// AFTER this block's coin leaves are appended (docs/ZK_MEMBERSHIP_SPEND.md). ---
	if !c.predictedCMRootMatches(b) {
		return fmt.Errorf("%w: commitment-tree root mismatch", errValidation)
	}

	// --- PRE-STATE root: the header commits the PARENT's residual consensus state
	// (emitted/incentivePool, disk-set commitments, in-RAM maps). validate runs at the
	// parent tip, so this is the SAME value the miner committed — no prediction. See
	// chain/stateroot.go. ---
	if c.stateRootLocked() != h.StateRoot {
		return fmt.Errorf("%w: state-root mismatch", errValidation)
	}
	return nil
}

// blockTagsFromTxs collects every key-image/nullifier a block spends, in the
// exact order applyBlock records them (per non-coinbase tx: transparent inputs
// then anonymous inputs). Used to predict/verify the header NullRoot and to feed
// the nullifier accumulator — the order MUST match applyBlock.
func blockTagsFromTxs(txs []*tx.Transaction) [][]byte {
	var out [][]byte
	for _, t := range txs {
		if t.IsCoinbase {
			continue
		}
		for _, in := range t.Inputs {
			if len(in.KeyImage) == 32 {
				// store the cofactor-cleared canonical nullifier (8·T); falls back to
				// the raw bytes only for an undecodable tag (which validation rejects
				// before this runs) so the order/content stays defined.
				if c, ok := commit.CanonicalNullifier(in.KeyImage); ok {
					out = append(out, c)
				} else {
					out = append(out, in.KeyImage)
				}
			}
		}
		for _, in := range t.AnonInputs {
			if c, ok := commit.CanonicalNullifier(in.Tag); ok {
				out = append(out, c)
			} else {
				out = append(out, in.Tag)
			}
		}
	}
	return out
}

// checkOutput validates a single output and returns its accumulator prime.
func (c *Chain) checkOutput(o *tx.Output, seenPrime map[string]bool, skipProofs bool) (*big.Int, error) {
	if len(o.OneTimeKey) != 32 || len(o.TxPubKey) != 32 || len(o.Commitment) != 32 {
		return nil, fmt.Errorf("%w: malformed output", errValidation)
	}
	// reject a non-canonical or identity one-time key: identity P (x=0) yields an
	// identity key-image and a degenerate, collision-prone nullifier.
	if pt, err := new(edwards25519.Point).SetBytes(o.OneTimeKey); err != nil || pt.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, fmt.Errorf("%w: invalid output key", errValidation)
	}
	if !skipProofs && !commit.VerifyRangeBytes(o.Commitment, o.RangeProof) {
		return nil, fmt.Errorf("%w: range proof invalid", errValidation)
	}
	pb, ok := accumulator.HashToPrimeVerifyableData(o.OneTimeKey, o.PrimeNonce)
	if !ok {
		return nil, fmt.Errorf("%w: invalid output prime", errValidation)
	}
	pk := hexstr(pb)
	if seenPrime[pk] {
		return nil, fmt.Errorf("%w: duplicate output prime in block", errValidation)
	}
	// An output one-time key must be globally unique (uniqueness of P). Enforce it
	// BLOCK-WIDE too: a non-canonical PrimeNonce lets the same key map to different
	// primes, so deduping on the prime alone is insufficient — two outputs in one
	// block could share a key (collapsing UTXO/coin state at apply). Dedup the key
	// itself (namespaced in the shared block map) and against the confirmed UTXO set.
	kk := "key:" + hexstr(o.OneTimeKey)
	if seenPrime[kk] {
		return nil, fmt.Errorf("%w: duplicate output key in block", errValidation)
	}
	// an output one-time key must be globally unique. Check against EVERY coin ever
	// created (the coin store), which also catches reuse of an already-spent key —
	// stronger than the old live-utxo-only check.
	if c.coinByKeyLocked(o.OneTimeKey) != nil {
		return nil, fmt.Errorf("%w: duplicate output key", errValidation)
	}
	if c.outPrimes.Has(pk) {
		return nil, fmt.Errorf("%w: duplicate output prime", errValidation)
	}
	seenPrime[pk] = true
	seenPrime[kk] = true
	return new(big.Int).SetBytes(pb), nil
}

// validateTxLocked validates a non-coinbase transaction at the given height.
func (c *Chain) validateTxLocked(t *tx.Transaction, height uint64, seenSpent, seenPrime map[string]bool) ([]*big.Int, error) {
	if t.IsCoinbase {
		return nil, fmt.Errorf("%w: coinbase out of position", errValidation)
	}
	// Post-quantum (Version-2) path: pure-PQ transactions are validated
	// separately and contribute no classical accumulator primes. The classical
	// path below is never entered for them, so its speed is unaffected.
	if hasPQ(t) {
		return nil, c.validatePQTxLocked(t, seenSpent, seenPrime)
	}
	// audit fix (txid malleability): PQBlindDiff is EXCLUDED from CoreHash (tx.go), so
	// it is unsigned space. hasPQ() keys only on PQInputs/PQOutputs, so a classical tx
	// carrying ONLY a PQBlindDiff routes down this path where it was never checked, and
	// a third party could attach/mutate it to change the txid without breaking the
	// signature. It is vestigial under public amounts, so reject any stray PQ field here.
	if len(t.PQBlindDiff) != 0 || len(t.PQInputs) != 0 || len(t.PQOutputs) != 0 {
		return nil, fmt.Errorf("%w: PQ fields on non-PQ transaction", errValidation)
	}
	// A CZKSpend is BOTH an input (consumes a coin via its nullifier) and an output
	// (mints LeafOut), so it satisfies both presence checks on its own.
	if len(t.Inputs)+len(t.AnonInputs)+len(t.SwapInputs)+len(t.VaultInputs)+len(t.ZKInputs)+len(t.CZKSpends) == 0 {
		return nil, fmt.Errorf("%w: no inputs", errValidation)
	}
	if len(t.Outputs)+len(t.SwapOutputs)+len(t.VaultOutputs)+len(t.ZKOutputs)+len(t.CZKSpends) == 0 {
		return nil, fmt.Errorf("%w: no outputs", errValidation)
	}
	if len(t.Inputs) > tx.MaxInputs || len(t.AnonInputs) > tx.MaxInputs ||
		len(t.SwapInputs) > tx.MaxInputs || len(t.Outputs) > tx.MaxOutputs || len(t.SwapOutputs) > tx.MaxOutputs ||
		len(t.VaultInputs) > tx.MaxInputs || len(t.VaultOutputs) > tx.MaxOutputs {
		return nil, fmt.Errorf("%w: too many inputs/outputs", errValidation)
	}
	// non-coinbase txs must not carry coinbase-only fields (malleability/abuse)
	if t.Height != 0 || t.Minted != 0 || len(t.ReferrerTag) != 0 || t.ExtraNonce != 0 {
		return nil, fmt.Errorf("%w: coinbase-only fields set on normal tx", errValidation)
	}
	// minimum fee (anti-spam)
	minFee, ovf := mulU64(uint64(len(t.Serialize())), config.MinFeePerByte)
	if ovf {
		return nil, fmt.Errorf("%w: fee computation overflow", errValidation)
	}
	if t.Fee < minFee {
		return nil, fmt.Errorf("%w: fee below minimum", errValidation)
	}

	ctx := t.CoreHash()
	// Skip the expensive EC proof verifications if we already verified this exact
	// tx (by full txid) during mempool admission — its proofs are immutable. All
	// cheap structural / double-spend / UTXO-state checks below STILL run.
	id := t.Hash()
	skip := c.proofVerified(id)

	// inputs: ownership + value-equality + UTXO availability + maturity + lock +
	// key-image (the coin's canonical nullifier, SHARED with the anonymous-spend
	// domain so a coin cannot be spent both transparently and anonymously).
	for _, in := range t.Inputs {
		if len(in.OutputRef) != 32 || len(in.PseudoCommitment) != 32 || len(in.KeyImage) != 32 {
			return nil, fmt.Errorf("%w: malformed input", errValidation)
		}
		ref := hexstr(in.OutputRef)
		if seenSpent[ref] {
			return nil, fmt.Errorf("%w: double-spend within block", errValidation)
		}
		entry, ok := c.utxoEntryLocked(in.OutputRef)
		if !ok {
			return nil, fmt.Errorf("%w: spends nonexistent or already-spent output", errValidation)
		}
		if entry.IsCoinbase && height < entry.Height+config.CoinbaseMaturity {
			return nil, fmt.Errorf("%w: spends immature coinbase", errValidation)
		}
		if height < entry.LockUntil {
			return nil, fmt.Errorf("%w: spends time-locked output", errValidation)
		}
		if !skip && !commit.VerifyOwnership(in.OutputRef, in.OwnershipProof, ctx[:]) {
			return nil, fmt.Errorf("%w: invalid ownership proof", errValidation)
		}
		if !skip && !commit.VerifyValueEquality(in.PseudoCommitment, entry.Commitment, in.EqualityProof, ctx[:]) {
			return nil, fmt.Errorf("%w: invalid value-equality proof", errValidation)
		}
		// key-image nullifier: keyed in the SAME namespace as anon tags so a
		// transparent and an anonymous spend of one coin collide here. Canonicalize
		// to the cofactor-cleared tag (8·T) so the (up to 8) torsion variants of one
		// coin's key-image collapse to a single nullifier — closes the key-image
		// torsion double-spend (Monero CVE-2017-12424). Reject low-order tags.
		kib, ok := commit.CanonicalNullifier(in.KeyImage)
		if !ok {
			return nil, fmt.Errorf("%w: non-canonical or low-order key-image", errValidation)
		}
		ki := hexstr(kib)
		if seenSpent[ki] {
			return nil, fmt.Errorf("%w: duplicate key-image in block", errValidation)
		}
		if c.tags.Has(ki) {
			return nil, fmt.Errorf("%w: double-spend (key-image already seen)", errValidation)
		}
		if !skip && !commit.VerifyKeyImage(in.OutputRef, in.KeyImage, in.KeyImageProof, ctx[:]) {
			return nil, fmt.Errorf("%w: invalid key-image proof", errValidation)
		}
		seenSpent[ref] = true
		seenSpent[ki] = true
	}

	// anonymous inputs: verify each joint proof, ring membership, maturity, and
	// key-image freshness. The spent coin stays hidden; double-spend is caught
	// by the tag set.
	for _, in := range t.AnonInputs {
		if len(in.Tag) != 32 || len(in.PseudoCommitment) != 32 {
			return nil, fmt.Errorf("%w: malformed anon input", errValidation)
		}
		// canonicalize the anon tag to its cofactor-cleared form (8·T) so torsion
		// variants of one coin's tag collapse to a single nullifier (key-image
		// torsion double-spend, Monero CVE-2017-12424). Reject low-order tags.
		tagb, ok := commit.CanonicalNullifier(in.Tag)
		if !ok {
			return nil, fmt.Errorf("%w: non-canonical or low-order anon tag", errValidation)
		}
		tk := hexstr(tagb)
		if seenSpent[tk] {
			return nil, fmt.Errorf("%w: duplicate key-image in block", errValidation)
		}
		if c.tags.Has(tk) {
			return nil, fmt.Errorf("%w: anonymous double-spend (key-image seen)", errValidation)
		}
		// The ring is the canonical membership of a complete, mature pool —
		// reconstructed by consensus (the sender only names the pool id), so
		// verification cost is bounded by PoolSize and there is no decoy choice.
		ringKeys, ringCommits, ok := c.poolMembersLocked(in.PoolID, height)
		if !ok {
			return nil, fmt.Errorf("%w: anon pool incomplete or immature", errValidation)
		}
		n := len(ringKeys)
		if n < 2 || n&(n-1) != 0 {
			return nil, fmt.Errorf("%w: pool size must be a power of two >= 2", errValidation)
		}
		if !skip && !commit.VerifyAnonSpendBytes(ringKeys, ringCommits, in.PseudoCommitment, in.Tag, in.Proof, ctx[:]) {
			return nil, fmt.Errorf("%w: anonymous spend proof invalid", errValidation)
		}
		seenSpent[tk] = true
	}

	// swap inputs: claim (before unlock, sig under ClaimKey) or refund (at/after
	// unlock, sig under RefundKey). The locked amount re-enters as public value.
	var publicIn uint64
	for _, in := range t.SwapInputs {
		if len(in.SwapKey) != 32 {
			return nil, fmt.Errorf("%w: malformed swap input", errValidation)
		}
		sk := "swap:" + hexstr(in.SwapKey)
		if seenSpent[sk] {
			return nil, fmt.Errorf("%w: duplicate swap spend in block", errValidation)
		}
		sw, ok := c.swaps[hexstr(in.SwapKey)]
		if !ok {
			return nil, fmt.Errorf("%w: spends nonexistent/closed swap", errValidation)
		}
		sig, err := commit.ParseFullSig(in.Sig)
		if err != nil {
			return nil, fmt.Errorf("%w: bad swap signature", errValidation)
		}
		if in.IsRefund {
			if height < sw.UnlockHeight {
				return nil, fmt.Errorf("%w: swap refund before unlock height", errValidation)
			}
			if !skip && !commit.VerifyFull(sw.RefundKey, ctx[:], sig) {
				return nil, fmt.Errorf("%w: invalid swap refund signature", errValidation)
			}
		} else {
			// #11 reorg grace margin: a claim is valid only a margin of blocks BEFORE
			// the unlock height (height + SwapReorgMargin <= UnlockHeight), leaving a
			// dead-zone [UnlockHeight-margin, UnlockHeight) where neither claim nor
			// refund is valid. This MUST match swap.SwapOutput.VerifyClaim exactly so
			// consensus and the helper agree (a mismatch is itself a bug). Underflow-safe:
			// a swap with UnlockHeight < margin has no claim window (refund-only).
			if sw.UnlockHeight < config.SwapReorgMargin || height > sw.UnlockHeight-config.SwapReorgMargin {
				return nil, fmt.Errorf("%w: swap claim within reorg margin of unlock height", errValidation)
			}
			if !skip {
				// Atomicity binding: the claim signature MUST be the adaptor
				// pre-signature adapted by the secret, i.e. its nonce equals
				// ClaimR + ClaimT. This forces publication of the claim to reveal
				// the adaptor secret (Extract = s_full − s'); a rogue independent
				// signature uses an unbound nonce and is rejected here even though
				// it would verify under a rogue-controlled ClaimKey.
				if !swap.ClaimBindingOK(sig.R, sw.ClaimR, sw.ClaimT) {
					return nil, fmt.Errorf("%w: swap claim not bound to adaptor pre-signature", errValidation)
				}
				if !commit.VerifyFull(sw.ClaimKey, ctx[:], sig) {
					return nil, fmt.Errorf("%w: invalid swap claim signature", errValidation)
				}
			}
		}
		var ovf2 bool
		publicIn, ovf2 = addU64(publicIn, sw.Amount)
		if ovf2 {
			return nil, fmt.Errorf("%w: swap input amount overflow", errValidation)
		}
		seenSpent[sk] = true
	}

	// vault claims: a matured vault releases principal + yield as PUBLIC value
	// re-entering the confidential pool (publicIn). Yield is paid from the
	// incentive pool — the block-level affordability check (Σ yields ≤ pool) is in
	// validateBlockLocked. Double-claim is caught block-wide via "vaultin:".
	for _, in := range t.VaultInputs {
		if len(in.VaultKey) != 32 {
			return nil, fmt.Errorf("%w: malformed vault input", errValidation)
		}
		vk := "vaultin:" + hexstr(in.VaultKey)
		if seenSpent[vk] {
			return nil, fmt.Errorf("%w: duplicate vault claim in block", errValidation)
		}
		v, ok := c.vaults[hexstr(in.VaultKey)]
		if !ok {
			return nil, fmt.Errorf("%w: claims nonexistent/closed vault", errValidation)
		}
		if height < v.Maturity() {
			return nil, fmt.Errorf("%w: vault claim before maturity", errValidation)
		}
		sig, err := commit.ParseFullSig(in.Sig)
		if err != nil {
			return nil, fmt.Errorf("%w: bad vault signature", errValidation)
		}
		if !skip && !commit.VerifyFull(v.OwnerKey, ctx[:], sig) {
			return nil, fmt.Errorf("%w: invalid vault claim signature", errValidation)
		}
		// The claimer STATES in.Yield; consensus caps it at the vault's entitled
		// yield at THIS block height (full for a fixed term, pro-rata for a flexible
		// Term==0 vault). Stating less is allowed (forgoing yield); stating more is a
		// hard reject. Using the stated value keeps the wallet's value-conservation
		// proof exact regardless of how many blocks after building the claim is mined.
		cap, ok := vaultYieldAt(v, height)
		if !ok {
			return nil, fmt.Errorf("%w: vault yield computation overflow", errValidation)
		}
		if in.Yield > cap {
			return nil, fmt.Errorf("%w: vault claim yield exceeds entitlement", errValidation)
		}
		var ovf2 bool
		if publicIn, ovf2 = addU64(publicIn, v.Amount); ovf2 {
			return nil, fmt.Errorf("%w: vault principal overflow", errValidation)
		}
		if publicIn, ovf2 = addU64(publicIn, in.Yield); ovf2 {
			return nil, fmt.Errorf("%w: vault yield overflow", errValidation)
		}
		seenSpent[vk] = true
	}

	// swap outputs: lock public value into a new contract (publicOut). Swap-output
	// keys are deduped BLOCK-WIDE via seenSpent (namespaced "swapout:"), not just
	// per-tx, so two txs in one block cannot register the same swap key (the second
	// would silently overwrite the first at apply, burning the first's funds).
	publicOut := t.Fee
	for _, so := range t.SwapOutputs {
		if len(so.SwapKey) != 32 || len(so.ClaimKey) != 32 || len(so.RefundKey) != 32 ||
			len(so.ClaimA) != 32 || len(so.ClaimB) != 32 || len(so.ClaimR) != 32 || len(so.ClaimT) != 32 {
			return nil, fmt.Errorf("%w: malformed swap output", errValidation)
		}
		// Rogue-key defense: the aggregate claim key must equal A+B where each
		// contributed share carries a verified proof-of-possession. This blocks a
		// claimer from registering a cancelling share A' = R−B that would let them
		// control the aggregate key alone and steal the OBX without revealing the
		// adaptor secret. (audit: swap 2-of-2 claim-key rogue-key attack)
		if !skip {
			agg := swap.AggregateKeyVerified(so.ClaimA, so.ClaimB, so.PoPA, so.PoPB)
			if agg == nil || !bytes.Equal(agg.Bytes(), so.ClaimKey) {
				return nil, fmt.Errorf("%w: swap claim key not a proven 2-of-2 aggregate", errValidation)
			}
			// Atomicity binding: the adaptor point T committed here must be
			// non-identity (T=0 collapses the claim into a plain signature that
			// reveals no secret). ClaimBindingOK at claim time enforces the rest.
			Tp, err := new(edwards25519.Point).SetBytes(so.ClaimT)
			if err != nil || Tp.Equal(edwards25519.NewIdentityPoint()) == 1 {
				return nil, fmt.Errorf("%w: swap adaptor point invalid", errValidation)
			}
			if _, err := new(edwards25519.Point).SetBytes(so.ClaimR); err != nil {
				return nil, fmt.Errorf("%w: swap pre-signature nonce invalid", errValidation)
			}
		}
		k := hexstr(so.SwapKey)
		if seenSpent["swapout:"+k] || c.swaps[k] != nil {
			return nil, fmt.Errorf("%w: duplicate swap key", errValidation)
		}
		// CONSENSUS adaptor-nonce uniqueness (audit #14): reject any swap output whose
		// pre-signature nonce ClaimR was EVER funded before (persistent swapNonces set)
		// or appears twice in this block (block-wide "swapnonce:" dedup). Reusing R
		// across two claims under the same aggregate key leaks the secret share; the
		// honest path draws a fresh R per swap (swapsession.DeriveNonce), so a fresh
		// swap NEVER collides here. Keyed on ClaimR alone — the safe superset of the
		// precise (ClaimKey,ClaimR) leak condition (see Chain.swapNonces).
		rk := hexstr(so.ClaimR)
		if seenSpent["swapnonce:"+rk] {
			return nil, fmt.Errorf("%w: duplicate swap adaptor nonce in block", errValidation)
		}
		if c.swapNonces[rk] {
			return nil, fmt.Errorf("%w: swap adaptor nonce reuse (ClaimR already funded)", errValidation)
		}
		if so.Amount == 0 || so.Amount > config.MoneySupplyCap {
			return nil, fmt.Errorf("%w: bad swap amount", errValidation)
		}
		// F-1 FIX (fund-freeze, defense-in-depth): reject a SwapOutput whose claim
		// window is PROVABLY DEAD at fund time. A claim is valid iff
		// height + SwapReorgMargin <= UnlockHeight (see VerifyClaim and the swap-input
		// claim path above), so funding with UnlockHeight < height + SwapReorgMargin
		// registers a swap that can NEVER be claimed — a taker that locked XNO into it
		// could only be refunded against (frozen XNO). Such an output should never get
		// on-chain. Underflow-safe (margin is a constant addend). This is the consensus
		// backstop to the off-chain taker/maker checks in pkg/swapsession; it uses only
		// the reorg margin (the extra SwapMinClaimWindow headroom is a per-counterparty
		// liveness concern, not a consensus rule).
		if so.UnlockHeight < height+config.SwapReorgMargin {
			return nil, fmt.Errorf("%w: swap unlock height within reorg margin (dead claim window)", errValidation)
		}
		seenSpent["swapout:"+k] = true
		seenSpent["swapnonce:"+rk] = true
		var ovf2 bool
		publicOut, ovf2 = addU64(publicOut, so.Amount)
		if ovf2 {
			return nil, fmt.Errorf("%w: swap output amount overflow", errValidation)
		}
	}

	// vault deposits: lock PUBLIC value into a new vault (publicOut). Keys are
	// deduped block-wide ("vaultout:") and against live vaults, like swap outputs.
	for _, vo := range t.VaultOutputs {
		if len(vo.VaultKey) != 32 || len(vo.OwnerKey) != 32 {
			return nil, fmt.Errorf("%w: malformed vault output", errValidation)
		}
		if _, ok := config.VaultRateBps(vo.Term); !ok {
			return nil, fmt.Errorf("%w: invalid vault term", errValidation)
		}
		if vo.Amount == 0 || vo.Amount > config.MoneySupplyCap {
			return nil, fmt.Errorf("%w: bad vault amount", errValidation)
		}
		k := hexstr(vo.VaultKey)
		if seenSpent["vaultout:"+k] || c.vaults[k] != nil {
			return nil, fmt.Errorf("%w: duplicate vault key", errValidation)
		}
		// reject a non-canonical / identity owner key (degenerate Schnorr verifier)
		if pt, err := new(edwards25519.Point).SetBytes(vo.OwnerKey); err != nil || pt.Equal(edwards25519.NewIdentityPoint()) == 1 {
			return nil, fmt.Errorf("%w: invalid vault owner key", errValidation)
		}
		seenSpent["vaultout:"+k] = true
		var ovf2 bool
		publicOut, ovf2 = addU64(publicOut, vo.Amount)
		if ovf2 {
			return nil, fmt.Errorf("%w: vault output amount overflow", errValidation)
		}
	}

	// outputs
	var primes []*big.Int
	for i := range t.Outputs {
		p, err := c.checkOutput(&t.Outputs[i], seenPrime, skip)
		if err != nil {
			return nil, err
		}
		primes = append(primes, p)
	}

	// ZK anonymous spends bring PUBLIC value into the confidential pool (like swap
	// claims / vault claims): the spent amount is revealed and bound into the coin's
	// committed leaf by the STARK, so it adds to publicIn for conservation.
	zkIn, zerr := c.validateZKInputsLocked(t, seenSpent, skip)
	if zerr != nil {
		return nil, zerr
	}
	var zovf bool
	if publicIn, zovf = addU64(publicIn, zkIn); zovf {
		return nil, fmt.Errorf("%w: public value overflow", errValidation)
	}
	// ZK mints take public value OUT of the confidential pool (publicOut), bound to
	// the leaf by the mint proof so a creator can't mint more than they declare.
	zkOut, zoerr := c.validateZKOutputsLocked(t, skip)
	if zoerr != nil {
		return nil, zoerr
	}
	if publicOut, zovf = addU64(publicOut, zkOut); zovf {
		return nil, fmt.Errorf("%w: public value overflow", errValidation)
	}
	// Confidential ZK→ZK spends: amounts hidden, only the Fee leaves the pool — add it to
	// publicIn (balanced by the tx fee in publicOut). LeafOut is appended to the tree (no
	// public value, hidden amount). The cspendFull proof binds a_in = a_out + Fee.
	czkIn, czerr := c.validateCZKSpendsLocked(t, seenSpent, skip)
	if czerr != nil {
		return nil, czerr
	}
	if publicIn, zovf = addU64(publicIn, czkIn); zovf {
		return nil, fmt.Errorf("%w: public value overflow", errValidation)
	}

	// generalized value conservation:
	//   Σ pseudoIns + publicIn·H − Σ outs − publicOut·H == z·G
	// where publicIn = Σ swap-input amounts, publicOut = fee + Σ swap-output amounts.
	pseudoIns := make([][]byte, 0, len(t.Inputs)+len(t.AnonInputs))
	for _, in := range t.Inputs {
		pseudoIns = append(pseudoIns, in.PseudoCommitment)
	}
	for _, in := range t.AnonInputs {
		pseudoIns = append(pseudoIns, in.PseudoCommitment)
	}
	outs := commitmentList(t.Outputs)
	if !skip && !commit.VerifyConservationGen(pseudoIns, outs, publicIn, publicOut, t.Conservation, ctx[:]) {
		return nil, fmt.Errorf("%w: value conservation invalid", errValidation)
	}
	if !skip {
		c.markProofVerified(id)
	}
	return primes, nil
}

// medianTimePastLocked returns the median timestamp of the last 11 blocks.
func (c *Chain) medianTimePastLocked() int64 {
	const n = 11
	start := 0
	if len(c.headers) > n {
		start = len(c.headers) - n
	}
	var tsv []int64
	for _, hh := range c.headers[start:] {
		tsv = append(tsv, hh.Timestamp)
	}
	sort.Slice(tsv, func(i, j int) bool { return tsv[i] < tsv[j] })
	return tsv[len(tsv)/2]
}

func commitmentList(outs []tx.Output) [][]byte {
	l := make([][]byte, len(outs))
	for i, o := range outs {
		l[i] = o.Commitment
	}
	return l
}

// prewarmProofCacheLocked best-effort verifies the per-tx proofs of a block's
// non-coinbase txs IN PARALLEL, populating the verified-proof cache so the authoritative
// sequential pass in validateBlockLocked skips re-verifying them. This is a PURE
// OPTIMIZATION and is sound by construction:
//   - A tx is marked verified ONLY if its full validateTxLocked succeeds against current
//     confirmed state (with throwaway per-goroutine dedup maps), so a bad-proof tx is
//     never cached ⇒ no false accept.
//   - Any error here is ignored; the sequential pass re-validates authoritatively ⇒ no
//     false reject, and in-block cross-tx conflicts (which the throwaway maps cannot see)
//     are caught there.
// It only READS chain state, under the caller's c.mu.RLock (no writer can run), and writes
// only to the vmu-guarded proof cache — so the parallelism is race-free. The win is for
// initial sync and blocks whose txs were not in our mempool; steady-state txs are already
// cached at admission, so this is a no-op for them.
// parallelVerifyEnabled gates the parallel pre-verification pass. Default on; a
// benchmark/diagnostic can disable it (env OBX_SEQ_VERIFY=1) to measure the speedup.
var parallelVerifyEnabled = os.Getenv("OBX_SEQ_VERIFY") != "1"

func (c *Chain) prewarmProofCacheLocked(txs []*tx.Transaction, height uint64) {
	if !parallelVerifyEnabled {
		return
	}
	workers := runtime.NumCPU()
	if workers < 2 || len(txs) < 2 {
		return
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for _, t := range txs {
		if t.IsCoinbase || c.proofVerified(t.Hash()) {
			continue // coinbase carries no proofs; already-cached needs no work
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t *tx.Transaction) {
			defer wg.Done()
			defer func() { <-sem }()
			// A panic anywhere in validateTxLocked's call graph runs in THIS child
			// goroutine; a recover() in the parent can't catch it, so it would crash the
			// whole node. This is a best-effort pre-warm (the authoritative sequential
			// pass re-validates), so swallow the panic and just skip caching. (audit)
			defer func() { _ = recover() }()
			ss := make(map[string]bool)
			sp := make(map[string]bool)
			if _, err := c.validateTxLocked(t, height, ss, sp); err == nil {
				c.markProofVerified(t.Hash())
			}
		}(t)
	}
	wg.Wait()
}

// ValidateStandaloneTx validates a single non-coinbase transaction against
// current confirmed state (for mempool admission).
func (c *Chain) ValidateStandaloneTx(t *tx.Transaction) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if t.IsCoinbase {
		return fmt.Errorf("%w: coinbase not standalone", errValidation)
	}
	seenSpent := make(map[string]bool)
	seenPrime := make(map[string]bool)
	_, err := c.validateTxLocked(t, c.headers[len(c.headers)-1].Height+1, seenSpent, seenPrime)
	return err
}

// expectedCoinbaseMintedChecked computes the coinbase total with overflow
// guards. minted = baseReward − poolContribution + fees. Referrals are NEVER
// minted (supply invariant: per-block new coins = baseReward only), so a sybil
// self-referrer can gain nothing. See docs/INVENTION_REFERRAL.md.
func (c *Chain) expectedCoinbaseMintedChecked(fees uint64, referrerTag []byte) (uint64, error) {
	base, pool, _ := c.blockEconomics(referrerTag)
	if pool > base {
		return 0, fmt.Errorf("%w: pool contribution exceeds reward", errValidation)
	}
	v := base - pool
	v, ovf := addU64(v, fees)
	if ovf {
		return 0, fmt.Errorf("%w: minted overflow (fees)", errValidation)
	}
	return v, nil
}

// ExpectedCoinbaseMintedLocked is the lock-free variant used by builders.
func (c *Chain) ExpectedCoinbaseMintedLocked(fees uint64, referrerTag []byte) uint64 {
	v, err := c.expectedCoinbaseMintedChecked(fees, referrerTag)
	if err != nil {
		return 0
	}
	return v
}

// addU64 returns a+b and whether it overflowed.
func addU64(a, b uint64) (uint64, bool) {
	s := a + b
	return s, s < a
}

// mulU64 returns a*b and whether it overflowed.
func mulU64(a, b uint64) (uint64, bool) {
	if a == 0 || b == 0 {
		return 0, false
	}
	p := a * b
	return p, p/a != b
}
