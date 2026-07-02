package chain

import (
	"fmt"

	"obscura/pkg/block"
	"obscura/pkg/config"
	"obscura/pkg/stark"
	"obscura/pkg/tx"
)

// ZK anonymous-spend consensus glue (docs/ZK_MEMBERSHIP_SPEND.md). A ZKOutput mints
// a 256-bit Poseidon commitment leaf into the wide commitment tree; a ZKInput spends
// some coin by a transparent STARK proving membership against a recent root anchor
// while revealing only a nullifier serial + the public amount.
//
// The node verifies against the O(1) tree root with NO ring/coin set — the
// constant-size, post-quantum endgame. Nodes are 4-element (256-bit) for ~2¹²⁸
// collision resistance (collision-width fix). State (frontier + anchors + nullifiers)
// is snapshot/reset/replay-safe.

// cmLeavesFromTxs returns every ZKOutput leaf in a block, in applyBlock order
// (coinbase first, then txs; ZKOutputs in order). MUST match apply order so the
// header CMRoot prediction lines up.
func cmLeavesFromTxs(txs []*tx.Transaction) []stark.Node256 {
	var out []stark.Node256
	for _, t := range txs {
		for i := range t.ZKOutputs {
			// strict parse: only canonical leaves are appended (validation rejects
			// non-canonical, so predict and apply stay in lock-step).
			if n, ok := stark.ParseNode(t.ZKOutputs[i].Leaf); ok {
				out = append(out, n)
			}
		}
		// Confidential spends also mint a fresh output coin (hidden amount); its LeafOut
		// is appended right after this tx's ZKOutputs — same order in predict and apply.
		for i := range t.CZKSpends {
			if n, ok := stark.ParseNode(t.CZKSpends[i].LeafOut); ok {
				out = append(out, n)
			}
		}
	}
	return out
}

// parseZKAmount validates a ZK public amount: it must be ≤ MoneySupplyCap, which is
// strictly below the Goldilocks modulus P (guarded by TestMoneySupplyCapBelowP), so
// the amount's in-circuit field binding equals its raw uint64 value used in
// conservation — no aliasing.
func parseZKAmount(v uint64) (stark.Felt, bool) {
	if v > config.MoneySupplyCap {
		return 0, false
	}
	return stark.NewFelt(v), true
}

// validateZKOutputsLocked verifies every ZK mint in a tx and returns the public
// value they take OUT of the confidential pool (publicOut). Each leaf's value is
// bound to its declared Amount by the mint proof (anti-inflation).
func (c *Chain) validateZKOutputsLocked(t *tx.Transaction, skip bool) (uint64, error) {
	if len(t.ZKOutputs) == 0 {
		return 0, nil
	}
	if len(t.ZKOutputs) > tx.MaxOutputs {
		return 0, fmt.Errorf("%w: too many zk outputs", errValidation)
	}
	bind := zkBind(t)
	var publicOut uint64
	for i := range t.ZKOutputs {
		o := &t.ZKOutputs[i]
		// STRICT canonical decode (see validateZKInputsLocked): rejects a non-canonical
		// leaf so the appended tree node, the header-committed root, and the mint proof's
		// reduced leaf always agree.
		leaf, lOK := stark.ParseNode(o.Leaf)
		if !lOK {
			return 0, fmt.Errorf("%w: malformed or non-canonical zk leaf", errValidation)
		}
		amount, amtOK := parseZKAmount(o.Amount)
		if !amtOK {
			return 0, fmt.Errorf("%w: zk mint amount exceeds supply cap", errValidation)
		}
		if !skip {
			proof, err := stark.UnmarshalProof(o.MintProof)
			if err != nil {
				return 0, fmt.Errorf("%w: zk mint decode: %v", errValidation, err)
			}
			// nf-note mint: proves cm = sponge(pk, amount, rho, blind) for the public
			// amount (anti-inflation). pk is the recipient's published nf-address.
			if !stark.VerifyNfMint(amount, leaf, bind, proof, stark.ZKQueries) {
				return 0, fmt.Errorf("%w: zk mint proof invalid", errValidation)
			}
		}
		var ovf bool
		if publicOut, ovf = addU64(publicOut, o.Amount); ovf {
			return 0, fmt.Errorf("%w: zk mint value overflow", errValidation)
		}
	}
	return publicOut, nil
}

// zkBind derives the tx-binding domain for a ZK proof from the FULL tx CoreHash
// (256-bit), so a proof cannot be lifted into a different transaction (e.g. with
// redirected outputs). Using the full hash — not a 64-bit prefix — closes a ~2⁶⁴
// output-redirection/theft vector (audit finding).
func zkBind(t *tx.Transaction) []byte {
	ctx := t.CoreHash()
	return ctx[:]
}

// predictCMRoot returns the commitment-tree root after a block's coin leaves are
// appended (header CMRoot commitment).
func (c *Chain) predictCMRoot(txs []*tx.Transaction) [32]byte {
	return cmRootBytes(c.cmTree.RootAfter(cmLeavesFromTxs(txs)))
}

// cmRootBytes encodes a 256-bit root node into the header's [32]byte CMRoot field.
func cmRootBytes(root stark.Node256) [32]byte {
	var b [32]byte
	copy(b[:], stark.NodeBytes(root))
	return b
}

// recordCMAnchorLocked whitelists EVERY epoch root (current + finalized) as a spend
// anchor, keeping only the most recent config.MaxAnchorWindow DISTINCT roots (rolling
// window). Recording ALL epoch roots — not just the current one — is REQUIRED: when an
// epoch fills and rolls MID-BLOCK (several coins crossing the boundary), the finalized
// epoch's terminal root is never the current root at a block boundary, so recording
// only the current root would leave that epoch's coins permanently unspendable
// (anchor never whitelisted). The dedup keeps this cheap (each root recorded once).
// Caller holds the write lock.
func (c *Chain) recordCMAnchorLocked() {
	if c.cmTree.TotalCount() == 0 {
		return
	}
	roots := c.cmTree.Roots()
	// Finalized epoch terminal roots (all but the current epoch) are PERMANENT anchors
	// — bounded by the number of epochs, so old coins never become unspendable.
	for _, root := range roots[:len(roots)-1] {
		key := hexstr(stark.NodeBytes(root))
		c.cmFinal[key] = true
		c.cmRoots[key] = true
	}
	// The current epoch's root changes every minting block; window these snapshots so
	// the anchor set stays bounded (a spender must witness against a reasonably recent
	// current-epoch root). When this epoch later finalizes, its terminal root is moved
	// to the permanent set above and survives window eviction below.
	cur := hexstr(stark.NodeBytes(roots[len(roots)-1]))
	if !c.cmRoots[cur] {
		c.cmRoots[cur] = true
		c.cmRootOrder = append(c.cmRootOrder, cur)
	}
	for len(c.cmRootOrder) > config.MaxAnchorWindow {
		oldest := c.cmRootOrder[0]
		c.cmRootOrder = c.cmRootOrder[1:]
		if !c.cmFinal[oldest] { // never evict a finalized epoch root
			delete(c.cmRoots, oldest)
		}
	}
}

// validateZKInputsLocked verifies every ZK spend in a tx and returns the total
// public value they bring in (added to publicIn for conservation). seenSpent dedups
// nullifiers within a block. Caller holds the lock.
func (c *Chain) validateZKInputsLocked(t *tx.Transaction, seenSpent map[string]bool, skip bool) (uint64, error) {
	if len(t.ZKInputs) == 0 {
		return 0, nil
	}
	if len(t.ZKInputs) > tx.MaxInputs {
		return 0, fmt.Errorf("%w: too many zk inputs", errValidation)
	}
	bind := zkBind(t)
	var publicIn uint64
	for i := range t.ZKInputs {
		in := &t.ZKInputs[i]
		// STRICT canonical decode (parse-or-reject). This STRUCTURALLY eliminates the
		// field↔bytes aliasing class: a non-canonical serial/anchor (raw ≥ P) cannot be
		// decoded, so the raw bytes used for dedup/whitelist and the field element used
		// in the proof are always the SAME value. (Two consensus-breakers of this class
		// — inflation + double-spend — are documented in docs/SECURITY_AUDIT.md.)
		// 32B recipient-secret nullifier nf=H(nsk,rho). STRICT canonical decode keeps the
		// raw bytes (dedup/whitelist key) and the field-node used in the proof identical.
		nf, sOK := stark.ParseNode(in.Nullifier)
		if !sOK {
			return 0, fmt.Errorf("%w: malformed or non-canonical zk nullifier", errValidation)
		}
		anchor, aOK := stark.ParseNode(in.Anchor)
		if !aOK {
			return 0, fmt.Errorf("%w: malformed or non-canonical zk anchor", errValidation)
		}
		// Amount: bound ≤ MoneySupplyCap (which is < P, see the invariant test), so its
		// field binding cannot be aliased against the raw-uint64 conservation value.
		amount, amtOK := parseZKAmount(in.Amount)
		if !amtOK {
			return 0, fmt.Errorf("%w: zk spend amount exceeds supply cap", errValidation)
		}
		nk := "zk:" + hexstr(in.Nullifier)
		if seenSpent[nk] {
			return 0, fmt.Errorf("%w: duplicate zk nullifier in block", errValidation)
		}
		if c.zkNull[hexstr(in.Nullifier)] {
			return 0, fmt.Errorf("%w: zk double-spend (nullifier already seen)", errValidation)
		}
		if !c.cmRoots[hexstr(in.Anchor)] {
			return 0, fmt.Errorf("%w: unknown zk anchor", errValidation)
		}
		if !skip {
			proof, err := stark.UnmarshalProof(in.Proof)
			if err != nil {
				return 0, fmt.Errorf("%w: zk proof decode: %v", errValidation, err)
			}
			// nf-spend: proves knowledge of the recipient secret nk with pk=H(nk,0)
			// (spend authority — a thief who only knows the note cannot spend), membership
			// of cm=sponge(pk,amount,rho,blind) at anchor, and nf=H(nk,rho).
			if !stark.VerifyNfSpend(amount, anchor, nf, bind, stark.ZKDepth, proof, stark.ZKQueries) {
				return 0, fmt.Errorf("%w: zk spend proof invalid", errValidation)
			}
		}
		var ovf bool
		if publicIn, ovf = addU64(publicIn, in.Amount); ovf {
			return 0, fmt.Errorf("%w: zk public value overflow", errValidation)
		}
		seenSpent[nk] = true
	}
	return publicIn, nil
}

// Compile-time guard: confidential amounts/fee are range-bound to ConfidentialBits, which
// MUST stay ≤ stark.MaxRangeBits so 2^bits < the Goldilocks modulus (no field wraparound —
// the anti-inflation invariant). If someone raises ConfidentialBits past MaxRangeBits this
// array length goes negative and the build fails. (Consensus review minor note, hardened.)
var _ = [stark.MaxRangeBits - config.ConfidentialBits]struct{}{}

// validateCZKSpendsLocked verifies every CONFIDENTIAL ZK→ZK spend in a tx. Each one
// atomically destroys a member coin (revealing nullifier Serial) and mints LeafOut, with
// both amounts HIDDEN; only the public Fee leaves the confidential pool, so Fee is the
// value returned (added to publicIn, balanced by the tx fee). Caller holds the lock.
func (c *Chain) validateCZKSpendsLocked(t *tx.Transaction, seenSpent map[string]bool, skip bool) (uint64, error) {
	if len(t.CZKSpends) == 0 {
		return 0, nil
	}
	if len(t.CZKSpends) > tx.MaxInputs {
		return 0, fmt.Errorf("%w: too many confidential zk spends", errValidation)
	}
	bind := zkBind(t)
	var publicIn uint64
	for i := range t.CZKSpends {
		s := &t.CZKSpends[i]
		// 32B recipient-secret nullifier nf=H(nsk,rho); strict canonical decode.
		nf, sOK := stark.ParseNode(s.Nullifier)
		if !sOK {
			return 0, fmt.Errorf("%w: malformed or non-canonical czk nullifier", errValidation)
		}
		anchor, aOK := stark.ParseNode(s.Anchor)
		if !aOK {
			return 0, fmt.Errorf("%w: malformed or non-canonical czk anchor", errValidation)
		}
		leafOut, lOK := stark.ParseNode(s.LeafOut)
		if !lOK {
			return 0, fmt.Errorf("%w: malformed or non-canonical czk leaf", errValidation)
		}
		// FEE RANGE-CHECK (SECURITY_AUDIT FINDING 5): the circuit proves a_in=a_out+Fee in
		// the field, so a wrapped "negative" fee (P−k, a huge uint64) would let a_out>a_in
		// and inflate. Bound Fee to the same range the circuit binds the amounts to.
		if s.Fee >= (uint64(1) << config.ConfidentialBits) {
			return 0, fmt.Errorf("%w: czk fee out of range", errValidation)
		}
		// nullifier set is SHARED with the public ZK spend (ZKInput) so a coin cannot be
		// spent via both paths — same "zk:"+nullifier key (now the 32B nf).
		nk := "zk:" + hexstr(s.Nullifier)
		if seenSpent[nk] {
			return 0, fmt.Errorf("%w: duplicate czk nullifier in block", errValidation)
		}
		if c.zkNull[hexstr(s.Nullifier)] {
			return 0, fmt.Errorf("%w: czk double-spend (nullifier already seen)", errValidation)
		}
		if !c.cmRoots[hexstr(s.Anchor)] {
			return 0, fmt.Errorf("%w: unknown czk anchor", errValidation)
		}
		if !skip {
			proof, err := stark.UnmarshalProof(s.Proof)
			if err != nil {
				return 0, fmt.Errorf("%w: czk proof decode: %v", errValidation, err)
			}
			// confidential nf-spend: proves spend authority (nk), membership, nf=H(nk,rho),
			// mints cmOut=sponge(pkOut,a_out,rho_out,blind_out), and balance a_in=a_out+Fee,
			// all amounts HIDDEN. nf needs the recipient secret nk — the sender cannot forge it.
			if !stark.VerifyCnfSpend(nf, anchor, leafOut, stark.NewFelt(s.Fee), bind,
				stark.ZKDepth, config.ConfidentialBits, proof, stark.ZKQueries) {
				return 0, fmt.Errorf("%w: czk spend proof invalid", errValidation)
			}
		}
		var ovf bool
		if publicIn, ovf = addU64(publicIn, s.Fee); ovf {
			return 0, fmt.Errorf("%w: czk fee overflow", errValidation)
		}
		seenSpent[nk] = true
	}
	return publicIn, nil
}

// predictedCMRootMatches checks the header CMRoot equals the root after this block.
func (c *Chain) predictedCMRootMatches(b *block.Block) bool {
	return c.predictCMRoot(b.Txs) == b.Header.CMRoot
}

// --- wallet/spender accessors for the wide commitment tree ---

// ZKRoot returns the current commitment-tree root as the 32-byte anchor a ZKInput
// references.
func (c *Chain) ZKRoot() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return stark.NodeBytes(c.cmTree.CurrentRoot())
}

// ZKDepth returns the commitment-tree depth (the spend circuit's path length).
func (c *Chain) ZKDepth() int { return stark.ZKDepth }

// ZKStateSize returns the byte size of the node-side commitment-tree state
// (frontier + root + count) — O(depth), independent of the number of coins.
func (c *Chain) ZKStateSize() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cmTree.MarshalState())
}

// ZKFindLeaf locates a coin leaf (by its 32-byte node encoding) across all epochs.
func (c *Chain) ZKFindLeaf(leaf []byte) (epoch int, index uint64, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	n, lok := stark.ParseNode(leaf)
	if !lok {
		return 0, 0, false
	}
	return c.cmTree.Find(n)
}

// ZKWitnessFor returns everything a spender needs for a coin: the anchor (its EPOCH
// root — a coin is proven a member of its own epoch, not the current one) and the
// authentication path. This is the constant-cost membership witness regardless of how
// many epochs/coins exist in total.
func (c *Chain) ZKWitnessFor(leaf []byte) (anchor []byte, path stark.MerklePath256, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	n, lok := stark.ParseNode(leaf)
	if !lok {
		return nil, stark.MerklePath256{}, false
	}
	ep, idx, found := c.cmTree.Find(n)
	if !found {
		return nil, stark.MerklePath256{}, false
	}
	p, root, pok := c.cmTree.PathFor(ep, idx)
	if !pok {
		return nil, stark.MerklePath256{}, false
	}
	return stark.NodeBytes(root), p, true
}
