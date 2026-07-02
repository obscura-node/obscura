package chain

import (
	"math/big"
	"time"

	bolt "go.etcd.io/bbolt"

	"obscura/pkg/block"
	"obscura/pkg/commit"
	"obscura/pkg/config"
	"obscura/pkg/group"
	"obscura/pkg/tx"
)

// GenesisTimestamp is the fixed creation time of the genesis block.
const GenesisTimestamp int64 = 1_700_000_000

// initGenesis builds and applies the deterministic genesis block.
func (c *Chain) initGenesis() error {
	cb := &tx.Transaction{
		Version:    1,
		IsCoinbase: true,
		Height:     0,
		Minted:     0,
		// genesis coinbase has no outputs and mints nothing; conservation of an
		// empty coinbase (minted 0, no outputs) is the identity with z=0.
	}
	// The genesis coinbase carries a FIXED, deterministic conservation field so
	// the genesis block is byte-identical on every node (a randomized Schnorr
	// proof here would give each node a different genesis hash). Genesis is the
	// trust root and its conservation is not validated (height 0 is skipped).
	cb.Conservation = []byte("OBSCURA-GENESIS-v1")

	hdr := block.Header{
		Version:    1,
		Height:     0,
		PrevHash:   [32]byte{},
		Timestamp:  GenesisTimestamp,
		Difficulty: config.GenesisDifficulty,
		Nonce:      0,
		AccValue:   c.G.Marshal(c.acc.Value()),
		AccSize:    0,
		CMRoot:     cmRootBytes(c.cmTree.CurrentRoot()), // empty commitment-tree root
		StateRoot:  c.stateRootLocked(),                 // PRE-STATE root over the (empty) pre-genesis state
	}
	b := &block.Block{Header: hdr, Txs: []*tx.Transaction{cb}}
	b.Header.MerkleRoot = block.MerkleRoot(b.Txs)
	b.Header.NumTxs = uint32(len(b.Txs)) // committed so height-1 blocks can challenge genesis
	// genesis is PoR-exempt (no prior block to challenge); PoRRoot stays zero.
	return c.applyBlock(b, true)
}

// applyBlock mutates chain state for a (validated or genesis) block. Caller
// holds the write lock (or is single-threaded during replay).
//
// Persistence happens FIRST (durably writing the block) before in-memory state
// is mutated, so a crash/IO error cannot leave RAM ahead of disk.
func (c *Chain) applyBlock(b *block.Block, persist bool) error {
	c.invalidateStateRoot() // state-root memo: this block mutates residual state (#perf)
	if len(b.Txs) == 0 || !b.Txs[0].IsCoinbase {
		return errValidation
	}
	cb := b.Txs[0]

	// 1) durably persist the block first (body + the additive txid->height query
	// index, committed atomically in the same write transaction).
	if persist && c.db != nil {
		if err := c.db.Update(func(dtx *bolt.Tx) error {
			if err := dtx.Bucket(bucketBlocks).Put(heightKey(b.Header.Height), b.Serialize()); err != nil {
				return err
			}
			return indexBlockTxs(dtx, b)
		}); err != nil {
			return err
		}
	}

	// 2) add all output primes to the accumulator (add-only) and create UTXOs.
	// The class-group accumulator update is BATCHED into a single exponentiation:
	// acc' = acc^(∏ output primes), instead of one Exp per output. Since
	// acc^p1^p2..^pm = acc^(∏p), AccValue is byte-identical to the per-output form and to
	// what the block template predicts (template.go), but it pays the ~1-2s class-group
	// Exp cost once per block rather than once per output. Per-output bookkeeping (the
	// disk-set prime + the coin record) still runs in the loop.
	// Collect the block's output primes, then fold them into a single exponent
	// with a balanced parallel product tree (group.ProductTree). Integer
	// multiplication is associative+commutative, so the resulting big.Int — and
	// therefore acc' = acc^(∏p) — is BYTE-IDENTICAL to the previous serial
	// accProd.Mul fold and to the block template's prediction. Proven by
	// pkg/group TestProductTreeEqualsSerial / TestProductTreeApplyShape /
	// TestProductTreeExpIdentical (g^serial == g^tree at 256- and 2048-bit).
	// The tree keeps big.Int operand sizes balanced (Karatsuba/Toom) and runs
	// levels in parallel, so a large block's exponent build is ~7× faster
	// without any change to the consensus value.
	accPrimes := make([]*big.Int, 0, 8)
	for _, t := range b.Txs {
		for i := range t.Outputs {
			o := &t.Outputs[i]
			pb, ok := accPrime(o.OneTimeKey, o.PrimeNonce)
			if !ok {
				continue
			}
			p := new(big.Int).SetBytes(pb)
			if c.acc.Contains(p) {
				// validation guarantees uniqueness; treat as a hard error.
				return errValidation
			}
			accPrimes = append(accPrimes, p)
			c.outPrimes.Add(hexstr(pb))
			// add-only "all coins ever" set for anonymity-ring lookups + UTXO
			// derivation (commitment/height/coinbase/lock all live in the coin
			// record). Disk-backed (coinstore.go) — only an O(1) count in RAM.
			c.addCoinLocked(o.OneTimeKey, o.Commitment, b.Header.Height, t.IsCoinbase, o.LockUntil)
		}
	}
	// Single batched class-group exponentiation for the whole block (see comment above).
	accProd := group.ProductTree(accPrimes)
	c.acc.AddBatch(accProd, len(accPrimes))

	// 2c) append ZK coin commitments to the Poseidon commitment tree (in the same
	// order as cmLeavesFromTxs / the header CMRoot prediction), then whitelist the
	// new root as a spend anchor (Zcash-style; witnesses against any past root stay
	// valid). docs/ZK_MEMBERSHIP_SPEND.md.
	for _, leaf := range cmLeavesFromTxs(b.Txs) {
		c.cmTree.Append(leaf)
	}
	c.recordCMAnchorLocked() // bounded rolling anchor window

	// 2b) add post-quantum outputs to the PQ anonymity set + UTXO map (add-only
	// Merkle accumulator; rebuilt deterministically on replay).
	for _, t := range b.Txs {
		for i := range t.PQOutputs {
			o := &t.PQOutputs[i]
			key := hexstr(o.OneTimeKey)
			if _, exists := c.pqUtxo[key]; exists {
				return errValidation
			}
			idx := c.pqAcc.Add(o.OneTimeKey)
			c.pqIndex[key] = idx
			c.pqUtxo[key] = &tx.PQOutput{
				OneTimeKey: append([]byte(nil), o.OneTimeKey...),
				Amount:     o.Amount,
			}
		}
	}
	// record the new PQ anonymity-set root as a valid anchor (witnesses built
	// against any past root stay verifiable — Zcash-style anchor set). The
	// degenerate empty-set root is never whitelisted (a spend always references a
	// non-empty set).
	// NOTE: pqRoots is NOT capped by cardinality — it is CONSUMED as the PQ anchor
	// set, so a hard "stop when full" cap would become a liveness wall (recent
	// roots stop being anchorable). Bounding it correctly needs a height-gated
	// rolling window (accept anchors within N blocks of the tip + evict older);
	// that is the documented TODO (docs/PRUNING_DESIGN.md #4). Left unbounded here
	// (PQ is the experimental Version-2 path) to avoid the liveness wall.
	if c.pqAcc.Len() > 0 {
		c.pqRoots[hexstr(c.pqAcc.Root())] = true
	}

	// 3) spend inputs: remove transparent outputs from UTXO; record anon tags.
	for _, t := range b.Txs {
		if t.IsCoinbase {
			continue
		}
		for _, in := range t.Inputs {
			c.spent.Add(hexstr(in.OutputRef)) // mark output spent (utxo = coins ∧ ¬spent)
			// record the coin's key-image in the SHARED nullifier set, so the same
			// coin can never also be spent anonymously (and vice-versa). Also append
			// to the nullifier accumulator (committed in the header NullRoot) — the
			// order here MUST match blockTagsFromTxs.
			if len(in.KeyImage) == 32 {
				// record the cofactor-cleared canonical nullifier (8·T) so torsion
				// variants of one coin's key-image collide here and in the accumulator
				// (must match blockTagsFromTxs / validate.go).
				ki := in.KeyImage
				if c2, ok := commit.CanonicalNullifier(in.KeyImage); ok {
					ki = c2
				}
				c.tags.Add(hexstr(ki))
				c.nullAcc.Add(ki)
			}
		}
		for _, in := range t.AnonInputs {
			tg := in.Tag
			if c2, ok := commit.CanonicalNullifier(in.Tag); ok {
				tg = c2
			}
			c.tags.Add(hexstr(tg))
			c.nullAcc.Add(tg)
		}
		for _, in := range t.SwapInputs {
			delete(c.swaps, hexstr(in.SwapKey)) // swap claimed/refunded
		}
		// post-quantum spends: record the nullifier and retire the PQ UTXO. The
		// leaf stays in the add-only accumulator AND pqIndex is kept, so the spent
		// coin remains a usable anonymity-set decoy / provable member (spentness is
		// tracked solely by pqUtxo removal + the nullifier set).
		for _, in := range t.PQInputs {
			delete(c.pqUtxo, hexstr(in.OutputRef))
			c.pqNull[hexstr(in.Nullifier)] = true
			// record the WOTS+ root revealed by this spend so it can never be
			// revealed again (one-time-signature reuse defense — see pqvalidate.go).
			c.pqWots[hexstr(in.WotsRoot)] = true
		}
		// ZK anonymous spends: record the revealed serial in the nullifier set. The
		// coin commitment stays in the (append-only) tree as a decoy / provable member.
		for _, in := range t.ZKInputs {
			c.zkNull[hexstr(in.Nullifier)] = true
		}
		// confidential ZK→ZK spends record their nullifier in the SAME set (cross-path
		// double-spend guard); their LeafOut is appended to the tree by cmLeavesFromTxs.
		for _, s := range t.CZKSpends {
			c.zkNull[hexstr(s.Nullifier)] = true
		}
	}
	// register newly-funded swap contracts
	for _, t := range b.Txs {
		for _, so := range t.SwapOutputs {
			c.swaps[hexstr(so.SwapKey)] = &SwapEntry{
				Amount:       so.Amount,
				ClaimKey:     append([]byte(nil), so.ClaimKey...),
				RefundKey:    append([]byte(nil), so.RefundKey...),
				UnlockHeight: so.UnlockHeight,
				ClaimR:       append([]byte(nil), so.ClaimR...),
				ClaimT:       append([]byte(nil), so.ClaimT...),
			}
			// record the adaptor pre-signature nonce in the CONSENSUS uniqueness set so
			// the same ClaimR can never be funded again (audit #14). UNBOUNDED and never
			// deleted — even after the swap is claimed/refunded, R stays seen; reorg-safety
			// comes from snapshot/restore+replay (resetState clears it, restore reloads the
			// fork-point set, replay re-adds), exactly like zkNull.
			c.swapNonces[hexstr(so.ClaimR)] = true
		}
	}

	// staking vaults: settle matured claims (pay yield from the incentive pool and
	// close the vault) and register new deposits. Validation already guaranteed
	// maturity, authorization, unique keys, and Σ yield ≤ incentivePool, so this is
	// pure bookkeeping. Done before the block's pool contribution is added, so the
	// decrement matches the pre-block pool the affordability check used.
	for _, t := range b.Txs {
		if t.IsCoinbase {
			continue
		}
		for _, in := range t.VaultInputs {
			key := hexstr(in.VaultKey)
			if _, ok := c.vaults[key]; !ok {
				continue
			}
			// Pay the STATED, validation-capped yield from the incentive pool.
			if y := in.Yield; y <= c.incentivePool {
				c.incentivePool -= y
			} else {
				c.incentivePool = 0 // defensive; validation prevents this
			}
			delete(c.vaults, key)
		}
		for _, vo := range t.VaultOutputs {
			// rate is validated as a known term in validateTxLocked, so the lookup
			// always succeeds here; snapshot it so the yield promise is immutable.
			rate, _ := config.VaultRateBps(vo.Term)
			c.vaults[hexstr(vo.VaultKey)] = &VaultEntry{
				Amount:        vo.Amount,
				Term:          vo.Term,
				RateBps:       rate,
				OwnerKey:      append([]byte(nil), vo.OwnerKey...),
				DepositHeight: b.Header.Height,
			}
		}
	}

	// 4) economics (overflow-safe; tail emission never wraps).
	if b.Header.Height > 0 {
		var fees uint64
		for i := 1; i < len(b.Txs); i++ {
			fees += b.Txs[i].Fee
		}
		base, pool, _ := c.blockEconomics(cb.ReferrerTag)
		// SUPPLY INVARIANT: the only new coins per block are the base reward.
		// Referrals are NEVER minted (a sound, sybil-resistant referral must be a
		// voluntary fee-share / tip — see docs/INVENTION_REFERRAL.md), so they
		// can never inflate supply or profit a self-referrer.
		if c.emitted+base < c.emitted { // overflow guard
			c.emitted = ^uint64(0)
		} else {
			c.emitted += base
		}
		if c.incentivePool+pool >= c.incentivePool {
			c.incentivePool += pool
		}
		_ = fees
	}

	// record checkpoint (accumulator value after this block). BOUNDED: this set is
	// not consumed by active consensus (the header AccValue chain is the canonical
	// anchor history), so we cap it to a rolling window to keep node state bounded
	// (pruning design #4). Once full, stop recording — older checkpoints are
	// reconstructable from headers if ever needed.
	if len(c.accValues) < config.MaxAnchorWindow {
		accBytes := c.G.Marshal(c.acc.Value())
		c.accValues[hexstr(blakeHash(accBytes))] = true
	}

	// index
	c.headers = append(c.headers, b.Header)
	c.byHash[b.Header.ID()] = b.Header.Height
	c.cacheBlock(b.Header.Height, b) // bounded RAM cache; durable copy is in bolt
	return nil
}

// CandidateTimestamp returns a sensible timestamp for a new block.
func CandidateTimestamp(tipTs int64) int64 {
	now := time.Now().Unix()
	if now <= tipTs {
		return tipTs + 1
	}
	return now
}
