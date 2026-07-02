package wallet

import (
	"bytes"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/blake2b"

	"obscura/pkg/block"
	"obscura/pkg/commit"
	"obscura/pkg/config"
	"obscura/pkg/stark"
	"obscura/pkg/tx"
)

// zkSecretsFromShared deterministically derives a ZK coin's (rho, blind) from a
// stealth shared secret, so the SENDER (who computes the shared secret) and the
// RECIPIENT (who recomputes it from their view key) agree without communication.
//
// rho is the coin's per-note randomness. The on-chain NULLIFIER is nf = H(nsk, rho)
// where nsk is the RECIPIENT's secret (never the sender's): the sender knows rho but
// NOT nsk, so it can neither spend the coin nor precompute the nf the recipient will
// reveal — closing the sender-can-steal + sender↔spend-linkability holes (Zcash-Sapling
// recipient-secret nullifier; docs/ZK_MEMBERSHIP_SPEND.md).
func zkSecretsFromShared(shared []byte) (rho, blind stark.Felt) {
	s := blake2b.Sum256(append([]byte("OBX/zk/rho"), shared...))
	b := blake2b.Sum256(append([]byte("OBX/zk/blind"), shared...))
	return stark.FeltFromBytes(s[:8]), stark.FeltFromBytes(b[:8])
}

// Wallet support for the fully-anonymous ZK spend (docs/ZK_MEMBERSHIP_SPEND.md):
// minting a transparent coin into the Poseidon commitment tree, then spending it
// anonymously with a STARK membership proof. Coins are simple public-value legs
// (publicOut to mint, publicIn to spend), so conservation reuses the existing
// generalized Schnorr proof.

// ZKCoin is the secret material for a received nf-note; keep it to spend later.
// Spending derives the nullifier nf = H(Nsk, Rho) and proves spend authority via Nsk
// (the recipient's nullifier secret, set at scan time) — so only the owner can spend.
type ZKCoin struct {
	Amount uint64
	Rho    stark.Felt // per-note randomness (delivered via the stealth shared secret)
	Blind  stark.Felt
	Nsk    stark.Felt // OWNER's nullifier secret (= the matched key's NfSecret); needed to spend
	Leaf   []byte     // 32B note commitment cm = sponge(pk, amount, rho, blind)
}

// CreateZKMint shields value into a ZK coin owned by THIS wallet (mint-to-self).
func (w *Wallet) CreateZKMint(view ChainView, mintAmount, fee uint64) (*tx.Transaction, *ZKCoin, error) {
	return w.CreateZKMintTo(view, w.Address(), mintAmount, fee)
}

// CreateZKMintTo spends transparent outputs to mint a ZK coin of value mintAmount
// payable to `dest` (a private ZK→ZK transfer): the coin's secrets are derived from
// a stealth shared secret so only `dest` can later discover + spend it (the
// recipient finds it via ScanZKCoins). Returns the tx and the ZKCoin (the sender's
// view of it — see zkSecretsFromShared for the linkability caveat).
func (w *Wallet) CreateZKMintTo(view ChainView, dest commit.StealthAddress, mintAmount, fee uint64) (*tx.Transaction, *ZKCoin, error) {
	if w.IsViewOnly() {
		return nil, nil, errors.New("wallet: view-only wallet cannot spend")
	}
	if mintAmount == 0 {
		return nil, nil, errors.New("wallet: mint amount must be positive")
	}
	need, ovf := addCheck(mintAmount, fee)
	if ovf {
		return nil, nil, errors.New("wallet: amount+fee overflow")
	}
	spendHeight := view.Height() + 1
	var selected []*OwnedOutput
	var total uint64
	for _, o := range w.Outputs {
		if o.Spent || o.reserved {
			continue
		}
		if o.IsCoinbase && spendHeight < o.Height+config.CoinbaseMaturity {
			continue
		}
		if spendHeight < o.Out.LockUntil {
			continue
		}
		selected = append(selected, o)
		var ovf2 bool
		if total, ovf2 = addCheck(total, o.Amount); ovf2 {
			return nil, nil, errors.New("wallet: balance overflow")
		}
		if total >= need {
			break
		}
	}
	if total < need {
		return nil, nil, errors.New("wallet: insufficient spendable funds")
	}

	// stealth delivery: derive the coin secrets from a shared secret only `dest` can
	// reconstruct, and attach the stealth one-time key + ephemeral pubkey + view tag.
	r := commit.RandomScalar()
	so := commit.CreateOutputDeterministic(dest, r)
	shared := commit.SharedSecretSender(dest, r)
	rho, blind := zkSecretsFromShared(shared)
	// nf-note paid to the recipient's published nf-address pk (= dest.NfPk). The sender
	// builds cm from pk + (rho,blind) but cannot derive the recipient's nsk, so cannot
	// later spend or link this coin (the nullifier nf=H(nsk,rho) needs nsk).
	pk := stark.NodeFromBytes(dest.NfPk)
	leaf := stark.NfNoteFromPk(pk, stark.NewFelt(mintAmount), rho, blind)
	zko := tx.ZKOutput{
		Leaf:     stark.NodeBytes(leaf),
		Amount:   mintAmount,
		Key:      so.P.Bytes(),
		TxPubKey: so.R.Bytes(),
		ViewTag:  commit.ViewTag(shared),
	}

	t := &tx.Transaction{Version: 1, Fee: fee, ZKOutputs: []tx.ZKOutput{zko}}

	// change output (Pedersen) for the remainder.
	var outBlindings []*edwards25519.Scalar
	change := total - need
	if change > 0 {
		chOut, cb, err := buildOutput(w.keys.Addr, change, 0)
		if err != nil {
			return nil, nil, err
		}
		t.Outputs = append(t.Outputs, chOut)
		outBlindings = append(outBlindings, cb)
	}

	// inputs (pseudo-commitments + key-image values bound pre-CoreHash).
	var pseudoBlindings []*edwards25519.Scalar
	for _, o := range selected {
		pr := commit.RandomScalar()
		pseudoBlindings = append(pseudoBlindings, pr)
		t.Inputs = append(t.Inputs, tx.Input{
			OutputRef:        append([]byte(nil), o.Out.OneTimeKey...),
			PseudoCommitment: commit.Commit(o.Amount, pr).Bytes(),
			KeyImage:         commit.KeyImage(o.OneTime).Bytes(),
		})
	}

	ctx := t.CoreHash()
	bind := ctx[:] // full CoreHash domain (256-bit tx binding)

	// mint proof: cm = sponge(pk, mintAmount, rho, blind), binding the leaf to mintAmount
	// (anti-inflation) and to the recipient's pk, while hiding rho/blind.
	mp, err := stark.ProveNfMint(pk, stark.NewFelt(mintAmount), rho, blind, leaf, bind, stark.ZKQueries)
	if err != nil {
		return nil, nil, err
	}
	blob, err := stark.MarshalProof(mp)
	if err != nil {
		return nil, nil, err
	}
	t.ZKOutputs[0].MintProof = blob

	// input proofs.
	for i, o := range selected {
		own, err := commit.ProveOwnership(o.Out.OneTimeKey, o.OneTime, ctx[:])
		if err != nil {
			return nil, nil, err
		}
		d := new(edwards25519.Scalar).Subtract(pseudoBlindings[i], o.Mask)
		eq, err := commit.ProveValueEquality(t.Inputs[i].PseudoCommitment, o.Out.Commitment, d, ctx[:])
		if err != nil {
			return nil, nil, err
		}
		t.Inputs[i].OwnershipProof = own
		t.Inputs[i].EqualityProof = eq
		t.Inputs[i].KeyImageProof = commit.ProveKeyImageProof(o.OneTime, ctx[:])
	}

	// conservation: z = Σ pseudoBlindings − Σ change-blindings; publicOut = fee+mint.
	z := edwards25519.NewScalar()
	for _, s := range pseudoBlindings {
		z.Add(z, s)
	}
	for _, s := range outBlindings {
		z.Subtract(z, s)
	}
	pseudoIns := make([][]byte, len(t.Inputs))
	for i, in := range t.Inputs {
		pseudoIns[i] = in.PseudoCommitment
	}
	outs := commitmentsOf(t.Outputs)
	publicOut, ovf2 := addCheck(fee, mintAmount)
	if ovf2 {
		return nil, nil, errors.New("wallet: publicOut overflow")
	}
	cons, err := commit.ProveConservationGen(pseudoIns, outs, 0, publicOut, z, ctx[:])
	if err != nil {
		return nil, nil, err
	}
	t.Conservation = cons

	for _, o := range selected {
		o.reserved = true
	}
	// The returned coin carries THIS wallet's nsk; it is spendable only when the mint was
	// to our own address (pk == our NfPk). For a payment to someone else, our nsk does not
	// match the note's pk, so a spend attempt with it cannot verify (the recipient finds
	// and spends the coin via ScanZKCoins, which records THEIR nsk).
	return t, &ZKCoin{Amount: mintAmount, Rho: rho, Blind: blind, Nsk: w.keys.NfSecret(), Leaf: stark.NodeBytes(leaf)}, nil
}

// CreateZKSpend spends a ZK coin anonymously to dest. The caller supplies the
// commitment-tree anchor + the coin's authentication path (from the chain). Reveals
// only the nullifier serial + the public amount; hides which coin is spent.
func (w *Wallet) CreateZKSpend(coin *ZKCoin, anchor []byte, path stark.MerklePath256, depth int, dest commit.StealthAddress, fee uint64) (*tx.Transaction, error) {
	if coin.Amount <= fee {
		return nil, errors.New("wallet: amount does not cover fee")
	}
	sendAmount := coin.Amount - fee

	destOut, db, err := buildOutput(dest, sendAmount, 0)
	if err != nil {
		return nil, err
	}
	// nullifier nf = H(nsk, rho): only derivable with the owner's nsk.
	nf := stark.NfNullifier(coin.Nsk, coin.Rho)
	t := &tx.Transaction{
		Version: 1, Fee: fee,
		Outputs: []tx.Output{destOut},
		ZKInputs: []tx.ZKInput{{
			Nullifier: stark.NodeBytes(nf),
			Amount:    coin.Amount,
			Anchor:    append([]byte(nil), anchor...),
		}},
	}

	ctx := t.CoreHash()
	bind := ctx[:] // full CoreHash domain (256-bit tx binding)
	root := stark.NodeFromBytes(anchor)
	pf, err := stark.ProveNfSpend(coin.Nsk, stark.NewFelt(coin.Amount), coin.Rho, coin.Blind, path, depth, root, nf, bind, stark.ZKQueries)
	if err != nil {
		return nil, err
	}
	blob, err := stark.MarshalProof(pf)
	if err != nil {
		return nil, err
	}
	t.ZKInputs[0].Proof = blob

	// conservation: pseudoIns empty, publicIn = amount, publicOut = fee; z = −db.
	z := edwards25519.NewScalar().Subtract(edwards25519.NewScalar(), db)
	outs := commitmentsOf(t.Outputs)
	cons, err := commit.ProveConservationGen(nil, outs, coin.Amount, fee, z, ctx[:])
	if err != nil {
		return nil, err
	}
	t.Conservation = cons
	return t, nil
}

// czkAmountMask derives an 8-byte keystream from the stealth shared secret to en/decrypt
// the hidden output amount carried in CZKSpend.EncAmount.
func czkAmountMask(shared []byte) [8]byte {
	h := blake2b.Sum256(append([]byte("OBX/zk/czk-amt"), shared...))
	var m [8]byte
	copy(m[:], h[:8])
	return m
}

func xorU64LE(v uint64, mask [8]byte) []byte {
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = byte(v>>(8*i)) ^ mask[i]
	}
	return out
}

func unxorU64LE(b []byte, mask [8]byte) (uint64, bool) {
	if len(b) != 8 {
		return 0, false
	}
	var v uint64
	for i := 0; i < 8; i++ {
		v |= uint64(b[i]^mask[i]) << (8 * i)
	}
	return v, true
}

// CreateCZKSpend builds a CONFIDENTIAL ZK→ZK transfer: it spends `coin` and pays a fresh
// hidden-amount coin (a_out = coin.Amount − fee) to `dest`, revealing only the nullifier,
// anchor, output leaf and fee. The amounts are hidden by the ZK-masked STARK
// (pkg/stark/cspend_full.go). The recipient recovers the coin via ScanZKCoins.
func (w *Wallet) CreateCZKSpend(coin *ZKCoin, anchor []byte, path stark.MerklePath256, depth int, dest commit.StealthAddress, fee uint64) (*tx.Transaction, error) {
	if w.IsViewOnly() {
		return nil, errors.New("wallet: view-only wallet cannot spend")
	}
	if coin.Amount <= fee {
		return nil, errors.New("wallet: amount does not cover fee")
	}
	limit := uint64(1) << config.ConfidentialBits
	if coin.Amount >= limit || fee >= limit {
		return nil, errors.New("wallet: amount/fee exceeds confidential range (2^ConfidentialBits)")
	}
	aOut := coin.Amount - fee

	// stealth delivery: derive the OUTPUT note's (rho, blind) + amount mask for `dest`.
	r := commit.RandomScalar()
	so := commit.CreateOutputDeterministic(dest, r)
	shared := commit.SharedSecretSender(dest, r)
	rhoOut, blindOut := zkSecretsFromShared(shared)
	// output note paid to dest's nf-address; nullifier of the SPENT note from our nsk+rho.
	pkOut := stark.NodeFromBytes(dest.NfPk)
	cmOut := stark.NfNoteFromPk(pkOut, stark.NewFelt(aOut), rhoOut, blindOut)
	nf := stark.NfNullifier(coin.Nsk, coin.Rho)

	t := &tx.Transaction{
		Version: 1, Fee: fee,
		CZKSpends: []tx.CZKSpend{{
			Nullifier: stark.NodeBytes(nf),
			Anchor:    append([]byte(nil), anchor...),
			LeafOut:   stark.NodeBytes(cmOut),
			Fee:       fee,
			Key:       so.P.Bytes(),
			TxPubKey:  so.R.Bytes(),
			ViewTag:   commit.ViewTag(shared),
			EncAmount: xorU64LE(aOut, czkAmountMask(shared)),
		}},
	}

	ctx := t.CoreHash()
	bind := ctx[:] // full CoreHash domain (256-bit tx binding)
	root := stark.NodeFromBytes(anchor)
	pf, err := stark.ProveCnfSpend(coin.Nsk, stark.NewFelt(coin.Amount), coin.Rho, coin.Blind, path,
		depth, root, pkOut, stark.NewFelt(aOut), rhoOut, blindOut, nf, cmOut, stark.NewFelt(fee),
		bind, config.ConfidentialBits, stark.ZKQueries)
	if err != nil {
		return nil, err
	}
	blob, err := stark.MarshalProof(pf)
	if err != nil {
		return nil, err
	}
	t.CZKSpends[0].Proof = blob

	// conservation: no Pedersen legs; only the public fee re-enters (publicIn=fee) and is
	// the tx fee (publicOut=fee), so the value balances with z = 0.
	cons, err := commit.ProveConservationGen(nil, nil, fee, fee, edwards25519.NewScalar(), ctx[:])
	if err != nil {
		return nil, err
	}
	t.Conservation = cons
	return t, nil
}

// ZKCoinForNullifier returns the owned ZK note whose nullifier nf = H(nsk, rho)
// equals nf (raw 32B), or nil. Used to resolve which coin a previously-sent — and
// possibly stuck — anonymous/confidential spend consumed, so it can be rebuilt for a
// fee bump. The nullifier is public, so a plain comparison is fine.
func (w *Wallet) ZKCoinForNullifier(nf []byte) *ZKCoin {
	for _, c := range w.zkCoins {
		got := stark.NodeBytes(stark.NfNullifier(c.Nsk, c.Rho))
		if bytes.Equal(got, nf) {
			return c
		}
	}
	return nil
}

// BumpZKSpend builds a replace-by-fee (RBF) replacement for a stuck ANONYMOUS (ZK,
// public-amount) or CONFIDENTIAL (CZK, hidden-amount) spend `prev`. It re-spends the
// SAME coin to the same destination at a higher fee. Because the nullifier
// nf = H(nsk, rho) depends only on the coin — NOT on the fee or output amount — the
// replacement carries the IDENTICAL nullifier and therefore conflicts with prev in
// every mempool, superseding it under the RBF policy (mempool.checkReplacementLocked)
// without ever risking a second, independent spend. This closes the gap where only
// transparent-input txs could be bumped: the very transactions whose privacy matters
// most previously had no stuck-tx recovery.
//
// The caller supplies a FRESH membership witness (anchor + path) for the coin,
// re-fetched from the node so it cannot age out of the anchor window while the
// original sits stuck.
//
// PRIVACY: like any RBF, the replacement shares the spent coin's nullifier with the
// original, so the two are publicly linkable as the same spend attempt. This is
// inherent to replacing a stuck tx; bump only when the original is genuinely stuck.
func (w *Wallet) BumpZKSpend(prev *tx.Transaction, coin *ZKCoin, anchor []byte, path stark.MerklePath256, depth int, dest commit.StealthAddress, newFee uint64) (*tx.Transaction, error) {
	if w.IsViewOnly() {
		return nil, errors.New("wallet: view-only wallet cannot spend")
	}
	if newFee <= prev.Fee {
		return nil, errors.New("wallet: new fee must exceed the original fee")
	}
	if coin == nil {
		return nil, errors.New("wallet: spent coin is not known to this wallet (cannot rebuild)")
	}

	// Identify prev's nullifier and which spend kind it is, then rebuild the matching
	// kind at the higher fee. Exactly one of CZKSpends / ZKInputs must be present.
	var prevNf []byte
	var rebuilt *tx.Transaction
	var err error
	switch {
	case len(prev.CZKSpends) == 1 && len(prev.ZKInputs) == 0:
		prevNf = prev.CZKSpends[0].Nullifier
		rebuilt, err = w.CreateCZKSpend(coin, anchor, path, depth, dest, newFee)
	case len(prev.ZKInputs) == 1 && len(prev.CZKSpends) == 0:
		prevNf = prev.ZKInputs[0].Nullifier
		rebuilt, err = w.CreateZKSpend(coin, anchor, path, depth, dest, newFee)
	default:
		return nil, errors.New("wallet: bump supports only a single-input anonymous or confidential ZK spend")
	}
	if err != nil {
		return nil, err
	}

	// SAFETY: the replacement MUST carry the same nullifier as prev. If it does not,
	// we would be creating a SECOND independent spend (double-pay risk) instead of
	// replacing the stuck one — refuse rather than broadcast that.
	var newNf []byte
	if len(rebuilt.CZKSpends) == 1 {
		newNf = rebuilt.CZKSpends[0].Nullifier
	} else {
		newNf = rebuilt.ZKInputs[0].Nullifier
	}
	if !bytes.Equal(newNf, prevNf) {
		return nil, errors.New("wallet: rebuilt spend nullifier does not match the original — refusing (would be a second spend, not a replacement)")
	}

	// Surface the mempool RBF fee floor up front so the node does not reject with a
	// cryptic error: a single-conflict replacement must pay at least
	// prev.Fee + size*MinFeePerByte (checkReplacementLocked absolute-fee rule).
	minBump := prev.Fee + uint64(len(rebuilt.Serialize()))*config.MinFeePerByte
	if newFee < minBump {
		return nil, fmt.Errorf("wallet: new fee %d below RBF floor; needs at least %d (= original fee %d + size*%d/byte)",
			newFee, minBump, prev.Fee, config.MinFeePerByte)
	}
	return rebuilt, nil
}

func commitmentsOf(outs []tx.Output) [][]byte {
	c := make([][]byte, len(outs))
	for i := range outs {
		c[i] = outs[i].Commitment
	}
	return c
}

// ScanZKCoins inspects a block's ZK mints and returns those payable to this wallet
// (a received ZK→ZK transfer), reconstructing each coin's secrets from the stealth
// shared secret so it can later be spent with CreateZKSpend. A coin is only returned
// when the reconstructed (serial, blind) actually re-derive the committed leaf.
func (w *Wallet) ScanZKCoins(b *block.Block) []*ZKCoin {
	keys := w.subKeys()
	var found []*ZKCoin
	for _, t := range b.Txs {
		for i := range t.ZKOutputs {
			o := &t.ZKOutputs[i]
			if len(o.Key) != 32 || len(o.TxPubKey) != 32 || len(o.Leaf) != 32 {
				continue
			}
			P, err := new(edwards25519.Point).SetBytes(o.Key)
			if err != nil {
				continue
			}
			R, err := new(edwards25519.Point).SetBytes(o.TxPubKey)
			if err != nil {
				continue
			}
			so := &commit.StealthOutput{P: P, R: R}
			var k *commit.StealthKeys
			for _, cand := range keys {
				if cand.ScanMatch(so, o.ViewTag) {
					k = cand
					break
				}
			}
			if k == nil {
				continue
			}
			rho, blind := zkSecretsFromShared(k.SharedSecret(so))
			pk := stark.NodeFromBytes(k.Addr.NfPk)
			if stark.NfNoteFromPk(pk, stark.NewFelt(o.Amount), rho, blind) != stark.NodeFromBytes(o.Leaf) {
				continue // not actually ours / inconsistent (cm must reproduce under OUR pk)
			}
			found = append(found, &ZKCoin{
				Amount: o.Amount, Rho: rho, Blind: blind, Nsk: k.NfSecret(),
				Leaf: append([]byte(nil), o.Leaf...),
			})
		}
		// confidential spends also deliver a fresh coin to the recipient, but the amount
		// is HIDDEN (only in EncAmount) — decrypt it, then confirm it re-derives the leaf.
		for i := range t.CZKSpends {
			s := &t.CZKSpends[i]
			if len(s.Key) != 32 || len(s.TxPubKey) != 32 || len(s.LeafOut) != 32 {
				continue
			}
			P, err := new(edwards25519.Point).SetBytes(s.Key)
			if err != nil {
				continue
			}
			R, err := new(edwards25519.Point).SetBytes(s.TxPubKey)
			if err != nil {
				continue
			}
			so := &commit.StealthOutput{P: P, R: R}
			var k *commit.StealthKeys
			for _, cand := range keys {
				if cand.ScanMatch(so, s.ViewTag) {
					k = cand
					break
				}
			}
			if k == nil {
				continue
			}
			shared := k.SharedSecret(so)
			rho, blind := zkSecretsFromShared(shared)
			amount, ok := unxorU64LE(s.EncAmount, czkAmountMask(shared))
			if !ok {
				continue
			}
			pk := stark.NodeFromBytes(k.Addr.NfPk)
			if stark.NfNoteFromPk(pk, stark.NewFelt(amount), rho, blind) != stark.NodeFromBytes(s.LeafOut) {
				continue // not ours / tampered EncAmount
			}
			found = append(found, &ZKCoin{
				Amount: amount, Rho: rho, Blind: blind, Nsk: k.NfSecret(),
				Leaf: append([]byte(nil), s.LeafOut...),
			})
		}
	}
	return found
}
