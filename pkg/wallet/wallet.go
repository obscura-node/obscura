// Package wallet manages keys, scans the chain for owned outputs, and builds
// sound confidential transactions: authenticated ownership proofs, value-binding
// equality proofs, stealth outputs, range proofs, and conservation proofs.
package wallet

import (
	"encoding/binary"
	"errors"

	"filippo.io/edwards25519"

	"obscura/pkg/accumulator"
	"obscura/pkg/block"
	"obscura/pkg/commit"
	"obscura/pkg/config"
	"obscura/pkg/stark"
	"obscura/pkg/tx"
)

// ChainView is the read access a wallet needs to build transactions. In the
// sound model the wallet builds spends entirely offline from its own scanned
// outputs, so it only needs the current height (for maturity/lock selection).
type ChainView interface {
	Height() uint64
}

// OwnedOutput is an output this wallet can spend.
type OwnedOutput struct {
	Out         tx.Output
	Amount      uint64
	Mask        *edwards25519.Scalar // commitment blinding
	OneTime     *edwards25519.Scalar // one-time secret (x with x·G = P)
	Height      uint64
	IsCoinbase  bool
	Spent       bool
	SpentHeight uint64 // block height where this output was spent (0 if unspent). Lets
	// ScanBlockUndo roll back spends that were orphaned by a reorg (audit #19).
	SourceTx string // txid that created this output (set on scan; not persisted)
	reserved bool   // locally reserved by a not-yet-confirmed spend
}

// SentTx records an outgoing payment this wallet created, so it can show history
// and support replace-by-fee (BumpFee) on a stuck payment. Dest/Amount are kept
// to rebuild a replacement; Raw is the serialized original.
type SentTx struct {
	TxID     string
	Dest     []byte // 96-byte encoded stealth address (A||B||NfPk)
	Amount   uint64
	Fee      uint64
	Raw      []byte // serialized original transaction (for bumping)
	Height   uint64 // 0 = still pending (not yet seen in a block)
	Replaced bool   // superseded by a replace-by-fee bump
	DestR    []byte // destination output's tx secret r (for the sender out-proof)
}

// Wallet holds keys and tracked outputs.
type Wallet struct {
	keys        *commit.StealthKeys
	Outputs     []*OwnedOutput
	Sent        []*SentTx
	subCount    uint32            // highest generated subaddress index (0 = only main account)
	lastScanned uint64            // highest block height already scanned
	pendingR    map[string][]byte // txid -> destination output tx secret r (for out-proofs)
	// zkCoins holds the secret material for ZK notes this wallet can spend (minted to
	// self or received via ScanZKCoins). They are NOT recoverable from the transparent
	// scan, so they MUST be persisted with the scan state (see MarshalState/RestoreState).
	zkCoins []*ZKCoin
}

// ZKCoins returns the wallet's spendable ZK notes (minted-to-self or received).
func (w *Wallet) ZKCoins() []*ZKCoin { return w.zkCoins }

// AddZKCoin records a ZK note so it can be spent later (and persisted). Duplicate
// leaves are ignored so re-scanning a block does not store the same coin twice.
func (w *Wallet) AddZKCoin(c *ZKCoin) {
	if c == nil {
		return
	}
	for _, e := range w.zkCoins {
		if len(e.Leaf) == len(c.Leaf) && string(e.Leaf) == string(c.Leaf) {
			return
		}
	}
	w.zkCoins = append(w.zkCoins, c)
}

// subKeys returns the keypairs the wallet scans against: the main account plus
// every generated subaddress.
func (w *Wallet) subKeys() []*commit.StealthKeys {
	ks := make([]*commit.StealthKeys, 0, w.subCount+1)
	ks = append(ks, w.keys)
	for i := uint32(1); i <= w.subCount; i++ {
		ks = append(ks, w.keys.Subaddress(i))
	}
	return ks
}

// SubaddressCount returns how many subaddresses have been generated.
func (w *Wallet) SubaddressCount() uint32 { return w.subCount }

// SubaddressAt returns the address for sub-account index i (0 = main).
func (w *Wallet) SubaddressAt(i uint32) commit.StealthAddress {
	return w.keys.Subaddress(i).Addr
}

// NewSubaddress generates the next subaddress and returns its index and address.
func (w *Wallet) NewSubaddress() (uint32, commit.StealthAddress) {
	w.subCount++
	return w.subCount, w.keys.Subaddress(w.subCount).Addr
}

// SentHistory returns the recorded outgoing payments (most-recent last).
func (w *Wallet) SentHistory() []*SentTx { return w.Sent }

// FindSent returns the recorded sent tx with the given id, or nil.
func (w *Wallet) FindSent(txid string) *SentTx {
	for _, s := range w.Sent {
		if s.TxID == txid {
			return s
		}
	}
	return nil
}

// RecordSent stores an outgoing payment after it is submitted.
func (w *Wallet) RecordSent(t *tx.Transaction, dest commit.StealthAddress, amount uint64) {
	var destR []byte
	if w.pendingR != nil {
		destR = w.pendingR[t.HashHex()]
	}
	w.Sent = append(w.Sent, &SentTx{
		TxID:   t.HashHex(),
		Dest:   dest.Encode(),
		Amount: amount,
		Fee:    t.Fee,
		Raw:    t.Serialize(),
		DestR:  destR,
	})
}

// LastScanned returns the highest block height this wallet has scanned, so a
// client can scan only newer blocks instead of rescanning from genesis.
func (w *Wallet) LastScanned() uint64 { return w.lastScanned }

// New creates a fresh random wallet.
func New() *Wallet { return &Wallet{keys: commit.NewStealthKeys()} }

// FromSeed derives a wallet deterministically from a seed.
func FromSeed(seed []byte) *Wallet { return &Wallet{keys: commit.StealthKeysFromSeed(seed)} }

// FromViewKey builds a WATCH-ONLY wallet from a 64-byte view key: it can scan,
// detect incoming outputs, and report balances, but cannot spend.
func FromViewKey(vk []byte) (*Wallet, error) {
	k, err := commit.StealthKeysFromViewKey(vk)
	if err != nil {
		return nil, err
	}
	return &Wallet{keys: k}, nil
}

// IsViewOnly reports whether this wallet cannot spend (watch-only).
func (w *Wallet) IsViewOnly() bool { return w.keys.IsViewOnly() }

// ViewKey exports this wallet's 64-byte view key for creating a watch-only wallet.
func (w *Wallet) ViewKey() []byte { return w.keys.ViewKey() }

// Address returns the public stealth address.
func (w *Wallet) Address() commit.StealthAddress { return w.keys.Addr }

// AddressBytes returns the 96-byte encoded address (A||B||NfPk).
func (w *Wallet) AddressBytes() []byte { return w.keys.Addr.Encode() }

// Balance returns the spendable balance (atomic units).
func (w *Wallet) Balance() uint64 {
	var b uint64
	for _, o := range w.Outputs {
		if !o.Spent {
			b += o.Amount
		}
	}
	return b
}

// ScanBlock detects owned outputs and marks spent ones (by output reference).
func (w *Wallet) ScanBlock(b *block.Block) {
	// mark spends: an input's OutputRef is the spent output's one-time key.
	spentRefs := make(map[string]bool)
	for _, t := range b.Txs {
		for _, in := range t.Inputs {
			spentRefs[string(in.OutputRef)] = true
		}
	}
	for _, o := range w.Outputs {
		if spentRefs[string(o.Out.OneTimeKey)] && !o.Spent {
			o.Spent = true
			o.SpentHeight = b.Header.Height // recorded so a reorg can roll this spend back (#19)
		}
	}
	// detect new owned outputs (scan against the main account + all subaddresses)
	keys := w.subKeys()
	for _, t := range b.Txs {
		txid := t.HashHex()
		for i := range t.Outputs {
			w.tryClaim(&t.Outputs[i], b.Header.Height, t.IsCoinbase, txid, keys)
		}
	}
	// detect ZK notes paid to this wallet (shielded mints + confidential spends). These
	// are NOT recoverable from the transparent scan, so capture + retain them here so a
	// reload can still spend them (persisted via MarshalState).
	for _, c := range w.ScanZKCoins(b) {
		w.AddZKCoin(c)
	}
	// confirm any of our recorded outgoing payments that landed in this block
	if len(w.Sent) > 0 {
		for _, t := range b.Txs {
			if s := w.FindSent(t.HashHex()); s != nil && s.Height == 0 {
				s.Height = b.Header.Height
			}
		}
	}
	if b.Header.Height > w.lastScanned {
		w.lastScanned = b.Header.Height
	}
}

// ScanBlockUndo rolls back every scan effect at heights >= fromHeight, so a wallet can
// recover from a chain reorg (audit #19). Without it, an output marked Spent in a block that
// gets orphaned stays Spent forever (balance understated, funds look unspendable, the user may
// re-send), and an output received in an orphaned block lingers (balance overstated). After
// calling this, the caller re-scans the NEW branch forward from fromHeight (the fork point).
// Genesis (height 0) is immutable, so fromHeight is clamped to >= 1.
func (w *Wallet) ScanBlockUndo(fromHeight uint64) {
	if fromHeight == 0 {
		fromHeight = 1
	}
	kept := w.Outputs[:0]
	for _, o := range w.Outputs {
		// drop outputs first seen in an orphaned block — they do not exist on the new branch
		// (the forward re-scan re-claims them if still present there).
		if o.Height >= fromHeight {
			continue
		}
		// un-spend outputs whose spending tx was orphaned.
		if o.Spent && o.SpentHeight >= fromHeight {
			o.Spent = false
			o.SpentHeight = 0
		}
		kept = append(kept, o)
	}
	w.Outputs = kept
	// un-confirm sent payments that were mined only in the orphaned suffix.
	for _, s := range w.Sent {
		if s.Height >= fromHeight {
			s.Height = 0
		}
	}
	if w.lastScanned >= fromHeight {
		w.lastScanned = fromHeight - 1
	}
}

// MarshalState serializes the wallet's scan state (last-scanned height + owned
// outputs) so a client can persist it and avoid rescanning from genesis. The
// seed/keys are NOT included — reload keys from the seed, then RestoreState.
func (w *Wallet) MarshalState() []byte {
	var b []byte
	put64 := func(v uint64) { var n [8]byte; binary.BigEndian.PutUint64(n[:], v); b = append(b, n[:]...) }
	put32 := func(p []byte) { var x [32]byte; copy(x[:], p); b = append(b, x[:]...) }
	putBool := func(v bool) {
		if v {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
	}
	put64(w.lastScanned)
	put64(uint64(len(w.Outputs)))
	for _, o := range w.Outputs {
		put32(o.Out.OneTimeKey)
		put32(o.Out.Commitment)
		put64(o.Out.LockUntil)
		put64(o.Amount)
		b = append(b, o.Mask.Bytes()...) // 32
		// view-only wallets have no one-time spend secret; persist 32 zero bytes
		// (an all-zero scalar restores back to nil, see RestoreState).
		if o.OneTime != nil {
			b = append(b, o.OneTime.Bytes()...) // 32
		} else {
			b = append(b, make([]byte, 32)...)
		}
		put64(o.Height)
		putBool(o.IsCoinbase)
		putBool(o.Spent)
	}
	// sent-payment history (appended after outputs; older state files simply lack
	// this section and restore with an empty history)
	putBytes := func(p []byte) { put64(uint64(len(p))); b = append(b, p...) }
	put64(uint64(len(w.Sent)))
	for _, s := range w.Sent {
		putBytes([]byte(s.TxID))
		putBytes(s.Dest)
		put64(s.Amount)
		put64(s.Fee)
		putBytes(s.Raw)
		put64(s.Height)
		putBool(s.Replaced)
		putBytes(s.DestR)
	}
	// subaddress count (appended after the sent section; older files lack it)
	put64(uint64(w.subCount))
	// spent-heights (appended; parallel to Outputs, same order). Older readers ignore the
	// trailing bytes; newer readers use them to roll back orphaned spends on reorg (#19).
	for _, o := range w.Outputs {
		put64(o.SpentHeight)
	}
	// ZK notes (appended; older files lack this section and restore with no ZK coins).
	// Each coin: amount, rho, blind, nsk (8-byte felts), then the 32-byte leaf. These are
	// secret spend material, so the on-disk state must be encrypted by the caller.
	put64(uint64(len(w.zkCoins)))
	for _, c := range w.zkCoins {
		put64(c.Amount)
		b = append(b, stark.FeltBytes(c.Rho)...)   // 8
		b = append(b, stark.FeltBytes(c.Blind)...) // 8
		b = append(b, stark.FeltBytes(c.Nsk)...)   // 8
		put32(c.Leaf)
	}
	return b
}

// RestoreState loads scan state produced by MarshalState into a wallet whose
// keys are already derived from the seed.
func (w *Wallet) RestoreState(data []byte) error {
	pos := 0
	get64 := func() (uint64, error) {
		if pos+8 > len(data) {
			return 0, errors.New("wallet: short state")
		}
		v := binary.BigEndian.Uint64(data[pos:])
		pos += 8
		return v, nil
	}
	get := func(n int) ([]byte, error) {
		if pos+n > len(data) {
			return nil, errors.New("wallet: short state")
		}
		v := data[pos : pos+n]
		pos += n
		return v, nil
	}
	ls, err := get64()
	if err != nil {
		return err
	}
	cnt, err := get64()
	if err != nil {
		return err
	}
	if cnt > 1<<24 {
		return errors.New("wallet: implausible output count")
	}
	outs := make([]*OwnedOutput, 0, cnt)
	for i := uint64(0); i < cnt; i++ {
		otk, err := get(32)
		if err != nil {
			return err
		}
		com, err := get(32)
		if err != nil {
			return err
		}
		lock, err := get64()
		if err != nil {
			return err
		}
		amt, err := get64()
		if err != nil {
			return err
		}
		mb, err := get(32)
		if err != nil {
			return err
		}
		ob, err := get(32)
		if err != nil {
			return err
		}
		h, err := get64()
		if err != nil {
			return err
		}
		flags, err := get(2)
		if err != nil {
			return err
		}
		mask, err := new(edwards25519.Scalar).SetCanonicalBytes(mb)
		if err != nil {
			return err
		}
		// an all-zero one-time secret means "view-only" (no spend secret) → nil,
		// not the literal scalar 0 (which would be a bogus spend key).
		var ot *edwards25519.Scalar
		if !allZero(ob) {
			ot, err = new(edwards25519.Scalar).SetCanonicalBytes(ob)
			if err != nil {
				return err
			}
		}
		outs = append(outs, &OwnedOutput{
			Out:        tx.Output{OneTimeKey: append([]byte(nil), otk...), Commitment: append([]byte(nil), com...), LockUntil: lock},
			Amount:     amt,
			Mask:       mask,
			OneTime:    ot,
			Height:     h,
			IsCoinbase: flags[0] == 1,
			Spent:      flags[1] == 1,
		})
	}
	w.lastScanned = ls
	w.Outputs = outs

	// sent-payment history (optional trailing section; absent in older state files)
	w.Sent = nil
	if pos >= len(data) {
		return nil
	}
	getBytes := func() ([]byte, error) {
		n, err := get64()
		if err != nil {
			return nil, err
		}
		if n > 1<<20 {
			return nil, errors.New("wallet: implausible sent field")
		}
		return get(int(n))
	}
	scnt, err := get64()
	if err != nil {
		return err
	}
	if scnt > 1<<20 {
		return errors.New("wallet: implausible sent count")
	}
	for i := uint64(0); i < scnt; i++ {
		txid, err := getBytes()
		if err != nil {
			return err
		}
		dest, err := getBytes()
		if err != nil {
			return err
		}
		amt, err := get64()
		if err != nil {
			return err
		}
		fee, err := get64()
		if err != nil {
			return err
		}
		raw, err := getBytes()
		if err != nil {
			return err
		}
		h, err := get64()
		if err != nil {
			return err
		}
		rep, err := get(1)
		if err != nil {
			return err
		}
		destR, err := getBytes()
		if err != nil {
			return err
		}
		w.Sent = append(w.Sent, &SentTx{
			TxID:     string(txid),
			Dest:     append([]byte(nil), dest...),
			Amount:   amt,
			Fee:      fee,
			Raw:      append([]byte(nil), raw...),
			Height:   h,
			Replaced: rep[0] == 1,
			DestR:    append([]byte(nil), destR...),
		})
	}
	// subaddress count (optional trailing field; absent in older state files)
	w.subCount = 0
	if pos < len(data) {
		sc, err := get64()
		if err != nil {
			return err
		}
		if sc > 1<<20 {
			return errors.New("wallet: implausible subaddress count")
		}
		w.subCount = uint32(sc)
	}
	// spent-heights (optional trailing section; absent in older files → SpentHeight stays 0,
	// which only means a pre-upgrade spend can't be reorg-rolled-back). Parallel to Outputs.
	if pos < len(data) {
		for _, o := range w.Outputs {
			sh, err := get64()
			if err != nil {
				return err
			}
			o.SpentHeight = sh
		}
	}
	// ZK notes (optional trailing section; absent in older files → no ZK coins).
	w.zkCoins = nil
	if pos < len(data) {
		zcnt, err := get64()
		if err != nil {
			return err
		}
		if zcnt > 1<<20 {
			return errors.New("wallet: implausible zk-coin count")
		}
		for i := uint64(0); i < zcnt; i++ {
			amt, err := get64()
			if err != nil {
				return err
			}
			rb, err := get(8)
			if err != nil {
				return err
			}
			bb, err := get(8)
			if err != nil {
				return err
			}
			nb, err := get(8)
			if err != nil {
				return err
			}
			leaf, err := get(32)
			if err != nil {
				return err
			}
			w.zkCoins = append(w.zkCoins, &ZKCoin{
				Amount: amt,
				Rho:    stark.FeltFromBytes(rb),
				Blind:  stark.FeltFromBytes(bb),
				Nsk:    stark.FeltFromBytes(nb),
				Leaf:   append([]byte(nil), leaf...),
			})
		}
	}
	return nil
}

func (w *Wallet) tryClaim(o *tx.Output, height uint64, isCoinbase bool, sourceTx string, keys []*commit.StealthKeys) {
	if len(o.OneTimeKey) != 32 || len(o.TxPubKey) != 32 || len(o.Commitment) != 32 {
		return
	}
	P, err := new(edwards25519.Point).SetBytes(o.OneTimeKey)
	if err != nil {
		return
	}
	R, err := new(edwards25519.Point).SetBytes(o.TxPubKey)
	if err != nil {
		return
	}
	so := &commit.StealthOutput{P: P, R: R}
	// find which account (main or a subaddress) owns this output. The view-tag
	// pre-filter inside ScanMatch skips ~255/256 of non-owned outputs cheaply.
	var k *commit.StealthKeys
	for _, cand := range keys {
		if cand.ScanMatch(so, o.ViewTag) {
			k = cand
			break
		}
	}
	if k == nil {
		return
	}
	// avoid duplicates
	for _, ex := range w.Outputs {
		if string(ex.Out.OneTimeKey) == string(o.OneTimeKey) {
			return
		}
	}
	shared := k.SharedSecret(so)
	amount := commit.DecryptAmount(shared, o.EncAmount)
	mask, err := commit.DecryptScalar(shared, o.EncMask)
	if err != nil {
		return
	}
	// CRITICAL: verify the decrypted (amount, mask) actually open the on-chain
	// commitment. A malicious sender could otherwise encrypt inconsistent values
	// to make the output appear received but be unspendable / mis-valued.
	if string(commit.Commit(amount, mask).Bytes()) != string(o.Commitment) {
		return
	}
	// view-only wallets can detect+value the output but not derive its spend
	// secret; record it with a nil OneTime (balance works, spending does not).
	var x *edwards25519.Scalar
	if !k.IsViewOnly() {
		x, err = k.OneTimeSecret(so)
		if err != nil {
			return
		}
	}
	w.Outputs = append(w.Outputs, &OwnedOutput{
		Out:        *o,
		Amount:     amount,
		Mask:       mask,
		OneTime:    x,
		Height:     height,
		IsCoinbase: isCoinbase,
		SourceTx:   sourceTx,
	})
}

// buildOutput creates a stealth output paying `amount` to dest. Returns the
// output and its commitment blinding (needed for conservation).
func buildOutput(dest commit.StealthAddress, amount uint64, lockUntil uint64) (tx.Output, *edwards25519.Scalar, error) {
	out, blinding, _, err := buildOutputR(dest, amount, lockUntil)
	return out, blinding, err
}

// buildOutputR is buildOutput that also returns the per-output transaction secret
// r (with R = r·G), needed by the sender to later prove the payment (out-proof).
func buildOutputR(dest commit.StealthAddress, amount uint64, lockUntil uint64) (tx.Output, *edwards25519.Scalar, *edwards25519.Scalar, error) {
	r := commit.RandomScalar()
	so := commit.CreateOutputDeterministic(dest, r)
	shared := commit.SharedSecretSender(dest, r)

	C, blinding, rp, err := commit.ProveRange(amount)
	if err != nil {
		return tx.Output{}, nil, nil, err
	}
	_, nonce := accumulator.HashToPrime(so.P.Bytes())

	out := tx.Output{
		OneTimeKey: so.P.Bytes(),
		TxPubKey:   so.R.Bytes(),
		Commitment: C.Bytes(),
		RangeProof: rp.Serialize(),
		PrimeNonce: nonce,
		LockUntil:  lockUntil,
		EncAmount:  commit.EncryptAmount(shared, amount),
		EncMask:    commit.EncryptScalar(shared, blinding),
		ViewTag:    commit.ViewTag(shared),
	}
	return out, blinding, r, nil
}

// CreateTransaction builds a sound confidential transaction sending `amount` to
// dest with the given fee, spending the wallet's outputs. Built entirely offline
// from the wallet's own scanned outputs.
func (w *Wallet) CreateTransaction(view ChainView, dest commit.StealthAddress, amount, fee uint64) (*tx.Transaction, error) {
	if w.IsViewOnly() {
		return nil, errors.New("wallet: view-only wallet cannot spend")
	}
	if amount == 0 {
		return nil, errors.New("wallet: amount must be positive")
	}
	need, ovf := addCheck(amount, fee)
	if ovf {
		return nil, errors.New("wallet: amount+fee overflow")
	}
	spendHeight := view.Height() + 1

	var selected []*OwnedOutput
	var total uint64
	for _, o := range w.Outputs {
		if o.Spent || o.reserved {
			continue
		}
		if o.IsCoinbase && spendHeight < o.Height+config.CoinbaseMaturity {
			continue // immature coinbase
		}
		if spendHeight < o.Out.LockUntil {
			continue // time-locked
		}
		selected = append(selected, o)
		var ovf2 bool
		total, ovf2 = addCheck(total, o.Amount)
		if ovf2 {
			return nil, errors.New("wallet: balance overflow")
		}
		if total >= need {
			break
		}
	}
	if total < need {
		return nil, errors.New("wallet: insufficient spendable funds")
	}

	return w.buildSpend(selected, dest, amount, fee)
}

// CreateTransactionFrom builds a transaction spending EXACTLY the given owned
// output (must be unspent, unreserved, mature and unlocked, and cover amount+fee).
// Useful for precise UTXO control — e.g. a load generator that fans one output
// into two roughly-equal spendable outputs. The output is reserved on success.
func (w *Wallet) CreateTransactionFrom(view ChainView, o *OwnedOutput, dest commit.StealthAddress, amount, fee uint64) (*tx.Transaction, error) {
	if w.IsViewOnly() {
		return nil, errors.New("wallet: view-only wallet cannot spend")
	}
	if o == nil || o.Spent || o.reserved {
		return nil, errors.New("wallet: output unavailable")
	}
	spendHeight := view.Height() + 1
	if o.IsCoinbase && spendHeight < o.Height+config.CoinbaseMaturity {
		return nil, errors.New("wallet: immature coinbase")
	}
	if spendHeight < o.Out.LockUntil {
		return nil, errors.New("wallet: time-locked output")
	}
	need, ovf := addCheck(amount, fee)
	if ovf || o.Amount < need {
		return nil, errors.New("wallet: output does not cover amount+fee")
	}
	return w.buildSpend([]*OwnedOutput{o}, dest, amount, fee)
}

// SpendableOutputs returns the wallet's outputs that are spendable at the given
// height (unspent, unreserved, mature coinbase, and past any time-lock).
func (w *Wallet) SpendableOutputs(spendHeight uint64) []*OwnedOutput {
	var out []*OwnedOutput
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
		out = append(out, o)
	}
	return out
}

// SpendableBalance returns the total atomic value the wallet can ACTUALLY spend at
// spendHeight: the sum of SpendableOutputs(spendHeight) amounts — i.e. Balance()
// minus immature coinbase, time-locked, and locally-reserved outputs. The UI uses
// this for "Max" / amount hints so a suggested amount can't exceed what a spend can
// select (Balance() overstates it). Balance() intentionally still reports the gross
// unspent total (other callers depend on that); this is the spendable subset.
func (w *Wallet) SpendableBalance(spendHeight uint64) uint64 {
	var b uint64
	for _, o := range w.SpendableOutputs(spendHeight) {
		b += o.Amount
	}
	return b
}

// CreateSweepTransaction spends ALL of the wallet's spendable (mature, unlocked)
// outputs to a single destination, sending total−fee with no change. Useful to
// empty a wallet or consolidate dust.
func (w *Wallet) CreateSweepTransaction(view ChainView, dest commit.StealthAddress, fee uint64) (*tx.Transaction, error) {
	if w.IsViewOnly() {
		return nil, errors.New("wallet: view-only wallet cannot spend")
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
		var ovf bool
		total, ovf = addCheck(total, o.Amount)
		if ovf {
			return nil, errors.New("wallet: balance overflow")
		}
	}
	if len(selected) == 0 || total <= fee {
		return nil, errors.New("wallet: nothing to sweep (balance does not cover the fee)")
	}
	// amount = total − fee  ⇒  change is exactly zero (single output)
	return w.buildSpend(selected, dest, total-fee, fee)
}

// buildSpend constructs a transparent transaction from an EXPLICIT input set
// (used by CreateTransaction after selection, and by BumpFee to reuse the exact
// same inputs for a replace-by-fee bump). It recomputes the change to absorb the
// fee.
func (w *Wallet) buildSpend(selected []*OwnedOutput, dest commit.StealthAddress, amount, fee uint64) (*tx.Transaction, error) {
	need, ovf := addCheck(amount, fee)
	if ovf {
		return nil, errors.New("wallet: amount+fee overflow")
	}
	var total uint64
	for _, o := range selected {
		var ovf2 bool
		total, ovf2 = addCheck(total, o.Amount)
		if ovf2 {
			return nil, errors.New("wallet: balance overflow")
		}
	}
	if total < need {
		return nil, errors.New("wallet: insufficient spendable funds")
	}

	t := &tx.Transaction{Version: 1, Fee: fee}

	// outputs: destination + change
	var outBlindings []*edwards25519.Scalar
	destOut, db, destR, err := buildOutputR(dest, amount, 0)
	if err != nil {
		return nil, err
	}
	t.Outputs = append(t.Outputs, destOut)
	outBlindings = append(outBlindings, db)

	change := total - need
	if change > 0 {
		chOut, cb, err := buildOutput(w.keys.Addr, change, 0)
		if err != nil {
			return nil, err
		}
		t.Outputs = append(t.Outputs, chOut)
		outBlindings = append(outBlindings, cb)
	}

	// inputs (proofs filled after CoreHash is known): OutputRef + pseudo-commit
	var pseudoBlindings []*edwards25519.Scalar
	for _, o := range selected {
		pr := commit.RandomScalar()
		pseudo := commit.Commit(o.Amount, pr)
		pseudoBlindings = append(pseudoBlindings, pr)
		t.Inputs = append(t.Inputs, tx.Input{
			OutputRef:        append([]byte(nil), o.Out.OneTimeKey...),
			PseudoCommitment: pseudo.Bytes(),
			// key-image VALUE (T = x·U) is set pre-CoreHash so it is bound by it;
			// its DLEQ proof is filled after, like the other proofs.
			KeyImage: commit.KeyImage(o.OneTime).Bytes(),
		})
	}

	// context binds all proofs to the tx content (excludes the proofs themselves)
	ctx := t.CoreHash()

	// fill ownership + value-equality + key-image proofs for each input
	for i, o := range selected {
		own, err := commit.ProveOwnership(o.Out.OneTimeKey, o.OneTime, ctx[:])
		if err != nil {
			return nil, err
		}
		// d = pseudoBlinding - realBlinding  (proves equal committed value)
		d := new(edwards25519.Scalar).Subtract(pseudoBlindings[i], o.Mask)
		eq, err := commit.ProveValueEquality(t.Inputs[i].PseudoCommitment, o.Out.Commitment, d, ctx[:])
		if err != nil {
			return nil, err
		}
		t.Inputs[i].OwnershipProof = own
		t.Inputs[i].EqualityProof = eq
		t.Inputs[i].KeyImageProof = commit.ProveKeyImageProof(o.OneTime, ctx[:])
	}

	// conservation: z = Σ pseudoBlindings − Σ outBlindings
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
	outs := make([][]byte, len(t.Outputs))
	for i, o := range t.Outputs {
		outs[i] = o.Commitment
	}
	cons, err := commit.ProveConservation(pseudoIns, outs, fee, z, ctx[:])
	if err != nil {
		return nil, err
	}
	t.Conservation = cons

	// stash the destination output's tx secret r (keyed by txid) so RecordSent can
	// persist it for a later sender payment proof.
	if w.pendingR == nil {
		w.pendingR = make(map[string][]byte)
	}
	w.pendingR[t.HashHex()] = destR.Bytes()

	// reserve selected outputs so a subsequent build doesn't double-select them
	for _, o := range selected {
		o.reserved = true
	}
	return t, nil
}

// BumpFee builds a replace-by-fee (RBF) replacement for a previously-created
// transparent transaction `prev`: it re-spends the EXACT SAME inputs to the same
// destination/amount but with a higher fee (absorbed from the change). Because it
// reuses prev's inputs, the replacement conflicts with prev in every mempool and
// supersedes it under the RBF policy — without risking a second, independent
// payment.
//
// PRIVACY: a bump shares input references with the original, so the two are
// publicly linkable. This is inherent to any re-spend and unavoidable; bump only
// when the original is genuinely stuck.
func (w *Wallet) BumpFee(prev *tx.Transaction, dest commit.StealthAddress, amount, newFee uint64) (*tx.Transaction, error) {
	if w.IsViewOnly() {
		return nil, errors.New("wallet: view-only wallet cannot spend")
	}
	if newFee <= prev.Fee {
		return nil, errors.New("wallet: new fee must exceed the original fee")
	}
	if len(prev.Inputs) == 0 {
		return nil, errors.New("wallet: can only bump transparent-input transactions")
	}
	refs := make(map[string]bool, len(prev.Inputs))
	for _, in := range prev.Inputs {
		refs[string(in.OutputRef)] = true
	}
	var selected []*OwnedOutput
	seen := make(map[string]bool)
	for _, o := range w.Outputs {
		k := string(o.Out.OneTimeKey)
		if refs[k] && !seen[k] {
			selected = append(selected, o)
			seen[k] = true
		}
	}
	if len(selected) != len(refs) {
		return nil, errors.New("wallet: original inputs are not all owned/known to this wallet")
	}
	return w.buildSpend(selected, dest, amount, newFee)
}

// ProvePayment produces a receipt proof that this wallet's address received the
// given owned output (and lets a verifier learn its amount), without revealing
// any keys. The output must come from a fresh scan (the persisted state omits the
// tx pubkey needed for the proof).
func (w *Wallet) ProvePayment(o *OwnedOutput) (commit.PaymentProof, error) {
	if len(o.Out.TxPubKey) != 32 {
		return commit.PaymentProof{}, errors.New("wallet: output lacks tx pubkey (rescan to prove)")
	}
	P, err := new(edwards25519.Point).SetBytes(o.Out.OneTimeKey)
	if err != nil {
		return commit.PaymentProof{}, err
	}
	R, err := new(edwards25519.Point).SetBytes(o.Out.TxPubKey)
	if err != nil {
		return commit.PaymentProof{}, err
	}
	return w.keys.ProveReceipt(&commit.StealthOutput{P: P, R: R}, o.Out.EncAmount), nil
}

// ProvePaymentBundle produces a self-contained, node-free receipt proof for an
// owned output: it bundles the output's on-chain data with the proof so a verifier
// needs only the bundle and the claimed address.
func (w *Wallet) ProvePaymentBundle(o *OwnedOutput) (commit.ReceiptBundle, error) {
	if len(o.Out.TxPubKey) != 32 {
		return commit.ReceiptBundle{}, errors.New("wallet: output lacks tx pubkey (rescan to prove)")
	}
	P, err := new(edwards25519.Point).SetBytes(o.Out.OneTimeKey)
	if err != nil {
		return commit.ReceiptBundle{}, err
	}
	R, err := new(edwards25519.Point).SetBytes(o.Out.TxPubKey)
	if err != nil {
		return commit.ReceiptBundle{}, err
	}
	so := &commit.StealthOutput{P: P, R: R}
	return commit.ReceiptBundle{
		Out:       so,
		EncAmount: append([]byte(nil), o.Out.EncAmount...),
		Proof:     w.keys.ProveReceipt(so, o.Out.EncAmount),
	}, nil
}

// ProveSpendBundle produces a SENDER payment proof for a recorded outgoing
// payment: it proves THIS wallet paid the recorded destination, using the tx
// secret stashed at send time. Verifiable offline by anyone with the bundle and
// the recipient address (same VerifyBundle as a receipt proof).
func (w *Wallet) ProveSpendBundle(s *SentTx) (commit.ReceiptBundle, error) {
	if len(s.DestR) != 32 {
		return commit.ReceiptBundle{}, errors.New("wallet: no tx secret stored for this payment (cannot prove)")
	}
	r, err := new(edwards25519.Scalar).SetCanonicalBytes(s.DestR)
	if err != nil {
		return commit.ReceiptBundle{}, err
	}
	prev, err := tx.Deserialize(s.Raw)
	if err != nil {
		return commit.ReceiptBundle{}, err
	}
	if len(prev.Outputs) == 0 {
		return commit.ReceiptBundle{}, errors.New("wallet: payment has no outputs")
	}
	o := prev.Outputs[0] // destination is always the first output
	P, err := new(edwards25519.Point).SetBytes(o.OneTimeKey)
	if err != nil {
		return commit.ReceiptBundle{}, err
	}
	R, err := new(edwards25519.Point).SetBytes(o.TxPubKey)
	if err != nil {
		return commit.ReceiptBundle{}, err
	}
	addr, err := commit.DecodeAddress(s.Dest)
	if err != nil {
		return commit.ReceiptBundle{}, err
	}
	return commit.ReceiptBundle{
		Out:       &commit.StealthOutput{P: P, R: R},
		EncAmount: append([]byte(nil), o.EncAmount...),
		Proof:     commit.ProveSpend(r, addr, o.EncAmount),
	}, nil
}

// ReleaseReserved clears this output's local spend reservation.
func (o *OwnedOutput) ReleaseReserved() { o.reserved = false }

// ReleaseReservation clears the local input reservations made by a transaction
// that will not be submitted (e.g. a throwaway build used only to measure size,
// or an abandoned/failed send), so those outputs are selectable again.
func (w *Wallet) ReleaseReservation(t *tx.Transaction) {
	refs := make(map[string]bool, len(t.Inputs))
	for _, in := range t.Inputs {
		refs[string(in.OutputRef)] = true
	}
	for _, o := range w.Outputs {
		if refs[string(o.Out.OneTimeKey)] {
			o.reserved = false
		}
	}
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func addCheck(a, b uint64) (uint64, bool) {
	s := a + b
	return s, s < a
}

// CreateAnonTransaction builds a SENDER-ANONYMOUS transaction sending `amount`
// to dest. The spent coin is hidden inside the canonical ring of the frozen
// anonymity pool `poolID`, whose ordered members are (poolKeys, poolCommits) —
// obtained from the chain's PoolMembers. The wallet must own one coin in the
// pool that covers amount+fee.
func (w *Wallet) CreateAnonTransaction(view ChainView, poolID uint64, poolKeys, poolCommits [][]byte, dest commit.StealthAddress, amount, fee uint64) (*tx.Transaction, error) {
	if w.IsViewOnly() {
		return nil, errors.New("wallet: view-only wallet cannot spend")
	}
	if amount == 0 {
		return nil, errors.New("wallet: amount must be positive")
	}
	ringSize := len(poolKeys)
	if ringSize < 2 || ringSize&(ringSize-1) != 0 || len(poolCommits) != ringSize {
		return nil, errors.New("wallet: pool size must be a power of two >= 2")
	}
	need, ovf := addCheck(amount, fee)
	if ovf {
		return nil, errors.New("wallet: amount+fee overflow")
	}

	// find the owned coin's index within the pool
	l := -1
	var owned *OwnedOutput
	for idx, rk := range poolKeys {
		for _, o := range w.Outputs {
			if o.Spent || o.reserved || o.Amount < need {
				continue
			}
			if string(o.Out.OneTimeKey) == string(rk) {
				l, owned = idx, o
				break
			}
		}
		if owned != nil {
			break
		}
	}
	if owned == nil {
		return nil, errors.New("wallet: no eligible owned coin in this pool")
	}

	// build edwards points for the proof (ownership ring = pool keys)
	ownRing := make([]*edwards25519.Point, ringSize)
	for i, rk := range poolKeys {
		p, err := new(edwards25519.Point).SetBytes(rk)
		if err != nil {
			return nil, err
		}
		ownRing[i] = p
	}

	// pseudo-commitment to the spent coin's value, and value opening d
	rp := commit.RandomScalar()
	pseudo := commit.Commit(owned.Amount, rp)
	d := new(edwards25519.Scalar).Subtract(owned.Mask, rp)
	tag := commit.KeyImage(owned.OneTime)

	// outputs: dest + change
	t := &tx.Transaction{Version: 1, Fee: fee}
	var outBlindings []*edwards25519.Scalar
	destOut, db, err := buildOutput(dest, amount, 0)
	if err != nil {
		return nil, err
	}
	t.Outputs = append(t.Outputs, destOut)
	outBlindings = append(outBlindings, db)
	change := owned.Amount - need
	if change > 0 {
		chOut, cb, err := buildOutput(w.keys.Addr, change, 0)
		if err != nil {
			return nil, err
		}
		t.Outputs = append(t.Outputs, chOut)
		outBlindings = append(outBlindings, cb)
	}

	// assemble the anon input WITHOUT the proof, so CoreHash is well-defined
	t.AnonInputs = []tx.AnonInput{{
		PoolID:           poolID,
		Tag:              tag.Bytes(),
		PseudoCommitment: pseudo.Bytes(),
	}}
	ctx := t.CoreHash()

	// valRing = poolCommits - pseudo ; build the joint proof
	valRing := make([]*edwards25519.Point, ringSize)
	cprime, _ := new(edwards25519.Point).SetBytes(pseudo.Bytes())
	for i, cb := range poolCommits {
		cp, err := new(edwards25519.Point).SetBytes(cb)
		if err != nil {
			return nil, err
		}
		valRing[i] = new(edwards25519.Point).Subtract(cp, cprime)
	}
	proof, _, err := commit.ProveAnonSpend(ownRing, valRing, l, owned.OneTime, d, ctx[:])
	if err != nil {
		return nil, err
	}
	t.AnonInputs[0].Proof = proof.Serialize()

	// conservation: z = rp − Σ out blindings
	z := new(edwards25519.Scalar).Set(rp)
	for _, s := range outBlindings {
		z.Subtract(z, s)
	}
	outs := make([][]byte, len(t.Outputs))
	for i, o := range t.Outputs {
		outs[i] = o.Commitment
	}
	cons, err := commit.ProveConservation([][]byte{pseudo.Bytes()}, outs, fee, z, ctx[:])
	if err != nil {
		return nil, err
	}
	t.Conservation = cons
	owned.reserved = true
	return t, nil
}

// FundSwap builds a transaction that locks `amount` OBX into an on-chain swap
// contract (SwapOut) with the given claim/refund keys and unlock height, paying
// from this wallet's outputs.
// The atomicity/rogue-key binding fields (claimA, claimB, popA, popB, claimR,
// claimT) are required by consensus (see pkg/swap and pkg/chain/validate.go):
// claimKey must equal claimA+claimB with a valid proof-of-possession for each
// share, and the claim signature is bound to the pre-signature nonce claimR and
// adaptor point claimT.
func (w *Wallet) FundSwap(view ChainView, swapKey []byte, amount uint64, claimKey, refundKey, claimA, claimB, popA, popB, claimR, claimT []byte, unlockHeight, fee uint64) (*tx.Transaction, error) {
	if w.IsViewOnly() {
		return nil, errors.New("wallet: view-only wallet cannot spend")
	}
	need, ovf := addCheck(amount, fee)
	if ovf {
		return nil, errors.New("wallet: amount+fee overflow")
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
		var ovf bool
		if total, ovf = addCheck(total, o.Amount); ovf { // audit: guard the input-sum like every other site
			return nil, errors.New("wallet: input sum overflow")
		}
		if total >= need {
			break
		}
	}
	if total < need {
		return nil, errors.New("wallet: insufficient spendable funds for swap")
	}

	t := &tx.Transaction{Version: 1, Fee: fee}
	t.SwapOutputs = []tx.SwapOut{{
		SwapKey: swapKey, Amount: amount, ClaimKey: claimKey, RefundKey: refundKey, UnlockHeight: unlockHeight,
		ClaimA: claimA, ClaimB: claimB, PoPA: popA, PoPB: popB, ClaimR: claimR, ClaimT: claimT,
	}}
	var outBlindings []*edwards25519.Scalar
	change := total - need
	if change > 0 {
		chOut, cb, err := buildOutput(w.keys.Addr, change, 0)
		if err != nil {
			return nil, err
		}
		t.Outputs = append(t.Outputs, chOut)
		outBlindings = append(outBlindings, cb)
	}
	var pseudoBlindings []*edwards25519.Scalar
	for _, o := range selected {
		pr := commit.RandomScalar()
		t.Inputs = append(t.Inputs, tx.Input{
			OutputRef:        append([]byte(nil), o.Out.OneTimeKey...),
			PseudoCommitment: commit.Commit(o.Amount, pr).Bytes(),
			KeyImage:         commit.KeyImage(o.OneTime).Bytes(),
		})
		pseudoBlindings = append(pseudoBlindings, pr)
	}
	ctx := t.CoreHash()
	for i, o := range selected {
		own, err := commit.ProveOwnership(o.Out.OneTimeKey, o.OneTime, ctx[:])
		if err != nil {
			return nil, err
		}
		d := new(edwards25519.Scalar).Subtract(pseudoBlindings[i], o.Mask)
		eq, err := commit.ProveValueEquality(t.Inputs[i].PseudoCommitment, o.Out.Commitment, d, ctx[:])
		if err != nil {
			return nil, err
		}
		t.Inputs[i].KeyImageProof = commit.ProveKeyImageProof(o.OneTime, ctx[:])
		t.Inputs[i].OwnershipProof = own
		t.Inputs[i].EqualityProof = eq
	}
	// conservation: Σ pseudoIns − Σ change − (fee+amount)·H == z·G
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
	outs := make([][]byte, len(t.Outputs))
	for i, o := range t.Outputs {
		outs[i] = o.Commitment
	}
	cons, err := commit.ProveConservationGen(pseudoIns, outs, 0, fee+amount, z, ctx[:])
	if err != nil {
		return nil, err
	}
	t.Conservation = cons
	for _, o := range selected {
		o.reserved = true
	}
	return t, nil
}

// BuildSwapSpend builds a claim (isRefund=false) or refund (true) spend of a
// swap contract, paying amount−fee to this wallet. `sign` produces the 64-byte
// signature over the tx CoreHash (the 2-of-2 adapted signature for a claim, or a
// plain Schnorr signature under the refund key for a refund).
func (w *Wallet) BuildSwapSpend(swapKey []byte, amount uint64, isRefund bool, fee uint64, sign func(coreHash []byte) []byte) (*tx.Transaction, error) {
	if fee >= amount {
		return nil, errors.New("wallet: fee >= swap amount")
	}
	t := &tx.Transaction{Version: 1, Fee: fee}
	out, rOut, err := buildOutput(w.keys.Addr, amount-fee, 0)
	if err != nil {
		return nil, err
	}
	t.Outputs = []tx.Output{out}
	t.SwapInputs = []tx.SwapIn{{SwapKey: swapKey, IsRefund: isRefund}}
	ctx := t.CoreHash()
	t.SwapInputs[0].Sig = sign(ctx[:])
	// conservation: amount·H − C_out − fee·H == z·G ; z = −rOut
	z := new(edwards25519.Scalar).Subtract(edwards25519.NewScalar(), rOut)
	cons, err := commit.ProveConservationGen(nil, [][]byte{out.Commitment}, amount, fee, z, ctx[:])
	if err != nil {
		return nil, err
	}
	t.Conservation = cons
	return t, nil
}

// BuildCoinbase constructs the coinbase paying `minted` to this wallet.
func (w *Wallet) BuildCoinbase(height, minted uint64, referrerTag []byte) (*tx.Transaction, error) {
	return BuildCoinbaseTo(w.keys.Addr, height, minted, referrerTag)
}

// BuildCoinbaseTo constructs a coinbase paying `minted` to an arbitrary stealth
// address (used by the node miner when mining to a specified address).
func BuildCoinbaseTo(dest commit.StealthAddress, height, minted uint64, referrerTag []byte) (*tx.Transaction, error) {
	t := &tx.Transaction{
		Version:     1,
		IsCoinbase:  true,
		Height:      height,
		Minted:      minted,
		ReferrerTag: referrerTag,
	}
	out, blinding, err := buildOutput(dest, minted, 0)
	if err != nil {
		return nil, err
	}
	t.Outputs = append(t.Outputs, out)

	// coinbase conservation: residual = minted·H − C_out = (−blinding)·G
	z := edwards25519.NewScalar().Subtract(edwards25519.NewScalar(), blinding)
	outs := [][]byte{out.Commitment}
	ctx := t.CoreHash()
	cons, err := commit.ProveCoinbaseConservation(minted, outs, z, ctx[:])
	if err != nil {
		return nil, err
	}
	t.Conservation = cons
	return t, nil
}
