package wallet

import (
	cryptorand "crypto/rand"
	"errors"
	"math/big"

	"filippo.io/edwards25519"

	"obscura/pkg/commit"
	"obscura/pkg/config"
	"obscura/pkg/tx"
)

// audit: ROUND2 [106] vaultKeyDomain separates per-vault owner-key derivation
// from every other seed-derived key (stealth keys, maker key, XNO funding key).

// VaultKey is a staking-vault owner keypair: the public key authorizes claims by
// signing the tx CoreHash (Schnorr, verified by commit.VerifyFull). It is
// independent of the OBX stealth keys.
type VaultKey struct {
	x   *edwards25519.Scalar
	Pub []byte
}

// NewVaultKey generates a fresh vault owner keypair.
func NewVaultKey() *VaultKey {
	x := commit.RandomScalar()
	p := new(edwards25519.Point).ScalarBaseMult(x)
	return &VaultKey{x: x, Pub: p.Bytes()}
}

// DeriveVaultKey deterministically derives a wallet's vault owner keypair from
// its seed AND a per-vault identifier, so a (e.g. web/WASM) wallet can always
// reconstruct the key needed to claim a vault from the seed plus that id alone —
// no separate secret to back up.
//
// audit: ROUND2 [106] (HIGH, privacy) — the old DeriveVaultKey(seed) returned ONE
// fixed keypair per wallet, reused as the plaintext OwnerKey on EVERY VaultOut.
// Since OwnerKey is on-chain forever, an observer could cluster all of a wallet's
// vaults by that identical pubkey, and one deanonymized deposit deanonymized them
// all. Mixing the per-vault `id` in yields a FRESH, unlinkable owner pubkey for
// every vault while staying deterministically reproducible. The id used at deposit
// MUST be the id replayed at claim (see BuildVaultDepositForSeed / the WASM claim
// path) or the vault becomes unspendable; we key on the 32-byte vaultID itself,
// which the wallet already persists and replays to claim.
func DeriveVaultKey(seed, id []byte) *VaultKey {
	x := commit.HashToScalar([]byte("Obscura/vault-key/v1"), seed, id)
	p := new(edwards25519.Point).ScalarBaseMult(x)
	return &VaultKey{x: x, Pub: p.Bytes()}
}

// Sign produces the claim authorization over a tx CoreHash.
func (k *VaultKey) Sign(coreHash []byte) []byte { return commit.Sign(k.x, coreHash).Serialize() }

// VaultYield computes principal·rate(term)/10_000 (overflow-safe). ok=false if the
// term is not an allowed term.
func VaultYield(principal, term uint64) (uint64, bool) {
	bps, ok := config.VaultRateBps(term)
	if !ok {
		return 0, false
	}
	y := new(big.Int).Mul(new(big.Int).SetUint64(principal), new(big.Int).SetUint64(bps))
	y.Div(y, big.NewInt(10_000))
	if !y.IsUint64() {
		return 0, false
	}
	return y.Uint64(), true
}

// BuildVaultDeposit locks `amount` OBX into a vault for `term` blocks, claimable
// later by `ownerPub`. The locked amount is a public-OUT leg (like a swap lock);
// the fee + amount are paid from confidential inputs, with change returned.
// Returns the tx and the freshly-generated 32-byte vault id.
//
// The caller is responsible for choosing/holding the matching owner secret. For a
// seed-only (web/WASM) wallet prefer BuildVaultDepositForSeed, which derives an
// UNLINKABLE per-vault owner key (audit: ROUND2 [106]).
func (w *Wallet) BuildVaultDeposit(view ChainView, ownerPub []byte, amount, term, fee uint64) (*tx.Transaction, []byte, error) {
	vaultID := make([]byte, 32)
	if _, err := cryptorand.Read(vaultID); err != nil {
		return nil, nil, err
	}
	t, err := w.buildVaultDepositWithID(view, ownerPub, vaultID, amount, term, fee)
	if err != nil {
		return nil, nil, err
	}
	return t, vaultID, nil
}

// BuildVaultDepositForSeed is the production (seed-only) deposit path: it generates
// the per-vault id FIRST, derives a FRESH owner key bound to that id, and locks the
// deposit to it. The returned vault id is the SAME id the owner key is derived from,
// so replaying it through DeriveVaultKey(seed, vaultID) at claim time reproduces the
// exact key (round-trip proven in TestDeriveVaultKeyPerVaultUnlinkableRoundTrip).
//
// audit: ROUND2 [106] — keying on the random per-vault id (vs one fixed seed key)
// makes every vault's on-chain OwnerKey distinct and unlinkable.
func (w *Wallet) BuildVaultDepositForSeed(view ChainView, seed []byte, amount, term, fee uint64) (*tx.Transaction, []byte, error) {
	vaultID := make([]byte, 32)
	if _, err := cryptorand.Read(vaultID); err != nil {
		return nil, nil, err
	}
	owner := DeriveVaultKey(seed, vaultID)
	t, err := w.buildVaultDepositWithID(view, owner.Pub, vaultID, amount, term, fee)
	if err != nil {
		return nil, nil, err
	}
	return t, vaultID, nil
}

// buildVaultDepositWithID builds a vault deposit with a caller-supplied 32-byte
// vault id (so the id can be chosen BEFORE the owner key is derived from it).
func (w *Wallet) buildVaultDepositWithID(view ChainView, ownerPub, vaultID []byte, amount, term, fee uint64) (*tx.Transaction, error) {
	if w.IsViewOnly() {
		return nil, errors.New("wallet: view-only wallet cannot spend")
	}
	if len(ownerPub) != 32 {
		return nil, errors.New("wallet: vault owner key must be 32 bytes")
	}
	if len(vaultID) != 32 {
		return nil, errors.New("wallet: vault id must be 32 bytes")
	}
	if _, ok := config.VaultRateBps(term); !ok {
		return nil, errors.New("wallet: invalid vault term")
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
		if total, ovf = addCheck(total, o.Amount); ovf { // audit: guard the input-sum
			return nil, errors.New("wallet: input sum overflow")
		}
		if total >= need {
			break
		}
	}
	if total < need {
		return nil, errors.New("wallet: insufficient spendable funds for vault")
	}

	t := &tx.Transaction{Version: 1, Fee: fee}
	t.VaultOutputs = []tx.VaultOut{{
		VaultKey: vaultID, Amount: amount, Term: term, OwnerKey: append([]byte(nil), ownerPub...),
	}}
	var outBlindings []*edwards25519.Scalar
	if change := total - need; change > 0 {
		ch, cb, err := buildOutput(w.keys.Addr, change, 0)
		if err != nil {
			return nil, err
		}
		t.Outputs = append(t.Outputs, ch)
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

// BuildVaultClaim claims a matured vault, paying principal + yield (minus fee) to
// this wallet as a fresh confidential output. The principal + yield re-enter as a
// public-IN leg. Authorized by the vault key. Modeled on BuildSwapSpend.
// For a FLEXIBLE vault (term == 0) the yield is pro-rata over (claimHeight −
// depositHeight); claimHeight should be the current chain tip — consensus accepts
// any later inclusion height since it only CAPS the stated yield. For a fixed-term
// vault the heights are ignored and the full snapshotted rate is paid.
func (w *Wallet) BuildVaultClaim(key *VaultKey, vaultID []byte, principal, term, fee, depositHeight, claimHeight uint64) (*tx.Transaction, error) {
	if w.IsViewOnly() {
		return nil, errors.New("wallet: view-only wallet cannot receive claim proceeds")
	}
	if len(vaultID) != 32 {
		return nil, errors.New("wallet: bad vault id")
	}
	var yield uint64
	if term == 0 {
		var elapsed uint64
		if claimHeight > depositHeight {
			elapsed = claimHeight - depositHeight
		}
		yield = config.VaultFlexYield(principal, elapsed)
	} else {
		var ok bool
		if yield, ok = VaultYield(principal, term); !ok {
			return nil, errors.New("wallet: invalid vault term")
		}
	}
	total, ovf := addCheck(principal, yield)
	if ovf {
		return nil, errors.New("wallet: principal+yield overflow")
	}
	if fee >= total {
		return nil, errors.New("wallet: fee >= claim proceeds")
	}
	out, rOut, err := buildOutput(w.keys.Addr, total-fee, 0)
	if err != nil {
		return nil, err
	}
	t := &tx.Transaction{Version: 1, Fee: fee, Outputs: []tx.Output{out}}
	t.VaultInputs = []tx.VaultIn{{VaultKey: append([]byte(nil), vaultID...), Yield: yield}}
	ctx := t.CoreHash()
	t.VaultInputs[0].Sig = key.Sign(ctx[:])
	// (principal+yield)·H − C_out − fee·H == z·G ; z = −rOut
	z := new(edwards25519.Scalar).Subtract(edwards25519.NewScalar(), rOut)
	cons, err := commit.ProveConservationGen(nil, [][]byte{out.Commitment}, total, fee, z, ctx[:])
	if err != nil {
		return nil, err
	}
	t.Conservation = cons
	return t, nil
}
