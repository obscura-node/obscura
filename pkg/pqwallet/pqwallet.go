// Package pqwallet builds post-quantum (Version-2) Obscura transactions using
// the real pkg/tx wire types, so they flow through the genuine pkg/chain
// validation and apply path. It is the wallet side of the PQ variant promoted
// into the consensus engine (the chain side lives in pkg/chain/pqvalidate.go).
//
// The consensus PQ value layer uses PUBLIC amounts (sound; see pqvalidate.go):
// recipient privacy and spend authority are post-quantum, the amount is public
// pending the confidential range proof. This wallet therefore detects payments
// by ML-KEM tag (pqstealth), holds one-time hybrid keys (pqsign) for spend
// authority, and builds spends that conserve value over public amounts.
// See docs/POST_QUANTUM_ROADMAP.md.
package pqwallet

import (
	"errors"

	"golang.org/x/crypto/blake2b"

	"obscura/pkg/pqsign"
	"obscura/pkg/pqstealth"
	"obscura/pkg/tx"
)

const nullDom = "Obscura/pq/nullifier/v1"

// NullifierOf must match pkg/chain's pqNullifierOf: it binds to the full output
// key (BLAKE2b(P‖R)), not just R, so two outputs sharing a WOTS root do not
// collide on one nullifier.
func NullifierOf(outputKey []byte) []byte {
	d, _ := blake2b.New256(nil)
	d.Write([]byte(nullDom))
	d.Write(outputKey)
	return d.Sum(nil)
}

// Account is a minimal PQ wallet.
type Account struct {
	view  *pqstealth.ViewKey
	owned map[string]*pqsign.HybridPriv
	pubs  map[string]*pqsign.HybridPub
	// used burns spent one-time WOTS+ keys (by committed Key = H(P‖R)).
	// AUDIT FIX: WOTS+ is a ONE-time signature — producing a second signature
	// under the same seed leaks the secret. We refuse to ever sign twice under
	// the same one-time key. See docs/POST_QUANTUM_ROADMAP.md.
	used map[string]bool
}

// NewAccount creates a fresh PQ account.
func NewAccount() (*Account, error) {
	v, err := pqstealth.GenerateViewKey()
	if err != nil {
		return nil, err
	}
	return &Account{
		view:  v,
		owned: map[string]*pqsign.HybridPriv{},
		pubs:  map[string]*pqsign.HybridPub{},
		used:  map[string]bool{},
	}, nil
}

// StealthPub is the ML-KEM public key a payer encapsulates to.
func (a *Account) StealthPub() []byte { return a.view.PublicKey() }

// NewReceiveKey mints a one-time hybrid keypair for a payer to address.
func (a *Account) NewReceiveKey() (*pqsign.HybridPub, error) {
	priv, pub, err := pqsign.GenerateHybrid()
	if err != nil {
		return nil, err
	}
	a.owned[hexKey(pub.Key)] = priv
	a.pubs[hexKey(pub.Key)] = pub
	return pub, nil
}

// BuildOutput (payer side) creates a tx.PQOutput paying `amount` (public) to a
// recipient, with an ML-KEM stealth tag so only the recipient detects it.
func BuildOutput(recipientStealthPub []byte, recipientHybrid *pqsign.HybridPub, amount uint64) (tx.PQOutput, error) {
	ann, _, err := pqstealth.Send(recipientStealthPub, amount)
	if err != nil {
		return tx.PQOutput{}, err
	}
	return tx.PQOutput{
		OneTimeKey:    append([]byte(nil), recipientHybrid.Key...),
		Amount:        amount,
		KEMCiphertext: ann.KEMCiphertext,
		ViewTag:       ann.Tag,
	}, nil
}

// Detected is an owned output.
type Detected struct {
	Out    tx.PQOutput
	Amount uint64
	Priv   *pqsign.HybridPriv
	Pub    *pqsign.HybridPub
	// acct is the wallet that detected this output. It owns the burn set of
	// spent one-time WOTS+ keys so BuildSpendTx can refuse OTS key reuse.
	acct *Account
}

// Scan detects an output (by stealth tag) and, if owned, returns its spend key.
func (a *Account) Scan(o *tx.PQOutput) (*Detected, bool) {
	if o == nil {
		return nil, false
	}
	if _, ok := a.view.DetectTag(o.KEMCiphertext, o.ViewTag); !ok {
		return nil, false
	}
	priv, owns := a.owned[hexKey(o.OneTimeKey)]
	if !owns {
		return nil, false
	}
	return &Detected{Out: *o, Amount: o.Amount, Priv: priv, Pub: a.pubs[hexKey(o.OneTimeKey)], acct: a}, true
}

// Payment is a spend destination.
type Payment struct {
	StealthPub []byte
	Hybrid     *pqsign.HybridPub
	Amount     uint64
}

// BuildSpendTx builds a Version-2 PQ transaction spending `in` to the payments,
// paying `fee` (public, burned). Requires Σ payment amounts + fee == in.Amount.
// `anchor` is the PQ root the `membership` proof targets (from chain.PQRoot /
// chain.PQProve).
func BuildSpendTx(in *Detected, payments []Payment, fee uint64, anchor, membership []byte) (*tx.Transaction, error) {
	if in == nil || in.Priv == nil || in.Pub == nil {
		return nil, errors.New("pqwallet: not owned / no spend key")
	}
	// AUDIT FIX: WOTS+ is a one-time signature. Signing a second message under
	// the same seed leaks the WOTS+ secret. Refuse to re-sign a one-time key
	// that this wallet has already spent (identified by the committed key
	// H(P‖R)); the key must be burned after its single use.
	keyID := hexKey(in.Pub.Key)
	if in.acct != nil && in.acct.used[keyID] {
		return nil, errors.New("pqwallet: one-time key already spent (WOTS+ reuse forbidden)")
	}
	var outSum uint64
	for _, p := range payments {
		outSum += p.Amount
	}
	if outSum+fee != in.Amount {
		return nil, errors.New("pqwallet: value does not balance")
	}

	outs := make([]tx.PQOutput, 0, len(payments))
	for _, p := range payments {
		o, err := BuildOutput(p.StealthPub, p.Hybrid, p.Amount)
		if err != nil {
			return nil, err
		}
		outs = append(outs, o)
	}

	t := &tx.Transaction{
		Version: 2,
		Fee:     fee,
		PQInputs: []tx.PQInput{{
			OutputRef:  append([]byte(nil), in.Out.OneTimeKey...),
			P:          append([]byte(nil), in.Pub.P...),
			WotsRoot:   append([]byte(nil), in.Pub.R...),
			Nullifier:  NullifierOf(in.Out.OneTimeKey),
			Anchor:     append([]byte(nil), anchor...),
			Membership: membership,
		}},
		PQOutputs: outs,
	}
	ctx := t.CoreHash()
	sig, err := pqsign.HybridSign(in.Priv, in.Pub, ctx[:])
	if err != nil {
		return nil, err
	}
	t.PQInputs[0].HybridSig = marshalHybridSig(sig)
	// AUDIT FIX: burn the one-time key now that it has produced its single
	// WOTS+ signature; any subsequent BuildSpendTx on it must fail.
	if in.acct != nil {
		in.acct.used[keyID] = true
	}
	return t, nil
}

func marshalHybridSig(sig *pqsign.HybridSig) []byte {
	var out []byte
	var l [4]byte
	be32(l[:], uint32(len(sig.Schnorr)))
	out = append(out, l[:]...)
	out = append(out, sig.Schnorr...)
	be32(l[:], uint32(len(sig.Wots)))
	out = append(out, l[:]...)
	out = append(out, sig.Wots...)
	return out
}

func be32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func hexKey(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexd[v>>4]
		out[i*2+1] = hexd[v&0x0f]
	}
	return string(out)
}
