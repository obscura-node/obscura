//go:build pq

package pqtx

import (
	"errors"

	"golang.org/x/crypto/blake2b"

	"obscura/pkg/pqcommit"
	"obscura/pkg/pqsign"
	"obscura/pkg/pqstealth"
)

// Account is a minimal PQ wallet: a stealth view key for detecting/decrypting
// payments plus a set of owned one-time hybrid keypairs (spend authority).
type Account struct {
	view  *pqstealth.ViewKey
	owned map[string]*pqsign.HybridPriv // keyed by hybrid one-time key (hex of Key)
	pubs  map[string]*pqsign.HybridPub
}

// NewAccount creates a fresh PQ account.
func NewAccount() (*Account, error) {
	v, err := pqstealth.GenerateViewKey()
	if err != nil {
		return nil, err
	}
	return &Account{view: v, owned: map[string]*pqsign.HybridPriv{}, pubs: map[string]*pqsign.HybridPub{}}, nil
}

// StealthPub is the public ML-KEM key a payer encapsulates to.
func (a *Account) StealthPub() []byte { return a.view.PublicKey() }

// NewReceiveKey mints a fresh one-time hybrid keypair to hand to a payer (the
// payer puts its Key in the output's OneTimeKey). The secret is retained so the
// account can later spend the received output.
func (a *Account) NewReceiveKey() (*pqsign.HybridPub, error) {
	priv, pub, err := pqsign.GenerateHybrid()
	if err != nil {
		return nil, err
	}
	a.owned[hexKey(pub.Key)] = priv
	a.pubs[hexKey(pub.Key)] = pub
	return pub, nil
}

// randFromSS deterministically expands a shared secret into a short randomness
// vector for pqcommit, so the commitment blinding need not be transmitted: the
// payer derives it from the KEM shared secret and the recipient re-derives the
// same value after decapsulation.
func randFromSS(ss []byte) []int32 {
	xof, _ := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	xof.Write([]byte("Obscura/pq/commit-rand/v1"))
	xof.Write(ss)
	r := make([]int32, pqcommit.RandLen)
	buf := make([]byte, 4)
	for i := range r {
		xof.Read(buf)
		v := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
		r[i] = int32(v%(2*pqcommit.RandB+1)) - pqcommit.RandB
	}
	return r
}

// BuildOutput (payer side) creates a PQ output paying `amount` to a recipient
// identified by their stealth public key and a fresh hybrid public key. It
// returns the output and the KEM shared secret (which also seeded the commitment
// blinding). Amount must be < pqcommit.Q (single-limb demo).
func BuildOutput(recipientStealthPub []byte, recipientHybrid *pqsign.HybridPub, amount uint64) (*PQOutput, []byte, error) {
	ann, ss, err := pqstealth.Send(recipientStealthPub, amount)
	if err != nil {
		return nil, nil, err
	}
	c, err := pqcommit.Commit(amount, randFromSS(ss))
	if err != nil {
		return nil, nil, err
	}
	out := &PQOutput{
		Version:       Version,
		OneTimeKey:    append([]byte(nil), recipientHybrid.Key...),
		Commitment:    c.Bytes(),
		KEMCiphertext: ann.KEMCiphertext,
		ViewTag:       ann.Tag,
		EncAmount:     ann.EncAmount,
		MAC:           ann.MAC,
	}
	return out, ss, nil
}

// Detected describes an output the account recognizes as its own.
type Detected struct {
	Out    *PQOutput
	Amount uint64
	SS     []byte             // KEM shared secret (re-derives the commitment blinding)
	Priv   *pqsign.HybridPriv // spend authority for this output
	Pub    *pqsign.HybridPub
}

// Scan checks whether an output belongs to this account (stealth detection) AND
// whether the account holds its spend key. ok is true only if both hold.
func (a *Account) Scan(o *PQOutput) (*Detected, bool) {
	if o == nil || o.Version != Version {
		return nil, false
	}
	amount, ss, ok := a.view.Scan(o.announcement())
	if !ok {
		return nil, false
	}
	priv, owns := a.owned[hexKey(o.OneTimeKey)]
	if !owns {
		return nil, false
	}
	return &Detected{Out: o, Amount: amount, SS: ss, Priv: priv, Pub: a.pubs[hexKey(o.OneTimeKey)]}, true
}

// Payment is a spend destination.
type Payment struct {
	StealthPub []byte
	Hybrid     *pqsign.HybridPub
	Amount     uint64
}

// BuildSpend (owner side) spends a detected output, creating new outputs to the
// given payments. It mirrors the classical buildSpend ordering: the nullifier is
// set pre-CoreHash (bound), then the HybridSig is produced over CoreHash. It
// computes the aggregate blinding difference so the ledger can check value
// conservation. Requires Σ payment amounts + fee == input amount.
func BuildSpend(in *Detected, payments []Payment, fee uint64) (*PQSpend, error) {
	if in == nil || in.Priv == nil {
		return nil, errors.New("pqtx: not owned / no spend key")
	}
	var outSum uint64
	for _, p := range payments {
		outSum += p.Amount
	}
	if outSum+fee != in.Amount {
		return nil, errors.New("pqtx: value does not balance")
	}

	rIn := randFromSS(in.SS)
	// d = r_in − Σ r_out (aggregate blinding difference for conservation)
	d := make([]int32, pqcommit.RandLen)
	copy(d, rIn)

	outs := make([]PQOutput, 0, len(payments))
	for _, p := range payments {
		o, ss, err := BuildOutput(p.StealthPub, p.Hybrid, p.Amount)
		if err != nil {
			return nil, err
		}
		rOut := randFromSS(ss)
		for i := range d {
			d[i] -= rOut[i]
		}
		outs = append(outs, *o)
	}

	s := &PQSpend{
		Version:   Version,
		OutputRef: append([]byte(nil), in.Out.OneTimeKey...),
		P:         append([]byte(nil), in.Pub.P...),
		WotsRoot:  append([]byte(nil), in.Pub.R...),
		Nullifier: NullifierOf(in.Pub.R),
		Outputs:   outs,
		Fee:       fee,
		BlindDiff: d,
	}
	// Sign the CoreHash with the hybrid one-time key (classical ⊕ WOTS+).
	sig, err := pqsign.HybridSign(in.Priv, in.Pub, s.CoreHash())
	if err != nil {
		return nil, err
	}
	s.HybridSig = serializeHybridSig(sig)
	return s, nil
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
