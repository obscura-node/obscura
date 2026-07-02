package commit

import (
	"errors"

	"filippo.io/edwards25519"
)

// Payment proofs (Block 27 — see docs/INVENTION_TXPROOF.md). A recipient can prove
// to a third party that a specific on-chain stealth output was a payment to their
// address (and reveal its amount) WITHOUT revealing their view/spend keys and
// WITHOUT linking any of their other outputs.
//
// How: the recipient publishes the ECDH shared point D = a·R (a = view secret,
// R = output's tx pubkey) together with a Chaum-Pedersen DLEQ proving that the
// SAME secret `a` satisfies both A = a·G (their published view key) and D = a·R.
// Given D, anyone can recompute the one-time key Hs(D)·G + B and confirm it equals
// the output's P, and can decrypt the output's amount. D reveals nothing about a.

const paymentProofDom = "Obscura/payment-proof"

// PaymentProof is a receipt proof for one stealth output.
type PaymentProof struct {
	D     *edwards25519.Point // shared point a·R == r·A
	Proof DLEQProof
}

// proveReceipt builds a receipt proof from the recipient's view secret a, their
// address view point A (= a·G), and the output's tx pubkey R. The encrypted
// amount is bound into the proof (authenticated), so the proven amount cannot be
// altered after the fact.
func proveReceipt(a *edwards25519.Scalar, out *StealthOutput, encAmount []byte) PaymentProof {
	// p1 = a·G = A, p2 = a·R = D
	_, d, proof := ProveDLEQ(a, BasePoint, out.R, paymentProofDom, encAmount)
	return PaymentProof{D: d, Proof: proof}
}

// ProveReceipt produces a payment (receipt) proof for an output this keypair
// owns, binding the output's encrypted amount. It does not check ownership;
// callers should only call it for owned outputs (a non-owned output yields a
// proof that fails verification).
func (k *StealthKeys) ProveReceipt(out *StealthOutput, encAmount []byte) PaymentProof {
	return proveReceipt(k.a, out, encAmount)
}

// ProveSpend builds a SENDER (out) proof: the payer, who knows the per-output tx
// secret r (with R = r·G), proves the output was a payment to `addr` by showing
// D = r·A and a DLEQ that the same r satisfies R = r·G and D = r·A, binding the
// encrypted amount. Symmetric to ProveReceipt and verified by the same VerifyPayment.
func ProveSpend(r *edwards25519.Scalar, addr StealthAddress, encAmount []byte) PaymentProof {
	// p1 = r·G = R, p2 = r·A = D
	_, d, proof := ProveDLEQ(r, BasePoint, addr.A, paymentProofDom, encAmount)
	return PaymentProof{D: d, Proof: proof}
}

// VerifyPayment checks a payment proof: that `addr` is the recipient of output
// `out`, and returns the output's decrypted amount. encAmount is the output's
// on-chain encrypted amount field. It accepts BOTH a recipient (in) proof and a
// sender (out) proof — either party can attest the same fact.
func VerifyPayment(addr StealthAddress, out *StealthOutput, encAmount []byte, pp PaymentProof) (uint64, bool) {
	if pp.D == nil {
		return 0, false
	}
	// Recipient orientation: A = a·G and D = a·R share secret a (view key).
	// Sender orientation:    R = r·G and D = r·A share secret r (tx key).
	// encAmount is bound into the proof, so a tampered amount fails verification.
	recipientOK := VerifyDLEQ(BasePoint, addr.A, out.R, pp.D, pp.Proof, paymentProofDom, encAmount)
	senderOK := VerifyDLEQ(BasePoint, out.R, addr.A, pp.D, pp.Proof, paymentProofDom, encAmount)
	if !recipientOK && !senderOK {
		return 0, false
	}
	// The shared point must reconstruct the output's one-time key for (A,B).
	hs := HashToScalar([]byte("Obscura/stealth"), pp.D.Bytes())
	expected := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(hs), addr.B)
	if expected.Equal(out.P) != 1 {
		return 0, false
	}
	return DecryptAmount(pp.D.Bytes(), encAmount), true
}

// Serialize encodes a payment proof as 96 bytes (D || C || S).
func (pp PaymentProof) Serialize() []byte {
	out := make([]byte, 0, 96)
	out = append(out, pp.D.Bytes()...)
	out = append(out, pp.Proof.Serialize()...)
	return out
}

// ReceiptBundle is a self-contained, node-free payment proof: it carries the
// on-chain output data a verifier needs (one-time key P, tx pubkey R, encrypted
// amount) plus the receipt proof. A verifier needs only this bundle and the
// claimed address.
type ReceiptBundle struct {
	Out       *StealthOutput
	EncAmount []byte // 8 bytes
	Proof     PaymentProof
}

// Serialize encodes a bundle as 168 bytes: P(32) R(32) encAmount(8) D(32) C(32) S(32).
func (rb ReceiptBundle) Serialize() []byte {
	out := make([]byte, 0, 168)
	out = append(out, rb.Out.P.Bytes()...)
	out = append(out, rb.Out.R.Bytes()...)
	enc := rb.EncAmount
	if len(enc) != 8 {
		enc = make([]byte, 8)
	}
	out = append(out, enc...)
	out = append(out, rb.Proof.Serialize()...)
	return out
}

// ParseReceiptBundle decodes a 168-byte bundle.
func ParseReceiptBundle(b []byte) (ReceiptBundle, error) {
	if len(b) != 168 {
		return ReceiptBundle{}, errors.New("txproof: receipt bundle must be 168 bytes")
	}
	P, err := new(edwards25519.Point).SetBytes(b[:32])
	if err != nil {
		return ReceiptBundle{}, err
	}
	R, err := new(edwards25519.Point).SetBytes(b[32:64])
	if err != nil {
		return ReceiptBundle{}, err
	}
	enc := append([]byte(nil), b[64:72]...)
	pp, err := ParsePaymentProof(b[72:])
	if err != nil {
		return ReceiptBundle{}, err
	}
	return ReceiptBundle{Out: &StealthOutput{P: P, R: R}, EncAmount: enc, Proof: pp}, nil
}

// VerifyBundle verifies a receipt bundle against a claimed recipient address,
// returning the proven amount.
func VerifyBundle(addr StealthAddress, rb ReceiptBundle) (uint64, bool) {
	return VerifyPayment(addr, rb.Out, rb.EncAmount, rb.Proof)
}

// ParsePaymentProof decodes a 96-byte payment proof.
func ParsePaymentProof(b []byte) (PaymentProof, error) {
	if len(b) != 96 {
		return PaymentProof{}, errors.New("txproof: payment proof must be 96 bytes")
	}
	d, err := new(edwards25519.Point).SetBytes(b[:32])
	if err != nil {
		return PaymentProof{}, err
	}
	pr, err := ParseDLEQ(b[32:])
	if err != nil {
		return PaymentProof{}, err
	}
	return PaymentProof{D: d, Proof: pr}, nil
}
