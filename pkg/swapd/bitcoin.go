package swapd

import (
	"crypto/sha256"
	"errors"
)

// BitcoinClient is the Bitcoin-side capability a BTC↔OBX atomic swap needs. The
// BTC leg is a standard HTLC: funds are redeemable by the redeemer's key WITH the
// preimage of a SHA256 hashlock, or refundable by the funder after a CLTV
// timelock. The hashlock preimage is the OBX adaptor secret `t` (revealed when the
// OBX claim is published) — so no cross-curve cryptography is needed and Obscura
// consensus is unchanged. See docs/INVENTION_CROSSCHAIN_SWAPS.md.
//
// A production build implements this against bitcoind/Electrum using the P2WSH
// script from BtcHTLCScript. No mock backend ships; BTC is gated OFF in config.SettleableAssets until a real backend lands.
type BitcoinClient interface {
	// FundHTLC locks `amountSat` into an HTLC with hashlock `hash` (= SHA256(t)),
	// redeemable by `redeemPub` (with the preimage) or refundable by `refundPub`
	// at/after block height `locktime`. Returns a lock id.
	FundHTLC(amountSat uint64, hash, redeemPub, refundPub []byte, locktime uint32) (lockID string, err error)
	// Confirmed reports whether the HTLC funding has enough confirmations to be
	// safe against reorgs.
	Confirmed(lockID string) bool
	// Redeem spends the HTLC via the hashlock path: requires SHA256(preimage)==hash
	// and a signature under redeemPub. Publishing it reveals the preimage on-chain.
	Redeem(lockID string, preimage, redeemPub []byte, dest string) error
	// Refund spends the HTLC via the timelock path: only at/after locktime, with a
	// signature under refundPub.
	Refund(lockID string, refundPub []byte, dest string) error
	// RevealedPreimage returns the preimage exposed by a completed Redeem (so the
	// counterparty can learn `t` from the Bitcoin chain if it is revealed there).
	RevealedPreimage(lockID string) ([]byte, bool)
	// Balance returns funds credited to a destination (for tests).
	Balance(dest string) uint64
}

// Bitcoin script opcodes used by the HTLC.
const (
	opIF                 = 0x63
	opELSE               = 0x67
	opENDIF              = 0x68
	opDROP               = 0x75
	opEQUALVERIFY        = 0x88
	opSHA256             = 0xa8
	opCHECKSIG           = 0xac
	opCHECKLOCKTIMEVERIFY = 0xb1
)

// BtcHTLCScript builds the standard atomic-swap HTLC redeem script:
//
//	OP_IF
//	  OP_SHA256 <hash> OP_EQUALVERIFY <redeemPub> OP_CHECKSIG
//	OP_ELSE
//	  <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <refundPub> OP_CHECKSIG
//	OP_ENDIF
//
// The P2WSH commitment is SHA256(script); fund the swap by paying that witness
// program. hash must be 32 bytes; pubkeys 33-byte compressed secp256k1.
func BtcHTLCScript(hash, redeemPub, refundPub []byte, locktime uint32) ([]byte, error) {
	if len(hash) != 32 {
		return nil, errors.New("swapd: htlc hash must be 32 bytes")
	}
	if len(redeemPub) != 33 || len(refundPub) != 33 {
		return nil, errors.New("swapd: pubkeys must be 33-byte compressed")
	}
	var s []byte
	s = append(s, opIF)
	s = append(s, opSHA256)
	s = append(s, pushData(hash)...)
	s = append(s, opEQUALVERIFY)
	s = append(s, pushData(redeemPub)...)
	s = append(s, opCHECKSIG)
	s = append(s, opELSE)
	s = append(s, pushData(scriptNum(int64(locktime)))...)
	s = append(s, opCHECKLOCKTIMEVERIFY)
	s = append(s, opDROP)
	s = append(s, pushData(refundPub)...)
	s = append(s, opCHECKSIG)
	s = append(s, opENDIF)
	return s, nil
}

// BtcWitnessProgram returns SHA256(script) — the 32-byte P2WSH witness program a
// funder pays to (bech32-encoded as a bc1.../tb1... address by the live adapter).
func BtcWitnessProgram(script []byte) []byte {
	h := sha256.Sum256(script)
	return h[:]
}

// pushData encodes a canonical minimal push of b (lengths used here are < 76).
func pushData(b []byte) []byte {
	if len(b) < 0x4c {
		return append([]byte{byte(len(b))}, b...)
	}
	// not needed for our 32/33-byte pushes, but keep it correct for small scriptNums
	return append([]byte{0x4c, byte(len(b))}, b...)
}

// scriptNum encodes n as a minimal, little-endian, sign-magnitude CScriptNum
// (used for the CLTV locktime push). n is non-negative here.
func scriptNum(n int64) []byte {
	if n == 0 {
		return nil
	}
	var out []byte
	for n > 0 {
		out = append(out, byte(n&0xff))
		n >>= 8
	}
	// if the most-significant byte has its high bit set, append 0x00 so it is not
	// read as negative.
	if out[len(out)-1]&0x80 != 0 {
		out = append(out, 0x00)
	}
	return out
}

// HashPreimage returns the HTLC hashlock for a preimage: SHA256(preimage). The
// preimage is the 32-byte encoding of the OBX adaptor secret `t`.
func HashPreimage(preimage []byte) []byte {
	h := sha256.Sum256(preimage)
	return h[:]
}
