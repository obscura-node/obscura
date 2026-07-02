package swapsession

import (
	"crypto/sha512"
	"encoding/json"
	"errors"
	"math/big"
	"os"
)

// Role identifies which side of the swap a party plays.
type Role string

const (
	// RoleMaker is the OBX-side funder. It holds shares b + sB, funds the OBX
	// SwapOut FIRST, and (after the taker locks XNO) claims the OBX — revealing
	// sA — then sweeps the XNO with the recovered sA+sB. Its downside risk (the
	// locked OBX) is protected by the SwapOutput's on-chain refund timelock.
	RoleMaker Role = "maker"
	// RoleTaker is the XNO-side funder. It holds shares a + sA, and locks XNO to
	// the joint account ONLY AFTER it has verified the OBX SwapOut is on-chain at
	// the agreed amount/key/timelock. It is protected by that sequencing.
	RoleTaker Role = "taker"
)

// Phase tracks how far a session has progressed, so a crashed party can resume
// or refund from a persisted SwapState.
type Phase string

const (
	PhaseInit     Phase = "init"     // shares exchanged, nothing on-chain yet
	PhaseFunded   Phase = "funded"   // OBX SwapOut funded+confirmed
	PhaseXNOLock  Phase = "xno_lock" // XNO locked to the joint account
	PhaseClaimed  Phase = "claimed"  // OBX claim mined (sA revealed on-chain)
	PhaseSwept    Phase = "swept"    // XNO swept — swap complete
	PhaseRefunded Phase = "refunded" // aborted: OBX reclaimed via the refund branch
)

// SwapState is the minimal serializable record a party needs to RESUME a swap
// after a crash, or to drive a standalone REFUND. It deliberately holds ONLY the
// party's OWN private share (never the peer's), plus the peer's PUBLIC material.
//
// SECURITY: OwnShareClaim (a or b) and OwnShareXNO (sA or sB) are the party's
// secret halves — a SwapState file is therefore as sensitive as a wallet key and
// must be stored protected. Crucially, a maker's state never contains a/sA and a
// taker's never contains b/sB, so a single compromised file cannot reconstruct
// either joint key alone (that is the whole point of fix #2).
type SwapState struct {
	SwapID [32]byte `json:"swap_id"`
	Role   Role     `json:"role"`
	Phase  Phase    `json:"phase"`

	// Own private shares (32B scalar encodings). For a maker these are b, sB; for
	// a taker they are a, sA. The OTHER party's shares are NEVER stored here.
	OwnShareClaim []byte `json:"own_share_claim"`
	OwnShareXNO   []byte `json:"own_share_xno"`

	// Peer + agreed PUBLIC material (all derivable joint keys come from these).
	PeerClaimShare []byte `json:"peer_claim_share"` // B (if maker stores...) — peer's A or B
	PeerXNOShare   []byte `json:"peer_xno_share"`   // peer's Sa or Sb
	OwnNonceR      []byte `json:"own_nonce_r"`      // own ra·G or rb·G (committed)
	PeerNonceR     []byte `json:"peer_nonce_r"`     // peer's nonce point
	AdaptorT       []byte `json:"adaptor_t"`        // T = sA·G
	ClaimKey       []byte `json:"claim_key"`        // K = A+B
	AggNonceR      []byte `json:"agg_nonce_r"`      // R = Ra+Rb
	XNOAccountPub  []byte `json:"xno_account_pub"`  // (sA+sB)·G

	// On-chain / ledger references and amounts.
	SwapKey []byte `json:"swap_key"` // OBX SwapOut id
	OBXAmount uint64 `json:"obx_amount"`
	// XNOAmount is the RAW XNO (128-bit, 1 XNO = 1e30 raw) the taker locks. It is a
	// *big.Int because raw overflows uint64 even at sub-cent scale; encoding/json
	// round-trips it exactly (as a JSON number) for crash-resume.
	XNOAmount    *big.Int `json:"xno_amount"`
	Fee          uint64   `json:"fee"`
	UnlockHeight uint64 `json:"unlock_height"`
	XNOLockID    string `json:"xno_lock_id"`
	SweepDest    string `json:"sweep_dest"` // where the maker sends the swept XNO

	// PeerClaimHalf is the taker's verified pre-signature half ŝ_a = ra + e·a over the
	// co-signed claim core hash (carried in ClaimRequest, checked in CoSignClaim before
	// the maker releases its own half). The maker stores it DURABLY so it can extract the
	// adaptor secret sA INDEPENDENTLY from the on-chain claim — sA = S_full − ŝ_a − ŝ_b —
	// with ZERO taker cooperation after co-signing. A maker that co-signs, crashes, and
	// resumes still holds ŝ_a and can sweep the XNO from chain data alone. Nil until the
	// maker has co-signed. This is PUBLIC-equivalent material (a one-time Schnorr response
	// the taker also publishes inside the on-chain claim), so storing it leaks no secret.
	PeerClaimHalf []byte `json:"peer_claim_half,omitempty"`

	// CoSignedCoreHash is the ONE claim core hash this maker has co-signed (F3 fix).
	// The pre-signature nonce rb is committed on-chain (in R=Ra+Rb) BEFORE any claim
	// exists, so co-signing two DISTINCT core hashes under the same rb leaks
	// b=(sb1-sb2)/(e1-e2). The guard MUST survive a crash: it is persisted here (not
	// only in memory) so a maker that co-signs, crashes, and resumes via LoadState
	// still refuses a SECOND distinct co-sign. Nil/empty means nothing co-signed yet.
	CoSignedCoreHash []byte `json:"cosigned_core_hash,omitempty"`
}

// Save persists the state as JSON at path (mode 0600 — it holds a secret share).
func (s *SwapState) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

// LoadState restores a SwapState from a JSON file.
func LoadState(path string) (*SwapState, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s SwapState
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.Role != RoleMaker && s.Role != RoleTaker {
		return nil, errors.New("swapsession: state has unknown role")
	}
	return &s, nil
}

// ownTermHash is the STABLE per-party context the deterministic claim nonce
// (#13) is bound to. Each party derives its OWN nonce independently as
// DeriveNonce(own_xno_share, ownTermHash) — there is no joint input, so the
// taker can derive Ra at Init time (before it has seen the maker's shares) and
// the maker can derive Rb symmetrically. The hash folds in the swap id, the
// party's own claim/XNO shares (fresh-random per swap), and the agreed amounts.
//
// WHY this is enough for nonce-safety: a nonce only ever needs to be UNIQUE per
// (own secret, signing context). Both inputs to DeriveNonce here — the party's
// own secret share and this term hash — are functions of the exact swap being
// signed. A retry that renegotiates the cryptographic terms redraws the shares
// (or changes the amounts), changing the hash and hence the nonce; an identical
// re-run over the same shares+terms re-derives the SAME nonce, which is harmless
// (the same context yields the same sig). What must never happen — the same
// nonce reused under two DIFFERENT challenges — cannot, because the only way to
// get a different challenge is a different on-chain coreHash, which only arises
// from different terms, which change this hash.
//
// It is deliberately distinct from the on-chain tx CoreHash the claim signature
// is computed over (that hash depends on R = Ra+Rb, which depends on the nonces
// — binding nonces to it would be circular).
func ownTermHash(swapID [32]byte, ownClaimShare, ownXNOShare []byte, obxAmt uint64, xnoAmt *big.Int) []byte {
	h := sha512.New()
	h.Write([]byte("Obscura/swapsession/term/v1"))
	h.Write(swapID[:])
	h.Write(ownClaimShare)
	h.Write(ownXNOShare)
	var n [8]byte
	put := func(v uint64) {
		n[0] = byte(v)
		n[1] = byte(v >> 8)
		n[2] = byte(v >> 16)
		n[3] = byte(v >> 24)
		n[4] = byte(v >> 32)
		n[5] = byte(v >> 40)
		n[6] = byte(v >> 48)
		n[7] = byte(v >> 56)
		h.Write(n[:])
	}
	put(obxAmt)
	// XNO amount is a 128-bit raw value (*big.Int): fold in its big-endian magnitude
	// LENGTH-PREFIXED so distinct amounts (incl. trailing-zero differences) yield
	// distinct hashes and hence distinct nonces. A nil amount hashes as length 0.
	var raw []byte
	if xnoAmt != nil {
		raw = xnoAmt.Bytes()
	}
	put(uint64(len(raw)))
	h.Write(raw)
	return h.Sum(nil)
}
