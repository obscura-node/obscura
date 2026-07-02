// Package swapnet is the P2P TRANSPORT that carries the two-party
// pkg/swapsession handshake between two SEPARATE nodes over the existing
// pkg/p2p network. Where pkg/swapsession exchanges its six messages (Init,
// MakerCommit, Funded, XNOLocked, ClaimRequest, ClaimPreSig) via direct
// in-process Go calls, swapnet moves the SAME serialized blobs over a real
// p2p connection: a maker on one node and a taker on another complete a swap
// by message-passing, with NEITHER party ever holding both secret shares.
//
// Layering:
//
//	pkg/swapsession  — the protocol (crypto, state machine, guards). UNCHANGED.
//	pkg/swapnet      — this package: envelopes, routing-by-SwapID, the maker/taker
//	                   coordinators that DRIVE a swapsession.Maker/Taker, timeouts,
//	                   persistence/resume.
//	pkg/p2p          — the wire: one new DIRECTED message kind (msgSwapSession) +
//	                   SendSwapSession(peer) + an OnSwapSession callback. p2p does
//	                   NO swap logic; the envelope is opaque to it.
//
// Security note: the transport adds NO trust. Every swapsession message
// re-validates its own crypto on arrival (proofs-of-possession, joint-key
// derivation, the on-chain SwapOut check, the F1/F2/F3/F-1 guards), so a
// malicious or buggy transport can only DENY service, never steal funds. The
// coordinator rejects envelopes for unknown swaps and (via the session's own
// SwapID checks) replayed/cross-bound messages.
package swapnet

import (
	"encoding/binary"
	"errors"
)

// Kind tags which swapsession message a directed envelope carries. The byte is
// distinct from the swapsession role byte (which lives INSIDE the payload) so
// the coordinator can route on Kind without parsing the crypto.
type Kind byte

const (
	KindInit         Kind = 1 // TAKER -> MAKER : opens the session
	KindMakerCommit  Kind = 2 // MAKER -> TAKER
	KindFunded       Kind = 3 // MAKER -> TAKER : OBX SwapOut is on-chain
	KindXNOLocked    Kind = 4 // TAKER -> MAKER : XNO locked to the joint account
	KindClaimRequest Kind = 5 // TAKER -> MAKER : claim core hash to co-sign
	KindClaimPreSig  Kind = 6 // MAKER -> TAKER : maker's pre-signature half
	// KindAbort is an out-of-band notice that the sender is abandoning the swap
	// (e.g. a guard rejected a message). It is advisory only — safety never
	// depends on receiving it; the funder's timeout+refund is the real backstop.
	KindAbort Kind = 7
)

// maxEnvelopePayload bounds the inner swapsession blob. The largest message
// (Init) is well under 1 KiB; this cap keeps a malformed/oversized envelope
// from allocating unboundedly. p2p's own maxMsgBytes is a further outer bound.
const maxEnvelopePayload = 1 << 16

var errEnvelope = errors.New("swapnet: malformed envelope")

// Envelope is the DIRECTED unit p2p carries to a specific counterparty: the
// SwapID it belongs to, the Kind of swapsession message, and the opaque
// serialized swapsession Payload. Routing to the right in-flight session is by
// SwapID; the Kind tells the coordinator which Parse*/Handle* to run. The
// payload itself is self-authenticating (the swapsession Validate logic), so
// the envelope header carries no security weight beyond addressing.
type Envelope struct {
	SwapID  [32]byte
	Kind    Kind
	Payload []byte
}

// Serialize encodes the envelope: SwapID(32) Kind(1) len(4) Payload.
func (e *Envelope) Serialize() []byte {
	b := make([]byte, 0, 37+len(e.Payload))
	b = append(b, e.SwapID[:]...)
	b = append(b, byte(e.Kind))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(e.Payload)))
	b = append(b, l[:]...)
	b = append(b, e.Payload...)
	return b
}

// ParseEnvelope decodes a wire envelope, rejecting truncated or oversized input.
func ParseEnvelope(b []byte) (*Envelope, error) {
	if len(b) < 37 {
		return nil, errEnvelope
	}
	e := &Envelope{}
	copy(e.SwapID[:], b[0:32])
	e.Kind = Kind(b[32])
	n := binary.BigEndian.Uint32(b[33:37])
	if n > maxEnvelopePayload || int(n) != len(b)-37 {
		return nil, errEnvelope
	}
	if n > 0 {
		e.Payload = append([]byte(nil), b[37:]...)
	}
	return e, nil
}
