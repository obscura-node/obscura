// Package takerdrive runs the TAKER side of a pkg/swapsession atomic swap as a
// standalone, dependency-light loop — so the SAME protocol can execute in the
// browser (WebAssembly) instead of on a node. It is the non-custodial counterpart
// to pkg/swapnet's Coordinator.driveTaker: it drives the exact same six-message
// handshake against a swapsession.Taker, but with NO node registry, NO file
// persistence, and NO os/net dependencies — every side effect goes through three
// injected interfaces (TakerOBX, XNOLocker, Transport). In the browser those
// interfaces are backed by the WASM wallet (signing) + fetch to the node relay
// (chain reads, maker message passing, Nano publish); in tests they are backed by
// an in-process chain + MockNano.
//
// This package adds a new EXECUTION HOST for the taker. It does NOT modify
// pkg/swapsession (the protocol, crypto, and F1/F2/F3/F-1/F-A/F-B/F-C guards are
// reused verbatim).
//
// TRUST CAVEAT (audit C-1 — IMPORTANT, differs from the full-node taker): the
// swapsession.Taker re-validates every inbound message AND the on-chain SwapOut.
// For a full p2p node taker that independently validates the chain, a hostile
// transport can only DENY service, never steal. But when this driver runs in a
// LIGHT CLIENT (the browser, via the relay), its ENTIRE view of the OBX chain —
// FindSwapOut, Height, claim broadcast — comes from the relay (the maker's node).
// checkSwapOut only proves the returned SwapOutput echoes the agreed K/R/T/amount/
// unlock, all of which the maker already knows, so a malicious operator CAN
// fabricate chain state, induce the taker to lock real XNO, extract sA from the
// relayed claim, and sweep it. Therefore a browser taker TRUSTS THE RELAY OPERATOR
// with its XNO: point the wallet at YOUR OWN node, or treat the hosted swap as
// custodial-trust on the operator. (Independent light-client chain verification /
// multi-node claim broadcast is the required fix before any value-bearing use.)
package takerdrive

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"obscura/pkg/commit"
	"obscura/pkg/swapsession"
)

// Kind tags which swapsession message an envelope carries. These bytes MUST equal
// pkg/swapnet's Kind constants so the node relay can forward takerdrive envelopes
// straight onto the existing p2p swap transport unchanged. A guard test asserts
// the equality (takerdrive deliberately does NOT import swapnet, to stay wasm-safe
// and free of the coordinator/os/p2p dependencies).
type Kind byte

const (
	KindInit         Kind = 1
	KindMakerCommit  Kind = 2
	KindFunded       Kind = 3
	KindXNOLocked    Kind = 4
	KindClaimRequest Kind = 5
	KindClaimPreSig  Kind = 6
	KindClaimDone    Kind = 8
)

// Transport is the directed message channel to the maker. Send delivers a
// swapsession message of the given Kind; Recv blocks for the next inbound message
// (the relay routes by SwapID on the node side). Both may block — in the browser
// they await fetch round-trips; the driver runs on its own goroutine so blocking
// is fine.
type Transport interface {
	Send(kind Kind, payload []byte) error
	Recv() (kind Kind, payload []byte, err error)
}

// Phase is an optional progress callback so a UI can show a coarse status
// (init → xno_lock → claimed → done) without parsing protocol internals.
type Phase func(phase string)

// Params are the agreed swap terms (matched to the maker's offer by the caller).
type Params struct {
	SwapID    [32]byte
	OBXAmount uint64   // OBX atomic the taker will claim
	XNOAmount *big.Int // RAW XNO (1 XNO = 1e30 raw) the taker locks
	Fee       uint64   // OBX fee both sides use
}

// fundingPoll bounds how long VerifyFundedAndLock retries while the taker waits
// for the maker's OBX funding block to become visible (the host's FindSwapOut may
// momentarily lag). The bridge's FindSwapOut typically blocks until synced, so
// this is a backstop, not the primary wait.
const (
	fundingPollAttempts = 120
	fundingPollDelay    = 2 * time.Second
)

// RunTaker drives a full taker swap to completion (PhaseClaimed + courtesy
// ClaimDone) or returns the first error. It is SAFE TO RUN ON A GOROUTINE and has
// no global state. onPhase may be nil.
//
// Sequence (identical to swapnet.driveTaker, minus persistence/registry):
//
//	send Init → recv MakerCommit → recv Funded → verify on-chain + lock XNO →
//	send XNOLocked → send ClaimRequest → recv ClaimPreSig → finalize+mine claim →
//	(courtesy) send ClaimDone.
func RunTaker(p Params, obx swapsession.TakerOBX, nano swapsession.XNOLocker, tr Transport, onPhase Phase) error {
	report := func(s string) {
		if onPhase != nil {
			onPhase(s)
		}
	}

	tk := swapsession.NewTaker(p.SwapID, p.OBXAmount, p.XNOAmount, p.Fee, obx)

	// 1) send Init.
	if err := tr.Send(KindInit, tk.Init().Serialize()); err != nil {
		return fmt.Errorf("send Init: %w", err)
	}
	report("init")

	// 2) await MakerCommit.
	mc, err := recvParse(tr, KindMakerCommit, func(b []byte) (*swapsession.MakerCommit, error) {
		return swapsession.ParseMakerCommit(b)
	})
	if err != nil {
		return err
	}
	if err := tk.HandleMakerCommit(mc); err != nil {
		return fmt.Errorf("HandleMakerCommit: %w", err)
	}
	// audit 2026-07-01 item #7: the maker has now committed and starts mining the
	// OBX-funding block on-chain (~1 block interval) before Funded arrives — this
	// is a distinct, real wait from the Init/MakerCommit round-trip above. Report
	// it as its own phase so the UI shows an accurate state instead of a client-side
	// timeout guess ("if the maker accepted, it's probably funding now").
	report("funding")

	// 3) await Funded → verify on-chain + lock XNO → send XNOLocked.
	funded, err := recvParse(tr, KindFunded, func(b []byte) (*swapsession.Funded, error) {
		return swapsession.ParseFunded(b)
	})
	if err != nil {
		return err
	}
	// UX audit [136]: report the phase transition BEFORE the slow/risky step starts,
	// not after — VerifyFundedAndLock is the one that actually moves real XNO and can
	// take a while (on-chain verify + a live Nano RPC round-trip), so the UI must say
	// "locking your XNO…" WHILE that's happening, not still show the previous phase
	// for the whole duration and only flip once the money has already moved.
	report("xno_lock")
	var locked *swapsession.XNOLocked
	for attempt := 0; ; attempt++ {
		locked, err = tk.VerifyFundedAndLock(nano, funded)
		if err == nil {
			break
		}
		// ErrFundingNotVisible is a transient sync gap (no XNO is locked until the
		// funding verifies), so poll instead of aborting. Any other error is a real
		// safe-leg refusal — abort with NOTHING at risk (the taker never locked XNO).
		if errors.Is(err, swapsession.ErrFundingNotVisible) && attempt < fundingPollAttempts {
			time.Sleep(fundingPollDelay)
			continue
		}
		return fmt.Errorf("VerifyFundedAndLock: %w", err)
	}
	if err := tr.Send(KindXNOLocked, locked.Serialize()); err != nil {
		return fmt.Errorf("send XNOLocked: %w", err)
	}

	// 4) build claim request → send → await ClaimPreSig → finalize (mine claim).
	req, err := tk.BuildClaimRequest()
	if err != nil {
		return fmt.Errorf("BuildClaimRequest: %w", err)
	}
	// UX audit [136]: same fix as above — "claiming OBX…" must show WHILE waiting
	// on the maker's ClaimPreSig (the actual wait), not only once it's already done.
	report("claimed")
	if err := tr.Send(KindClaimRequest, req.Serialize()); err != nil {
		return fmt.Errorf("send ClaimRequest: %w", err)
	}
	ps, err := recvParse(tr, KindClaimPreSig, func(b []byte) (*swapsession.ClaimPreSig, error) {
		return swapsession.ParseClaimPreSig(b)
	})
	if err != nil {
		return err
	}
	aggPre, fullSig, err := tk.FinalizeClaim(ps)
	if err != nil {
		return fmt.Errorf("FinalizeClaim: %w", err)
	}

	// 5) courtesy ClaimDone relay (pure latency hint — the maker extracts sA from
	// the on-chain claim regardless; withholding/corrupting it cannot strand the
	// maker, per the griefing fix). A failed relay is NOT a taker-side failure: the
	// taker already holds its OBX.
	_ = tr.Send(KindClaimDone, claimDonePayload(aggPre, fullSig))
	report("done")
	return nil
}

// recvParse reads the next envelope, asserts its Kind, and parses its payload.
func recvParse[T any](tr Transport, want Kind, parse func([]byte) (T, error)) (T, error) {
	var zero T
	kind, payload, err := tr.Recv()
	if err != nil {
		return zero, err
	}
	if kind == KindAbortInternal {
		return zero, errors.New("takerdrive: maker aborted the swap")
	}
	if kind != want {
		return zero, fmt.Errorf("takerdrive: expected %s, got kind %d", kindName(want), kind)
	}
	v, err := parse(payload)
	if err != nil {
		return zero, fmt.Errorf("takerdrive: parse %s: %w", kindName(want), err)
	}
	return v, nil
}

// KindAbortInternal mirrors swapnet.KindAbort (7) — an advisory maker abort. We
// surface it as a clear error rather than a kind-mismatch.
const KindAbortInternal Kind = 7

func kindName(k Kind) string {
	switch k {
	case KindInit:
		return "Init"
	case KindMakerCommit:
		return "MakerCommit"
	case KindFunded:
		return "Funded"
	case KindXNOLocked:
		return "XNOLocked"
	case KindClaimRequest:
		return "ClaimRequest"
	case KindClaimPreSig:
		return "ClaimPreSig"
	case KindClaimDone:
		return "ClaimDone"
	default:
		return fmt.Sprintf("Kind(%d)", byte(k))
	}
}

// claimDonePayload encodes (presig.R || presig.S || fullSig serialized) — the
// exact wire format pkg/swapnet.claimDonePayload uses, so the node relay forwards
// it to the maker unchanged.
func claimDonePayload(presig *commit.AdaptorSig, fullSig *commit.FullSig) []byte {
	b := make([]byte, 0, 32+32+64)
	b = append(b, padOrTrim(presig.R, 32)...)
	b = append(b, padOrTrim(presig.S, 32)...)
	b = append(b, fullSig.Serialize()...)
	return b
}

func padOrTrim(p []byte, n int) []byte {
	if len(p) == n {
		return p
	}
	out := make([]byte, n)
	copy(out, p)
	return out
}
