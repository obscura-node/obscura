package swapnet

import (
	"encoding/hex"
	"math/big"
	"time"

	"obscura/pkg/swapsession"
)

// Session is the caller-facing handle to one in-flight swap started via Take.
// (Maker sessions are started internally on an inbound Init and not exposed.)
type Session struct {
	s *session
}

// ID returns the swap's 32-byte identifier.
func (h *Session) ID() [32]byte { return h.s.id }

// Wait blocks until the session terminates, then returns nil on success
// (taker: OBX claimed) or the terminal error (timeout, abort, guard rejection).
func (h *Session) Wait() error {
	<-h.s.done
	return h.s.err
}

// WaitFor blocks until the session terminates or d elapses. ok is false on
// timeout (the session is still running). On termination it returns the terminal
// error like Wait.
func (h *Session) WaitFor(d time.Duration) (err error, ok bool) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-h.s.done:
		return h.s.err, true
	case <-t.C:
		return nil, false
	}
}

// Succeeded reports whether the session reached its success terminal state
// (taker: claim mined; maker: XNO swept). Only meaningful after Wait returns.
func (h *Session) Succeeded() bool { return h.s.swept }

// SwapKey returns the ON-CHAIN OBX SwapOut key for this session (the maker-minted
// id the Fund tx created, which the claim/refund spend), hex-encoded, or "" if it
// is not yet known (set once the taker has verified the maker's Funded message).
// The trade tape joins to this key so both nodes record the swap under the SAME
// on-chain identifier — unlike the per-session SwapID, which never appears on-chain.
func (h *Session) SwapKey() string {
	h.s.c.mu.Lock()
	defer h.s.c.mu.Unlock()
	if h.s.st == nil || len(h.s.st.SwapKey) == 0 {
		return ""
	}
	return hex.EncodeToString(h.s.st.SwapKey)
}

// ---- read-only snapshot for the RPC/UI layer --------------------------------

// SwapStep is one named milestone of a swap lifecycle and whether it is done.
// The ordered list lets a UI render a progress bar that reflects EACH step.
type SwapStep struct {
	Name string `json:"name"`
	Done bool   `json:"done"`
}

// SessionView is a thread-safe, value-only snapshot of one in-flight (or just
// finished) session for the RPC layer. It carries the swap id (hex), the role,
// the live phase string, the agreed amounts, the derived ordered step list, and
// the session's start time. It NEVER exposes any secret share (those live only in
// the SwapState file); only public progress metadata crosses this boundary.
type SessionView struct {
	ID        string     `json:"id"`
	Role      string     `json:"role"`
	Phase     string     `json:"phase"`
	OBXAmount uint64     `json:"obx_amount"`
	XNOAmount *big.Int   `json:"xno_amount"` // RAW XNO (128-bit)
	SwapKey   string     `json:"swap_key"`   // hex on-chain OBX SwapOut key ("" until known)
	Steps     []SwapStep `json:"steps"`
	Updated   int64      `json:"updated"`
}

// stepOrder is the canonical lifecycle order a swap advances through. The done
// flags are derived from the current phase: every step at or before the phase's
// rank is done. Refund is a terminal off-ramp (it sets done on the refunded step
// only, leaving the claim/sweep steps NOT done — the swap aborted).
var stepOrder = []string{"init", "funded", "xno_lock", "claim", "sweep", "done"}

// phaseRank maps a swapsession.Phase to how many leading stepOrder entries are
// done. PhaseRefunded is handled specially (a separate terminal step).
func phaseRank(p swapsession.Phase) int {
	switch p {
	case swapsession.PhaseInit:
		return 1 // init done
	case swapsession.PhaseFunded:
		return 2 // init, funded
	case swapsession.PhaseXNOLock:
		return 3 // init, funded, xno_lock
	case swapsession.PhaseClaimed:
		return 4 // + claim
	case swapsession.PhaseSwept:
		return 6 // + sweep + done (terminal success)
	default:
		return 1
	}
}

// stepsFor derives the ordered step list for a phase. A refunded swap returns a
// list whose only done step is the terminal "refunded" off-ramp.
func stepsFor(p swapsession.Phase) []SwapStep {
	if p == swapsession.PhaseRefunded {
		out := make([]SwapStep, 0, len(stepOrder)+1)
		// init was always reached before a refund; mark it done, the rest not.
		for i, name := range stepOrder {
			out = append(out, SwapStep{Name: name, Done: i == 0})
		}
		out = append(out, SwapStep{Name: "refunded", Done: true})
		return out
	}
	rank := phaseRank(p)
	out := make([]SwapStep, 0, len(stepOrder))
	for i, name := range stepOrder {
		out = append(out, SwapStep{Name: name, Done: i < rank})
	}
	return out
}

// ActiveSessions returns a value-only snapshot of every session currently in the
// coordinator's registry (running or freshly terminal but not yet unregistered).
// It is safe to call concurrently with running swaps: it copies value fields
// under the registry lock. The phase read is a best-effort live view — a session
// mid-transition may briefly report the prior phase, which is acceptable for a
// UI progress display. Sessions with no bound state yet (registered but the
// driver has not set st) are reported in PhaseInit.
func (c *Coordinator) ActiveSessions() []SessionView {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]SessionView, 0, len(c.sessions))
	for id, s := range c.sessions {
		phase := swapsession.PhaseInit
		var obx uint64
		var swapKey string
		xno := new(big.Int)
		if s.st != nil {
			phase = s.st.Phase
			obx = s.st.OBXAmount
			if s.st.XNOAmount != nil {
				xno = new(big.Int).Set(s.st.XNOAmount)
			}
			if len(s.st.SwapKey) > 0 {
				swapKey = hex.EncodeToString(s.st.SwapKey)
			}
		}
		out = append(out, SessionView{
			ID:        hex.EncodeToString(id[:]),
			Role:      string(s.role),
			Phase:     string(phase),
			OBXAmount: obx,
			XNOAmount: xno,
			SwapKey:   swapKey,
			Steps:     stepsFor(phase),
			Updated:   s.started,
		})
	}
	return out
}
