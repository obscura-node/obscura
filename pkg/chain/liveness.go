package chain

// Sync/liveness OBSERVABILITY (additive; no consensus/validation semantics).
// TipLiveness tracks when the chain tip last ADVANCED as observed by this
// process's wall clock, so the RPC layer can report an honest "is this node
// stuck?" signal (/status blocks_behind + /health degraded-on-stall) without
// touching validation or fork choice. It deliberately lives beside the chain
// rather than inside AddBlock: it is an observer, not a participant.

import (
	"sync"
	"time"
)

// TipLiveness is a poll-driven tip-advance tracker. Callers feed it the current
// tip height (Observe) whenever they sample the chain (e.g. on each /status,
// /health or /metrics request); it records the wall-clock time of the last
// observed CHANGE and reports how long the tip has been static since.
//
// Honesty notes:
//   - The first observation seeds the clock, so a freshly (re)started node is
//     never instantly "stalled" — it gets a full stall window from process start.
//   - ANY height change (including a reorg to a lower height) counts as chain
//     activity: a reorging node is alive, not stuck.
//   - Because it is poll-driven, the reported stall duration is measured between
//     polls: a tip that advanced and polls that observed it keep the clock fresh;
//     a stuck tip lets the duration grow monotonically. It never claims an
//     advance that was not observed.
type TipLiveness struct {
	mu          sync.Mutex
	seeded      bool
	lastHeight  uint64
	lastAdvance time.Time
}

// NewTipLiveness returns an empty tracker; the first Observe seeds it.
func NewTipLiveness() *TipLiveness { return &TipLiveness{} }

// Observe records the current tip height and returns how long the tip has been
// unchanged (zero when this observation itself is a change / the first one).
func (t *TipLiveness) Observe(height uint64) time.Duration {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.seeded || height != t.lastHeight {
		t.seeded = true
		t.lastHeight = height
		t.lastAdvance = now
		return 0
	}
	return now.Sub(t.lastAdvance)
}

// LastAdvance returns the wall-clock time of the last observed tip change (zero
// time if never observed). Read-only introspection for tests/metrics.
func (t *TipLiveness) LastAdvance() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastAdvance
}
