package p2p

import (
	"math/rand"
	"time"

	"obscura/pkg/tx"
)

// Dandelion++ transaction-origin privacy (Block 4 — see
// docs/INVENTION_DANDELION.md). A transaction first travels a private "stem":
// each node relays it to exactly ONE per-epoch stem successor (an outbound
// peer), for a few hops, before "fluffing" (normal flood broadcast). By the
// time it floods, the true origin is hidden behind the stem path — so a network
// observer cannot tie the transaction to the originating node/IP. A fail-safe
// timer fluffs the tx if it is not seen propagating, preventing black-holing.

const (
	stemEpoch     = 60 * time.Second // how often the stem successor rotates
	stemFluffProb = 0.30             // per-epoch probability the node is in fluff mode (~3 hops)
	stemEmbargo   = 8 * time.Second  // relay fail-safe: fluff if not seen propagating
	// audit fix (first-spy): the ORIGIN's fail-safe embargo is bumped LONGER than a relay's
	// so that, on a fully-stemmed or black-holed path, a DOWNSTREAM relay's timer fires
	// first and IT fluffs — not the originating node. Relays start their timers slightly
	// later (after the stem reaches them) but with the shorter base, so they still beat the
	// origin. Combined with the per-epoch fluff mode (a fluff-mode relay normally broadcasts
	// first, cancelling every embargo), this keeps the origin from being the first fluffer.
	originEmbargoBump = 6 * time.Second
	embargoJitter     = 2 * time.Second // blur absolute fluff timing across nodes

	// audit: SECURITY_AUDIT_2026-07-01 (application-level black-hole / first-spy).
	// The black-hole defense only works if EVERY stem relayer — not just the origin —
	// independently arms a fluff embargo. A malicious successor that ACCEPTS the stem
	// tx (no TCP error) but silently never relays/fluffs it must be out-raced by an
	// intermediate honest relayer, so that an adversary adjacent to the origin sees a
	// relay (not the origin) fluff first. armEmbargo registers each relayed tx in the
	// bounded pendingEmbargo map (origin and intermediate hops alike); embargoSweepLoop
	// fluffs expired, still-unseen entries. The set is capped and self-draining so a
	// tx flood cannot exhaust memory or spawn unbounded timer goroutines.
	embargoSweepInterval = 1 * time.Second
	maxPendingEmbargo    = 50_000 // bound on simultaneously-tracked stem embargoes
)

// embargoEntry is one pending fail-safe fluff: the tx payload to broadcast and the
// absolute deadline after which (if still unseen) this node fluffs it itself.
type embargoEntry struct {
	payload  []byte
	deadline time.Time
}

// stemEpochLoop rotates the stem successor each epoch (chosen from outbound
// peers, per Dandelion++).
func (n *Node) stemEpochLoop() {
	go n.embargoSweepLoop() // audit: SECURITY_AUDIT_2026-07-01 — per-hop black-hole fail-safe
	n.rotateStemPeer()
	t := time.NewTicker(stemEpoch)
	defer t.Stop()
	for {
		select {
		case <-n.done:
			return
		case <-t.C:
			n.rotateStemPeer()
		}
	}
}

func (n *Node) rotateStemPeer() {
	var outbound []*peer
	n.mu.Lock()
	for _, p := range n.peers {
		if p.outbound {
			outbound = append(outbound, p)
		}
	}
	n.mu.Unlock()
	n.stemMu.Lock()
	if len(outbound) == 0 {
		n.stemPeer = nil
	} else {
		n.stemPeer = outbound[rand.Intn(len(outbound))]
	}
	// audit fix (Dandelion++): decide stem-vs-fluff ONCE per epoch per node, not with a
	// per-tx/per-hop coin flip. A per-tx flip leaks statistically — across many txs an
	// observer separates a node's stemmed vs fluffed traffic and narrows the origin. The
	// paper's design is a per-epoch pseudorandom mode: this epoch the node either relays
	// all stem txs onward or fluffs them, so individual txs reveal nothing about origin.
	n.fluffMode = rand.Float64() < stemFluffProb
	n.stemMu.Unlock()
}

// stemRelay either continues the stem (relay to the single stem successor) or
// transitions to fluff (flood broadcast). `from` is the peer we received the
// stem from (nil if we originated the tx).
func (n *Node) stemRelay(t *tx.Transaction, payload []byte, from *peer) {
	id := t.Hash()
	n.stemMu.Lock()
	sp := n.stemPeer
	fluffMode := n.fluffMode           // per-epoch per-node decision (set in rotateStemPeer)
	already := n.fluffedSeenLocked(id) // check BOTH generations, not just the live one
	n.stemMu.Unlock()
	if already {
		return
	}

	// Fluff if Dandelion is off, we have no stem successor, the successor is the
	// peer we got it from (avoid a trivial 2-cycle), or this epoch's mode is fluff.
	if !n.dandelion || sp == nil || (from != nil && sp == from) || fluffMode {
		n.fluff(id, payload, from)
		return
	}

	// Continue the stem: relay privately to the single successor, with a small
	// exponential delay, and arm the fail-safe fluff timer.
	delay := time.Duration(rand.ExpFloat64() * float64(time.Second))
	if delay > stemEmbargo/2 {
		delay = stemEmbargo / 2
	}
	go func() {
		select {
		case <-n.done:
			return
		case <-time.After(delay):
		}
		if err := n.send(sp, msgStemTx, payload); err != nil {
			// audit fix (first-spy): on a successor send failure do NOT immediately fluff.
			// An immediate fluff makes THIS node (which may be the origin) the first and
			// instant fluffer — the exact timing signal a first-spy adversary uses to
			// deanonymize. The embargo timer armed below is the fail-safe: it fluffs after
			// stemEmbargo if the tx is not seen propagating, so the tx still spreads (with a
			// uniform delay) without singling this node out as the source.
			_ = err
		}
	}()
	// audit: SECURITY_AUDIT_2026-07-01 — EVERY hop arms its own embargo (origin AND
	// intermediate relayers); origin (from==nil) waits longer so a downstream relay
	// out-races it and fluffs first even against an application-level black hole.
	n.armEmbargo(id, payload, from == nil)
}

// maxFluffedSet bounds the remembered-txid set so it cannot grow without limit
// over the node's lifetime (txids only matter for the propagation window). When
// the live set fills, it rotates to a single previous generation, so memory is
// bounded to ~2× this while recent membership is preserved.
const maxFluffedSet = 100_000

// fluffedSeenLocked reports whether id was recently fluffed (caller holds stemMu).
func (n *Node) fluffedSeenLocked(id [32]byte) bool {
	return n.fluffed[id] || n.fluffedOld[id]
}

// rememberFluffedLocked records id, rotating generations at the cap (caller holds stemMu).
func (n *Node) rememberFluffedLocked(id [32]byte) {
	if len(n.fluffed) >= maxFluffedSet {
		n.fluffedOld = n.fluffed
		n.fluffed = make(map[[32]byte]bool, maxFluffedSet)
	}
	n.fluffed[id] = true
	// audit: SECURITY_AUDIT_2026-07-01 — once a tx is fluffed (by us, or seen on the
	// network via markFluffed), cancel any pending embargo so the sweep never re-fluffs.
	delete(n.pendingEmbargo, id)
}

// fluff floods the transaction to all peers (except the source) and records it.
func (n *Node) fluff(id [32]byte, payload []byte, except *peer) {
	n.stemMu.Lock()
	if n.fluffedSeenLocked(id) {
		n.stemMu.Unlock()
		return
	}
	n.rememberFluffedLocked(id)
	n.stemMu.Unlock()
	if except != nil {
		n.broadcast(msgTx, payload, except.conn)
	} else {
		n.broadcast(msgTx, payload, nil)
	}
}

// armEmbargo registers a fail-safe fluff for a stem tx this node just relayed
// onward. It is called at EVERY hop — by the origin (isOrigin) AND by every
// intermediate relayer — so a downstream honest relay out-races the origin and
// fluffs first even against an application-level black hole (a successor that
// accepts the stem tx but silently never relays it).
//
// audit: SECURITY_AUDIT_2026-07-01 — replaces the previous per-tx timer goroutine
// with a bounded entry in pendingEmbargo, swept by embargoSweepLoop. This keeps
// the per-hop semantics while bounding memory and goroutines under a tx flood.
func (n *Node) armEmbargo(id [32]byte, payload []byte, isOrigin bool) {
	d := stemEmbargo
	if isOrigin {
		d += originEmbargoBump // anti first-spy: let a downstream relay fluff first
	}
	d += time.Duration(rand.Int63n(int64(embargoJitter)))
	deadline := time.Now().Add(d)
	n.stemMu.Lock()
	defer n.stemMu.Unlock()
	if n.fluffedSeenLocked(id) {
		return // already propagating — no embargo needed
	}
	if n.pendingEmbargo == nil {
		n.pendingEmbargo = make(map[[32]byte]*embargoEntry, 1024)
	}
	if _, ok := n.pendingEmbargo[id]; ok {
		return // already tracked — keep the earliest (shortest) deadline
	}
	if len(n.pendingEmbargo) >= maxPendingEmbargo {
		// Bounded: under an extreme stem flood, stop tracking new embargoes rather
		// than grow without limit. The tx was already relayed onward at the stem
		// hop, and downstream relayers still arm their own embargoes; the sweep
		// drains expired entries every embargoSweepInterval, so the cap self-relieves.
		return
	}
	n.pendingEmbargo[id] = &embargoEntry{payload: payload, deadline: deadline}
}

// embargoSweepLoop periodically fluffs stem txs whose per-hop embargo expired
// without the tx being seen propagating (black-hole fail-safe), and evicts
// entries already seen fluffed. One sweep goroutine per node (vs. one timer
// goroutine per tx), so resource use is bounded under load.
func (n *Node) embargoSweepLoop() {
	t := time.NewTicker(embargoSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-n.done:
			return
		case <-t.C:
			n.sweepEmbargo()
		}
	}
}

// sweepEmbargo fluffs every expired, still-unseen pending embargo and drops any
// entry already observed fluffed by the network (embargo cancellation).
func (n *Node) sweepEmbargo() {
	now := time.Now()
	type fire struct {
		id      [32]byte
		payload []byte
	}
	var toFluff []fire
	n.stemMu.Lock()
	for id, e := range n.pendingEmbargo {
		if n.fluffedSeenLocked(id) {
			delete(n.pendingEmbargo, id) // seen as fluff -> cancel embargo
			continue
		}
		if !now.Before(e.deadline) {
			toFluff = append(toFluff, fire{id, e.payload})
			delete(n.pendingEmbargo, id)
		}
	}
	n.stemMu.Unlock()
	// fluff outside the lock (fluff() re-acquires stemMu); it is idempotent and
	// no-ops if the tx was concurrently seen fluffed.
	for _, f := range toFluff {
		n.fluff(f.id, f.payload, nil)
	}
}

// markFluffed records that a tx has entered the fluff phase (seen as a normal
// broadcast), cancelling any pending embargo and stopping re-stemming.
func (n *Node) markFluffed(id [32]byte) {
	n.stemMu.Lock()
	n.rememberFluffedLocked(id)
	n.stemMu.Unlock()
}
