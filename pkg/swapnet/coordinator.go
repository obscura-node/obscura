package swapnet

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"obscura/pkg/commit"
	"obscura/pkg/config"
	"obscura/pkg/swapsession"
)

// swapDebug enables verbose transport tracing for diagnosing two-party delivery
// (set OBX_SWAP_DEBUG=1). Off by default so production stays silent.
var swapDebug = os.Getenv("OBX_SWAP_DEBUG") != ""

func swapLog(format string, a ...any) {
	if swapDebug {
		log.Printf("[swapnet] "+format, a...)
	}
}

// Transport is the directed point-to-point send the coordinator needs. The real
// implementation wraps *p2p.Node.SendSwapSession; tests can supply an in-memory
// pair. `peer` is an opaque routing handle (a p2p remote address): the taker
// learns the maker's handle when it dials/connects; the maker learns the taker's
// from the inbound envelope. Send must deliver to ONLY that peer (never gossip).
type Transport interface {
	Send(peer string, env *Envelope) error
}

// PeerResolver is an OPTIONAL Transport capability. When a Send fails because the
// counterparty's connection dropped, the coordinator asks the transport to re-resolve
// the counterparty's CURRENT live handle (it may have reconnected under a new ephemeral
// port). The real p2p transport implements this via p2p.SwapPeerForHost; the in-memory
// test transport does not (its handles never go stale), so the assertion just fails
// and Send errors as before.
type PeerResolver interface {
	ResolvePeer(stale string) (string, bool)
}

// MakerCaps supplies the maker side's OBX + XNO capabilities for a given swap.
// The coordinator calls NewMakerOBX once per accepted swap (so each session funds
// from the node's own chain+miner) and Nano() for the shared XNO ledger client.
type MakerCaps interface {
	// NewMakerOBX returns the OBX funding/refund capability for a fresh maker
	// session. Implementations bind the node's chain+miner+wallet (see the test
	// host / cmd integration).
	NewMakerOBX() swapsession.MakerOBX
	Nano() swapsession.XNOSweeper
	// SweepDest is where the maker sends the swept XNO.
	SweepDest() string
}

// TakerCaps supplies the taker side's capabilities.
type TakerCaps interface {
	NewTakerOBX() swapsession.TakerOBX
	Nano() swapsession.XNOLocker
}

// Coordinator is the per-node swap engine. It owns a registry of in-flight
// sessions keyed by SwapID, routes inbound envelopes to the right one, drives the
// maker/taker state machines against the swapsession protocol, persists each
// session's SwapState for crash-resume, and arms a refund if a counterparty
// stalls. One Coordinator runs on each node.
type Coordinator struct {
	tr       Transport
	maker    MakerCaps
	taker    TakerCaps
	stateDir string // where per-session SwapState JSON is persisted ("" = no persistence)
	fee      uint64 // OBX fee both sides use (not negotiated in-band today; see Config.Fee)

	// onMakerDone, if set, is invoked exactly once when a MAKER session reaches a
	// terminal state, with success=true iff the XNO was swept. It lets the node
	// reconcile its OWN order book: on success, decrement the maker's matched offer +
	// record the trade under the on-chain SwapKey (so the maker and taker nodes agree
	// on remaining size + tape the swap by the same key); on failure, RELEASE the
	// offer reservation taken in AcceptInit so a stalled/aborted swap does not leave
	// the offer permanently under-committed. Runs on the maker's session goroutine, so
	// it must not block.
	onMakerDone func(s MakerSettlement, success bool)

	// acceptInit gates maker auto-funding on an inbound Init (F-A). It is the
	// node operator's opt-in: it must return true for the coordinator to spin up a
	// maker session (which FUNDS OBX on-chain) in response to an Init. nil means
	// DENY ALL — a node that wants to make swaps MUST supply this, ideally binding
	// the Init to one of its own live published offers (see Config.AcceptInit).
	acceptInit func(*swapsession.Init, string) bool

	// deadline a session may sit at one phase before the funder arms a refund /
	// the taker aborts. Kept small in tests.
	timeout time.Duration

	mu       sync.Mutex
	sessions map[[32]byte]*session

	// done is closed by Stop to unblock all session goroutines.
	done     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// Config configures a Coordinator. maker/taker may each be nil if this node only
// plays one role; at least one must be set.
type Config struct {
	Transport Transport
	Maker     MakerCaps
	Taker     TakerCaps
	StateDir  string        // persist SwapState here (resume on restart); "" disables
	Timeout   time.Duration // per-phase stall deadline before refund/abort
	// Fee is the OBX fee BOTH parties use for the swap funding/claim/refund. It is
	// not negotiated in the Init envelope today (the offer fixes it out of band); the
	// maker uses this configured value and the taker passes the matching fee to Take.
	// Fee negotiation over the wire is listed as NOT covered.
	Fee uint64

	// AcceptInit gates whether this node, as a MAKER, will auto-fund OBX in
	// response to an inbound Init (F-A). It is invoked with the PARSED Init and the
	// sender's routing handle; returning true authorizes a maker session (which then
	// funds OBX on-chain), false drops the Init WITHOUT funding.
	//
	// SECURITY: this is a DENY-BY-DEFAULT opt-in. If it is nil, the coordinator
	// funds NOTHING for inbound Inits — a node that makes swaps MUST set it. The
	// intended (and recommended) implementation binds the Init to one of the node's
	// OWN live published offers, e.g. by checking (OBXAmount, XNOAmount, Fee, asset
	// pair) against the node's swapbook offer book and rejecting anything that does
	// not match a live offer. That full offer-book binding is the documented
	// follow-up; at minimum an operator must opt in here so blind auto-fund is never
	// the default. The Fee the maker uses is still Config.Fee (not carried in Init).
	AcceptInit func(init *swapsession.Init, fromPeer string) bool

	// OnMakerDone, if set, is called once per MAKER session when it terminates, with
	// success=true iff the XNO was swept. The node binds this to its swapbook so the
	// MAKER side decrements the matched offer + records the trade on success — joined
	// to the ACTUAL on-chain SwapKey (the Fund tx's swap key), not the session nonce —
	// and RELEASES the offer reservation taken at AcceptInit time on failure, so both
	// counterparties' books converge. Optional.
	OnMakerDone func(s MakerSettlement, success bool)
}

// MakerSettlement is handed to OnMakerDone when a maker session terminates. It
// carries the public settlement facts a node needs to reconcile its order book +
// trade tape: the on-chain SwapKey (hex), the peer (taker) handle, and the agreed
// amounts. It NEVER carries any secret share.
type MakerSettlement struct {
	SwapID    [32]byte // the per-session id
	SwapKey   string   // hex on-chain OBX SwapOut key (the Fund tx key) — the tape join
	Peer      string   // taker's routing handle
	OBXAmount uint64
	XNOAmount *big.Int
}

// New builds a Coordinator. It does not start any sessions; the taker calls Take
// to open one, and the maker reacts to inbound Init envelopes via Deliver.
func New(cfg Config) (*Coordinator, error) {
	if cfg.Transport == nil {
		return nil, errors.New("swapnet: nil transport")
	}
	if cfg.Maker == nil && cfg.Taker == nil {
		return nil, errors.New("swapnet: a coordinator needs a maker and/or taker capability")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &Coordinator{
		tr:             cfg.Transport,
		maker:          cfg.Maker,
		taker:          cfg.Taker,
		stateDir:       cfg.StateDir,
		timeout:        cfg.Timeout,
		fee:            cfg.Fee,
		acceptInit:     cfg.AcceptInit,
		onMakerDone:    cfg.OnMakerDone,
		sessions:       make(map[[32]byte]*session),
		done:           make(chan struct{}),
	}, nil
}

// Stop signals all session goroutines to wind down and waits for them. Safe to
// call once; subsequent calls are no-ops.
func (c *Coordinator) Stop() {
	c.stopOnce.Do(func() { close(c.done) })
	c.wg.Wait()
}

// session is one in-flight swap. Inbound envelopes are pushed onto `in`; the
// driving goroutine selects on it. role is fixed at creation.
type session struct {
	c    *Coordinator // back-reference so a Session handle can read st under c.mu
	id   [32]byte
	role swapsession.Role
	pmu  sync.Mutex // guards peer (rebound from the p2p read goroutine on reconnect)
	peer string     // counterparty routing handle (current live connection address)
	in   chan *Envelope
	done  chan struct{} // closed when the driver exits
	err   error         // terminal error (if any), read after done
	swept bool          // maker: XNO swept / taker: claim mined → success

	// st points at the driving party's SwapState (the SAME object the Maker/Taker
	// mutates as it advances phases), so a snapshot read (ActiveSessions) reflects
	// the live phase + amounts. It is set once before the driver starts advancing
	// the state machine. Reads are racy-by-design (best-effort UI view), so the
	// snapshot copies only value fields under c.mu — see ActiveSessions.
	st      *swapsession.SwapState
	started int64 // unix seconds the session was registered (for "updated"/age)
}

func (s *session) getPeer() string  { s.pmu.Lock(); defer s.pmu.Unlock(); return s.peer }
func (s *session) setPeer(p string)  { s.pmu.Lock(); s.peer = p; s.pmu.Unlock() }

// sameHost reports whether two routing handles share a host (IP/onion), ignoring the
// port. A counterparty whose connection drops + reconnects mid-swap reappears under a
// new EPHEMERAL source port but the SAME host — so a SwapID match from the same host
// is the genuine peer reconnecting, not an injector.
func sameHost(a, b string) bool { return hostPart(a) == hostPart(b) }
func hostPart(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}

// statePath is where a session persists its SwapState.
func (c *Coordinator) statePath(id [32]byte) string {
	if c.stateDir == "" {
		return ""
	}
	return filepath.Join(c.stateDir, fmt.Sprintf("swap-%x.json", id))
}

// save persists st if a state dir is configured. A persistence error is logged
// (returned) but never aborts a swap mid-flight on its own — the in-memory state
// is authoritative for the live run; persistence only matters for crash-resume.
func (c *Coordinator) save(st *swapsession.SwapState) error {
	p := c.statePath(st.SwapID)
	if p == "" {
		return nil
	}
	return st.Save(p)
}

// register adds a session to the registry, rejecting a duplicate SwapID (replay
// / collision protection at the transport layer; the swapsession SwapID checks
// are the deeper backstop) and enforcing the F-A DoS caps: a global ceiling on
// total concurrent sessions and a per-peer ceiling on sessions with one
// counterparty. Both caps bound the `sessions` map and the per-session
// goroutines so a peer cannot flood the node into resource exhaustion (for a
// maker, each session also funds OBX on-chain — see startMaker).
func (c *Coordinator) register(s *session) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.sessions[s.id]; ok {
		return fmt.Errorf("swapnet: swap %x already in flight", s.id)
	}
	if config.SwapMaxSessions > 0 && len(c.sessions) >= config.SwapMaxSessions {
		return fmt.Errorf("swapnet: at session cap (%d) — refusing new swap", config.SwapMaxSessions)
	}
	if sp := s.getPeer(); config.SwapMaxSessionsPerPeer > 0 && sp != "" {
		n := 0
		for _, other := range c.sessions {
			if other.getPeer() == sp {
				n++
			}
		}
		if n >= config.SwapMaxSessionsPerPeer {
			return fmt.Errorf("swapnet: peer %s at per-peer session cap (%d) — refusing new swap",
				sp, config.SwapMaxSessionsPerPeer)
		}
	}
	if s.started == 0 {
		s.started = time.Now().Unix()
	}
	c.sessions[s.id] = s
	return nil
}

// setState binds the driving party's live SwapState to the session so a snapshot
// read reflects its current phase + amounts. Held under c.mu so ActiveSessions
// sees a consistent pointer.
func (c *Coordinator) setState(s *session, st *swapsession.SwapState) {
	c.mu.Lock()
	s.st = st
	c.mu.Unlock()
}

func (c *Coordinator) unregister(id [32]byte) {
	c.mu.Lock()
	delete(c.sessions, id)
	c.mu.Unlock()
}

func (c *Coordinator) lookup(id [32]byte) (*session, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.sessions[id]
	return s, ok
}

// Deliver routes one inbound directed envelope (received over p2p) to its
// session. fromPeer is the sender's routing handle. An Init for an UNKNOWN swap
// spins up a fresh MAKER session (if this node makes); any other unknown-swap
// envelope is dropped (no session to route to — reject unknown/replayed). This is
// the method a p2p OnSwapSession callback feeds.
func (c *Coordinator) Deliver(fromPeer string, raw []byte) {
	env, err := ParseEnvelope(raw)
	if err != nil {
		return // malformed: drop silently (no session to penalize here)
	}
	swapLog("Deliver kind=%d from peer=%q swap=%x", env.Kind, fromPeer, env.SwapID[:4])
	if s, ok := c.lookup(env.SwapID); ok {
		// F-C: bind inbound envelopes to the session's counterparty. The session
		// records the peer it is talking to (the taker's handle for a maker session,
		// the maker's handle for a taker session); an envelope from ANY OTHER peer is
		// dropped. Without this, any peer who learns an in-flight SwapID could inject a
		// KindAbort to force teardown, or flood the buffered `in` channel to starve the
		// real counterparty's message. SwapID alone is NOT an authenticator.
		if cur := s.getPeer(); fromPeer != cur {
			// F-C: the 32-byte SwapID is unguessable and only ever travels on this
			// DIRECTED (never-gossiped) transport, so it IS the authenticator — a third
			// party can't learn it. A long swap's P2P link can drop + reconnect mid-flight
			// (e.g. during the slow real-XNO lock), and the counterparty reappears under a
			// NEW ephemeral source port. A SwapID match from the SAME HOST is that genuine
			// reconnect: RE-BIND to it (so our replies route over the live connection)
			// instead of dropping, which used to freeze the swap at xno_lock/claim. Only a
			// DIFFERENT host (could be a griefer who somehow learned the id) is rejected.
			if sameHost(fromPeer, cur) {
				swapLog("REBIND swap=%x peer %q -> %q (counterparty reconnected)", env.SwapID[:4], cur, fromPeer)
				s.setPeer(fromPeer)
			} else {
				swapLog("DROP kind=%d: fromPeer=%q != session.peer=%q (F-C bind, diff host)", env.Kind, fromPeer, cur)
				return // not the counterparty for this swap → drop (griefing protection)
			}
		}
		// route to the live session. A non-blocking send: if the session's buffer is
		// full (a flood on one SwapID) we drop rather than stall the p2p read loop.
		select {
		case s.in <- env:
		default:
		}
		return
	}
	// Unknown swap. Only a brand-new Init to a making node opens a session.
	if env.Kind == KindInit && c.maker != nil {
		c.startMaker(fromPeer, env)
		return
	}
	// Anything else for an unknown swap is unroutable → drop (reject unknown/replay).
	swapLog("DROP kind=%d from peer=%q: unknown swap %x (no session)", env.Kind, fromPeer, env.SwapID[:4])
}

// ---- taker side -------------------------------------------------------------

// Take opens a swap as the TAKER against the maker reachable at peer, for the
// given amounts. It returns once the session goroutine has started; the caller
// waits on the returned session's completion via Wait. The SwapID is MINTED HERE
// from a fresh high-entropy nonce (commit.RandomScalar) — it is NOT derived from
// the public offer terms, so a third party watching the offer book cannot predict
// or precompute an in-flight SwapID and inject envelopes into the session (F-C
// depends on SwapIDs being unguessable as well as sender-bound). The OBX/XNO
// amounts must match the maker's offer terms. The caller reads the minted id via
// Session.ID.
func (c *Coordinator) Take(peer string, obxAmount uint64, xnoAmount *big.Int, fee uint64) (*Session, error) {
	if c.taker == nil {
		return nil, errors.New("swapnet: this coordinator has no taker capability")
	}
	// fresh, unpredictable SwapID (32B from a uniformly-random scalar). Retry on the
	// astronomically unlikely event of a registry collision with a live swap.
	var swapID [32]byte
	for attempt := 0; ; attempt++ {
		copy(swapID[:], commit.RandomScalar().Bytes())
		s := &session{c: c, id: swapID, role: swapsession.RoleTaker, peer: peer,
			in: make(chan *Envelope, 8), done: make(chan struct{})}
		err := c.register(s)
		if err == nil {
			tk := swapsession.NewTaker(swapID, obxAmount, xnoAmount, fee, c.taker.NewTakerOBX())
			c.setState(s, tk.State())
			c.wg.Add(1)
			go c.driveTaker(s, tk)
			return &Session{s: s}, nil
		}
		if attempt >= 4 {
			return nil, err
		}
	}
}

// driveTaker runs the taker state machine, sending/receiving over the transport.
func (c *Coordinator) driveTaker(s *session, tk *swapsession.Taker) {
	defer c.wg.Done()
	defer close(s.done)
	defer c.unregister(s.id)

	_ = c.save(tk.State())

	// 1) send Init.
	if err := c.send(s, KindInit, tk.Init().Serialize()); err != nil {
		s.err = fmt.Errorf("send Init: %w", err)
		return
	}

	// 2) await MakerCommit.
	env, err := c.recv(s)
	if err != nil {
		s.err = err
		return
	}
	mc, err := parseTaker(env, KindMakerCommit, func(b []byte) (any, error) {
		m, e := swapsession.ParseMakerCommit(b)
		return m, e
	})
	if err != nil {
		s.err = err
		return
	}
	if err := tk.HandleMakerCommit(mc.(*swapsession.MakerCommit)); err != nil {
		s.err = fmt.Errorf("HandleMakerCommit: %w", err)
		c.abort(s)
		return
	}
	_ = c.save(tk.State())

	// 3) await Funded → verify on-chain + lock XNO → send XNOLocked.
	env, err = c.recv(s)
	if err != nil {
		s.err = err
		return
	}
	fm, err := parseTaker(env, KindFunded, func(b []byte) (any, error) {
		m, e := swapsession.ParseFunded(b)
		return m, e
	})
	if err != nil {
		s.err = err
		return
	}
	// VerifyFundedAndLock fails with ErrFundingNotVisible when this taker simply has not
	// SYNCED the maker's funding block yet (it can lag the maker's miner). That is a
	// transient sync gap, not a swap failure — poll until the block arrives instead of
	// aborting (and stranding nothing: no XNO is locked until the funding verifies). Any
	// OTHER error is a real safe-leg refusal → abort. Bounded so a genuinely-missing
	// funding still aborts (then nothing is at risk; the taker never locked XNO).
	var locked *swapsession.XNOLocked
	for attempt := 0; ; attempt++ {
		locked, err = tk.VerifyFundedAndLock(c.taker.Nano(), fm.(*swapsession.Funded))
		if err == nil {
			break
		}
		if errors.Is(err, swapsession.ErrFundingNotVisible) && attempt < 60 {
			if attempt == 0 {
				swapLog("taker: funding not synced yet, polling…")
			}
			select {
			case <-c.done:
				s.err = err
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		// safe leg ordering refused to lock XNO; nothing at risk for the taker.
		s.err = fmt.Errorf("VerifyFundedAndLock: %w", err)
		c.abort(s)
		return
	}
	_ = c.save(tk.State())
	if err := c.send(s, KindXNOLocked, locked.Serialize()); err != nil {
		s.err = fmt.Errorf("send XNOLocked: %w", err)
		return
	}

	// 4) build claim request → send → await ClaimPreSig → finalize (mine claim).
	req, err := tk.BuildClaimRequest()
	if err != nil {
		s.err = fmt.Errorf("BuildClaimRequest: %w", err)
		return
	}
	if err := c.send(s, KindClaimRequest, req.Serialize()); err != nil {
		s.err = fmt.Errorf("send ClaimRequest: %w", err)
		return
	}
	env, err = c.recv(s)
	if err != nil {
		s.err = err
		return
	}
	ps, err := parseTaker(env, KindClaimPreSig, func(b []byte) (any, error) {
		m, e := swapsession.ParseClaimPreSig(b)
		return m, e
	})
	if err != nil {
		s.err = err
		return
	}
	aggPre, fullSig, err := tk.FinalizeClaim(ps.(*swapsession.ClaimPreSig))
	if err != nil {
		s.err = fmt.Errorf("FinalizeClaim: %w", err)
		return
	}
	_ = c.save(tk.State())

	// 5) OPTIONAL latency hint: relay the aggregate pre-sig + full sig. This is NO LONGER
	// a safety dependency — the maker extracts sA INDEPENDENTLY from the on-chain claim
	// using the ŝ_a it verified+stored at co-sign time (sA = S_full − ŝ_a − ŝ_b). A taker
	// that withholds, corrupts, or never sends this relay CANNOT freeze the maker's XNO
	// sweep (the griefing fix). We still send it as a courtesy so a healthy maker can
	// notice the claim a little sooner; the maker ignores its contents and reads the chain.
	done := claimDonePayload(aggPre, fullSig)
	if err := c.send(s, KindClaimDone, done); err != nil {
		// the taker already HAS its OBX (claim mined). The maker recovers sA from chain
		// regardless; a failed relay changes nothing, so this is not a taker-side failure.
		s.swept = true
		return
	}
	s.swept = true // taker success = OBX claimed.
}

// ---- maker side -------------------------------------------------------------

// startMaker spins up a maker session in response to an inbound Init. It is
// invoked from Deliver on the p2p read goroutine, so it must not block: it
// authorizes the Init (F-A), registers the session and launches the driver, then
// hands the Init envelope to it.
func (c *Coordinator) startMaker(peer string, initEnv *Envelope) {
	// F-A: do NOT auto-fund OBX for an unauthenticated Init. Parse it and run the
	// operator's AcceptInit gate FIRST; a nil gate denies all (no blind auto-fund).
	init, err := swapsession.ParseInit(initEnv.Payload)
	if err != nil {
		return // malformed Init → drop, fund nothing
	}
	if c.acceptInit == nil || !c.acceptInit(init, peer) {
		swapLog("startMaker DENY Init from peer=%q swap=%x (acceptInit=false)", peer, initEnv.SwapID[:4])
		// Tell the counterparty explicitly instead of silently dropping. Without
		// this, a denied Init (e.g. the quoted offer expired/changed between the
		// taker's quote and submit) left an honest taker's UI hung at "connecting
		// to maker…" forever with zero feedback — no error, no retry, no signal
		// anything was wrong. Best-effort/advisory only (same as abort()): no
		// session exists yet, nothing was funded, there is nothing to protect here.
		_ = c.tr.Send(peer, &Envelope{SwapID: initEnv.SwapID, Kind: KindAbort, Payload: nil})
		return // not an accepted offer / no opt-in → drop, fund nothing
	}
	swapLog("startMaker ACCEPT Init from peer=%q swap=%x", peer, initEnv.SwapID[:4])
	s := &session{c: c, id: initEnv.SwapID, role: swapsession.RoleMaker, peer: peer,
		in: make(chan *Envelope, 8), done: make(chan struct{})}
	if err := c.register(s); err != nil {
		return // duplicate swap id / at a session cap → ignore (replay + DoS protection)
	}
	c.wg.Add(1)
	go c.driveMaker(s, initEnv)
}

// driveMaker runs the maker state machine.
func (c *Coordinator) driveMaker(s *session, initEnv *Envelope) {
	defer c.wg.Done()
	defer close(s.done)
	defer c.unregister(s.id)

	init, err := swapsession.ParseInit(initEnv.Payload)
	if err != nil {
		s.err = fmt.Errorf("parse Init: %w", err)
		return
	}
	obx := c.maker.NewMakerOBX()
	mk := swapsession.NewMaker(s.id, init.OBXAmount, init.XNOAmount, c.fee,
		c.maker.SweepDest(), obx)
	c.setState(s, mk.State())

	// Maker-side book reconciliation fires EXACTLY ONCE on terminal, regardless of
	// which return path is taken (success, refund, abort), so the node can commit the
	// trade on success or release the AcceptInit reservation on failure. s.swept is
	// the success flag (set just before this driver returns on a swept session).
	if c.onMakerDone != nil {
		defer func() {
			st := mk.State()
			c.onMakerDone(MakerSettlement{
				SwapID:    s.id,
				SwapKey:   hex.EncodeToString(st.SwapKey),
				Peer:      s.getPeer(),
				OBXAmount: st.OBXAmount,
				XNOAmount: cloneBig(st.XNOAmount),
			}, s.swept)
		}()
	}

	// 1) HandleInit → MakerCommit.
	mc, err := mk.HandleInit(init)
	if err != nil {
		s.err = fmt.Errorf("HandleInit: %w", err)
		c.abort(s)
		return
	}
	_ = c.save(mk.State())
	if err := c.send(s, KindMakerCommit, mc.Serialize()); err != nil {
		s.err = fmt.Errorf("send MakerCommit: %w", err)
		return
	}

	// 2) Fund OBX FIRST → send Funded. Honor the F-1 claim-window invariant when
	// choosing the unlock height (height + SwapTimelockWindow), clamped up to the
	// minimum claimable window the session itself enforces.
	unlock := chooseUnlockHeight(obx)
	funded, err := mk.Fund(unlock)
	if err != nil {
		s.err = fmt.Errorf("Fund: %w", err)
		c.abort(s)
		return
	}
	_ = c.save(mk.State())
	if err := c.send(s, KindFunded, funded.Serialize()); err != nil {
		s.err = fmt.Errorf("send Funded: %w", err)
		// OBX is funded but the taker never heard; arm refund.
		c.makerRefund(s, mk)
		return
	}

	// 3) await XNOLocked → confirm it pays the joint account the agreed amount.
	env, err := c.recv(s)
	if err != nil {
		// taker stalled before locking XNO → refund the funded OBX.
		s.err = err
		c.makerRefund(s, mk)
		return
	}
	xl, err := parseMaker(env, KindXNOLocked, func(b []byte) (any, error) {
		m, e := swapsession.ParseXNOLocked(b)
		return m, e
	})
	if err != nil {
		s.err = err
		c.makerRefund(s, mk)
		return
	}
	// ConfirmXNOLock fails with ErrXNOLockNotConfirmed when the taker's real XNO lock has
	// been broadcast but Nano has not cemented it yet (a few-second delay). That is
	// transient — POLL for confirmation instead of aborting+refunding, which would strand
	// the taker's just-locked XNO. WRONG-account / WRONG-amount errors are terminal (a
	// malicious or buggy lock) → abort + refund the OBX. Bounded so a lock that never
	// confirms still aborts (then refund makes the maker whole).
	{
		var cerr error
		for attempt := 0; ; attempt++ {
			cerr = mk.ConfirmXNOLock(c.maker.Nano(), xl.(*swapsession.XNOLocked))
			if cerr == nil {
				break
			}
			if errors.Is(cerr, swapsession.ErrXNOLockNotConfirmed) && attempt < 90 {
				if attempt == 0 {
					swapLog("maker: taker XNO lock not cemented yet, polling…")
				}
				select {
				case <-c.done:
					s.err = cerr
					return
				case <-time.After(2 * time.Second):
				}
				continue
			}
			s.err = fmt.Errorf("ConfirmXNOLock: %w", cerr)
			c.abort(s)
			c.makerRefund(s, mk)
			return
		}
	}
	_ = c.save(mk.State())

	// 4) await ClaimRequest → co-sign → send ClaimPreSig.
	env, err = c.recv(s)
	if err != nil {
		s.err = err
		c.makerRefund(s, mk)
		return
	}
	cr, err := parseMaker(env, KindClaimRequest, func(b []byte) (any, error) {
		m, e := swapsession.ParseClaimRequest(b)
		return m, e
	})
	if err != nil {
		s.err = err
		c.makerRefund(s, mk)
		return
	}
	presig, err := mk.CoSignClaim(cr.(*swapsession.ClaimRequest))
	if err != nil {
		s.err = fmt.Errorf("CoSignClaim: %w", err)
		c.abort(s)
		c.makerRefund(s, mk)
		return
	}
	_ = c.save(mk.State())
	if err := c.send(s, KindClaimPreSig, presig.Serialize()); err != nil {
		s.err = fmt.Errorf("send ClaimPreSig: %w", err)
		c.makerRefund(s, mk)
		return
	}

	// 5) recover sA and sweep the XNO — INDEPENDENTLY of the taker. A malicious taker can
	// mine the claim (taking the OBX and publishing on-chain the full claim sig that bakes
	// in sA) and then WITHHOLD/CORRUPT/never-send the KindClaimDone relay to try to strand
	// the maker's XNO. The maker no longer cares: it scrapes the on-chain full sig and
	// extracts sA = S_full − ŝ_a − ŝ_b, where ŝ_a was verified+stored at co-sign time and
	// ŝ_b is recomputed. NO taker cooperation is on the maker's fund-recovery path.
	if err := c.makerSweep(s, mk, obx); err != nil {
		s.err = err
		// audit fix: a taker that stalls AFTER the maker co-signed previously left the
		// funded OBX neither swept nor refunded (stranded). Once the claim window has
		// PROVABLY closed (errClaimWindowClosed: chain height reached UnlockHeight with no
		// claim mined, so the taker can no longer claim), reclaim the OBX via the timelock
		// refund. Any OTHER error (coordinator stopping) leaves it to crash-resume.
		if errors.Is(err, errClaimWindowClosed) {
			c.makerRefund(s, mk)
		}
		return
	}
	_ = c.save(mk.State())
	s.swept = true // maker success = XNO swept. (The deferred onMakerDone reconciles
	// the book/tape using this flag — see the top of driveMaker.)
}

// cloneBig returns a non-nil copy of v (nil → 0) so callers never share or nil-deref
// the maker's amount field.
func cloneBig(v *big.Int) *big.Int {
	if v == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(v)
}

// makerSweep recovers the adaptor secret and sweeps the XNO after the maker has
// co-signed — with ZERO dependency on taker cooperation. The maker waits for the
// claim to appear ON-CHAIN (it must, for the taker to take the OBX), scrapes the
// published full claim signature, and extracts sA INDEPENDENTLY:
//
//	sA = S_full − ŝ_a − ŝ_b
//
// ŝ_a is the taker's pre-sig half the maker verified+stored in CoSignClaim, ŝ_b the
// maker recomputes from its own b, rb. The maker NEVER needs the taker's KindClaimDone
// relay: a taker that claims the OBX and then withholds/corrupts (or never sends) the
// relay can no longer freeze the maker's XNO. The relay, if it still arrives, is at
// most a latency hint that the claim is mined — we drain such frames but ignore their
// contents and always extract from the chain.
//
// GRIEFING FIX: this is the only fund-recovery path; SweepXNOIndependent re-verifies
// sA·G==Sa ∧ (sA+sB)·G==account before paying out, so even a maliciously crafted
// (but pre-verified) ŝ_a cannot move XNO to a wrong place — it would only error.
func (c *Coordinator) makerSweep(s *session, mk *swapsession.Maker, obx swapsession.MakerOBX) error {
	// Poll the OBX chain for the mined claim. The taker MUST publish it on-chain to take
	// the OBX (revealing the full sig that bakes in sA), so a sweep succeeds as soon as the
	// claim is mined — independent of any off-chain relay. We drain inbound frames so a
	// flood on s.in cannot block; their contents are irrelevant to safety now.
	//
	// audit fix: the deadline is HEIGHT-based (UnlockHeight), NOT a short time-based one.
	// A taker can claim LATE (after a few minutes but before the on-chain claim window
	// closes), and sweeping must ALWAYS win when a claim exists (it reveals sA). Only once
	// the chain passes UnlockHeight with NO claim mined — at which point the taker can no
	// longer produce a valid claim (claim valid iff height + margin <= UnlockHeight) — is
	// the OBX provably refundable. The old code gave up after a short timer and returned an
	// error without arming the refund, stranding the maker's OBX; this returns a distinct
	// errClaimWindowClosed so the caller refunds, and never refunds while a claim is still
	// possible (which would risk losing both legs to a late claim).
	unlock := mk.State().UnlockHeight
	poll := time.NewTicker(time.Second)
	defer poll.Stop()
	for {
		if err := c.sweepFromChain(mk, obx); err == nil {
			return nil // taker claimed → sA extracted from chain → XNO swept
		}
		if obx.Height() >= unlock {
			return errClaimWindowClosed // window closed, no claim → OBX refundable
		}
		select {
		case <-c.done:
			return errors.New("swapnet: coordinator stopping before sweep")
		case <-s.in:
			// drain junk/relay/abort frames; the claim is read from the chain, not here.
		case <-poll.C:
		}
	}
}

// errClaimWindowClosed reports that the maker's post-co-sign watcher reached UnlockHeight
// with no taker claim mined, so the funded OBX is now refundable (see makerSweep).
var errClaimWindowClosed = errors.New("swapnet: claim window closed without a taker claim — OBX refundable")

// sweepFromChain scrapes the mined claim for swapKey from the OBX chain (the published
// full claim signature) and extracts sA INDEPENDENTLY via Maker.SweepXNOIndependent
// (sA = S_full − ŝ_a − ŝ_b), which re-verifies sA·G==Sa and (sA+sB)·G==account before
// paying out, so a wrong scrape only errors. Every input is on-chain (S_full) or held
// durably by the maker (ŝ_a from CoSignClaim, b/rb) — NO taker cooperation is needed.
func (c *Coordinator) sweepFromChain(mk *swapsession.Maker, obx swapsession.MakerOBX) error {
	st := mk.State()
	fullSigBytes, _, ok := obx.FindSwapSpend(st.SwapKey)
	if !ok {
		return fmt.Errorf("swapnet: no mined claim found on-chain for swap %x — cannot sweep yet", st.SwapID)
	}
	fullSig, err := commit.ParseFullSig(fullSigBytes)
	if err != nil {
		return fmt.Errorf("swapnet: on-chain claim sig malformed: %w", err)
	}
	if err := mk.SweepXNOIndependent(c.maker.Nano(), fullSig); err != nil {
		return fmt.Errorf("swapnet: SweepXNOIndependent (chain-scraped full sig): %w", err)
	}
	return nil
}

// makerRefund arms the OBX refund after the timelock when a swap aborts post-fund.
// The refund spend itself waits for the unlock height (MineRefund mines forward),
// so this is the liveness backstop for a stalled counterparty.
func (c *Coordinator) makerRefund(s *session, mk *swapsession.Maker) {
	if err := mk.Refund(); err != nil {
		// already settled (claimed/swept) or nothing funded → nothing to do.
		return
	}
	_ = c.save(mk.State())
}

// Resume re-drives persisted, non-terminal MAKER sessions after a restart (crash-resume).
// The audit found SwapState was saved but never LOADED, so a node that crashed after
// funding (or co-signing) an OBX SwapOut came back having forgotten the swap — the funded
// OBX was then neither swept nor refunded (stranded). Resume reconstructs each maker via
// swapsession.ResumeMaker (byte-identical, carrying the durable co-sign guard + stored ŝ_a)
// and runs the peer-INDEPENDENT chain-based sweep-or-refund watcher: if the taker's claim
// is (or becomes) on-chain it sweeps the XNO (sA is read from the chain), otherwise it
// reclaims the OBX once the claim window closes. Terminal (swept/refunded) and pre-fund
// (init) states are cleaned up. Call once after New, before serving new swaps. Taker states
// are left untouched here — a taker's downside is bounded by leg ordering, and re-driving a
// taker needs a live peer; it simply re-initiates if it wants to retry.
func (c *Coordinator) Resume() {
	if c.stateDir == "" || c.maker == nil {
		return
	}
	entries, err := os.ReadDir(c.stateDir)
	if err != nil {
		swapLog("resume: cannot read state dir %s: %v", c.stateDir, err)
		return
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "swap-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(c.stateDir, name)
		st, err := swapsession.LoadState(path)
		if err != nil {
			swapLog("resume: bad state %s: %v", name, err)
			continue
		}
		if st.Role != swapsession.RoleMaker {
			continue
		}
		switch st.Phase {
		case swapsession.PhaseSwept, swapsession.PhaseRefunded, swapsession.PhaseInit:
			_ = os.Remove(path) // terminal or nothing funded → clean up
			continue
		}
		c.wg.Add(1)
		go c.resumeMakerRecovery(st)
	}
}

// resumeMakerRecovery runs the chain-based OBX-recovery watcher for one persisted maker
// session (phase funded/xno_lock/claimed). It is peer-independent: makerSweep reads the
// taker's claim from the OBX chain and, failing that until the claim window closes, the
// refund reclaims the OBX. A minimal session (no live peer; s.in never receives) is enough.
func (c *Coordinator) resumeMakerRecovery(st *swapsession.SwapState) {
	defer c.wg.Done()
	obx := c.maker.NewMakerOBX()
	mk, err := swapsession.ResumeMaker(st, obx)
	if err != nil {
		swapLog("resume %x: %v", st.SwapID, err)
		return
	}
	s := &session{c: c, id: st.SwapID, role: swapsession.RoleMaker, in: make(chan *Envelope), st: mk.State()}
	// F-C: without this, a replayed Init for the same SwapID during recovery bypasses
	// register()'s in-flight dedupe (this session was never in c.sessions) and falls through
	// to startMaker, which funds OBX a second time for the same swap. Registering routes any
	// such replay to THIS session instead (dropped there as a peer/host mismatch).
	if err := c.register(s); err != nil {
		swapLog("resume %x: register: %v (continuing recovery unregistered)", st.SwapID, err)
	} else {
		defer c.unregister(s.id)
	}
	swapLog("resume: re-driving maker %x from phase %s", st.SwapID, st.Phase)
	if err := c.makerSweep(s, mk, obx); err != nil {
		if errors.Is(err, errClaimWindowClosed) {
			c.makerRefund(s, mk)
		}
		return
	}
	_ = c.save(mk.State())
	// success: XNO swept, the swap is complete — drop the persisted state.
	if p := c.statePath(st.SwapID); p != "" {
		_ = os.Remove(p)
	}
}

// ---- transport helpers ------------------------------------------------------

// send wraps a serialized swapsession message in an envelope and ships it to the
// session's counterparty.
func (c *Coordinator) send(s *session, kind Kind, payload []byte) error {
	env := &Envelope{SwapID: s.id, Kind: kind, Payload: payload}
	peer := s.getPeer()
	if err := c.tr.Send(peer, env); err == nil {
		swapLog("send kind=%d to peer=%q ok", kind, peer)
		return nil
	} else {
		// The counterparty's connection can drop mid-swap (e.g. our own block flood while
		// it is busy with the slow XNO lock) and it then reconnects under a NEW ephemeral
		// port. The counterparty may be BLOCKED waiting for exactly this message, so no
		// inbound frame will arrive to trigger a Deliver-side rebind — WE must re-resolve
		// its live handle and retry, polling briefly while it reconnects. Aborting an
		// otherwise-healthy swap here is what previously stranded the XNO leg. Bounded so
		// a genuinely-gone peer still fails (then the funder's timeout+refund kicks in).
		lastErr := err
		r, ok := c.tr.(PeerResolver)
		if !ok {
			swapLog("send kind=%d to peer=%q FAILED (no resolver): %v", kind, peer, err)
			return err
		}
		for attempt := 0; attempt < 20; attempt++ {
			if live, found := r.ResolvePeer(peer); found {
				s.setPeer(live)
				if e := c.tr.Send(live, env); e == nil {
					swapLog("send kind=%d ok after reconnect (%q -> %q, attempt %d)", kind, peer, live, attempt)
					return nil
				} else {
					lastErr = e
				}
			}
			select {
			case <-c.done:
				return lastErr
			case <-time.After(2 * time.Second):
			}
		}
		swapLog("send kind=%d to peer=%q FAILED after reconnect retries: %v", kind, peer, lastErr)
		return lastErr
	}
}

// abort best-effort notifies the counterparty that this side is giving up. Purely
// advisory; safety never depends on it (the funder's timeout+refund is the real
// backstop).
func (c *Coordinator) abort(s *session) {
	_ = c.send(s, KindAbort, nil)
}

// recv blocks for the next inbound envelope on this session, honoring the
// per-phase timeout and coordinator shutdown. A KindAbort from the peer, a
// timeout, or shutdown all surface as an error so the driver can refund/clean up.
func (c *Coordinator) recv(s *session) (*Envelope, error) {
	timer := time.NewTimer(c.timeout)
	defer timer.Stop()
	for {
		select {
		case <-c.done:
			return nil, errors.New("swapnet: coordinator stopping")
		case <-timer.C:
			return nil, fmt.Errorf("swapnet: swap %x stalled past %s deadline", s.id, c.timeout)
		case env := <-s.in:
			if env.Kind == KindAbort {
				return nil, errors.New("swapnet: counterparty aborted the swap")
			}
			return env, nil
		}
	}
}

// ---- message parse helpers --------------------------------------------------

// parseTaker / parseMaker assert the envelope kind then run the supplied parser,
// surfacing a mismatch as an error (so an out-of-order / wrong-kind message aborts
// rather than being mis-handled).
func parseTaker(env *Envelope, want Kind, parse func([]byte) (any, error)) (any, error) {
	return parseKind(env, want, parse)
}
func parseMaker(env *Envelope, want Kind, parse func([]byte) (any, error)) (any, error) {
	return parseKind(env, want, parse)
}
func parseKind(env *Envelope, want Kind, parse func([]byte) (any, error)) (any, error) {
	if env.Kind != want {
		return nil, fmt.Errorf("swapnet: expected kind %d, got %d", want, env.Kind)
	}
	v, err := parse(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("swapnet: parse kind %d: %w", want, err)
	}
	return v, nil
}

// ---- claim-done relay (transport-level, not a swapsession message) ----------

const (
	// KindClaimDone is the taker's OPTIONAL final relay to the maker: the aggregate
	// pre-signature (R,S) and the published full claim signature. Since the griefing
	// fix it is a PURE LATENCY HINT — the maker no longer uses it for safety. The maker
	// extracts sA INDEPENDENTLY from the on-chain claim (sA = S_full − ŝ_a − ŝ_b, with
	// ŝ_a verified+stored at co-sign time), so withholding or corrupting this relay
	// CANNOT freeze the maker's XNO sweep. It carries only on-chain-observable data and
	// adds no protocol trust; the maker ignores its contents and reads the chain.
	KindClaimDone Kind = 8
)

// claimDonePayload encodes (presig.R || presig.S || fullSig serialized).
func claimDonePayload(presig *commit.AdaptorSig, fullSig *commit.FullSig) []byte {
	b := make([]byte, 0, 32+32+64)
	b = append(b, padOrTrim(presig.R, 32)...)
	b = append(b, padOrTrim(presig.S, 32)...)
	b = append(b, fullSig.Serialize()...)
	return b
}

func parseClaimDone(b []byte) (*commit.AdaptorSig, *commit.FullSig, error) {
	if len(b) != 32+32+64 {
		return nil, nil, errors.New("swapnet: bad ClaimDone payload")
	}
	pre := &commit.AdaptorSig{
		R: append([]byte(nil), b[0:32]...),
		S: append([]byte(nil), b[32:64]...),
	}
	full, err := commit.ParseFullSig(b[64:])
	if err != nil {
		return nil, nil, err
	}
	return pre, full, nil
}

func padOrTrim(p []byte, n int) []byte {
	if len(p) == n {
		return p
	}
	out := make([]byte, n)
	copy(out, p)
	return out
}

// ---- misc helpers -----------------------------------------------------------

// chooseUnlockHeight picks the maker's OBX unlock height honoring the F-1
// claim-window invariant: height + SwapTimelockWindow, but never below the
// minimum claimable window (SwapReorgMargin + SwapMinClaimWindow) that Maker.Fund
// itself enforces. Using the larger of the two keeps an honest, comfortably-open
// claim window regardless of how the consensus knobs are tuned in tests.
func chooseUnlockHeight(obx swapsession.MakerOBX) uint64 {
	h := obx.Height()
	window := config.SwapTimelockWindow
	if min := config.SwapReorgMargin + config.SwapMinClaimWindow; window < min+1 {
		window = min + 1
	}
	return h + window
}
