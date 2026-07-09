// Package p2p implements a hardened gossip network for Obscura: peers exchange
// blocks and transactions, sync the chain, and auto-discover one another via
// PEX (getaddr/addr) plus a persistent address book. Hardening includes a
// magic/version handshake, read/write deadlines, peer/connection caps, per-IP
// limits, ban scoring, and backoff-with-jitter dialing.
package p2p

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	"obscura/pkg/block"
	"obscura/pkg/chain"
	"obscura/pkg/config"
	"obscura/pkg/mempool"
	"obscura/pkg/swapbook"
	"obscura/pkg/tx"
)

// p2pDebug enables verbose block-sync tracing (OBX_P2P_DEBUG=1) for diagnosing
// multi-machine sync stalls. Off by default.
var p2pDebug = os.Getenv("OBX_P2P_DEBUG") != ""

// p2pNoBan (OBX_P2P_NO_BAN=1) disables the PERSISTENT 1-hour peer ban. Abusive
// connections are still dropped, but no IP lockout is recorded, so honest peers —
// our own auto-liquidity mesh and community nodes — reconnect immediately instead
// of being locked out for an hour. This is a LOCAL connectivity policy only: it does
// not change the wire protocol or anything a peer sees on the network, so it stays
// fully backward-compatible with old-binary nodes. Off by default.
var p2pNoBan = os.Getenv("OBX_P2P_NO_BAN") != ""

func p2pLog(format string, a ...any) {
	if p2pDebug {
		log.Printf("[p2p] "+format, a...)
	}
}

// message types
const (
	msgHello     = 1
	msgTip       = 2
	msgGetTip    = 3
	msgGetBlk    = 4
	msgBlock     = 5
	msgTx        = 6
	msgGetAddr   = 7
	msgAddr      = 8
	msgStemTx    = 9  // Dandelion++ stem-phase transaction (private relay)
	msgSwapOffer = 10 // a swap order-book offer (gossiped)
	msgGetOffers = 11 // request the peer's current offers

	// msgSwapSession carries one DIRECTED two-party atomic-swap session message
	// (pkg/swapsession) to a SPECIFIC counterparty peer — it is NOT gossiped. The
	// payload is opaque to p2p (a pkg/swapnet envelope: SwapID + Kind + the
	// serialized swapsession blob); routing to the right in-flight session by SwapID
	// is the coordinator's job. Unlike offers, this is point-to-point: the maker and
	// taker of a single swap exchange these only with each other. (Block: swap P2P
	// transport.)
	msgSwapSession = 12

	// snapshot fast-sync (pkg/p2p/snapsync.go): a far-behind node fast-forwards via the
	// peer's PoW-verified transfer snapshot instead of re-verifying every block.
	msgGetSnapshot = 13 // request the peer's transfer snapshot (chunked reply)
	msgSnapshot    = 14 // one chunk: [4B seq][4B total][8B height][chunk bytes]
)

// protocol / safety limits
const (
	protocolVersion = 2 // v2: hello carries advertised + peer-observed address (self-discovery)
	maxPeers        = 32
	maxInboundPerIP = 3

	// SoftwareVersion is this node's release version, advertised in the hello trailer so
	// the network can report a version distribution (how many nodes run each build). It is
	// appended as a backward-compatible trailer, so old peers (which never read it) keep
	// interoperating. Bump on release.
	SoftwareVersion = "1.0.0"

	// audit fix (eclipse, well-behaved flood): a single /16 with many distinct IPs,
	// each under maxInboundPerIP and never misbehaving (so the group ban-score never
	// trips), could otherwise fill the inbound table. Cap inbound CONNECTIONS per /16
	// group, and RESERVE outbound slots so an inbound flood can never starve the
	// node's own outbound dialling (the only links an attacker cannot pre-position).
	maxInboundPerGroup = 4                           // max concurrent inbound conns from one /16
	reservedOutbound   = 8                           // inbound is capped below maxPeers by this many
	maxInbound         = maxPeers - reservedOutbound // = 24; leaves 8 slots for outbound
	targetOutbound     = 8                           // outbound links the node actively maintains
	maxMsgBytes        = config.MaxBlockBytes + 4096
	readIdleTimeout    = 120 * time.Second
	writeTimeout       = 30 * time.Second
	banThreshold       = 20 // misbehavior points before disconnect+ban

	// --- audit fix: persistent per-group ban score + per-peer rate limiting ---
	// A per-connection score (peer.score) resets on reconnect, so an attacker could
	// dodge bans by cycling connections. We additionally keep a per-IP-group (/16)
	// score that PERSISTS across reconnects for the node's lifetime, with linear
	// time-decay so honest peers eventually recover. (audit: ban-score reset on reconnect)
	groupBanThreshold = 100         // accumulated group score that triggers an IP ban
	groupScoreDecay   = 1.0         // points recovered per minute of good behavior
	groupBanDuration  = int64(3600) // seconds an offending IP group stays banned

	// Per-peer inbound token bucket: caps the *rate* of messages a single peer may
	// send, preventing getblocks/getaddr/offer amplification + flood DoS. A peer that
	// drains the bucket is penalized and (on repeat abuse) banned. (audit: no rate limit)
	rateBucketCap    = 200.0 // burst capacity (tokens)
	rateRefillPerSec = 50.0  // sustained inbound msgs/sec allowed
	rateAbusePenalty = 6     // misbehavior points charged when a peer overruns its bucket
)

// networkMagic ties the wire protocol to this network (prevents cross-network /
// cross-fork connections corrupting state).
var networkMagic = func() uint32 {
	h := uint32(2166136261)
	for _, b := range []byte(config.NetworkSeed) {
		h = (h ^ uint32(b)) * 16777619
	}
	return h
}()

type peer struct {
	conn       net.Conn
	wmu        sync.Mutex // serializes writes to conn (prevents framing corruption)
	score      int        // HARD misbehavior (malformed/abuse) → persistent IP/group ban
	softScore  int        // SOFT, connection-local (fork/sync block-validation) → drop only, NO persistent ban
	outbound   bool
	listen     string // peer's advertised listen address (for PEX)
	version    string // peer's advertised software version (hello trailer; "" if un-upgraded)
	bestHeight uint64 // highest chain height this peer has advertised (hello + msgTip); advisory, like version

	// audit fix: per-peer inbound token bucket (rate limiting). Guarded by Node.mu.
	tokens   float64 // current tokens; one consumed per inbound message
	lastFill time.Time
}

// Node is a p2p network node.
type Node struct {
	addr  string
	chain *chain.Chain
	mp    *mempool.Mempool
	book  *AddrBook

	mu    sync.Mutex
	peers map[string]*peer // remoteAddr -> peer
	bans  map[string]int64 // ip -> unban unix time

	// audit fix: ban score keyed by IP group (/16), persisting across reconnects for
	// the node's lifetime with linear time-decay. Defeats ban-evasion-by-reconnect.
	// Guarded by mu.
	groupScores map[string]*groupScore // ipGroup -> accumulated score

	ln       net.Listener
	done     chan struct{}
	stopOnce sync.Once

	dialer         Dialer                      // outbound transport (clearnet or Tor)
	advMu          sync.RWMutex                // guards advertiseAddr / advertiseFixed / extVotes
	advertiseAddr  string                      // address announced to peers (public IP / .onion under Tor)
	advertiseFixed bool                        // true if pinned explicitly (operator/Tor) → no auto-learn
	extVotes       map[string]map[string]int64 // candidate addr -> reporter /16 group -> last-seen unix sec (anti-poison self-discovery; aged+bounded, see discovery.go)
	onionOnly      bool                        // Tor mode: only store/relay .onion peer addresses

	obook *swapbook.Book // gossiped XMR↔OBX swap order book

	// offerProv is a best-effort maker-pubkey -> source-peer directory built as
	// offers gossip in (msgSwapOffer / msgGetOffers replies): it records WHICH peer
	// relayed each maker's offer so /swaps/take can route the swap Init to that
	// maker's peer instead of blindly picking PeerAddrs()[0]. Guarded by provMu.
	//
	// HONEST LIMIT: this is RELAY provenance, not cryptographic origin proof — under
	// gossip the recorded peer is the LAST hop that forwarded the offer, which on a
	// multi-hop mesh may be a relay rather than the maker itself. On the small
	// devnet/direct-peer topologies this targets (the maker is a directly-connected
	// peer) the last hop IS the maker. A signed maker-contact field in the offer is
	// the full fix (deferred). The explicit ?peer= override always takes precedence.
	provMu    sync.Mutex
	offerProv map[string]string // hex(maker pubkey) -> source peer remote addr

	// Dandelion++ tx-origin privacy
	dandelion  bool
	stemMu     sync.Mutex
	stemPeer   *peer             // current epoch's stem successor (outbound)
	fluffMode  bool              // audit fix: per-epoch per-node stem/fluff decision (Dandelion++), not a per-tx coin flip
	fluffed    map[[32]byte]bool // txids already fluffed (idempotent fail-safe + loop stop)
	fluffedOld map[[32]byte]bool // previous generation (bounds memory; see rememberFluffedLocked)
	// audit: SECURITY_AUDIT_2026-07-01 — bounded per-hop black-hole embargo registry.
	// EVERY stem relayer (not just the origin) records each relayed tx here with an
	// independent random fluff deadline; embargoSweepLoop fluffs any entry whose
	// deadline expired without the tx being seen fluffed by the network. Guarded by
	// stemMu, lazily initialised in armEmbargo, capped at maxPendingEmbargo.
	pendingEmbargo map[[32]byte]*embargoEntry

	// snapshot fast-sync inbound reassembly (pkg/p2p/snapsync.go). Guarded by snapMu.
	snapMu   sync.Mutex
	snapXfer *snapXfer

	OnBlock func(*block.Block)

	// OnSwapSession, if set, is invoked for every inbound DIRECTED swap-session
	// message (msgSwapSession). fromPeer is the sending peer's remote address (the
	// handle SendSwapSession routes replies back to). The payload is the opaque
	// coordinator envelope (pkg/swapnet). The callback runs on the peer's read
	// goroutine, so it must not block; the coordinator hands work off to its own
	// session goroutine. (Block: swap P2P transport.)
	OnSwapSession func(fromPeer string, payload []byte)
}

// groupScore is a time-decaying misbehavior accumulator for an IP group (/16).
// (audit fix: persistent ban score across reconnects)
type groupScore struct {
	score   float64
	updated time.Time
}

// NewNode creates a node bound to listenAddr with an address book at bookPath.
func NewNode(listenAddr string, c *chain.Chain, mp *mempool.Mempool, bookPath string) *Node {
	return &Node{
		addr:        listenAddr,
		chain:       c,
		mp:          mp,
		book:        NewAddrBook(bookPath),
		peers:       make(map[string]*peer),
		bans:        make(map[string]int64),
		groupScores: make(map[string]*groupScore),
		done:        make(chan struct{}),
		dandelion:   true,
		fluffed:     make(map[[32]byte]bool),
		dialer:      clearnetDialer{timeout: 8 * time.Second},
		obook:       swapbook.NewBook(),
		offerProv:   make(map[string]string),
	}
}

// PeerForMaker returns the source peer that most recently relayed a live offer
// from maker (the maker-pubkey -> peer directory), so a taker can route the swap
// Init to the maker's peer rather than guessing. ok is false if no offer from this
// maker has been seen (the caller should then require an explicit ?peer=).
func (n *Node) PeerForMaker(maker []byte) (string, bool) {
	if len(maker) != 32 {
		return "", false
	}
	key := hex.EncodeToString(maker)
	n.provMu.Lock()
	defer n.provMu.Unlock()
	p, ok := n.offerProv[key]
	return p, ok
}

// recordOfferProvenance remembers that `from` relayed an offer made by `maker`, so
// PeerForMaker can later resolve the maker's peer. Best-effort + last-writer-wins;
// it is only a routing hint (the swap's own F-C counterparty binding is the real
// authenticator). A self-relayed offer (from == our own advertise addr) is skipped
// so a maker node does not record ITSELF as the route to its own offers.
func (n *Node) recordOfferProvenance(maker []byte, from string) {
	if len(maker) != 32 || from == "" {
		return
	}
	n.provMu.Lock()
	n.offerProv[hex.EncodeToString(maker)] = from
	n.provMu.Unlock()
}

// PostOffer adds a locally-created swap offer to the book and gossips it.
func (n *Node) PostOffer(o *swapbook.Offer) error {
	if _, err := n.obook.Add(o); err != nil {
		return err
	}
	// Gossip ASYNC: the offer is already in the local book (the caller's success
	// condition), so a back-pressured peer socket must never stall the caller — the
	// same reasoning as BroadcastBlock. Synchronous broadcast here made the RPC
	// /offer POST block past the website proxy's timeout when a peer's send buffer
	// was full, surfacing as a spurious "node unreachable" on a sell that actually
	// posted (live incident 2026-07-06). Peers also converge via periodic offer
	// gossip / msgGetOffers, so a dropped relay is self-healing.
	go n.broadcast(msgSwapOffer, o.Serialize(), nil)
	return nil
}

// Offers returns the current swap order book.
func (n *Node) Offers() []*swapbook.Offer { return n.obook.List() }

// MakerOffers returns the live offers in the book made by the given maker pubkey.
// Used by the node's auto-liquidity loop to count its own outstanding auto-offers.
func (n *Node) MakerOffers(maker []byte) []*swapbook.Offer { return n.obook.MakerOffers(maker) }

// Liquidity aggregates the live order book per directed pair (Σ give/get, offer +
// maker counts, best rate). Passthrough to the book for the RPC /liquidity route.
func (n *Node) Liquidity() ([]swapbook.PairLiquidity, int, int) { return n.obook.Liquidity() }

// Cancel removes a maker-authenticated offer from this node's book (the cancel is
// best-effort and local; gossiped copies expire by TTL). Passthrough to the book
// for the RPC POST /offer/cancel route.
func (n *Node) Cancel(offerID [32]byte, sig []byte) error { return n.obook.Cancel(offerID, sig) }

// Quote prices a taker giving giveSize of giveAsset for getAsset against the live
// book (depth-aware VWAP). Passthrough to the book for the RPC GET /quote route.
func (n *Node) Quote(giveAsset, getAsset string, giveSize uint64) (uint64, uint64, float64, int, bool) {
	return n.obook.Quote(giveAsset, getAsset, giveSize)
}

// Depth returns the cumulative rate ladder for a taker giving giveAsset for
// getAsset. Passthrough to the book for the RPC GET /depth route.
func (n *Node) Depth(giveAsset, getAsset string) []swapbook.DepthLevel {
	return n.obook.Depth(giveAsset, getAsset)
}

// Reserve atomically holds liquidity across matching offers for the take path.
// Passthrough to the book.
func (n *Node) Reserve(giveAsset, getAsset string, size uint64, opts swapbook.ReserveOpts) ([]swapbook.Reservation, uint64, uint64, error) {
	return n.obook.Reserve(giveAsset, getAsset, size, opts)
}

// CommitTrade finalizes a reservation set and records it on the trade tape.
func (n *Node) CommitTrade(res []swapbook.Reservation, giveAsset, getAsset, swapKey, takerPub string) swapbook.Trade {
	return n.obook.CommitTrade(res, giveAsset, getAsset, swapKey, takerPub)
}

// ReleaseReservation restores reserved liquidity on swap failure/timeout.
func (n *Node) ReleaseReservation(res []swapbook.Reservation) { n.obook.ReleaseReservation(res) }

// Trades returns the recent executed-trade tape for a pair (GET /trades).
func (n *Node) Trades(pair string, limit int) []swapbook.Trade { return n.obook.Trades(pair, limit) }

// LastPrice returns the most-recent trade price for a pair (GET /trades).
func (n *Node) LastPrice(pair string) (string, bool) { return n.obook.LastPrice(pair) }

// Candles aggregates the tape into OHLCV buckets (GET /candles).
func (n *Node) Candles(pair string, intervalSec int64, limit int) []swapbook.Candle {
	return n.obook.Candles(pair, intervalSec, limit)
}

// Stats24h summarizes the tape over the trailing 24h (GET /stats).
func (n *Node) Stats24h(pair string) swapbook.Stats24h { return n.obook.Stats24h(pair) }

// OfferFill returns one offer's live fill state (GET /order/<id>).
func (n *Node) OfferFill(id [32]byte) (swapbook.FillState, bool) { return n.obook.OfferFill(id) }

// Start begins listening, dials seeds, and launches discovery/sync loops.
func (n *Node) Start(seeds []string) error {
	// audit fix (Tor fail-closed): in onion-only mode the node must NOT expose a
	// clearnet inbound listener — that would leave its real IP directly reachable and
	// deanonymizable, defeating Tor. The Tor hidden service forwards inbound to a LOCAL
	// port, so bind the listener to loopback only; the public interface is never opened.
	listenAddr := n.addr
	if n.onionOnly {
		if _, port, err := net.SplitHostPort(n.addr); err == nil {
			listenAddr = net.JoinHostPort("127.0.0.1", port)
		}
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	n.ln = ln
	// adopt the actual bound address (supports ephemeral ":0" binding in tests).
	n.addr = ln.Addr().String()
	// default the advertised address to the listen address (clearnet); under Tor
	// SetTransport sets it to the node's .onion address instead. audit fix (Tor
	// fail-closed): never fall back to advertising the clearnet listen address in
	// onion-only mode — with no .onion address set the node advertises nothing (it can
	// still dial out over Tor) rather than leaking its real IP via PEX.
	if n.advertiseAddr == "" && !n.onionOnly {
		n.advertiseAddr = n.addr
	}
	for _, s := range seeds {
		n.book.AddSticky(s) // seeds are sticky bootstrap: retried on every start, never evicted
	}
	go n.acceptLoop(ln)
	for _, s := range seeds {
		go n.dial(s)
	}
	go n.discoveryLoop()
	go n.reconnectLoop() // 5-min sweep: re-dial recently-connected peers that dropped
	go n.syncLoop()
	go n.stemEpochLoop()
	return nil
}

// Addr returns the node's actual listen address (after binding).
func (n *Node) Addr() string { return n.addr }

// Stop shuts the node down: closes the listener, signals all loops to exit, and
// drops every peer connection (freeing the port). Safe to call multiple times.
func (n *Node) Stop() {
	n.stopOnce.Do(func() {
		close(n.done)
		if n.ln != nil {
			_ = n.ln.Close()
		}
		n.mu.Lock()
		for _, p := range n.peers {
			_ = p.conn.Close()
		}
		n.mu.Unlock()
		n.book.Save()
	})
}

func (n *Node) stopped() bool {
	select {
	case <-n.done:
		return true
	default:
		return false
	}
}

func (n *Node) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if !n.admitInbound(conn) {
			conn.Close()
			continue
		}
		go n.handle(conn, false, "")
	}
}

// admitInbound enforces total-peer, per-IP, and ban limits for inbound conns.
func (n *Node) admitInbound(conn net.Conn) bool {
	remote := conn.RemoteAddr().String()
	ip := hostOf(remote)
	grp := ipGroup(remote)
	n.mu.Lock()
	defer n.mu.Unlock()
	// audit fix: reject if IP banned OR its /16 group has saturated its persistent
	// misbehavior score (defeats ban-evasion by reconnecting from the same network).
	if n.groupBannedLocked(remote, time.Now().Unix()) {
		return false
	}
	// audit fix (eclipse): count INBOUND peers only and cap them at maxInbound, so an
	// inbound flood can never consume the slots reserved for outbound dialling; also
	// cap inbound per-/16 group so one network cannot fill the inbound table with many
	// well-behaved IPs (each under the per-IP limit, never tripping the group ban).
	inbound, perIP, perGroup := 0, 0, 0
	for _, p := range n.peers {
		if p.outbound {
			continue
		}
		inbound++
		rip := p.conn.RemoteAddr().String()
		if hostOf(rip) == ip {
			perIP++
		}
		if ipGroup(rip) == grp {
			perGroup++
		}
	}
	if inbound >= maxInbound || perGroup >= maxInboundPerGroup {
		return false
	}
	return perIP < maxInboundPerIP
}

// dial connects to addr with exponential backoff + jitter, honoring caps.
func (n *Node) dial(addr string) {
	backoff := 2 * time.Second
	for {
		if n.stopped() {
			return
		}
		n.mu.Lock()
		full := len(n.peers) >= maxPeers
		// audit fix: also skip dialing a group whose persistent score is saturated.
		alreadyBanned := n.groupBannedLocked(addr, time.Now().Unix())
		n.mu.Unlock()
		if !full && !alreadyBanned {
			conn, err := n.dialer.Dial(addr)
			if err == nil {
				n.book.Seen(addr)
				n.handle(conn, true, addr)
				backoff = 2 * time.Second // reset after a successful session
			} else {
				n.book.Failed(addr)
			}
		}
		// backoff with jitter, capped
		sleep := backoff + time.Duration(rand.Int63n(int64(backoff)))
		if sleep > 5*time.Minute {
			sleep = 5 * time.Minute
		}
		time.Sleep(sleep)
		if backoff < 5*time.Minute {
			backoff *= 2
		}
	}
}

func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func (n *Node) handle(conn net.Conn, outbound bool, dialedAddr string) {
	// Defense-in-depth: a panic in message parsing/dispatch must drop only this
	// peer, never crash the whole node (a Go panic in a goroutine is fatal).
	defer func() { _ = recover() }()
	remote := conn.RemoteAddr().String()
	p := &peer{conn: conn, outbound: outbound, listen: dialedAddr,
		tokens: rateBucketCap, lastFill: time.Now()} // audit fix: seed full rate-limit bucket
	n.mu.Lock()
	if len(n.peers) >= maxPeers {
		n.mu.Unlock()
		conn.Close()
		return
	}
	n.peers[remote] = p
	n.mu.Unlock()
	defer func() {
		conn.Close()
		n.mu.Lock()
		delete(n.peers, remote)
		n.mu.Unlock()
	}()

	// handshake: exchange hello (magic + version + height + our advertised addr + the
	// address we OBSERVE this peer connecting from — so the peer can learn its own public
	// address from us, the decentralized self-discovery that keeps the network seedless).
	if err := n.send(p, msgHello, n.helloPayload(remote)); err != nil {
		return
	}
	typ, payload, err := n.readMsg(conn)
	if err != nil {
		// A read error during the handshake is NOT evidence of misbehavior: the usual
		// causes are an honest peer restarting mid-dial, a peer that currently has US
		// banned closing the socket at accept, or plain network failure. Hard-banning
		// this case live-deadlocked the mainnet (2026-07-02): each side's failed
		// handshake read instantly group-banned the other, and every redial re-armed
		// the opposite ban, so restarting nodes one at a time could never recover —
		// only a simultaneous stop-both/start-both cleared it. Drop the connection
		// with no penalty; protocol garbage is judged below, once there are bytes to
		// judge (and readMsg's own frame-magic check already rejects cross-network
		// peers cheaply — their redials are bounded by dial backoff + inbound caps).
		return
	}
	if typ != msgHello || !n.checkHello(p, payload) {
		n.penalize(remote, banThreshold) // protocol violation -> ban
		return
	}
	_ = n.send(p, msgGetTip, nil)
	_ = n.send(p, msgGetAddr, nil)
	_ = n.send(p, msgGetOffers, nil)

	for {
		typ, payload, err := n.readMsg(conn)
		if err != nil {
			return
		}
		// audit fix: per-peer inbound rate limiting. A peer that exceeds its token
		// bucket is penalized; sustained abuse drives it over the ban threshold and
		// disconnects it (defends against getblocks/getaddr/offer flood amplification).
		//
		// CONSENSUS-CRITICAL: block-PROPAGATION and chain-sync messages are EXEMPT from
		// the bucket. Dropping a msgBlock / msgTip / msgGetTip silently stalls sync (the
		// dropped block is not re-sent until the next sync tick, and may chain into orphan
		// re-request storms), which can prevent the network from converging on one chain.
		// Normal block gossip during a mining burst must NEVER be rate-dropped. NOTE:
		// msgGetBlk (a peer ASKING us to serve a block) is deliberately NOT exempt — it is
		// cheap to send, expensive to serve, and was a serve-DoS vector (SECURITY_AUDIT).
		// These messages are still bounded elsewhere (per-message size cap, the 64-block
		// request window, read deadlines), so exempting them does not reopen a flood vector.
		if !rateExempt(typ) && !n.allowMsg(p) {
			// msgGetBlk over-rate is THROTTLED, not punished: dropping the request
			// already bounds our serve cost (the DoS defense), while an honest
			// laggard 100-200 blocks behind legitimately bursts past the bucket
			// re-requesting its 64-block window each tip tick. The penalty path
			// here was live-reproduced silently group-banning such a peer for an
			// hour (round-3 audit) — it stays for every OTHER over-rate type.
			if throttleWithoutPenalty(typ) {
				p2pLog("rate: throttled getblk from %s (bucket empty; no penalty)", remote)
				continue
			}
			if !n.penalize(remote, rateAbusePenalty) {
				return
			}
			continue // drop this message, keep the connection (peer still under threshold)
		}
		if !n.dispatch(p, typ, payload) {
			return // peer banned/over threshold
		}
	}
}

// throttleWithoutPenalty reports whether an over-rate message of this type is
// dropped WITHOUT charging the misbehavior penalty. msgGetBlk qualifies: dropping
// the request already bounds our serve cost (the DoS defense), while an honest
// laggard 100-200 blocks behind legitimately bursts past the bucket re-requesting
// its 64-block sync window on every tip tick — penalizing that was live-reproduced
// silently group-banning an honest syncing peer for an hour (round-3 audit).
func throttleWithoutPenalty(typ byte) bool { return typ == msgGetBlk }

// rateExempt reports whether a message type is consensus-critical (block
// propagation or chain sync) and therefore must NOT be subject to the inbound
// token bucket. Rate-dropping these breaks convergence; they are bounded by other
// means (message-size cap, bounded request windows, read deadlines).
func rateExempt(typ byte) bool {
	switch typ {
	// audit: msgGetBlk (a peer asking US to SERVE a block) is a disk-read SERVE cost,
	// not propagation — it is NOT exempt, so a peer can't spam unbounded block-serve
	// requests. A legitimately-syncing peer still gets blocks (the bucket's burst +
	// sustained rate comfortably cover sync). msgBlock (inbound propagation), msgTip,
	// and the cheap msgGetTip stay exempt.
	case msgBlock, msgTip, msgGetTip:
		return true
	case msgSnapshot:
		// inbound snapshot chunks of an IN-FLIGHT, locally-requested transfer must not be
		// rate-dropped (a dropped chunk stalls reassembly). Bounded instead by the reassembly
		// caps (snapMaxChunks/snapMaxBytes/timeout) and by being dropped unless they match a
		// transfer we requested from THIS peer. msgGetSnapshot (the expensive serve) is NOT
		// exempt — it stays rate-limited so a peer cannot spam snapshot exports.
		return true
	default:
		return false
	}
}

// allowMsg consumes one token from the peer's inbound bucket, refilling it based
// on elapsed time. Returns false when the peer is sending faster than the allowed
// sustained rate (after exhausting its burst). (audit fix: per-peer rate limiting)
func (n *Node) allowMsg(p *peer) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(p.lastFill).Seconds()
	if elapsed > 0 {
		p.tokens += elapsed * rateRefillPerSec
		if p.tokens > rateBucketCap {
			p.tokens = rateBucketCap
		}
		p.lastFill = now
	}
	if p.tokens < 1 {
		return false
	}
	p.tokens--
	return true
}

// helloPayload builds the handshake. observedPeer is the address WE see this connection
// coming from — echoed so the peer can discover its own public address (self-discovery).
// Layout: magic(4) ver(2) height(8) advLen(2) advertise(advLen) observed(rest).
func (n *Node) helloPayload(observedPeer string) []byte {
	b := make([]byte, 0, 48)
	var magic [4]byte
	binary.BigEndian.PutUint32(magic[:], networkMagic)
	b = append(b, magic[:]...)
	var ver [2]byte
	binary.BigEndian.PutUint16(ver[:], protocolVersion)
	b = append(b, ver[:]...)
	b = append(b, encodeU64(n.chain.Height())...)
	adv := n.getAdvertise()
	if !isRoutable(adv) {
		adv = "" // never advertise an undialable address (e.g. 0.0.0.0 listen addr)
	}
	var al [2]byte
	binary.BigEndian.PutUint16(al[:], uint16(len(adv)))
	b = append(b, al[:]...)
	b = append(b, []byte(adv)...)
	// Trailer (backward-compatible): obsLen(2) observed verLen(2) version.
	// Old peers treat everything after `advertise` as `observed` (a harmless garbled
	// self-hint); new peers length-split it and learn the peer's software version.
	var ol [2]byte
	binary.BigEndian.PutUint16(ol[:], uint16(len(observedPeer)))
	b = append(b, ol[:]...)
	b = append(b, []byte(observedPeer)...)
	var vl [2]byte
	binary.BigEndian.PutUint16(vl[:], uint16(len(SoftwareVersion)))
	b = append(b, vl[:]...)
	b = append(b, []byte(SoftwareVersion)...)
	return b
}

// parseHelloTrailer reads the optional version trailer (obsLen(2) observed verLen(2)
// version) appended after the advertise field. It falls back to treating the whole
// remainder as the observed-self string (the original layout) when the trailer is
// absent or malformed, so it interoperates with un-upgraded peers. version is "" when
// unknown. The exact-fit check makes a false positive on an old observed string
// effectively impossible.
func parseHelloTrailer(rest []byte) (observed, version string) {
	if len(rest) >= 2 {
		ol := int(binary.BigEndian.Uint16(rest[0:2]))
		if 2+ol <= len(rest) {
			obs := rest[2 : 2+ol]
			r2 := rest[2+ol:]
			if len(r2) >= 2 {
				vl := int(binary.BigEndian.Uint16(r2[0:2]))
				if 2+vl == len(r2) { // exact fit ⇒ this really is the new trailer
					return string(obs), string(r2[2 : 2+vl])
				}
			}
		}
	}
	return string(rest), "" // old layout: observed = rest, version unknown
}

func (n *Node) checkHello(p *peer, payload []byte) bool {
	if len(payload) < 16 { // magic+ver+height+advLen
		return false
	}
	if binary.BigEndian.Uint32(payload[0:4]) != networkMagic {
		return false
	}
	if binary.BigEndian.Uint16(payload[4:6]) != protocolVersion {
		return false
	}
	// height(8) at [6:14]; advLen(2) at [14:16]; advertise; then observed (rest).
	// Record the peer's advertised tip so /status can derive a sync/health flag.
	bestH := binary.BigEndian.Uint64(payload[6:14])
	advLen := int(binary.BigEndian.Uint16(payload[14:16]))
	if 16+advLen > len(payload) {
		return false
	}
	advertise := string(payload[16 : 16+advLen])
	// Self-connection guard: a "peer" advertising EXACTLY our own public address is
	// ourselves (a self-dial via a poisoned book entry — e.g. loopback:ownport spread
	// over PEX, live incident 2026-07-04) or an unreachable impersonator; either way
	// the connection is worthless and wedges gossip. Uses only the existing hello
	// fields, so it is wire-compatible with older peers.
	if selfAdv := n.getAdvertise(); selfAdv != "" && advertise == selfAdv {
		return false
	}
	observedSelf, peerVer := parseHelloTrailer(payload[16+advLen:])
	// audit ROUND2 [88]: p.bestHeight/version/listen are read under n.mu by BestKnownHeight /
	// PeerVersionCounts / the connected-addr sweep, so their WRITES must take n.mu too (the
	// p.score/p.tokens locking convention missed these three; a string field is a 2-word
	// header → genuine torn-read risk, not just staleness). Bound the peer-controlled version
	// string (the explorer also HTML-escapes it). Lock only the bare assignments —
	// maybeAddAddr/learnExternalFromPeer take locks themselves.
	routable := isRoutable(advertise)
	n.mu.Lock()
	p.bestHeight = bestH
	if l := len(peerVer); l > 0 && l <= 32 {
		p.version = peerVer
	}
	if routable {
		p.listen = advertise // the peer's advertised dialable address (PEX spreads REACHABLE peers)
	}
	n.mu.Unlock()
	if routable {
		n.maybeAddAddr(advertise)
	}
	// if WE dialed this peer, its observation of our source address tells us our own
	// public IP — decentralized self-discovery (no seed/config dependency).
	if p.outbound && observedSelf != "" {
		n.learnExternalFromPeer(observedSelf, p.conn.RemoteAddr().String())
	}
	return true
}

// dispatch handles a message; returns false if the peer must be disconnected.
func (n *Node) dispatch(p *peer, typ byte, payload []byte) bool {
	remote := p.conn.RemoteAddr().String()
	switch typ {
	case msgGetTip:
		_ = n.send(p, msgTip, encodeU64(n.chain.Height()))
	case msgTip:
		peerH := decodeU64(payload)
		n.mu.Lock()
		if peerH > p.bestHeight {
			p.bestHeight = peerH // audit ROUND2 [88]: guarded — read under n.mu elsewhere
		}
		n.mu.Unlock()
		ourH := n.chain.Height()
		// FAR behind a peer (fresh / long-restarted node): fast-forward via a verified
		// snapshot instead of re-verifying every block. Separate, bounded path; on failure
		// the block-window request below still runs as the fallback. (snapsync.go)
		n.maybeRequestSnapshot(p, peerH, ourH)
		// request a bounded window of missing blocks (avoid unbounded fan-out)
		limit := ourH + 64
		if peerH < limit {
			limit = peerH
		}
		for h := ourH + 1; h <= limit; h++ {
			_ = n.send(p, msgGetBlk, encodeU64(h))
		}
	case msgGetBlk:
		h := decodeU64(payload)
		if b, ok := n.chain.BlockByHeight(h); ok {
			err := n.send(p, msgBlock, b.Serialize())
			p2pLog("serve getBlk h=%d to %s -> send err=%v", h, remote, err)
		} else {
			p2pLog("serve getBlk h=%d to %s -> NOT FOUND", h, remote)
		}
	case msgBlock:
		b, err := block.DeserializeBlock(payload)
		if err != nil {
			p2pLog("recv block deserialize FAIL from %s: %v", remote, err)
			return n.penalize(remote, 5)
		}
		if err := n.chain.AddBlock(b); err != nil {
			p2pLog("recv block h=%d from %s -> AddBlock err=%v (orphan=%v)", b.Header.Height, remote, err, chain.IsOrphanErr(err))
			if chain.IsOrphanErr(err) {
				// parent unknown: request the missing intermediate blocks so the
				// orphan can connect (bounded window).
				ourH := n.chain.Height()
				limit := b.Header.Height
				if limit > ourH+64 {
					limit = ourH + 64
				}
				for h := ourH + 1; h <= limit; h++ {
					_ = n.send(p, msgGetBlk, encodeU64(h))
				}
				return true
			}
			// Non-orphan AddBlock failure = a consensus-VALIDATION rejection. This is NOT
			// necessarily abuse: a peer on a DIFFERENT FORK, or mid-resync after a chain
			// reset, sends blocks valid on ITS chain that fail under OURS (most commonly a
			// PoW-seed mismatch). Treat it as SOFT, connection-local misbehavior — drop a
			// connection that floods past connDropThreshold, but record NO persistent IP
			// ban, so an honest forked/resyncing peer reconnects immediately. (This is the
			// fix for the fork-on-reset bans. Genuinely malformed frames were already
			// hard-penalized at the deserialize step above; only structurally-valid,
			// consensus-rejected blocks reach here.)
			return n.penalizeConn(remote, 2)
		}
		p2pLog("recv block h=%d from %s -> applied (tip now %d)", b.Header.Height, remote, n.chain.Height())
		if n.mp != nil {
			n.mp.Remove(b.Txs)
		}
		if n.OnBlock != nil {
			n.OnBlock(b)
		}
		n.broadcast(msgBlock, b.Serialize(), p.conn)
	case msgTx:
		t, err := tx.Deserialize(payload)
		if err != nil || n.mp == nil {
			return n.penalize(remote, 5)
		}
		if err := n.mp.Add(t); err != nil {
			// A tx that fails mempool admission is NOT necessarily abuse: a node that is
			// BEHIND (or mid-resync) legitimately rejects the tip's txs because they spend
			// outputs / nullifiers it hasn't applied yet, and duplicates are normal gossip.
			// Hard-banning that relayer isolated a lagging node from the very peers feeding
			// it the chain — a behind node banned the community MINERS, cutting off block
			// delivery and freezing sync (live 2026-07-03). Treat as SOFT, connection-local:
			// no persistent IP/group ban, so an honest peer is never blocked for relaying
			// valid-but-not-yet-verifiable txs. Malformed tx BYTES still hard-ban above.
			return n.penalizeConn(remote, 1)
		}
		n.markFluffed(t.Hash()) // cancels any embargo; stops re-stemming
		n.broadcast(msgTx, payload, p.conn)
	case msgStemTx:
		t, err := tx.Deserialize(payload)
		if err != nil || n.mp == nil {
			return n.penalize(remote, 5)
		}
		if err := n.mp.Add(t); err != nil {
			return true // duplicate/known stem tx: drop silently (loop guard)
		}
		n.stemRelay(t, payload, p) // continue stem or transition to fluff
	case msgGetAddr:
		for _, a := range n.book.Sample(16) {
			// Don't SPREAD self-loopback poison persisted by older binaries (see
			// maybeAddAddr) — every clearnet node shares the standard port, so a
			// loopback:ownport entry self-wedges whoever we hand it to.
			if n.isSelfLoopback(a) {
				continue
			}
			_ = n.send(p, msgAddr, []byte(a))
		}
	case msgAddr:
		addr := string(payload)
		if _, _, err := net.SplitHostPort(addr); err == nil {
			n.maybeAddAddr(addr)
		}
	case msgSwapOffer:
		o, err := swapbook.ParseOffer(payload)
		if err != nil {
			return n.penalize(remote, 5)
		}
		isNew, err := n.obook.Add(o)
		if err != nil {
			// Connection-local penalty only: a stale-but-well-formed offer is normal
			// gossip, not abuse — a just-restarted peer relays its persisted book, and
			// every expired/superseded entry used to land 2 HARD points, so the miner's
			// 16-rung auto-liquidity ladder alone (32 pts > banThreshold 20) instantly
			// group-banned honest peers on reconnect (live incident 2026-07-02).
			// Undeserializable offer bytes above still take the hard penalize(5) path.
			return n.penalizeConn(remote, 2)
		}
		// Record WHICH peer relayed this maker's offer (refreshed on every admitted
		// offer, new or repeat) so /swaps/take can route the Init to the maker's peer.
		n.recordOfferProvenance(o.Maker, remote)
		if isNew {
			n.broadcast(msgSwapOffer, payload, p.conn) // gossip onward
		}
	case msgGetOffers:
		for i, o := range n.obook.List() {
			if i >= 256 {
				break // bound the response
			}
			_ = n.send(p, msgSwapOffer, o.Serialize())
		}
	case msgSwapSession:
		// Directed two-party swap-session traffic. p2p does NO protocol logic here:
		// it hands the opaque envelope to the coordinator, tagged with the sending
		// peer's remote address so replies route back over the SAME connection. If no
		// coordinator is wired, the message is simply ignored (a node not running a
		// swap coordinator has nothing to do with it) — not a protocol violation.
		if n.OnSwapSession != nil {
			n.OnSwapSession(remote, payload)
		}
	case msgGetSnapshot:
		// serve our verified transfer snapshot, chunked, off the read goroutine (export can
		// be large). msgGetSnapshot is rate-limited (NOT rateExempt) so this can't be spammed.
		// An optional payload targets specific missing chunks (receiver gap retry; snapsync.go).
		go n.serveSnapshot(p, payload)
	case msgSnapshot:
		n.recvSnapshotChunk(p, payload) // reassemble; verify+import on completion (snapsync.go)
	default:
		return n.penalize(remote, 10) // unknown message type
	}
	return true
}

// penalize adds misbehavior points; returns false (disconnect) once the peer
// exceeds the ban threshold, and records a temporary IP ban. It also accumulates
// a per-IP-group (/16) score that PERSISTS across reconnects (audit fix: a
// per-connection score alone lets attackers reset their tab by reconnecting), so a
// peer that keeps reconnecting to dodge bans still gets banned by its IP group.
func (n *Node) penalize(remote string, pts int) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now()
	disconnect := false
	if p, ok := n.peers[remote]; ok {
		p.score += pts
		if p.score >= banThreshold {
			if !p2pNoBan {
				n.bans[hostOf(remote)] = now.Unix() + groupBanDuration
			}
			disconnect = true
		}
	}
	// accumulate the persistent, time-decaying group score (survives reconnects).
	if n.addGroupScoreLocked(remote, float64(pts), now) >= groupBanThreshold {
		if !p2pNoBan {
			n.bans[hostOf(remote)] = now.Unix() + groupBanDuration
		}
		disconnect = true
	}
	if disconnect {
		// Bans were previously SILENT on both sides (round-3 audit: an operator could
		// not tell why a peer vanished for an hour). Always log the event.
		if p2pNoBan {
			log.Printf("p2p: dropped %s (misbehavior score over threshold; no-ban mode, may reconnect)", hostOf(remote))
		} else {
			log.Printf("p2p: BANNED %s for %ds (misbehavior score over threshold)", hostOf(remote), groupBanDuration)
		}
		return false
	}
	return true
}

// connDropThreshold is the per-CONNECTION soft-misbehavior budget. It is much larger
// than banThreshold (20) so a peer that is merely on a different fork / mid-resync can
// send many blocks that fail OUR validation (e.g. PoW that is valid on the peer's chain
// but mismatches under our chain's PoW seed) without being dropped — only a sustained
// flood on ONE connection crosses it.
const connDropThreshold = 400

// penalizeConn applies a CONNECTION-LOCAL penalty for failures that are a NORMAL part of
// sync/convergence rather than protocol abuse — chiefly a peer on a DIFFERENT FORK whose
// blocks fail our validation. Unlike penalize, it NEVER records a persistent IP/group
// ban: it can only drop the current connection once a single connection floods past
// connDropThreshold, after which the peer may reconnect immediately (so an honest node
// that briefly forked or is resyncing is never locked out — the fix for the
// fork-on-reset bans). Genuine garbage (undeserializable frames, unknown message types,
// rate-bucket abuse) still goes through penalize() and CAN earn a persistent ban.
func (n *Node) penalizeConn(remote string, pts int) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if p, ok := n.peers[remote]; ok {
		p.softScore += pts
		if p.softScore >= connDropThreshold {
			return false // drop THIS connection only; no persistent ban, reconnect allowed
		}
	}
	return true
}

// addGroupScoreLocked applies linear time-decay to an IP group's accumulated
// misbehavior score, adds pts, and returns the new total. Caller holds n.mu.
// (audit fix: persistent cross-reconnect ban scoring)
func (n *Node) addGroupScoreLocked(remote string, pts float64, now time.Time) float64 {
	g := ipGroup(remote)
	gs := n.groupScores[g]
	if gs == nil {
		gs = &groupScore{updated: now}
		n.groupScores[g] = gs
	}
	if decay := now.Sub(gs.updated).Minutes() * groupScoreDecay; decay > 0 {
		gs.score -= decay
		if gs.score < 0 {
			gs.score = 0
		}
		gs.updated = now
	}
	gs.score += pts
	return gs.score
}

// groupBannedLocked reports whether an address's IP group is currently banned
// (either by a recorded IP ban or a saturated persistent group score). Caller
// holds n.mu. (audit fix)
func (n *Node) groupBannedLocked(addr string, now int64) bool {
	if until, ok := n.bans[hostOf(addr)]; ok && now < until {
		return true
	}
	if gs := n.groupScores[ipGroup(addr)]; gs != nil && gs.score >= groupBanThreshold {
		return true
	}
	return false
}

// bootstrapWarnEvery rate-limits the "cannot bootstrap" operator warning.
const bootstrapWarnEvery = 5 * time.Minute

// discoveryLoop maintains the target peer count by dialing fresh addresses from
// the book and periodically saves the book.
func (n *Node) discoveryLoop() {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	var lastBootstrapWarn time.Time
	for {
		select {
		case <-n.done:
			return
		case <-t.C:
		}
		// Operator-visible bootstrap failure (not just OBX_P2P_DEBUG): zero peers AND
		// no address in the book that was ever reached / is still untried means every
		// configured seed (embedded, OBX_SEEDS, OBX_SEEDS_APPEND, --seeds) is failing —
		// DNS-seed hostnames that don't resolve land here too. Without this a node
		// silently mines an isolated fork. Rate-limited; clears itself once any peer
		// connects.
		if n.PeerCount() == 0 && n.book.AllUnreachable() && time.Since(lastBootstrapWarn) > bootstrapWarnEvery {
			lastBootstrapWarn = time.Now()
			log.Printf("p2p: WARN cannot bootstrap: no peers connected and all known seeds/addresses are unreachable — set OBX_SEEDS (or OBX_SEEDS_APPEND) to reachable host:port seeds")
		}
		n.mu.Lock()
		// audit fix (reserved outbound): target a fixed number of OUTBOUND links and
		// count only outbound peers — the old `maxPeers/2 - len(peers)` counted TOTAL
		// peers, so an inbound flood (len(peers) high) drove need<=0 and the node stopped
		// dialling out entirely, the precondition for an eclipse. Outbound links are the
		// ones an attacker cannot pre-position, so they must be maintained regardless.
		outbound := 0
		connected := make(map[string]bool)
		for _, p := range n.peers {
			if p.outbound {
				outbound++
			}
			if p.listen != "" {
				connected[p.listen] = true
			}
		}
		need := targetOutbound - outbound
		n.mu.Unlock()
		// Never dial OURSELVES. n.addr is the LISTEN address (e.g. 0.0.0.0:18080); our
		// own PUBLIC address (advertiseAddr, e.g. 1.2.3.4:18080) echoes back into the
		// address book via PEX, and filtering only n.addr let a node dial its own public
		// address — a self-loop that consumed peer slots + sync attention and starved the
		// real cross-machine peer (the multi-node sync stall: nodes connected only to
		// themselves and never to each other).
		n.advMu.RLock()
		selfAdv := n.advertiseAddr
		n.advMu.RUnlock()
		if need > 0 {
			for _, a := range n.book.Sample(need * 2) {
				// isSelfLoopback: never dial loopback:ownport — it connects to OURSELVES
				// (poisoned persisted books from before the maybeAddAddr filter existed).
				if a != n.addr && a != selfAdv && !connected[a] && !n.isSelfLoopback(a) {
					go n.dialOnce(a)
				}
			}
		}
		n.book.Save()
	}
}

// reconnectLoop runs every 5 minutes and proactively re-dials RECENTLY-CONNECTED peers
// that have since dropped or gone offline, so the node actively rejoins its last-known-
// good set after a transient partition or a peer restart. This is independent of
// discoveryLoop, which stops dialing once the outbound-slot target is met and therefore
// does NOT chase a specific good peer that just vanished. Together with sticky seeds,
// this keeps the mesh (and returning community nodes) glued back together. Purely local
// outbound behavior — no wire change.
func (n *Node) reconnectLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-n.done:
			return
		case <-t.C:
		}
		n.mu.Lock()
		connected := make(map[string]bool)
		for _, p := range n.peers {
			if p.listen != "" {
				connected[p.listen] = true
			}
		}
		n.mu.Unlock()
		n.advMu.RLock()
		selfAdv := n.advertiseAddr
		n.advMu.RUnlock()
		// Re-dial peers seen good within the last 24h that aren't currently connected.
		for _, a := range n.book.RecentlySeen(24 * 3600) {
			if a != n.addr && a != selfAdv && !connected[a] && !n.isSelfLoopback(a) {
				go n.dialOnce(a)
			}
		}
	}
}

// dialOnce attempts a single connection (feeler), without the retry loop.
func (n *Node) dialOnce(addr string) {
	n.mu.Lock()
	full := len(n.peers) >= maxPeers
	n.mu.Unlock()
	if full {
		return
	}
	conn, err := n.dialer.Dial(addr)
	if err != nil {
		n.book.Failed(addr)
		return
	}
	n.book.Seen(addr)
	n.handle(conn, true, addr)
}

// syncLoop periodically asks peers for their tip to drive block download.
func (n *Node) syncLoop() {
	t := time.NewTicker(8 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-n.done:
			return
		case <-t.C:
		}
		for _, p := range n.peerList() {
			_ = n.send(p, msgGetTip, nil)
		}
	}
}

func (n *Node) peerList() []*peer {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]*peer, 0, len(n.peers))
	for _, p := range n.peers {
		out = append(out, p)
	}
	return out
}

// broadcast sends to all peers except `except`, with per-peer write locks/
// deadlines so one slow peer cannot corrupt framing or stall everyone.
func (n *Node) broadcast(typ byte, payload []byte, except net.Conn) {
	for _, p := range n.peerList() {
		if p.conn == except {
			continue
		}
		_ = n.send(p, typ, payload)
	}
}

// SendSwapSession sends one DIRECTED swap-session envelope to a SPECIFIC connected
// peer, identified by its remote address (the `fromPeer` handle delivered to
// OnSwapSession, or — for the taker opening a swap — the address of the peer it
// connected to the maker on). The payload is opaque to p2p. Returns an error if no
// such peer is currently connected (the caller's session then times out / aborts).
// This is the point-to-point counterpart of broadcast: swap traffic must reach ONLY
// the counterparty, never the gossip mesh.
func (n *Node) SendSwapSession(peerAddr string, payload []byte) error {
	n.mu.Lock()
	p, ok := n.peers[peerAddr]
	n.mu.Unlock()
	if !ok {
		return fmt.Errorf("p2p: no connected peer %q for swap session", peerAddr)
	}
	return n.send(p, msgSwapSession, payload)
}

// SwapPeerForHost resolves the CURRENT live routing handle for a swap counterparty
// whose previous connection (stale) may have dropped and reconnected under a new
// ephemeral source port. Returns stale unchanged if still connected; otherwise the
// address of any connected peer sharing stale's host (an inbound peer reappears under
// the same IP/onion after a reconnect). Used by the swap transport so a maker's reply
// survives the counterparty recycling its connection mid-swap (e.g. under block flood
// while it is busy with the slow XNO lock). Host-precise in production (distinct IPs);
// on a single host it returns the sole same-host peer, which in a 1-counterparty swap
// is the right one.
func (n *Node) SwapPeerForHost(stale string) (string, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.peers[stale]; ok {
		return stale, true
	}
	host := hostOf(stale)
	for addr := range n.peers {
		if hostOf(addr) == host {
			return addr, true
		}
	}
	return "", false
}

// BroadcastBlock announces a newly mined block.
func (n *Node) BroadcastBlock(b *block.Block) { n.broadcast(msgBlock, b.Serialize(), nil) }

// BroadcastTx announces a locally-originated transaction. With Dandelion++ it
// enters the stem phase (relayed privately to a single successor) rather than
// being flooded, hiding the originating node/IP.
func (n *Node) BroadcastTx(t *tx.Transaction) {
	if n.dandelion {
		n.stemRelay(t, t.Serialize(), nil)
		return
	}
	n.broadcast(msgTx, t.Serialize(), nil)
}

// RelayTx admits a locally-produced transaction to the mempool and FLOODS it to all
// peers immediately, bypassing Dandelion's stem phase. Used for atomic-swap CLAIM
// spends: the claim must reach a miner promptly — in a two-party swap that is the
// MAKER, which wants the claim on-chain so it can recover sA and sweep the XNO — and
// the taker is often not an active miner / lags the tip (busy with the slow XNO lock),
// so it cannot reliably seal a canonical block itself. Privacy is moot here: the swap
// counterparty already knows this exact spend. Returns the mempool admission result
// but floods regardless, so a miner peer can still include it even if our own pool
// rejects a duplicate.
func (n *Node) RelayTx(t *tx.Transaction) error {
	var err error
	if n.mp != nil {
		err = n.mp.Add(t)
	}
	n.broadcast(msgTx, t.Serialize(), nil)
	return err
}

// PeerCount returns the number of connected peers.
func (n *Node) PeerCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.peers)
}

// BestKnownHeight returns the highest chain height advertised by any currently-
// connected peer (learned from the hello handshake + tip gossip) and the
// connected-peer count, so /status can derive a sync/health flag an integrator can
// trust before crediting deposits. ok is false when NO peer has advertised a height
// yet (e.g. zero peers, or only un-synced peers) — callers must NOT treat height 0
// as "synced". Aggregate only — never reveals which peer is at which height.
func (n *Node) BestKnownHeight() (height uint64, peers int, ok bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	peers = len(n.peers)
	for _, p := range n.peers {
		if p.bestHeight > 0 {
			ok = true
			if p.bestHeight > height {
				height = p.bestHeight
			}
		}
	}
	return height, peers, ok
}

// PeerVersionCounts returns a software-version histogram of the currently-connected
// peers PLUS this node itself. Peers that did not advertise a version (un-upgraded)
// are bucketed as "unknown". It returns aggregated counts only — never addresses — so
// it leaks nothing a privacy coin shouldn't expose (consistent with the /peers redaction).
func (n *Node) PeerVersionCounts() map[string]int {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := map[string]int{SoftwareVersion: 1} // count ourselves
	for _, p := range n.peers {
		v := p.version
		if v == "" {
			v = "unknown"
		}
		out[v]++
	}
	return out
}

// PeerAddrs returns the remote addresses of currently-connected peers.
func (n *Node) PeerAddrs() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]string, 0, len(n.peers))
	for addr := range n.peers {
		out = append(out, addr)
	}
	return out
}

// KnownAddrCount returns how many distinct node addresses this node has learned via
// PEX — a wider (still partial) proxy for network breadth than the connected-peer count.
func (n *Node) KnownAddrCount() int {
	if n.book == nil {
		return 0
	}
	return n.book.Size()
}

// --- wire framing with magic + deadlines ---

// send writes a framed message to a peer, holding the peer's write mutex so
// concurrent senders (sync loop, dispatch, broadcast) cannot interleave bytes.
func (n *Node) send(p *peer, typ byte, payload []byte) error {
	if len(payload) > maxMsgBytes {
		return fmt.Errorf("p2p: outbound message too large")
	}
	p.wmu.Lock()
	defer p.wmu.Unlock()
	conn := p.conn
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	var hdr [9]byte
	binary.BigEndian.PutUint32(hdr[0:4], networkMagic)
	hdr[4] = typ
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(payload)))
	if _, err := conn.Write(hdr[:]); err != nil {
		conn.Close() // see below
		return err
	}
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			// A peer whose socket stays full (not reading for >writeTimeout) is wedged,
			// not slow: left connected, it costs EVERY subsequent broadcast the full
			// writeTimeout stall, serially, forever (live incident 2026-07-04 — offer
			// gossip network-wide starved behind one stuck peer). Closing tears the
			// connection down via its read loop; a healthy peer just redials.
			conn.Close()
			return err
		}
	}
	return nil
}

func (n *Node) readMsg(conn net.Conn) (byte, []byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(readIdleTimeout))
	var hdr [9]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, nil, err
	}
	if binary.BigEndian.Uint32(hdr[0:4]) != networkMagic {
		return 0, nil, fmt.Errorf("p2p: bad network magic")
	}
	sz := binary.BigEndian.Uint32(hdr[5:9])
	if sz > maxMsgBytes {
		return 0, nil, fmt.Errorf("p2p: message too large")
	}
	payload := make([]byte, sz)
	if sz > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			return 0, nil, err
		}
	}
	return hdr[4], payload, nil
}

func encodeU64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}
func decodeU64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
