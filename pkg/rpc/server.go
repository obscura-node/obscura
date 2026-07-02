// Package rpc exposes a JSON-over-HTTP API for the Obscura node and a matching
// client used by the CLI wallet.
package rpc

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"obscura/pkg/block"
	"obscura/pkg/chain"
	"obscura/pkg/commit"
	"obscura/pkg/config"
	"obscura/pkg/fee"
	"obscura/pkg/mempool"
	"obscura/pkg/nanorpc"
	"obscura/pkg/pow"
	"obscura/pkg/stark"
	"obscura/pkg/swapbook"
	"obscura/pkg/swapd"
	"obscura/pkg/swapnet"
	"obscura/pkg/swaprelay"
	"obscura/pkg/tx"
	"obscura/pkg/wallet"
)

// OfferProvider exposes the swap order book to the RPC layer (implemented by the
// p2p node). Optional.
type OfferProvider interface {
	Offers() []*swapbook.Offer
	PostOffer(*swapbook.Offer) error
	// Liquidity aggregates the live book per directed pair for the /liquidity
	// endpoint (Σ give, Σ get, offer/maker counts, best rate).
	Liquidity() (pairs []swapbook.PairLiquidity, totalOffers, totalMakers int)
	// Cancel removes a live offer from this node's book if sig is a valid
	// maker-authenticated cancellation over the offer id (see Book.Cancel /
	// swapbook.CancelMessage). Powers POST /offer/cancel.
	Cancel(offerID [32]byte, sig []byte) error
	// Quote walks the live book to price a taker giving giveSize of giveAsset for
	// getAsset (depth-aware VWAP). Powers GET /quote.
	Quote(giveAsset, getAsset string, giveSize uint64) (filled, getOut uint64, vwap float64, offersUsed int, full bool)
	// Depth returns the cumulative rate ladder for a taker giving giveAsset for
	// getAsset, best-rate-first. Powers GET /depth.
	Depth(giveAsset, getAsset string) []swapbook.DepthLevel
	// Reserve atomically holds up to `size` of giveAsset across matching offers
	// (best-first), decrementing each offer's Remaining. Powers the take path:
	// reserve before settlement, commit on success, release on failure.
	Reserve(giveAsset, getAsset string, size uint64, opts swapbook.ReserveOpts) (res []swapbook.Reservation, getOut, giveIn uint64, err error)
	// CommitTrade finalizes a reservation set and records a Trade on the tape,
	// joined to on-chain settlement by swapKey.
	CommitTrade(res []swapbook.Reservation, giveAsset, getAsset, swapKey, takerPub string) swapbook.Trade
	// ReleaseReservation restores reserved liquidity on swap failure/timeout.
	ReleaseReservation(res []swapbook.Reservation)
	// Trades / LastPrice expose the executed-trade tape (GET /trades).
	Trades(pair string, limit int) []swapbook.Trade
	LastPrice(pair string) (string, bool)
	// Candles aggregates the tape into OHLCV buckets (GET /candles).
	Candles(pair string, intervalSec int64, limit int) []swapbook.Candle
	// Stats24h summarizes the tape over the trailing 24h (GET /stats).
	Stats24h(pair string) swapbook.Stats24h
	// MakerOffers lists a maker's live offers (GET /orders?maker=).
	MakerOffers(maker []byte) []*swapbook.Offer
	// OfferFill returns one offer's fill state (GET /order/<id>).
	OfferFill(id [32]byte) (swapbook.FillState, bool)
}

// SwapCoordinator exposes the in-flight swap engine to the RPC layer (implemented
// by *swapnet.Coordinator). Optional: nil keeps /swaps/* returning empty / 503.
type SwapCoordinator interface {
	// ActiveSessions snapshots every running/terminal-but-pending session for the
	// /swaps/active endpoint (value-only, no secret material).
	ActiveSessions() []swapnet.SessionView
	// Take starts a TAKER session against the maker reachable at peer for the given
	// amounts and returns its handle (its ID is the swap id). Used by /swaps/take.
	Take(peer string, obxAmount uint64, xnoAmount *big.Int, fee uint64) (*swapnet.Session, error)
}

// PeerProvider exposes connected-peer info to the RPC layer (implemented by the
// p2p node). Optional.
type PeerProvider interface {
	PeerCount() int
	PeerAddrs() []string
	// KnownAddrCount + PeerVersionCounts back the explorer's network panel (PEX-known
	// address count + the software-version distribution across connected peers + self,
	// counts only). mainnet-specific: mainnet's explorer.go calls these directly,
	// whereas root uses an optional type-assertion. The production *p2p.Node + the
	// test stubs implement them.
	KnownAddrCount() int
	PeerVersionCounts() map[string]int
	// PeerForMaker resolves the source peer that relayed a live offer from the given
	// maker pubkey (the maker-pubkey -> peer directory), so /swaps/take can route the
	// swap Init to the maker rather than guessing PeerAddrs()[0]. ok is false if no
	// offer from that maker has been seen.
	PeerForMaker(maker []byte) (string, bool)
}

// Server serves the node RPC.
type Server struct {
	chain      *chain.Chain
	mp         *mempool.Mempool
	bcast      func(*tx.Transaction)
	blockBcast func(*block.Block)
	offers     OfferProvider
	peers      PeerProvider
	nano       swapd.NanoClient // XNO swap-execution backend (operator-provided; nil disables XNO execution)
	swaps      SwapCoordinator  // in-flight swap engine (optional; nil keeps /swaps/* empty)

	// NON-CUSTODIAL browser swap (pkg/swaprelay + pkg/nanorpc). swapRelay bridges a
	// browser taker's swap envelopes to the local maker session; nanoPub is the
	// secret-free Nano client used to read/publish the blocks the BROWSER signed.
	// Both nil keeps /swaps/relay/* + /swaps/nano/* returning 503. Wired via
	// SetSwapRelay. Safe to expose publicly: the browser holds every key.
	swapRelay *swaprelay.Relay
	nanoPub   *nanorpc.Client

	// XNO PROCEEDS WALLET. The miner sells OBX for XNO; xnoSeed is the miner seed
	// from which the recoverable XNO proceeds account is derived
	// (swapd.MinerXNOAccount). xnoLedger reads balance/receivable and signs
	// withdrawals. Injected via SetXNO. The seed lives ONLY in-process and is
	// never emitted over the public proxy — only /xno/recovery (operator-gated)
	// reveals it. A nil ledger keeps /xno/account on the mock backend.
	xnoSeed   []byte
	xnoLedger xnoLedger
	// swapFee is the OBX fee a taker-initiated swap uses (matches the maker's
	// Config.Fee). Set alongside the coordinator so /swaps/take can pass it.
	swapFee uint64

	// Audit fix: the RPC surface was fully unauthenticated. Operator/sensitive
	// endpoints (full peer list, block template, block submit) are now gated to
	// loopback callers OR a bearer token (env OBX_RPC_TOKEN). authToken is read
	// once at construction; empty means "loopback only".
	authToken string

	// publicSwaps opts an operator IN to serving /swaps/take to UNTRUSTED (public)
	// callers. DEFAULT false (audit S3): a take started by an anonymous web visitor
	// locks THIS node operator's XNO into the swap and claims the resulting OBX to a
	// node-internal key — the remote user funds nothing and receives nothing, while
	// the operator's real XNO is drained. So public takes are denied unless the
	// operator sets OBX_PUBLIC_SWAPS=1 (e.g. a mock/demo node with no real funds).
	// Loopback / OBX_RPC_TOKEN callers (someone running their OWN node) are always
	// allowed regardless. Read once at construction.
	publicSwaps bool

	// Audit fix: /blocktemplate is a lock-contending DoS amplifier. Cache the
	// most recent template for a short TTL so a flood of requests can't grind the
	// chain locks ~once per request.
	tmplMu    sync.Mutex
	tmplCache map[string]cachedTemplate

	// audit:SECURITY_AUDIT_2026-07-01 (Finding 1) — O(1) hash->height index so a bogus
	// block-hash lookup is a map probe, not a full-chain disk scan.
	hashIdxMu    sync.Mutex
	blockHashIdx map[string]uint64
	hashIdxNext  uint64
	// audit:SECURITY_AUDIT_2026-07-01 (Finding 2) — short-TTL cache of the /explorer/swaps feed.
	swapsCacheMu   sync.Mutex
	swapsCache     []SwapEvent
	swapsCacheTip  uint64
	swapsCacheTime time.Time

	// Price time-series: a bounded in-memory ring buffer sampling the live order
	// book's best OBX/XNO taker rate, powering the explorer's realtime price chart
	// (/explorer/pricehistory). In-memory only — a node restart rebuilds it from
	// empty (per-node, non-consensus, like the instantaneous price cards).
	priceMu       sync.Mutex
	priceHist     []pricePoint
	priceStarted  sync.Once
	priceHistPath string // optional: JSON file to persist priceHist across restarts

	// network-metrics time series for the explorer sparklines + swap volume (metrics.go)
	metricsFields

	// observability state: uptime anchor, registered route table, request/duration
	// counters for /metrics + the access log (observe.go)
	observeFields
}

// SetPriceHistPath makes the price-history ring durable: it is loaded on the first
// sample and saved after each one, so a node restart no longer empties the chart.
// Call before Handler(). Empty path = in-memory only (the old behavior).
func (s *Server) SetPriceHistPath(p string) { s.priceHistPath = p }

// pricePoint is one sample of the best OBX/XNO taker rate at a unix time.
// Rate is the raw atomic "get/give" string (the same convention bestPrices /
// PairPrice.Rate emit) so the frontend's existing humanPrice/DEC math applies
// unchanged — never store a float, keep the privacy-chain convention.
type pricePoint struct {
	T    int64  // unix seconds
	Rate string // raw atomic "get_amount/give_amount"
}

// priceSampleInterval is how often the sampler records a point. 30s comfortably
// catches every block-driven book change (config.TargetBlockTime is 120s) while
// staying cheap.
const priceSampleInterval = 30 * time.Second

// priceHistCap bounds the ring: 720 points * 30s = 6 hours of history
// (~30 bytes/point -> ~22KB resident).
const priceHistCap = 720

// cachedTemplate is a short-TTL cached block template keyed by miner address.
type cachedTemplate struct {
	resp BlockTemplateResponse
	at   time.Time
}

// templateTTL bounds how often a fresh block template is built per address.
const templateTTL = 1 * time.Second

// NewServer creates an RPC server. bcast (optional) relays accepted txs to p2p.
func NewServer(c *chain.Chain, mp *mempool.Mempool, bcast func(*tx.Transaction)) *Server {
	publicSwaps := envTrue("OBX_PUBLIC_SWAPS")
	if publicSwaps {
		// audit #7-9: public /swaps/take does NOT yet support an INDEPENDENT taker — the XNO
		// is funded from THIS node's account and the OBX is claimed to THIS node's key, not the
		// web caller's. So enabling it exposes operator-funded liquidity to anyone, and the
		// caller receives nothing. Make that unmistakable; true per-user swaps need a
		// browser-side XNO wallet (taker-provided funding secret + OBX receive address).
		log.Printf("OBX_PUBLIC_SWAPS=1: WARNING — public swap-taking is OPERATOR-FUNDED. Untrusted " +
			"callers can lock THIS node's XNO and claim OBX to THIS node's key; the caller supplies " +
			"no key and receives no asset. This is demo/liquidity provisioning, NOT an independent " +
			"DEX. Leave it OFF on any node holding real funds until per-user funding is wired.")
	}
	srv := &Server{
		chain:       c,
		mp:          mp,
		bcast:       bcast,
		authToken:   os.Getenv("OBX_RPC_TOKEN"),
		publicSwaps: publicSwaps,
		tmplCache:   make(map[string]cachedTemplate),
	}
	srv.started = time.Now() // uptime anchor for /health + /metrics
	return srv
}

// SetBlockBroadcaster wires a function that relays an accepted (externally-mined)
// block to peers, enabling the /blocktemplate + /submitblock mining endpoints.
func (s *Server) SetBlockBroadcaster(f func(*block.Block)) { s.blockBcast = f }

// SetPeerProvider wires connected-peer info so /peers works.
func (s *Server) SetPeerProvider(p PeerProvider) { s.peers = p }

// SetOfferBook wires the swap order book so /offers and /offer work.
func (s *Server) SetOfferBook(p OfferProvider) { s.offers = p }

// SetNanoBackend wires the operator-provided Nano (XNO) swap-execution backend. Nil keeps
// the order book working while XNO execution stays disabled. NanoEnabled reports its state.
func (s *Server) SetNanoBackend(c swapd.NanoClient) { s.nano = c }

// SetSwapCoordinator wires the in-flight swap engine so /swaps/active and
// /swaps/take work. fee is the OBX fee taker sessions use (matches the maker's
// configured Config.Fee). nil coordinator keeps /swaps/active returning an empty
// list and /swaps/take returning 503.
func (s *Server) SetSwapCoordinator(c SwapCoordinator, fee uint64) {
	s.swaps = c
	s.swapFee = fee
}

// NanoEnabled reports whether an XNO swap-execution backend is configured.
func (s *Server) NanoEnabled() bool { return s.nano != nil }

// Handler returns the http.Handler with all routes registered.
//
// Audit fix: routes are split into PUBLIC read-only endpoints (served without
// auth) and OPERATOR/sensitive endpoints that mutate node state or leak
// operationally sensitive data. The operator set is gated by s.requireOperator
// to loopback callers or a bearer token (OBX_RPC_TOKEN).
func (s *Server) Handler() http.Handler {
	mux := newRouteMux() // records every pattern for /metrics labels + /openapi.json
	// --- PUBLIC: read-only / wallet-facing (no auth) ---
	mux.HandleFunc("/status", s.handleStatus)
	// Observability + machine-readable contract (observe.go / openapi.go):
	// readiness, liveness, Prometheus metrics, and the OpenAPI 3.0 schema.
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/metrics", s.handlePromMetrics)
	mux.HandleFunc("/openapi.json", s.handleOpenAPI)
	// Integrator endpoints (docs/NODE_API_AUDIT.md): node/network identity,
	// machine-readable params, and tx-by-hash lookup.
	mux.HandleFunc("/version", s.handleVersion)
	mux.HandleFunc("/params", s.handleParams)
	mux.HandleFunc("/tx", s.handleTx)
	mux.HandleFunc("/height", s.handleHeight)
	mux.HandleFunc("/accvalue", s.handleAccValue)
	mux.HandleFunc("/block", s.handleBlock)
	mux.HandleFunc("/blocks", s.handleBlocks)
	mux.HandleFunc("/headers", s.handleHeaders)
	mux.HandleFunc("/submittx", s.handleSubmitTx)
	// ZK anonymous-spend membership witness: a spender fetches its coin's anchor +
	// authentication path here, then builds the spend proof offline. Read-only.
	mux.HandleFunc("/zkwitness", s.handleZKWitness)
	mux.HandleFunc("/offers", s.handleOffers)
	mux.HandleFunc("/offers/json", s.handleOffersJSON)
	mux.HandleFunc("/offer", s.handlePostOffer)
	// Order-book price discovery: maker-authenticated cancel, depth-aware quote,
	// and the cumulative depth ladder. CORS-enabled, additive, read-only except
	// cancel (which is gated by the maker signature, not by operator auth).
	mux.HandleFunc("/offer/cancel", s.handleOfferCancel)
	mux.HandleFunc("/quote", s.handleQuote)
	mux.HandleFunc("/depth", s.handleDepth)
	// Swap UI contract: live liquidity, active swap sessions (each step), and
	// taker-initiated swaps. CORS-enabled (proxy-friendly) like the explorer.
	mux.HandleFunc("/liquidity", s.handleLiquidity)
	mux.HandleFunc("/swaps/active", s.handleSwapsActive)
	mux.HandleFunc("/swaps/take", s.handleSwapsTake)
	// NON-CUSTODIAL browser swap relay: the browser runs the taker (WASM) and
	// signs its own XNO + OBX legs; these endpoints only relay envelopes to the
	// local maker session and read/publish browser-signed Nano blocks. Public-safe
	// (no operator funds at risk) — unlike /swaps/take.
	mux.HandleFunc("/swaps/relay/open", s.handleSwapRelayOpen)
	mux.HandleFunc("/swaps/relay/send", s.handleSwapRelaySend)
	mux.HandleFunc("/swaps/relay/recv", s.handleSwapRelayRecv)
	mux.HandleFunc("/swaps/relay/status", s.handleSwapRelayStatus)
	mux.HandleFunc("/swaps/swapout", s.handleSwapOut)
	mux.HandleFunc("/swaps/nano/account", s.handleNanoAccount)
	mux.HandleFunc("/swaps/nano/receivable", s.handleNanoReceivable)
	mux.HandleFunc("/swaps/nano/receivable_status", s.handleNanoReceivableStatus)
	mux.HandleFunc("/swaps/nano/watch", s.handleNanoWatch) // SSE deposit push
	mux.HandleFunc("/swaps/nano/block", s.handleNanoBlock)
	mux.HandleFunc("/swaps/nano/publish", s.handleNanoPublish)
	// Matching-engine market-data + order status: the executed-trade tape, OHLCV
	// candles, 24h stats, and per-maker / per-order fill state. CORS-enabled,
	// read-only, off-chain (tape is per-node, non-consensus).
	mux.HandleFunc("/trades", s.handleTrades)
	mux.HandleFunc("/candles", s.handleCandles)
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/orders", s.handleOrders)
	mux.HandleFunc("/order/", s.handleOrder)
	mux.HandleFunc("/my", s.handleMy)
	mux.HandleFunc("/feerate", s.handleFeeRate)
	mux.HandleFunc("/mempool", s.handleMempool)
	mux.HandleFunc("/mining", s.handleMining) // node's own built-in-miner status (mining.go)
	mux.HandleFunc("/explorer/summary", s.handleExplorerSummary)
	mux.HandleFunc("/explorer/block", s.handleExplorerBlock)
	mux.HandleFunc("/explorer/blocks", s.handleExplorerBlocks) // paged descending block-summary list
	mux.HandleFunc("/explorer/mempool", s.handleExplorerMempool)
	mux.HandleFunc("/explorer/vaults", s.handleExplorerVaults)
	mux.HandleFunc("/explorer/pricehistory", s.handleExplorerPriceHistory)
	mux.HandleFunc("/explorer/metrics", s.handleExplorerMetrics) // sparkline series + swap volume
	mux.HandleFunc("/explorer/swaps", s.handleExplorerSwaps)
	// XNO proceeds account: the derived nano_ address + live balance/receivable.
	// PUBLIC and read-only — never touches the secret (safe to public-proxy).
	mux.HandleFunc("/xno/account", s.handleXNOAccount)
	// Launch the OBX/XNO price sampler once. Handler() is built a single time at
	// startup (cmd/obscura-node/main.go), and the Once makes a stray second build
	// harmless. The goroutine just skips ticks while no order book / no XNO offers
	// exist, so it is safe to start regardless of wiring order.
	s.priceStarted.Do(func() { go s.runPriceSampler() })
	s.metricsStarted.Do(func() { go s.runMetricsSampler() })
	// /peers is public but degrades to a count-only view for untrusted callers
	// (the full peer IP list is a deanonymization leak on a privacy coin).
	mux.HandleFunc("/peers", s.handlePeers)
	// --- OPERATOR / sensitive: state-changing or DoS-amplifying (gated) ---
	mux.HandleFunc("/blocktemplate", s.requireOperator(s.handleBlockTemplate))
	mux.HandleFunc("/submitblock", s.requireOperator(s.handleSubmitBlock))
	// XNO proceeds backup + withdraw. /xno/recovery reveals the seed-derived XNO
	// secret for LOCAL backup; /xno/withdraw signs a send to an external nano_
	// dest (secret derived in-process, never returned). BOTH are operator-gated
	// (loopback / OBX_RPC_TOKEN) and MUST NEVER be added to the public proxy.
	mux.HandleFunc("/xno/recovery", s.requireOperator(s.handleXNORecovery))
	mux.HandleFunc("/xno/withdraw", s.requireOperator(s.handleXNOWithdraw))
	// NOTE: the /witness endpoint was removed — it leaked which output a wallet
	// was interested in (deanonymization) and was an O(N) DoS amplifier. The
	// sound wallet builds spends entirely offline and never needs it.
	//
	// CORS: wrap the whole surface so browser clients can call a node directly
	// (header-only; does not relax operator gating). Disable with OBX_RPC_NO_CORS=1.
	//
	// observe (outermost): X-OBX-Api-Version header, per-route request/duration
	// metrics (labels normalized to the registered patterns recorded above), and
	// the opt-in access log (OBX_RPC_LOG=1).
	// Unmatched paths: JSON 404 in the unified {"error","code"} shape instead of
	// Go's plain-text default. Registered on the inner ServeMux directly so the
	// catch-all "/" never enters the recorded route table (metrics label it
	// "other"; the OpenAPI spec/tests enumerate only real endpoints).
	mux.ServeMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpErr(w, http.StatusNotFound, "no such endpoint (see /openapi.json)")
	})
	s.routes = mux.patterns
	return s.observe(mux, corsMiddleware(mux))
}

// envTrue reports whether an env var is set to a truthy value (1/true/yes/on).
func envTrue(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// isLoopback reports whether the request originates from the local host.
func isLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

// hasBearer reports whether the request carries the configured operator bearer
// token. Returns false when no token is configured.
func (s *Server) hasBearer(r *http.Request) bool {
	if s.authToken == "" {
		return false
	}
	const pfx = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, pfx) {
		return false
	}
	got := strings.TrimSpace(h[len(pfx):])
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.authToken)) == 1
}

// trusted reports whether the caller is allowed to reach operator/sensitive
// endpoints: loopback always, or a valid bearer token when OBX_RPC_TOKEN is set.
// proxiedPublic reports that a request was forwarded by the node's UI proxy in HOSTED mode —
// i.e. an arbitrary public web visitor, never the local operator. The UI proxy sets the
// X-OBX-Proxied header on a FRESH forwarded request (a client cannot forge it; the RPC is
// loopback-bound so the only public path in is the proxy). Such requests must not count as
// trusted on loopback alone (audit BUG-2: the proxy otherwise made every public caller look
// like loopback, silently bypassing the /swaps/take gate).
func proxiedPublic(r *http.Request) bool { return r.Header.Get("X-OBX-Proxied") == "1" }

func (s *Server) trusted(r *http.Request) bool {
	if proxiedPublic(r) {
		return s.hasBearer(r) // a hosted public visitor is untrusted unless it carries the operator token
	}
	return isLoopback(r) || s.hasBearer(r)
}

// requireOperator wraps a handler so only trusted callers (loopback or a valid
// bearer token) reach it. Audit fix: the operator surface was unauthenticated.
func (s *Server) requireOperator(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.trusted(r) {
			if s.authToken != "" {
				w.Header().Set("WWW-Authenticate", "Bearer")
			}
			httpErr(w, http.StatusForbidden, "forbidden: operator endpoint")
			return
		}
		h(w, r)
	}
}

// StatusResponse is the node status payload.
type StatusResponse struct {
	Coin          string `json:"coin"`
	Ticker        string `json:"ticker"`
	Height        uint64 `json:"height"`
	Difficulty    uint64 `json:"difficulty"`
	EmittedAtomic uint64 `json:"emitted_atomic"`
	EmittedOBX    string `json:"emitted_obx"`
	IncentivePool uint64 `json:"incentive_pool_atomic"`
	AccSize       uint64 `json:"accumulator_size"`
	Backend       string `json:"accumulator_backend"`
	PoWBackend    string `json:"pow_backend"`
	MempoolSize   int    `json:"mempool_size"`

	// Sync/health signal an integrator can trust BEFORE crediting deposits (audit
	// IMPORTANT #6). TipHeight mirrors Height (explicit name); PeerCount is the
	// connected-peer count. BestKnownHeight is the highest tip any connected peer has
	// advertised (omitted when no peer-height signal is available). Synced is the
	// best-effort verdict; SyncBasis names exactly how it was derived so a client is
	// never misled about its reliability.
	TipHeight       uint64 `json:"tip_height"`
	PeerCount       int    `json:"peer_count"`
	BestKnownHeight uint64 `json:"best_known_height,omitempty"`
	Synced          bool   `json:"synced"`
	SyncBasis       string `json:"sync_basis"`

	// Liveness/stuck-detection observability (P2P robustness). BlocksBehind is
	// max(best_known_height − tip_height, 0) — 0 when no peer height is known (see
	// SyncBasis; never fabricated). LastBlockAgeSeconds is now − tip header
	// timestamp (miner-set, consensus-bounded drift), 0 at genesis-only height.
	// SnapshotSync reports the p2p snapshot fast-sync transfer state; omitted when
	// the peer layer cannot report it.
	BlocksBehind        uint64              `json:"blocks_behind"`
	LastBlockAgeSeconds int64               `json:"last_block_age_seconds"`
	SnapshotSync        *SnapshotSyncStatus `json:"snapshot_sync,omitempty"`

	// stallReason (unexported, not serialized) is set by fillSyncStatus when the
	// stall rule fires: peers > 0 AND blocks_behind > chain.MaxReorgDepth AND no
	// observed tip advance for > 20×TargetBlockTime. /health serves it as 503
	// "degraded" with this reason. Detection only — no self-heal action is taken.
	stallReason string
}

// SnapshotSyncStatus mirrors the p2p snapshot fast-sync receiver state:
// state "idle" (nothing in flight) or "receiving" with chunk progress.
type SnapshotSyncStatus struct {
	State          string `json:"state"` // "idle" | "receiving"
	ReceivedChunks int    `json:"received_chunks,omitempty"`
	TotalChunks    int    `json:"total_chunks,omitempty"` // 0 until the first chunk arrives
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	tip := s.chain.Height()
	resp := StatusResponse{
		Coin:          config.CoinName,
		Ticker:        config.Ticker,
		Height:        tip,
		Difficulty:    s.chain.ExpectedDifficulty(),
		EmittedAtomic: s.chain.Emitted(),
		EmittedOBX:    config.FormatAmount(s.chain.Emitted()),
		IncentivePool: s.chain.IncentivePool(),
		AccSize:       s.chain.AccSize(),
		Backend:       config.AccumulatorBackend,
		PoWBackend:    pow.BackendName,
		TipHeight:     tip,
	}
	if s.mp != nil {
		resp.MempoolSize = s.mp.Size()
	}
	s.fillSyncStatus(&resp)
	writeJSON(w, resp)
}

// fillSyncStatus derives the sync/health fields. It prefers a REAL comparison of
// our tip against the best height our peers advertise (when the p2p layer exposes
// the optional BestKnownHeight capability); otherwise it falls back to a documented
// peer-count heuristic. It never fabricates: SyncBasis always states the method.
// It also fills the liveness fields (blocks_behind / last_block_age_seconds /
// snapshot_sync) and applies the stall-detection rule (see StatusResponse.stallReason).
func (s *Server) fillSyncStatus(resp *StatusResponse) {
	// Tip age + tip-advance observation are chain-side and independent of peers.
	// stalledFor is how long the tip has been observed unchanged (wall clock).
	var stalledFor time.Duration
	if s.chain != nil {
		if ts := s.chain.Tip().Timestamp; resp.TipHeight > 0 && ts > 0 {
			if age := time.Now().Unix() - ts; age > 0 {
				resp.LastBlockAgeSeconds = age
			}
		}
		stalledFor = s.observeTip(resp.TipHeight)
	}
	if s.peers == nil {
		resp.Synced = false
		resp.SyncBasis = "no_peer_provider"
		return
	}
	resp.PeerCount = s.peers.PeerCount()
	// Snapshot fast-sync transfer state (optional p2p capability).
	if sp, ok := s.peers.(interface {
		SnapshotSyncState() (string, int, int)
	}); ok && sp != nil {
		state, got, total := sp.SnapshotSyncState()
		ss := &SnapshotSyncStatus{State: state}
		if state == "receiving" {
			ss.ReceivedChunks, ss.TotalChunks = got, total
		}
		resp.SnapshotSync = ss
	}
	if bp, ok := s.peers.(interface {
		BestKnownHeight() (uint64, int, bool)
	}); ok && bp != nil {
		if best, _, known := bp.BestKnownHeight(); known {
			resp.BestKnownHeight = best
			if best > resp.TipHeight {
				resp.BlocksBehind = best - resp.TipHeight
			}
			resp.Synced = resp.TipHeight >= best
			resp.SyncBasis = "tip>=best_known_peer_height"
			// Stall detection (observability only; no self-heal): connected peers
			// say we are far behind (beyond the reorg-finality window, so this is
			// not normal jitter) AND the tip has not been observed to advance for
			// > 20×TargetBlockTime. A fresh node that is syncing (tip advancing)
			// never trips this — its stall clock keeps resetting.
			if thresh := time.Duration(20*config.TargetBlockTime) * time.Second; resp.PeerCount > 0 &&
				resp.BlocksBehind > chain.MaxReorgDepth && stalledFor > thresh {
				resp.stallReason = fmt.Sprintf(
					"sync stalled: %d blocks behind best-known peer height %d with no tip advance for %ds (> %ds = 20×target block time)",
					resp.BlocksBehind, best, int64(stalledFor.Seconds()), int64(thresh.Seconds()))
			}
			return
		}
		// peers may be connected but none has advertised a height yet.
		resp.Synced = resp.PeerCount > 0
		resp.SyncBasis = "no_peer_height_advertised_yet; heuristic synced=peers>0"
		return
	}
	// p2p layer can't report peer heights: best-effort heuristic only.
	resp.Synced = resp.PeerCount > 0
	resp.SyncBasis = "peer_count_only_no_height_signal; heuristic synced=peers>0"
}

func (s *Server) handleHeight(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]uint64{"height": s.chain.Height()})
}

// FeeRateResponse is a dynamic fee-estimation payload (Block 20). Rates are
// fee-per-byte in atomic units; multiply by your transaction's serialized size.
type FeeRateResponse struct {
	Target       int    `json:"target_blocks"`
	FeePerByte   uint64 `json:"fee_per_byte"`
	FloorPerByte uint64 `json:"floor_per_byte"`
	Window       int    `json:"window_blocks"`
}

// FeeWindow is how many recent blocks the estimator samples.
const FeeWindow = 30

func (s *Server) handleFeeRate(w http.ResponseWriter, r *http.Request) {
	target := 2
	if v := r.URL.Query().Get("target"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			target = n
		}
	}
	samples := s.chain.RecentFeeSamples(FeeWindow)
	rate := fee.Estimate(samples, target, config.MinFeePerByte)
	writeJSON(w, FeeRateResponse{
		Target:       target,
		FeePerByte:   rate,
		FloorPerByte: config.MinFeePerByte,
		Window:       len(samples),
	})
}

// BlockTemplateResponse is an unmined block for an external miner to grind.
type BlockTemplateResponse struct {
	Height     uint64 `json:"height"`
	Difficulty uint64 `json:"difficulty"`
	Block      string `json:"block"` // hex of the full serialized block (nonce = 0)
	Seed       string `json:"seed"`  // hex per-epoch PoW cache seed to grind under
}

// handleBlockTemplate builds a block (coinbase to ?address= + mempool txs) for an
// external miner to grind. The miner increments the header nonce until the PoW
// meets the difficulty, then posts it to /submitblock.
func (s *Server) handleBlockTemplate(w http.ResponseWriter, r *http.Request) {
	addrStr := r.URL.Query().Get("address")
	if addrStr == "" {
		httpErr(w, 400, "address required")
		return
	}
	dest, err := parseAddr(addrStr)
	if err != nil {
		httpErr(w, 400, "bad address: "+err.Error())
		return
	}
	// Audit fix: serve a short-TTL per-address cached template so a flood of
	// requests cannot grind the chain/mempool locks ~once per request (DoS
	// amplifier). A miner polling faster than templateTTL just re-gets the same
	// template, which is correct — the work is identical until the tip moves.
	s.tmplMu.Lock()
	if c, ok := s.tmplCache[addrStr]; ok && time.Since(c.at) < templateTTL && c.resp.Height == s.chain.Height()+1 {
		resp := c.resp
		s.tmplMu.Unlock()
		writeJSON(w, resp)
		return
	}
	s.tmplMu.Unlock()
	txs := s.mp.Select(1000)
	fees := chain.CollectedFees(txs)
	minted := s.chain.ExpectedCoinbaseMinted(fees, nil)
	cb, err := wallet.BuildCoinbaseTo(dest, s.chain.Height()+1, minted, nil)
	if err != nil {
		httpErr(w, 500, "coinbase: "+err.Error())
		return
	}
	tmpl, err := s.chain.BlockTemplate(append([]*tx.Transaction{cb}, txs...))
	if err != nil {
		httpErr(w, 500, "template: "+err.Error())
		return
	}
	resp := BlockTemplateResponse{
		Height:     tmpl.Header.Height,
		Difficulty: tmpl.Header.Difficulty,
		Block:      hex.EncodeToString(tmpl.Serialize()),
		Seed:       hex.EncodeToString(s.chain.PoWSeed(tmpl.Header.Height)),
	}
	s.tmplMu.Lock()
	s.tmplCache[addrStr] = cachedTemplate{resp: resp, at: time.Now()}
	s.tmplMu.Unlock()
	writeJSON(w, resp)
}

// handleSubmitBlock accepts a hex-serialized mined block, adds it to the chain,
// removes its txs from the mempool, and relays it to peers.
func (s *Server) handleSubmitBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpErr(w, 405, "POST required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2*config.MaxBlockBytes+1024)
	var req struct {
		Block string `json:"block"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, 400, "bad json")
		return
	}
	raw, err := hex.DecodeString(req.Block)
	if err != nil {
		httpErr(w, 400, "bad hex")
		return
	}
	b, err := block.DeserializeBlock(raw)
	if err != nil {
		httpErr(w, 400, "bad block: "+err.Error())
		return
	}
	if err := s.chain.AddBlock(b); err != nil {
		httpErr(w, 400, "rejected: "+err.Error())
		return
	}
	if s.mp != nil {
		s.mp.Remove(b.Txs)
	}
	if s.blockBcast != nil {
		s.blockBcast(b)
	}
	writeJSON(w, map[string]uint64{"height": b.Header.Height})
}

// parseAddr accepts a Base58 checksummed address or raw hex.
func parseAddr(s string) (commit.StealthAddress, error) {
	if a, err := commit.ParseHumanAddress(s); err == nil {
		return a, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return commit.StealthAddress{}, err
	}
	return commit.DecodeAddress(b)
}

// PeersResponse lists connected peers.
type PeersResponse struct {
	Count int      `json:"count"`
	Peers []string `json:"peers"`
}

func (s *Server) handlePeers(w http.ResponseWriter, r *http.Request) {
	if s.peers == nil {
		writeJSON(w, PeersResponse{Peers: []string{}})
		return
	}
	// Audit fix: the full peer IP list is a deanonymization leak on a privacy
	// coin. Only trusted (loopback / token) operators see the address list;
	// everyone else gets the count alone.
	if !s.trusted(r) {
		writeJSON(w, PeersResponse{Count: s.peers.PeerCount(), Peers: []string{}})
		return
	}
	addrs := s.peers.PeerAddrs()
	if addrs == nil {
		addrs = []string{}
	}
	writeJSON(w, PeersResponse{Count: s.peers.PeerCount(), Peers: addrs})
}

func (s *Server) handleMempool(w http.ResponseWriter, r *http.Request) {
	if s.mp == nil {
		writeJSON(w, mempool.Stats{})
		return
	}
	writeJSON(w, s.mp.Stats())
}

func (s *Server) handleAccValue(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"accvalue": hex.EncodeToString(s.chain.AccValue())})
}

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	// Block-by-hash: ?hash=<64hex> resolves the block by its Header.ID() via a
	// bounded backward scan (lets an explorer search a block hash / follow prev_hash).
	if hq := r.URL.Query().Get("hash"); hq != "" {
		if !validNanoHash(hq) { // reuse: a plain 64-hex check (not nano-specific)
			httpErr(w, 400, "bad hash")
			return
		}
		h, ok := s.findBlockHeightByHash(hq)
		if !ok {
			httpErr(w, 404, "not found")
			return
		}
		b, _ := s.chain.BlockByHeight(h)
		writeJSON(w, map[string]string{"block": hex.EncodeToString(b.Serialize())})
		return
	}
	hs := r.URL.Query().Get("height")
	h, err := strconv.ParseUint(hs, 10, 64)
	if err != nil {
		httpErr(w, 400, "bad height")
		return
	}
	b, ok := s.chain.BlockByHeight(h)
	if !ok {
		httpErr(w, 404, "not found")
		return
	}
	writeJSON(w, map[string]string{"block": hex.EncodeToString(b.Serialize())})
}

// handleBlocks serves a RANGE of full blocks (hex) in one response so a scanning
// wallet fetches O(N/batch) requests instead of one per height. Bounded per request
// (anti-DoS, and so one wallet sync does not monopolize the node or trip rate limits).
// Params: from (inclusive height), count (default/cap 256). Stops early at the tip.
func (s *Server) handleBlocks(w http.ResponseWriter, r *http.Request) {
	from, _ := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
	count, _ := strconv.ParseUint(r.URL.Query().Get("count"), 10, 64)
	if count == 0 || count > 256 {
		count = 256 // full blocks are large; keep the cap tighter than /headers
	}
	out := make([]string, 0, count)
	for h := from; h < from+count; h++ {
		b, ok := s.chain.BlockByHeight(h)
		if !ok {
			break // reached the tip (or a pruned body): return what we have
		}
		out = append(out, hex.EncodeToString(b.Serialize()))
	}
	writeJSON(w, map[string][]string{"blocks": out})
}

// ZKWitnessResponse is the membership witness for a ZK coin: the epoch anchor
// (root the coin is proven a member of), its authentication path (one 32-byte hex
// sibling per tree level, leaf-to-root), the leaf's index within that path, the
// tree depth, and ok=false when the leaf is unknown.
type ZKWitnessResponse struct {
	Anchor string   `json:"anchor"`
	Path   []string `json:"path"`
	Index  int      `json:"index"`
	Depth  int      `json:"depth"`
	OK     bool     `json:"ok"`
}

// handleZKWitness returns the anchor + authentication path a spender needs to build
// an anonymous ZK spend for the coin whose 32-byte leaf (note commitment) is given as
// ?leaf=<hex>. Read-only: the spend proof itself is built offline by the wallet.
func (s *Server) handleZKWitness(w http.ResponseWriter, r *http.Request) {
	depth := s.chain.ZKDepth()
	leafHex := r.URL.Query().Get("leaf")
	leaf, err := hex.DecodeString(leafHex)
	if err != nil || len(leaf) != 32 {
		httpErr(w, 400, "leaf must be 32-byte hex")
		return
	}
	anchor, path, ok := s.chain.ZKWitnessFor(leaf)
	if !ok {
		writeJSON(w, ZKWitnessResponse{Path: []string{}, Depth: depth, OK: false})
		return
	}
	sibs := make([]string, 0, len(path.Siblings))
	for _, n := range path.Siblings {
		sibs = append(sibs, hex.EncodeToString(stark.NodeBytes(n)))
	}
	writeJSON(w, ZKWitnessResponse{
		Anchor: hex.EncodeToString(anchor),
		Path:   sibs,
		Index:  path.Index,
		Depth:  depth,
		OK:     true,
	})
}

// handleHeaders serves a range of block HEADERS (hex) for SPV light clients —
// far cheaper than full blocks.
func (s *Server) handleHeaders(w http.ResponseWriter, r *http.Request) {
	from, _ := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
	count, _ := strconv.ParseUint(r.URL.Query().Get("count"), 10, 64)
	if count == 0 || count > 2000 {
		count = 2000 // cap per request (anti-DoS)
	}
	out := make([]string, 0, count)
	for h := from; h < from+count; h++ {
		hdr, ok := s.chain.HeaderByHeight(h)
		if !ok {
			break
		}
		out = append(out, hex.EncodeToString(hdr.Serialize()))
	}
	writeJSON(w, map[string][]string{"headers": out})
}

// handleOffers lists the current swap order book (hex-serialized offers).
func (s *Server) handleOffers(w http.ResponseWriter, r *http.Request) {
	if s.offers == nil {
		httpErr(w, 503, "order book unavailable")
		return
	}
	list := s.offers.Offers()
	out := make([]string, 0, len(list))
	for _, o := range list {
		out = append(out, hex.EncodeToString(o.Serialize()))
	}
	writeJSON(w, map[string][]string{"offers": out})
}

// OfferJSON is a decoded order-book offer for direct JSON consumption.
type OfferJSON struct {
	ID         string `json:"id"`
	Maker      string `json:"maker"`
	GiveAsset  string `json:"give_asset"`
	GetAsset   string `json:"get_asset"`
	GiveAmount uint64 `json:"give_amount"`
	GetAmount  uint64 `json:"get_amount"`
	Rate       string `json:"rate"` // get_amount/give_amount decimal string
	Expiry     int64  `json:"expiry"`
}

// handleOffersJSON lists the current swap order book as decoded JSON rows,
// with order id + rate, sorted by rate ascending.
func (s *Server) handleOffersJSON(w http.ResponseWriter, r *http.Request) {
	if s.offers == nil {
		httpErr(w, 503, "order book unavailable")
		return
	}
	list := s.offers.Offers()
	out := make([]OfferJSON, 0, len(list))
	for _, o := range list {
		id := o.ID()
		rate := "0"
		if o.GiveAmount != 0 {
			rate = fmt.Sprintf("%g", float64(o.GetAmount)/float64(o.GiveAmount))
		}
		out = append(out, OfferJSON{
			ID:         hex.EncodeToString(id[:]),
			Maker:      hex.EncodeToString(o.Maker),
			GiveAsset:  o.GiveAsset,
			GetAsset:   o.GetAsset,
			GiveAmount: o.GiveAmount,
			GetAmount:  o.GetAmount,
			Rate:       rate,
			Expiry:     o.Expiry,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		ri, _ := strconv.ParseFloat(out[i].Rate, 64)
		rj, _ := strconv.ParseFloat(out[j].Rate, 64)
		return ri < rj
	})
	// Pagination/totals (audit IMPORTANT #8): report the full book size so a client
	// knows when the response was truncated, and honor an explicit ?limit (default
	// 2000, hard cap 5000) plus ?offset (skip N rows from the rate-sorted list).
	// `offers` stays the same shape the UI reads.
	total := len(out)
	limit := 2000
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	offset := parseOffset(r)
	if offset > len(out) {
		offset = len(out)
	}
	out = out[offset:]
	if len(out) > limit {
		out = out[:limit]
	}
	writeJSON(w, OffersJSONResponse{Offers: out, Total: total, Offset: offset, Truncated: offset+len(out) < total})
}

// parseOffset reads the optional ?offset pagination param (>=0; bad input = 0).
func parseOffset(r *http.Request) int {
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// OffersJSONResponse is the decoded order-book listing with pagination metadata.
type OffersJSONResponse struct {
	Offers    []OfferJSON `json:"offers"`
	Total     int         `json:"total"`     // full live-book size before truncation
	Offset    int         `json:"offset"`    // rows skipped (?offset)
	Truncated bool        `json:"truncated"` // true when more offers exist beyond offset+len(offers)
}

// handlePostOffer accepts a hex-serialized swap offer and gossips it.
func (s *Server) handlePostOffer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpErr(w, 405, "POST required")
		return
	}
	if s.offers == nil {
		httpErr(w, 503, "order book unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req struct {
		Offer string `json:"offer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, 400, "bad json")
		return
	}
	raw, err := hex.DecodeString(req.Offer)
	if err != nil {
		httpErr(w, 400, "bad hex")
		return
	}
	o, err := swapbook.ParseOffer(raw)
	if err != nil {
		httpErr(w, 400, "bad offer")
		return
	}
	if err := s.offers.PostOffer(o); err != nil {
		httpErr(w, 400, "rejected: "+err.Error())
		return
	}
	id := o.ID()
	writeJSON(w, map[string]string{"offer_id": hex.EncodeToString(id[:])})
}

func (s *Server) handleSubmitTx(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpErr(w, 405, "POST required")
		return
	}
	// bound the request body (anti-DoS): hex tx <= 2*MaxTxBytes + slack.
	r.Body = http.MaxBytesReader(w, r.Body, 2*tx.MaxTxBytes+1024)
	var req struct {
		Tx string `json:"tx"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		httpErr(w, 400, "bad json")
		return
	}
	raw, err := hex.DecodeString(req.Tx)
	if err != nil {
		httpErr(w, 400, "bad hex")
		return
	}
	t, err := tx.Deserialize(raw)
	if err != nil {
		httpErr(w, 400, "bad tx: "+err.Error())
		return
	}
	if s.mp != nil {
		if err := s.mp.Add(t); err != nil {
			httpErr(w, 400, "rejected: "+err.Error())
			return
		}
	}
	if s.bcast != nil {
		s.bcast(t)
	}
	writeJSON(w, map[string]string{"txid": t.HashHex()})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr emits the unified JSON error body {"error":msg,"code":status} WITH the
// correct HTTP status, so a generic client can branch on the status code while the
// UI (which reads `.error`) keeps working. Kept as a thin alias of httpErr
// (observe.go) so the historical order-book/swap call sites need not change; the
// former plain-text http.Error core routes now use the same envelope.
func writeErr(w http.ResponseWriter, status int, msg string) { httpErr(w, status, msg) }
