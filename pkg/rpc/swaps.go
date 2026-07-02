package rpc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"

	"obscura/pkg/config"
	"obscura/pkg/swapbook"
	"obscura/pkg/swapd"
)

// Swap UI endpoints. These three routes are the contract the website wallet/
// explorer build against to reflect liquidity, the lifecycle of EACH in-flight
// swap, and to start a taker swap. All are CORS-enabled (proxy-friendly) like
// the explorer routes, and emit raw atomic amounts as strings so the frontend
// applies per-asset decimals exactly as it does elsewhere.

// LiquidityPair is one directed-pair liquidity row for /liquidity.
type LiquidityPair struct {
	Pair      string `json:"pair"`       // "OBX/XNO"
	GiveAsset string `json:"give_asset"` // maker gives
	GetAsset  string `json:"get_asset"`  // maker wants
	TotalGive string `json:"total_give"` // Σ give, atomic-string
	TotalGet  string `json:"total_get"`  // Σ get, atomic-string
	Offers    int    `json:"offers"`
	BestRate  string `json:"best_rate"` // raw get/give decimal string
}

// LiquidityResponse aggregates the live order book per pair.
type LiquidityResponse struct {
	Pairs       []LiquidityPair `json:"pairs"`
	TotalOffers int             `json:"total_offers"`
	TotalMakers int             `json:"total_makers"`
}

// handleLiquidity aggregates the live order book per pair: total give/get,
// offer count, and best rate (via the swapbook Book.Liquidity helper). Returns an
// empty pair list (not an error) when the book is wired but empty.
func (s *Server) handleLiquidity(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if s.offers == nil {
		httpErr(w, http.StatusServiceUnavailable, "order book unavailable")
		return
	}
	pairs, totalOffers, totalMakers := s.offers.Liquidity()
	out := LiquidityResponse{Pairs: make([]LiquidityPair, 0, len(pairs)), TotalOffers: totalOffers, TotalMakers: totalMakers}
	for _, p := range pairs {
		out.Pairs = append(out.Pairs, LiquidityPair{
			Pair:      p.Pair,
			GiveAsset: p.GiveAsset,
			GetAsset:  p.GetAsset,
			TotalGive: u64s(p.TotalGive),
			TotalGet:  u64s(p.TotalGet),
			Offers:    p.Offers,
			BestRate:  p.BestRate,
		})
	}
	writeJSON(w, out)
}

// handleOfferCancel cancels a single live offer. Body:
//
//	{"offer_id":"<hex>", "sig":"<hex>"}
//
// where sig is the maker's 64-byte cancellation signature over the offer id (see
// swapbook.CancelMessage / Book.SignCancel). It calls the book's Cancel, which
// verifies the signature was produced by that offer's maker before removing it.
// Returns {"ok":true} on success or {"error":...} otherwise. CORS-enabled like
// the other swap UI routes. Cancellation is best-effort and LOCAL to this node:
// gossiped copies on peers expire by TTL (offers carry short TTLs for this).
func (s *Server) handleOfferCancel(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		httpErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if s.offers == nil {
		writeErr(w, http.StatusServiceUnavailable, "order book unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var req struct {
		OfferID string `json:"offer_id"`
		Sig     string `json:"sig"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	idBytes, err := hex.DecodeString(req.OfferID)
	if err != nil || len(idBytes) != 32 {
		writeErr(w, http.StatusBadRequest, "bad offer_id")
		return
	}
	sig, err := hex.DecodeString(req.Sig)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad sig")
		return
	}
	var id [32]byte
	copy(id[:], idBytes)
	if err := s.offers.Cancel(id, sig); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// QuoteResponse is the depth-aware fill a taker would receive for a given size.
type QuoteResponse struct {
	Give       string `json:"give"`        // asset the taker gives
	Get        string `json:"get"`         // asset the taker receives
	Size       string `json:"size"`        // requested give size, atomic-string
	Filled     string `json:"filled"`      // give actually fillable, atomic-string
	GetOut     string `json:"get_out"`     // get received for `filled`, atomic-string
	VWAP       string `json:"vwap"`        // volume-weighted rate get/give
	OffersUsed int    `json:"offers_used"` // distinct offers consumed
	Full       bool   `json:"full"`        // true iff filled == size (book deep enough)
}

// handleQuote prices a taker giving ?size atomic units of ?give for ?get against
// the live book, walking offers best-rate-first (swapbook Book.Quote). CORS-
// enabled. Returns a partial-fill quote (full=false) when the book is too thin.
func (s *Server) handleQuote(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if s.offers == nil {
		httpErr(w, http.StatusServiceUnavailable, "order book unavailable")
		return
	}
	give := r.URL.Query().Get("give")
	get := r.URL.Query().Get("get")
	size, err := strconv.ParseUint(r.URL.Query().Get("size"), 10, 64)
	if err != nil || size == 0 || give == "" || get == "" {
		httpErr(w, http.StatusBadRequest, "give, get, and size>0 required")
		return
	}
	filled, getOut, vwap, offersUsed, full := s.offers.Quote(give, get, size)
	writeJSON(w, QuoteResponse{
		Give:       give,
		Get:        get,
		Size:       u64s(size),
		Filled:     u64s(filled),
		GetOut:     u64s(getOut),
		VWAP:       fmt.Sprintf("%g", vwap),
		OffersUsed: offersUsed,
		Full:       full,
	})
}

// DepthRung is one cumulative rung of the order-book depth ladder.
type DepthRung struct {
	Rate    string `json:"rate"`     // taker rate at this offer (get per give)
	Give    string `json:"give"`     // this offer's give capacity, atomic-string
	Get     string `json:"get"`      // this offer's get size, atomic-string
	CumGive string `json:"cum_give"` // cumulative give through this rung
	CumGet  string `json:"cum_get"`  // cumulative get through this rung
	OfferID string `json:"offer_id"` // hex offer id
}

// DepthResponse is the full depth ladder for one directed pair.
type DepthResponse struct {
	Give  string      `json:"give"`
	Get   string      `json:"get"`
	Rungs []DepthRung `json:"rungs"`
}

// handleDepth returns the cumulative rate ladder for a taker giving ?give for
// ?get (swapbook Book.Depth), best-rate-first. CORS-enabled.
func (s *Server) handleDepth(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if s.offers == nil {
		httpErr(w, http.StatusServiceUnavailable, "order book unavailable")
		return
	}
	give := r.URL.Query().Get("give")
	get := r.URL.Query().Get("get")
	if give == "" || get == "" {
		httpErr(w, http.StatusBadRequest, "give and get required")
		return
	}
	ladder := s.offers.Depth(give, get)
	out := DepthResponse{Give: give, Get: get, Rungs: make([]DepthRung, 0, len(ladder))}
	for _, d := range ladder {
		out.Rungs = append(out.Rungs, DepthRung{
			Rate:    fmt.Sprintf("%g", d.Rate),
			Give:    u64s(d.Give),
			Get:     u64s(d.Get),
			CumGive: u64s(d.CumGive),
			CumGet:  u64s(d.CumGet),
			OfferID: hex.EncodeToString(d.OfferID[:]),
		})
	}
	writeJSON(w, out)
}

// SwapSessionView is one in-flight swap session for /swaps/active.
type SwapSessionView struct {
	ID        string         `json:"id"`
	Role      string         `json:"role"`
	Phase     string         `json:"phase"`
	OBXAmount string         `json:"obx_amount"` // atomic-string
	XNOAmount string         `json:"xno_amount"` // raw-string
	Steps     []SwapStepView `json:"steps"`
	Updated   int64          `json:"updated"`
}

// SwapStepView is one lifecycle milestone and whether it is done.
type SwapStepView struct {
	Name string `json:"name"`
	Done bool   `json:"done"`
}

// SwapsActiveResponse lists every in-flight swap session.
type SwapsActiveResponse struct {
	Sessions []SwapSessionView `json:"sessions"`
}

// handleSwapsActive snapshots the coordinator's active sessions, deriving each
// session's ordered step list from its live phase. Returns an empty sessions
// array (never an error) when no coordinator is wired or none are in flight, so
// the UI can poll unconditionally.
func (s *Server) handleSwapsActive(w http.ResponseWriter, r *http.Request) {
	cors(w)
	out := SwapsActiveResponse{Sessions: []SwapSessionView{}}
	if s.swaps == nil {
		writeJSON(w, out)
		return
	}
	for _, v := range s.swaps.ActiveSessions() {
		steps := make([]SwapStepView, 0, len(v.Steps))
		for _, st := range v.Steps {
			steps = append(steps, SwapStepView{Name: st.Name, Done: st.Done})
		}
		out.Sessions = append(out.Sessions, SwapSessionView{
			ID:        displaySwapID(v.ID),
			Role:      v.Role,
			Phase:     v.Phase,
			OBXAmount: u64s(v.OBXAmount),
			XNOAmount: bigStr(v.XNOAmount),
			Steps:     steps,
			Updated:   v.Updated,
		})
	}
	writeJSON(w, out)
}

// displaySwapID derives a stable, DISPLAY-ONLY identifier from the live SwapID for
// the public /swaps/active feed. audit SECURITY_AUDIT_2026-07-01 #7: the raw SwapID is
// the swap relay's sole sender-authenticator, so publishing it on an unauthenticated
// endpoint let anyone forge an Abort once a taker had locked real XNO. The UI only shows
// this id as a truncated label (never routes on it), so a one-way hash fully preserves UX
// while leaking ZERO bits of the routable SwapID. (The relay's SwapID-as-auth design is a
// separate, swap-core item flagged for the core owner — not changed here.)
func displaySwapID(id string) string {
	h := sha256.Sum256([]byte("Obscura/swap-display-id\x00" + id))
	return hex.EncodeToString(h[:8])
}

// handleSwapsTake starts a TAKER session for a live offer. Body:
//
//	{"offer_id":"<hex>", "peer":"<optional p2p handle>"}
//
// The offer supplies the amounts (converted to OBX-atomic / XNO-raw). The maker's
// p2p routing handle is the honest gap: offers are GOSSIPED without retaining the
// source peer, and there is no maker-pubkey -> peer-address directory yet. So the
// caller MAY pass "peer" explicitly; if omitted we fall back to the first
// connected peer (fine for the local/devnet test topology this targets, where the
// single counterparty is the only connected node). A real deployment needs offer
// provenance / peer discovery here — see the report's "stubbed" notes.
func (s *Server) handleSwapsTake(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		httpErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	// SAFETY GATE (audit S3): a take started by an anonymous (non-operator) caller
	// locks THIS node operator's XNO into the swap and claims the resulting OBX to a
	// node-internal key — the remote user funds nothing and receives nothing, while
	// the operator's real XNO is drained. So public takes are DENIED unless the
	// operator explicitly opts in (OBX_PUBLIC_SWAPS=1, e.g. a mock/demo node with no
	// real funds). Loopback / OBX_RPC_TOKEN callers (someone running their OWN node)
	// are always allowed. See docs/NEW_USER_CRITICAL_ISSUES.md (S3).
	if !s.trusted(r) && !s.publicSwaps {
		w.WriteHeader(http.StatusForbidden)
		writeJSON(w, map[string]string{
			"error":  "swap-taking is disabled on this public node",
			"detail": "completing a take would lock the operator's XNO and credit the OBX to a node-internal key, not your wallet. Run your own Obscura node to take swaps trustlessly.",
		})
		return
	}
	if s.swaps == nil {
		writeErr(w, http.StatusServiceUnavailable, "swap engine unavailable")
		return
	}
	if s.offers == nil {
		writeErr(w, http.StatusServiceUnavailable, "order book unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)
	var req struct {
		OfferID string `json:"offer_id"`
		Peer    string `json:"peer"`
		// Type is the order type / time-in-force: "" or "market" (walk the book up
		// to Size), "ioc" (immediate-or-cancel: fill what's available), "fok"
		// (fill-or-kill: all-or-nothing). When OfferID is set and Type/Size are
		// omitted, the legacy single-offer take is used (reserve exactly that offer).
		Type string `json:"type"`
		// Size, when >0, is the giveAsset (XNO offer-units) the taker wants to fill
		// across the book for the market/IOC/FOK path. Ignored when taking by
		// OfferID without a Type.
		Size uint64 `json:"size"`
		// TakerPub is the taker's hex pubkey for self-trade prevention + tape
		// attribution. Optional.
		TakerPub string `json:"taker_pub"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}

	// The wired settlement leg is OBX maker / XNO taker: makers give OBX for XNO,
	// so a taker GIVES XNO and RECEIVES OBX. matchingOffers/Reserve are expressed
	// from the taker's orientation (give=XNO, get=OBX).
	const takerGive, takerGet = "XNO", "OBX"

	var takerPub []byte
	if req.TakerPub != "" {
		if pb, err := hex.DecodeString(req.TakerPub); err == nil && len(pb) == 32 {
			takerPub = pb
		}
	}

	// Determine the reserve size + order-type options. Two entry modes:
	//   1. by offer_id (legacy / explicit single offer): reserve that offer's full
	//      remaining getAsset capacity (the XNO the taker would pay it).
	//   2. by size + type (market/IOC/FOK): walk the book best-first up to Size.
	var (
		size uint64
		opts = swapbook.ReserveOpts{TakerPub: takerPub}
	)
	switch req.Type {
	case "", "market", "ioc", "fok":
	default:
		writeErr(w, http.StatusBadRequest, "unknown order type (want market|ioc|fok)")
		return
	}
	if req.Type == "fok" {
		opts.FOK = true
	}

	var pinned *swapbook.Offer
	if req.OfferID != "" {
		idBytes, err := hex.DecodeString(req.OfferID)
		if err != nil || len(idBytes) != 32 {
			writeErr(w, http.StatusBadRequest, "bad offer_id")
			return
		}
		var want [32]byte
		copy(want[:], idBytes)
		for _, o := range s.offers.Offers() {
			if o.ID() == want {
				pinned = o
				break
			}
		}
		if pinned == nil {
			writeErr(w, http.StatusNotFound, "offer not found (expired or unknown)")
			return
		}
		if pinned.GiveAsset != "OBX" || pinned.GetAsset != "XNO" {
			writeErr(w, http.StatusBadRequest, "only OBX/XNO offers are takeable by this node")
			return
		}
		// reserve exactly this offer's remaining XNO capacity unless a smaller Size
		// was requested.
		if fs, ok := s.offers.OfferFill(want); ok {
			size = fs.RemainingGet // XNO the taker can still pay into this offer
		} else {
			size = pinned.GetAmount
		}
		if req.Size > 0 && req.Size < size {
			size = req.Size
		}
	} else {
		if req.Size == 0 {
			writeErr(w, http.StatusBadRequest, "offer_id or size required")
			return
		}
		size = req.Size
	}

	// Reserve liquidity BEFORE starting the (slow, async) settlement swap. This
	// decrements the touched offers' Remaining under the book lock, so a concurrent
	// take cannot oversell the same liquidity.
	res, getOut, giveIn, err := s.offers.Reserve(takerGive, takerGet, size, opts)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// resolve the maker peer handle. Single-rung fan-out: the wired settlement leg
	// runs against ONE peer/maker. We reserve across rungs (the book state is
	// correct) but settle against the BEST rung. Deeper rungs are released so the
	// book is not left over-committed for liquidity this node cannot settle here.
	// MULTI-RUNG FAN-OUT (one session per maker, each maker's peer resolved from
	// offer provenance) is the documented follow-up — see the report.
	best := res[0]
	rest := res[1:]
	if len(rest) > 0 {
		s.offers.ReleaseReservation(rest)
	}

	// Resolve the maker peer. PRECEDENCE: (1) explicit ?peer override; (2) the
	// maker-pubkey -> peer directory keyed by the TAKEN offer's maker (best.Maker),
	// so the Init routes to the maker who actually posted the liquidity — NOT a blind
	// PeerAddrs()[0]. If the maker is unknown (no offer provenance recorded) and no
	// override is given, we REJECT rather than guess: settling against the wrong peer
	// would just fail the swap (its AcceptInit won't match) and tie up the reservation.
	peer := req.Peer
	if peer == "" {
		if s.peers == nil {
			s.offers.ReleaseReservation([]swapbook.Reservation{best})
			writeErr(w, http.StatusServiceUnavailable, "no peer specified and no peer provider wired")
			return
		}
		if p, ok := s.peers.PeerForMaker(best.Maker); ok && p != "" {
			peer = p
		} else {
			s.offers.ReleaseReservation([]swapbook.Reservation{best})
			writeErr(w, http.StatusBadRequest, "maker peer unknown for this offer (no provenance recorded); specify \"peer\" explicitly")
			return
		}
	}

	// Convert the BEST rung's amounts to the settlement leg units. best.Recv is the
	// OBX the taker receives (offer-units); best.Pay is the XNO it gives, in offer
	// units (1e12-scale). The on-ledger Nano lock is denominated in RAW (1 XNO = 1e30
	// raw), so convert offer-units → raw (×10^18) via swapd.XNOOfferUnitsToRaw BEFORE
	// settling. (Previously best.Pay — a 1e12-unit value — was fed straight into the
	// swap as raw, under-stating the locked XNO by 10^18×.)
	obxAtomic := offerUnitsToOBXAtomic(best.Recv)
	xnoRaw := swapd.XNOOfferUnitsToRaw(new(big.Int).SetUint64(best.Pay))
	if obxAtomic == 0 || xnoRaw.Sign() == 0 {
		s.offers.ReleaseReservation([]swapbook.Reservation{best})
		writeErr(w, http.StatusBadRequest, "reserved amounts too small to settle")
		return
	}

	sess, err := s.swaps.Take(peer, obxAtomic, xnoRaw, s.swapFee)
	if err != nil {
		s.offers.ReleaseReservation([]swapbook.Reservation{best})
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	id := sess.ID()

	// Hook the session's completion: COMMIT on success (record the trade joined to
	// the on-chain SwapKey), RELEASE on failure/timeout (restore the offer's
	// Remaining). Done in a goroutine so the HTTP response returns immediately with
	// the swap id; the UI polls /swaps/active + /trades for the outcome.
	committed := []swapbook.Reservation{best}
	go func() {
		err := sess.Wait()
		if err == nil && sess.Succeeded() {
			// JOIN: record the trade under the ACTUAL on-chain SwapKey (the maker's
			// Fund tx swap key, surfaced via Session.SwapKey) so the tape correlates
			// with the explorer's on-chain SwapEvent — and with the MAKER node's own
			// tape entry (OnMakerDone keys by the same SwapKey). The Session learns
			// it after verifying Funded; fall back to the session id only if it is
			// somehow empty (should not happen on a success).
			swapKey := sess.SwapKey()
			if swapKey == "" {
				swapKey = hex.EncodeToString(id[:])
			}
			s.offers.CommitTrade(committed, takerGive, takerGet, swapKey, req.TakerPub)
			return
		}
		s.offers.ReleaseReservation(committed)
	}()

	writeJSON(w, map[string]string{
		"swap_id":     hex.EncodeToString(id[:]),
		"reserved":    u64s(giveIn),
		"get_out":     u64s(getOut),
		"settling":    bigStr(xnoRaw),
		"obx_atomic":  u64s(obxAtomic),
		"order_type":  orType(req.Type),
		"rungs_total": u64s(uint64(len(res))),
	})
}

// orType normalizes the order-type string for the response.
func orType(t string) string {
	if t == "" {
		return "market"
	}
	return t
}

// offerUnitsToOBXAtomic converts an OBX amount in offer-display units (10^DEC.OBX)
// to on-chain ATOMIC units (10^12). Mirrors offerAmounts' OBX leg.
func offerUnitsToOBXAtomic(obxUnits uint64) uint64 {
	exp := 12 - config.AutoLiquidityDecimals["OBX"]
	if exp >= 0 {
		return obxUnits * pow10(exp)
	}
	return obxUnits / pow10(-exp)
}

// TradeJSON is one executed fill for the /trades tape.
type TradeJSON struct {
	Pair    string `json:"pair"`
	Price   string `json:"price"` // raw atomic get/give
	Give    string `json:"give"`  // atomic-string
	Get     string `json:"get"`   // atomic-string
	Maker   string `json:"maker"` // hex pubkey, "" if mixed
	Taker   string `json:"taker"`
	SwapKey string `json:"swap_key"` // hex on-chain swap key join, "" until settled
	Time    int64  `json:"time"`
}

// TradesResponse is the executed-trade tape for a pair plus the last price.
type TradesResponse struct {
	Pair      string      `json:"pair"`
	LastPrice string      `json:"last_price"` // "" if no trades
	Trades    []TradeJSON `json:"trades"`
	// Pagination metadata (audit IMPORTANT #8): Limit is the effective cap applied;
	// Offset is the rows skipped (?offset); Total is the full matching-tape size
	// (the tape itself is bounded server-side); Truncated is true when more rows
	// exist beyond offset+len(trades).
	Limit     int  `json:"limit"`
	Offset    int  `json:"offset"`
	Total     int  `json:"total"`
	Truncated bool `json:"truncated"`
}

// validMarketTicker checks one asset ticker of a market-data pair: 1..16 chars,
// alphanumeric plus '-' and '.' (matching swapbook's asset rules).
func validMarketTicker(t string) bool {
	if len(t) == 0 || len(t) > 16 {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// validMarketPair checks a "GIVE/GET" pair (e.g. "OBX/XNO"): exactly one slash,
// two valid tickers. Audit #14/#92: reject malformed/oversized pairs with a clear
// 400 instead of forwarding them and silently returning empty data.
func validMarketPair(p string) bool {
	if len(p) == 0 || len(p) > 40 {
		return false
	}
	slash := -1
	for i := 0; i < len(p); i++ {
		if p[i] == '/' {
			if slash >= 0 {
				return false // more than one slash
			}
			slash = i
		}
	}
	if slash <= 0 || slash == len(p)-1 {
		return false
	}
	return validMarketTicker(p[:slash]) && validMarketTicker(p[slash+1:])
}

// handleTrades returns the recent executed-trade tape for ?pair (taker-orientation
// "GIVE/GET", e.g. "XNO/OBX"), newest first, capped by ?limit (default 100). An
// empty pair returns trades across all pairs. CORS-enabled.
func (s *Server) handleTrades(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if s.offers == nil {
		httpErr(w, http.StatusServiceUnavailable, "order book unavailable")
		return
	}
	pair := r.URL.Query().Get("pair")
	// empty = all pairs (allowed); a NON-empty pair must be well-formed.
	if pair != "" && !validMarketPair(pair) {
		httpErr(w, http.StatusBadRequest, "bad pair (want GIVE/GET, e.g. OBX/XNO)")
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	// ?offset pagination: fetch the FULL matching tape (bounded server-side by the
	// tape cap — the same read /my already does) so `total` is honest, then window it.
	offset := parseOffset(r)
	tape := s.offers.Trades(pair, 0)
	total := len(tape)
	if offset > total {
		offset = total
	}
	tape = tape[offset:]
	if len(tape) > limit {
		tape = tape[:limit]
	}
	out := TradesResponse{Pair: pair, Trades: make([]TradeJSON, 0, len(tape)),
		Limit: limit, Offset: offset, Total: total, Truncated: offset+len(tape) < total}
	if pair != "" {
		if lp, ok := s.offers.LastPrice(pair); ok {
			out.LastPrice = lp
		}
	}
	for _, t := range tape {
		out.Trades = append(out.Trades, TradeJSON{
			Pair: t.Pair, Price: t.Price, Give: u64s(t.Give), Get: u64s(t.Get),
			Maker: t.Maker, Taker: t.Taker, SwapKey: t.SwapKey, Time: t.Time,
		})
	}
	writeJSON(w, out)
}

// handleCandles returns OHLCV candles for ?pair at ?interval seconds (default
// 3600), up to ?limit buckets (default 200), oldest-first. CORS-enabled.
func (s *Server) handleCandles(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if s.offers == nil {
		httpErr(w, http.StatusServiceUnavailable, "order book unavailable")
		return
	}
	pair := r.URL.Query().Get("pair")
	if !validMarketPair(pair) {
		httpErr(w, http.StatusBadRequest, "bad or missing pair (want GIVE/GET, e.g. OBX/XNO)")
		return
	}
	interval := int64(3600)
	if v := r.URL.Query().Get("interval"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			interval = n
		}
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	candles := s.offers.Candles(pair, interval, limit)
	if candles == nil {
		candles = []swapbook.Candle{}
	}
	writeJSON(w, map[string]any{"pair": pair, "interval_sec": interval, "candles": candles})
}

// handleStats returns the trailing-24h OHLC + volume summary for ?pair.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if s.offers == nil {
		httpErr(w, http.StatusServiceUnavailable, "order book unavailable")
		return
	}
	pair := r.URL.Query().Get("pair")
	if !validMarketPair(pair) {
		httpErr(w, http.StatusBadRequest, "bad or missing pair (want GIVE/GET, e.g. OBX/XNO)")
		return
	}
	st := s.offers.Stats24h(pair)
	writeJSON(w, map[string]any{
		"pair":       st.Pair,
		"volume":     u64s(st.Volume),
		"volume_get": u64s(st.VolumeGet),
		"high":       st.High,
		"low":        st.Low,
		"open":       st.Open,
		"last":       st.Last,
		"change":     st.Change,
		"trades":     st.Trades,
	})
}

// OrderJSON is one of a maker's live orders with its fill state for /orders.
type OrderJSON struct {
	ID            string `json:"id"`
	GiveAsset     string `json:"give_asset"`
	GetAsset      string `json:"get_asset"`
	GiveAmount    uint64 `json:"give_amount"`
	GetAmount     uint64 `json:"get_amount"`
	RemainingGive string `json:"remaining_give"`
	RemainingGet  string `json:"remaining_get"`
	Status        string `json:"status"`
	Expiry        int64  `json:"expiry"`
}

// OrdersResponse is a maker's live-order list plus pagination metadata
// (additive: `orders` keeps the exact shape clients already read).
type OrdersResponse struct {
	Orders    []OrderJSON `json:"orders"`
	Total     int         `json:"total"`     // full live-order count for this maker
	Offset    int         `json:"offset"`    // rows skipped (?offset)
	Truncated bool        `json:"truncated"` // true when more rows exist beyond offset+len(orders)
}

// handleOrders lists a maker's live orders + fill state for ?maker=<hexpub>,
// windowed by ?limit (default 500, cap 5000) + ?offset.
func (s *Server) handleOrders(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if s.offers == nil {
		httpErr(w, http.StatusServiceUnavailable, "order book unavailable")
		return
	}
	makerHex := r.URL.Query().Get("maker")
	maker, err := hex.DecodeString(makerHex)
	if err != nil || len(maker) != 32 {
		httpErr(w, http.StatusBadRequest, "maker=<32-byte hex pubkey> required")
		return
	}
	limit := 500
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	offset := parseOffset(r)
	list := s.offers.MakerOffers(maker)
	total := len(list)
	if offset > total {
		offset = total
	}
	list = list[offset:]
	if len(list) > limit {
		list = list[:limit]
	}
	out := make([]OrderJSON, 0, len(list))
	for _, o := range list {
		id := o.ID()
		oj := OrderJSON{
			ID: hex.EncodeToString(id[:]), GiveAsset: o.GiveAsset, GetAsset: o.GetAsset,
			GiveAmount: o.GiveAmount, GetAmount: o.GetAmount,
			RemainingGive: u64s(o.GiveAmount), RemainingGet: u64s(o.GetAmount),
			Status: "open", Expiry: o.Expiry,
		}
		if fs, ok := s.offers.OfferFill(id); ok {
			oj.RemainingGive = u64s(fs.RemainingGive)
			oj.RemainingGet = u64s(fs.RemainingGet)
			oj.Status = fs.Status.String()
		}
		out = append(out, oj)
	}
	writeJSON(w, OrdersResponse{Orders: out, Total: total, Offset: offset, Truncated: offset+len(out) < total})
}

// MyResponse joins a maker's live orders with their trade history (as maker OR
// taker) in one call. Previously the frontend fetched /orders and /trades
// separately and merged + filtered them client-side on every poll (audit
// 2026-07-01 "unnecessary frontending" item #6) — that merge logic had to stay
// in lockstep with these exact JSON shapes forever for no reason, since the
// node already has both sides of the join. Reuses OrderJSON/TradeJSON so the
// existing /orders and /trades responses are unaffected.
type MyResponse struct {
	Orders []OrderJSON `json:"orders"`
	Trades []TradeJSON `json:"trades"`
}

// handleMy returns ?maker=<hexpub>'s live orders (same as /orders) plus their
// trade history across ALL pairs, pre-filtered server-side to trades where
// they were maker or taker (same rows /trades would show after the client
// used to scan the tape itself), newest first, capped by ?limit (default 200).
// CORS-enabled.
func (s *Server) handleMy(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if s.offers == nil {
		httpErr(w, http.StatusServiceUnavailable, "order book unavailable")
		return
	}
	makerHex := r.URL.Query().Get("maker")
	maker, err := hex.DecodeString(makerHex)
	if err != nil || len(maker) != 32 {
		httpErr(w, http.StatusBadRequest, "maker=<32-byte hex pubkey> required")
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	out := MyResponse{Orders: []OrderJSON{}, Trades: []TradeJSON{}}
	for _, o := range s.offers.MakerOffers(maker) {
		id := o.ID()
		oj := OrderJSON{
			ID: hex.EncodeToString(id[:]), GiveAsset: o.GiveAsset, GetAsset: o.GetAsset,
			GiveAmount: o.GiveAmount, GetAmount: o.GetAmount,
			RemainingGive: u64s(o.GiveAmount), RemainingGet: u64s(o.GetAmount),
			Status: "open", Expiry: o.Expiry,
		}
		if fs, ok := s.offers.OfferFill(id); ok {
			oj.RemainingGive = u64s(fs.RemainingGive)
			oj.RemainingGet = u64s(fs.RemainingGet)
			oj.Status = fs.Status.String()
		}
		out.Orders = append(out.Orders, oj)
	}
	// Scan the FULL tape (all pairs, no pre-filter limit) so a maker/taker's own
	// trade can't fall off the page just because unrelated trades filled a
	// shared window — only the post-filter result is capped by ?limit.
	for _, t := range s.offers.Trades("", 0) {
		if t.Maker != makerHex && t.Taker != makerHex {
			continue
		}
		out.Trades = append(out.Trades, TradeJSON{
			Pair: t.Pair, Price: t.Price, Give: u64s(t.Give), Get: u64s(t.Get),
			Maker: t.Maker, Taker: t.Taker, SwapKey: t.SwapKey, Time: t.Time,
		})
		if len(out.Trades) >= limit {
			break
		}
	}
	writeJSON(w, out)
}

// handleOrder returns one order's status: GET /order/<hexid>.
func (s *Server) handleOrder(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if s.offers == nil {
		httpErr(w, http.StatusServiceUnavailable, "order book unavailable")
		return
	}
	idHex := r.URL.Path[len("/order/"):]
	idBytes, err := hex.DecodeString(idHex)
	if err != nil || len(idBytes) != 32 {
		httpErr(w, http.StatusBadRequest, "bad order id")
		return
	}
	var id [32]byte
	copy(id[:], idBytes)
	fs, ok := s.offers.OfferFill(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "order not found (expired or unknown)")
		return
	}
	writeJSON(w, map[string]any{
		"id":             idHex,
		"remaining_give": u64s(fs.RemainingGive),
		"remaining_get":  u64s(fs.RemainingGet),
		"status":         fs.Status.String(),
	})
}

// offerAmounts converts a live OBX->XNO offer's human-decimal give/get amounts
// into the units the swap leg uses: OBX in on-chain ATOMIC units (10^12) and XNO
// in its raw uint64 amount. OBX offer units are 10^DEC.OBX (8), so atomic =
// giveUnits * 10^(12-8). XNO is passed through as the agreed raw amount (both
// parties' Init carry the SAME value; the mock Nano treats it opaquely).
func offerAmounts(o *swapbook.Offer) (obxAtomic, xnoRaw uint64) {
	decOBX := config.AutoLiquidityDecimals["OBX"]
	exp := 12 - decOBX
	obxAtomic = o.GiveAmount
	if exp >= 0 {
		obxAtomic = o.GiveAmount * pow10(exp)
	} else {
		obxAtomic = o.GiveAmount / pow10(-exp)
	}
	return obxAtomic, o.GetAmount
}

// pow10 returns 10^n as a uint64 for small non-negative n.
func pow10(n int) uint64 {
	out := uint64(1)
	for i := 0; i < n; i++ {
		out *= 10
	}
	return out
}

// bigStr renders a raw amount (*big.Int, 128-bit XNO raw) as a decimal string,
// matching the "amounts cross the wire as strings" convention. nil → "0".
func bigStr(v *big.Int) string {
	if v == nil {
		return "0"
	}
	return v.String()
}

// u64s renders a uint64 as a decimal string (atomic/raw amounts cross the wire as
// strings to preserve the privacy-chain "never a float" convention).
func u64s(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
