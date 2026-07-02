package rpc

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"

	"obscura/pkg/block"
	"obscura/pkg/config"
	"obscura/pkg/tx"
)

// Block explorer JSON API. Amounts are confidential (Pedersen / lattice
// commitments), so the explorer surfaces what is PUBLIC on a privacy chain:
// block/tx structure, stealth one-time output keys, key-image nullifiers, public
// fees, and network stats — never the hidden amounts. This is what powers the
// production web explorer (website/explorer.html via a Vercel proxy).

func cors(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=2")
}

// ExplorerBlockSummary is a compact block row for the latest-blocks list.
type ExplorerBlockSummary struct {
	Height    uint64 `json:"height"`
	Hash      string `json:"hash"`
	Time      int64  `json:"time"`
	Txs       int    `json:"txs"`
	MintedOBX string `json:"minted_obx"`
}

// ExplorerSummary is the explorer landing payload: network stats + latest blocks.
type ExplorerSummary struct {
	Coin            string `json:"coin"`
	Ticker          string `json:"ticker"`
	Height          uint64 `json:"height"`
	Difficulty      uint64 `json:"difficulty"`
	TargetBlockTime int64  `json:"target_block_time"`
	EmittedOBX      string `json:"emitted_obx"`
	Mempool         int    `json:"mempool"`
	AccSize         uint64 `json:"anonymity_set"`
	PoWBackend      string `json:"pow_backend"`
	// network: nodes this node can see (its connected peers + PEX-known addresses) and
	// the software-version distribution across them + self. Counts only, never addresses.
	ConnectedPeers int            `json:"connected_peers"`
	KnownNodes     int            `json:"known_nodes"`
	VersionCounts  map[string]int `json:"version_counts"`
	// staking-vault stats (the supply-sink engagement gauge)
	TVL       string `json:"tvl_obx"`
	TVLAtomic uint64 `json:"tvl_atomic"`
	Vaults    int    `json:"vaults"`
	YieldPool string `json:"yield_pool_obx"`
	// market price, derived from the live swap order book (best rate per pair)
	Prices []PairPrice            `json:"prices"`
	Latest []ExplorerBlockSummary `json:"latest"`
}

// PairPrice is the best available market rate for one swap pair, derived from
// the live order book. Rate is the raw atomic ratio get_amount/give_amount
// (the frontend applies per-asset decimals to render a human price).
type PairPrice struct {
	Pair      string `json:"pair"`       // e.g. "OBX/XNO"
	Rate      string `json:"rate"`       // raw atomic get_amount/give_amount
	GiveAsset string `json:"give_asset"` // base asset of the pair
	GetAsset  string `json:"get_asset"`  // quote asset of the pair
	Offers    int    `json:"offers"`     // live offers backing this pair
}

func (s *Server) handleExplorerSummary(w http.ResponseWriter, r *http.Request) {
	cors(w)
	tip := s.chain.Height()
	resp := ExplorerSummary{
		Coin:            config.CoinName,
		Ticker:          config.Ticker,
		Height:          tip,
		Difficulty:      s.chain.ExpectedDifficulty(),
		TargetBlockTime: config.TargetBlockTime,
		EmittedOBX:      config.FormatAmount(s.chain.Emitted()),
		AccSize:         s.chain.AccSize(),
		TVLAtomic:       s.chain.TotalValueLocked(),
		TVL:             config.FormatAmount(s.chain.TotalValueLocked()),
		Vaults:          s.chain.VaultCount(),
		YieldPool:       config.FormatAmount(s.chain.IncentivePool()),
	}
	if s.mp != nil {
		resp.Mempool = s.mp.Size()
	}
	if s.peers != nil {
		resp.ConnectedPeers = s.peers.PeerCount()
		resp.KnownNodes = s.peers.KnownAddrCount()
		resp.VersionCounts = s.peers.PeerVersionCounts()
	}
	resp.Prices = bestPrices(s)
	n := 20
	for i := 0; i < n; i++ {
		if tip < uint64(i) {
			break
		}
		h := tip - uint64(i)
		b, ok := s.chain.BlockByHeight(h)
		if !ok {
			continue
		}
		resp.Latest = append(resp.Latest, ExplorerBlockSummary{
			Height:    h,
			Hash:      hexID(b.Header.ID()),
			Time:      b.Header.Timestamp,
			Txs:       len(b.Txs),
			MintedOBX: config.FormatAmount(mintedOf(b)),
		})
	}
	writeJSON(w, resp)
}

// ExplorerBlocks is a paged, DESCENDING slice of redacted block summaries (the
// same card shape as ExplorerSummary.Latest) plus the current tip height, so a
// UI can page backwards through the chain without a second round-trip.
type ExplorerBlocks struct {
	Tip    uint64                 `json:"tip"`    // current chain tip height
	From   uint64                 `json:"from"`   // first (highest) height in Blocks
	Count  int                    `json:"count"`  // len(Blocks)
	Blocks []ExplorerBlockSummary `json:"blocks"` // descending from From
}

// handleExplorerBlocks serves GET /explorer/blocks?from=<height>&count=<n≤50>:
// up to `count` privacy-redacted block summaries DESCENDING from `from`.
// Bounds are clamped rather than erroring where a sane answer exists: a missing
// or past-tip `from` starts at the tip, `count` defaults to 20 and is capped at
// 50, and the list stops at genesis. Malformed (non-numeric / non-positive)
// params are a 400.
func (s *Server) handleExplorerBlocks(w http.ResponseWriter, r *http.Request) {
	cors(w)
	tip := s.chain.Height()
	from := tip
	if v := r.URL.Query().Get("from"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			httpErr(w, 400, "bad from (want a non-negative integer)")
			return
		}
		if n < tip {
			from = n
		}
	}
	count := 20
	if v := r.URL.Query().Get("count"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			httpErr(w, 400, "bad count (want a positive integer)")
			return
		}
		count = n
	}
	if count > 50 {
		count = 50
	}
	out := ExplorerBlocks{Tip: tip, From: from, Blocks: []ExplorerBlockSummary{}}
	for i := 0; i < count; i++ {
		if from < uint64(i) {
			break // hit genesis
		}
		h := from - uint64(i)
		b, ok := s.chain.BlockByHeight(h)
		if !ok {
			continue
		}
		out.Blocks = append(out.Blocks, ExplorerBlockSummary{
			Height:    h,
			Hash:      hexID(b.Header.ID()),
			Time:      b.Header.Timestamp,
			Txs:       len(b.Txs),
			MintedOBX: config.FormatAmount(mintedOf(b)),
		})
	}
	out.Count = len(out.Blocks)
	writeJSON(w, out)
}

// ExplorerTx is a privacy-preserving tx view: structure + public fields only.
type ExplorerTx struct {
	Txid       string   `json:"txid"`
	Coinbase   bool     `json:"coinbase"`
	Kind       string   `json:"kind"` // coinbase | confidential | anonymous | swap | post-quantum
	NumInputs  int      `json:"num_inputs"`
	NumOutputs int      `json:"num_outputs"`
	FeeOBX     string   `json:"fee_obx"`
	FeeAtomic  uint64   `json:"fee_atomic"`  // public fee in atomic units (sizing/sorting)
	Amount     string   `json:"amount"`      // always "confidential" for non-coinbase
	KeyImages  []string `json:"key_images"`  // nullifiers (public)
	OutputKeys []string `json:"output_keys"` // stealth one-time keys (public)
}

// ExplorerMempool is a privacy-preserving live view of pending (unconfirmed)
// transactions — the "pending pool". Like the rest of the explorer it exposes
// only public structure (kind, counts, fees, nullifiers), never hidden amounts.
type ExplorerMempool struct {
	Count        int          `json:"count"`
	Bytes        int          `json:"bytes"`
	TotalFeesOBX string       `json:"total_fees_obx"`
	MinFeeRate   uint64       `json:"min_fee_rate"`
	MedFeeRate   uint64       `json:"median_fee_rate"`
	MaxFeeRate   uint64       `json:"max_fee_rate"`
	Pending      []ExplorerTx `json:"pending"`
}

func (s *Server) handleExplorerMempool(w http.ResponseWriter, r *http.Request) {
	cors(w)
	var out ExplorerMempool
	out.Pending = []ExplorerTx{}
	if s.mp == nil {
		writeJSON(w, out)
		return
	}
	st := s.mp.Stats()
	out.Count = st.Count
	out.Bytes = st.Bytes
	out.TotalFeesOBX = config.FormatAmount(st.TotalFees)
	out.MinFeeRate = st.MinFeeRate
	out.MedFeeRate = st.MedFeeRate
	out.MaxFeeRate = st.MaxFeeRate
	// Select returns the fee-prioritized pending set (the same ordering a miner
	// would pull) — cap the visualization at a sane number of nodes.
	for _, t := range s.mp.Select(80) {
		out.Pending = append(out.Pending, explorerTx(t))
	}
	writeJSON(w, out)
}

// ExplorerBlock is the full block view.
type ExplorerBlock struct {
	Height    uint64       `json:"height"`
	Hash      string       `json:"hash"`
	Prev      string       `json:"prev"`
	Time      int64        `json:"time"`
	Merkle    string       `json:"merkle"`
	MintedOBX string       `json:"minted_obx"`
	FeesOBX   string       `json:"fees_obx"`
	Txs       []ExplorerTx `json:"txs"`
}

func (s *Server) handleExplorerBlock(w http.ResponseWriter, r *http.Request) {
	cors(w)
	var (
		h  uint64
		b  *block.Block
		ok bool
	)
	// Block-by-hash: ?hash=<64hex> resolves via a bounded backward scan (explorer
	// "search by block hash"); otherwise ?height=N as before.
	if hq := r.URL.Query().Get("hash"); hq != "" {
		if !validNanoHash(hq) { // reuse: a plain 64-hex check (not nano-specific)
			httpErr(w, 400, "bad hash")
			return
		}
		h, ok = s.findBlockHeightByHash(hq)
		if !ok {
			httpErr(w, 404, "not found")
			return
		}
		b, _ = s.chain.BlockByHeight(h)
	} else {
		var err error
		h, err = strconv.ParseUint(r.URL.Query().Get("height"), 10, 64)
		if err != nil {
			httpErr(w, 400, "bad height")
			return
		}
		b, ok = s.chain.BlockByHeight(h)
		if !ok {
			httpErr(w, 404, "not found")
			return
		}
	}
	var fees uint64
	out := ExplorerBlock{
		Height:    h,
		Hash:      hexID(b.Header.ID()),
		Prev:      hexID(b.Header.PrevHash),
		Time:      b.Header.Timestamp,
		Merkle:    hexID(b.Header.MerkleRoot),
		MintedOBX: config.FormatAmount(mintedOf(b)),
	}
	for _, t := range b.Txs {
		if !t.IsCoinbase {
			fees += t.Fee
		}
		out.Txs = append(out.Txs, explorerTx(t))
	}
	out.FeesOBX = config.FormatAmount(fees)
	writeJSON(w, out)
}

func explorerTx(t *tx.Transaction) ExplorerTx {
	et := ExplorerTx{
		Txid:       t.HashHex(),
		Coinbase:   t.IsCoinbase,
		NumInputs:  len(t.Inputs) + len(t.AnonInputs) + len(t.SwapInputs) + len(t.PQInputs),
		NumOutputs: len(t.Outputs) + len(t.SwapOutputs) + len(t.PQOutputs),
		FeeOBX:     config.FormatAmount(t.Fee),
		FeeAtomic:  t.Fee,
		Amount:     "confidential",
	}
	switch {
	case t.IsCoinbase:
		et.Kind = "coinbase"
		et.Amount = config.FormatAmount(t.Minted) // coinbase reward is public
	case len(t.PQInputs) > 0 || len(t.PQOutputs) > 0:
		et.Kind = "post-quantum"
	case len(t.AnonInputs) > 0:
		et.Kind = "anonymous"
	case len(t.SwapInputs) > 0 || len(t.SwapOutputs) > 0:
		et.Kind = "atomic-swap"
	default:
		et.Kind = "confidential"
	}
	for _, in := range t.Inputs {
		et.KeyImages = append(et.KeyImages, short(in.KeyImage))
	}
	for _, in := range t.AnonInputs {
		et.KeyImages = append(et.KeyImages, short(in.Tag))
	}
	for _, o := range t.Outputs {
		et.OutputKeys = append(et.OutputKeys, short(o.OneTimeKey))
	}
	for i := range t.PQOutputs {
		et.OutputKeys = append(et.OutputKeys, short(t.PQOutputs[i].OneTimeKey))
	}
	return et
}

// ExplorerVault is a public view of a live staking vault (amounts are public for
// vaults, like atomic swaps; the owner is a stealth-independent vault key).
type ExplorerVault struct {
	Key           string `json:"key"` // hex vault id (wallet matches its local deposit)
	AmountOBX     string `json:"amount_obx"`
	Term          uint64 `json:"term_blocks"`
	RateBps       uint64 `json:"rate_bps"`
	DepositHeight uint64 `json:"deposit_height"`
	Maturity      uint64 `json:"maturity_height"`
}

// ExplorerVaults is the staking-vault overview: the supply-sink headline + list.
type ExplorerVaults struct {
	TVLOBX    string          `json:"tvl_obx"`
	Count     int             `json:"count"`
	YieldPool string          `json:"yield_pool_obx"`
	Vaults    []ExplorerVault `json:"vaults"`
}

func (s *Server) handleExplorerVaults(w http.ResponseWriter, r *http.Request) {
	cors(w)
	out := ExplorerVaults{
		TVLOBX:    config.FormatAmount(s.chain.TotalValueLocked()),
		Count:     s.chain.VaultCount(),
		YieldPool: config.FormatAmount(s.chain.IncentivePool()),
		Vaults:    []ExplorerVault{},
	}
	for _, v := range s.chain.VaultList() {
		out.Vaults = append(out.Vaults, ExplorerVault{
			Key:           v.Key,
			AmountOBX:     config.FormatAmount(v.Amount),
			Term:          v.Term,
			RateBps:       v.RateBps,
			DepositHeight: v.DepositHeight,
			Maturity:      v.Maturity,
		})
	}
	writeJSON(w, out)
}

// bestPrices derives a market price per swap pair from the live order book.
// For each distinct (give_asset,get_asset) pair present, it picks the BEST rate
// for the taker — the offer requiring the least get_amount per give_amount, i.e.
// the smallest get/give ratio (matching the "most favorable for the taker"
// convention Book.Best uses) — and emits the raw atomic ratio in Rate. The
// frontend applies per-asset decimals to render a human price. Returns an empty
// (non-nil) slice when the book is empty so the JSON is always a `prices` array.
func bestPrices(s *Server) []PairPrice {
	out := []PairPrice{}
	if s.offers == nil {
		return out
	}
	type agg struct {
		give, get string
		bestRatio float64 // best (lowest) get/give for the taker
		bestGive  uint64
		bestGet   uint64
		count     int
	}
	pairs := map[string]*agg{}
	for _, o := range s.offers.Offers() {
		if o == nil || o.GiveAmount == 0 || o.GetAmount == 0 {
			continue // guard divide-by-zero / degenerate offers
		}
		key := o.GiveAsset + "/" + o.GetAsset
		ratio := float64(o.GetAmount) / float64(o.GiveAmount)
		a := pairs[key]
		if a == nil {
			a = &agg{give: o.GiveAsset, get: o.GetAsset, bestRatio: ratio, bestGive: o.GiveAmount, bestGet: o.GetAmount}
			pairs[key] = a
		} else if ratio < a.bestRatio {
			a.bestRatio, a.bestGive, a.bestGet = ratio, o.GiveAmount, o.GetAmount
		}
		a.count++
	}
	for _, a := range pairs {
		out = append(out, PairPrice{
			Pair:      a.give + "/" + a.get,
			Rate:      strconv.FormatUint(a.bestGet, 10) + "/" + strconv.FormatUint(a.bestGive, 10),
			GiveAsset: a.give,
			GetAsset:  a.get,
			Offers:    a.count,
		})
	}
	// deterministic order; cap a few pairs to keep the stat strip tidy.
	sort.Slice(out, func(i, j int) bool { return out[i].Pair < out[j].Pair })
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

// obxXnoRate returns the BEST taker rate for the OBX/XNO pair as the raw atomic
// "get/give" string (consistent with PairPrice.Rate), or "" when the pair is
// absent from the live book. It reuses the same best-ratio selection logic as
// bestPrices but filters to give=="OBX" && get=="XNO" and skips the cap/sort.
func obxXnoRate(s *Server) string {
	if s.offers == nil {
		return ""
	}
	var (
		have      bool
		bestRatio float64
		bestGive  uint64
		bestGet   uint64
	)
	for _, o := range s.offers.Offers() {
		if o == nil || o.GiveAmount == 0 || o.GetAmount == 0 {
			continue
		}
		if o.GiveAsset != "OBX" || o.GetAsset != "XNO" {
			continue
		}
		ratio := float64(o.GetAmount) / float64(o.GiveAmount)
		if !have || ratio < bestRatio {
			have, bestRatio, bestGive, bestGet = true, ratio, o.GiveAmount, o.GetAmount
		}
	}
	if !have {
		return ""
	}
	return strconv.FormatUint(bestGet, 10) + "/" + strconv.FormatUint(bestGive, 10)
}

// recordPrice appends one OBX/XNO sample to the bounded ring buffer. Empty rates
// (pair absent) are skipped so the series is not polluted with zeros — this can
// leave time gaps, which the frontend tolerates by plotting per-index.
func (s *Server) recordPrice() {
	rate := obxXnoRate(s)
	if rate == "" {
		return
	}
	s.priceMu.Lock()
	s.priceHist = append(s.priceHist, pricePoint{T: time.Now().Unix(), Rate: rate})
	if len(s.priceHist) > priceHistCap {
		s.priceHist = s.priceHist[len(s.priceHist)-priceHistCap:]
	}
	s.priceMu.Unlock()
}

// loadPriceHist restores the persisted ring (if SetPriceHistPath was set and the
// file exists), so a restart keeps the chart history instead of rebuilding from
// zero. Bounded to priceHistCap. Best-effort — a missing/corrupt file is ignored.
func (s *Server) loadPriceHist() {
	if s.priceHistPath == "" {
		return
	}
	b, err := os.ReadFile(s.priceHistPath)
	if err != nil {
		return
	}
	var pts []pricePoint
	if json.Unmarshal(b, &pts) != nil {
		return
	}
	if len(pts) > priceHistCap {
		pts = pts[len(pts)-priceHistCap:]
	}
	s.priceMu.Lock()
	if len(s.priceHist) == 0 { // don't clobber samples already taken
		s.priceHist = pts
	}
	s.priceMu.Unlock()
}

// savePriceHist persists the ring atomically (temp + rename). Best-effort.
func (s *Server) savePriceHist() {
	if s.priceHistPath == "" {
		return
	}
	s.priceMu.Lock()
	b, err := json.Marshal(s.priceHist)
	s.priceMu.Unlock()
	if err != nil {
		return
	}
	tmp := s.priceHistPath + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, s.priceHistPath)
	}
}

// runPriceSampler restores any persisted history, takes an immediate sample (so the
// chart isn't empty on first poll) then samples every priceSampleInterval, saving
// after each. Launched once from Handler().
func (s *Server) runPriceSampler() {
	s.loadPriceHist()
	s.recordPrice()
	s.savePriceHist()
	t := time.NewTicker(priceSampleInterval)
	defer t.Stop()
	for range t.C {
		s.recordPrice()
		s.savePriceHist()
	}
}

// PricePointJSON is one rendered price-history sample.
type PricePointJSON struct {
	T    int64  `json:"t"`    // unix seconds
	Rate string `json:"rate"` // raw atomic get/give (frontend applies decimals)
}

// PriceHistory is the OBX/XNO realtime price time-series. Rate is the raw atomic
// "get/give" string per point; dec_give/dec_get carry the decimals the frontend
// uses to render a human price (OBX priced in XNO).
type PriceHistory struct {
	Pair      string           `json:"pair"`
	GiveAsset string           `json:"give_asset"`
	GetAsset  string           `json:"get_asset"`
	DecGive   int              `json:"dec_give"`
	DecGet    int              `json:"dec_get"`
	Points    []PricePointJSON `json:"points"`
}

func (s *Server) handleExplorerPriceHistory(w http.ResponseWriter, r *http.Request) {
	cors(w)
	out := PriceHistory{
		Pair:      "OBX/XNO",
		GiveAsset: "OBX",
		GetAsset:  "XNO",
		DecGive:   config.AutoLiquidityDecimals["OBX"], // uint64-safe display decimals (12)
		DecGet:    config.AutoLiquidityDecimals["XNO"], // uint64-safe display decimals (12)
		Points:    []PricePointJSON{},
	}
	s.priceMu.Lock()
	for _, p := range s.priceHist {
		out.Points = append(out.Points, PricePointJSON{T: p.T, Rate: p.Rate})
	}
	s.priceMu.Unlock()
	writeJSON(w, out)
}

// SwapEvent is one on-chain atomic-swap lifecycle event reconstructed from a
// block scan. HONEST LIMITS: this is the OBX-side contract lifecycle only
// (funded -> claimed/refunded); the cross-chain (BTC/XNO) leg and the order that
// produced the swap are off-chain and NOT represented here. Amount is the
// cleartext SwapOut.Amount captured at funding; claim/refund spends carry no
// amount, so it is only known when the funding output is within the scan window.
type SwapEvent struct {
	Kind         string `json:"kind"` // funded | claimed | refunded
	SwapKey      string `json:"swap_key"`
	AmountOBX    string `json:"amount_obx"` // "" when funding is outside the scan window
	Height       uint64 `json:"height"`
	UnlockHeight uint64 `json:"unlock_height"` // funding only (0 on spends)
	Time         int64  `json:"time"`          // block header timestamp
	Txid         string `json:"txid"`
}

// ExplorerSwaps is the recent on-chain swap-event feed (newest first).
type ExplorerSwaps struct {
	WindowBlocks int         `json:"window_blocks"`
	Events       []SwapEvent `json:"events"`
	// Pagination/totals (audit IMPORTANT #8): Total is the full event count found in
	// the scan window; Offset is the rows skipped (?offset); Truncated is true when
	// more events exist beyond offset+len(events). Honors ?limit (default 200, hard
	// cap 1000) + ?offset.
	Total     int  `json:"total"`
	Offset    int  `json:"offset"`
	Truncated bool `json:"truncated"`
}

// handleExplorerSwaps reconstructs recent swap lifecycle events by scanning the
// last N blocks (Option A: no new chain state). Funding amounts are carried
// forward to their later claim/refund within the scan window via a SwapKey map.
func (s *Server) handleExplorerSwaps(w http.ResponseWriter, r *http.Request) {
	cors(w)
	const window = 1000
	tip := s.chain.Height()
	out := ExplorerSwaps{WindowBlocks: window, Events: []SwapEvent{}}

	// audit:SECURITY_AUDIT_2026-07-01 (Finding 2) — serve the heavy 2x1000-block scan
	// from a short-TTL cache (invalidated when the tip advances) so a flood of
	// requests can't force a fresh re-scan each time. ?limit is applied per-request
	// from the cached full event slice, so different limits share one scan.
	const swapsCacheTTL = 3 * time.Second
	s.swapsCacheMu.Lock()
	events := s.swapsCache
	fresh := events != nil && s.swapsCacheTip == tip && time.Since(s.swapsCacheTime) < swapsCacheTTL
	s.swapsCacheMu.Unlock()
	if !fresh {
		events = s.scanSwapEvents(tip, window)
		s.swapsCacheMu.Lock()
		s.swapsCache = events
		s.swapsCacheTip = tip
		s.swapsCacheTime = time.Now()
		s.swapsCacheMu.Unlock()
	}

	out.Total = len(events)
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	offset := parseOffset(r)
	if offset > len(events) {
		offset = len(events)
	}
	out.Offset = offset
	out.Events = events[offset:] // read-only sub-slice of the cached slice
	if len(out.Events) > limit {
		out.Events = out.Events[:limit]
	}
	out.Truncated = offset+len(out.Events) < out.Total
	writeJSON(w, out)
}

// scanSwapEvents performs the heavy 2x window-block scan that reconstructs the recent
// swap lifecycle feed (newest first). Factored out of handleExplorerSwaps so the
// result can be cached (audit:SECURITY_AUDIT_2026-07-01, Finding 2). The returned
// slice is treated as immutable by callers so it is safe to share from the cache.
func (s *Server) scanSwapEvents(tip uint64, window int) []SwapEvent {
	events := []SwapEvent{}
	var lo uint64
	if tip >= uint64(window) {
		lo = tip - uint64(window) + 1
	}

	// Pass 1 (oldest -> newest): record every funding amount by SwapKey so a later
	// claim/refund spend within the window can show the locked OBX amount (the
	// spend tx itself carries no amount). Also seed from c.swaps for any still-open
	// contract funded before the window.
	amountBySwap := map[string]uint64{}
	for h := lo; h <= tip; h++ {
		b, ok := s.chain.BlockByHeight(h)
		if !ok {
			continue
		}
		for _, t := range b.Txs {
			for i := range t.SwapOutputs {
				so := t.SwapOutputs[i]
				amountBySwap[hex.EncodeToString(so.SwapKey)] = so.Amount
			}
		}
	}

	// Pass 2 (newest -> oldest): emit events reverse-chronologically.
	for h := tip; ; h-- {
		b, ok := s.chain.BlockByHeight(h)
		if ok {
			for _, t := range b.Txs {
				txid := t.HashHex()
				for i := range t.SwapInputs {
					in := t.SwapInputs[i]
					kind := "claimed"
					if in.IsRefund {
						kind = "refunded"
					}
					ev := SwapEvent{
						Kind:    kind,
						SwapKey: hex.EncodeToString(in.SwapKey),
						Height:  h,
						Time:    b.Header.Timestamp,
						Txid:    txid,
					}
					if amt, ok := amountBySwap[hex.EncodeToString(in.SwapKey)]; ok {
						ev.AmountOBX = config.FormatAmount(amt)
					}
					events = append(events, ev)
				}
				for i := range t.SwapOutputs {
					so := t.SwapOutputs[i]
					events = append(events, SwapEvent{
						Kind:         "funded",
						SwapKey:      hex.EncodeToString(so.SwapKey),
						AmountOBX:    config.FormatAmount(so.Amount),
						Height:       h,
						UnlockHeight: so.UnlockHeight,
						Time:         b.Header.Timestamp,
						Txid:         txid,
					})
				}
			}
		}
		if h == lo || h == 0 {
			break
		}
	}
	return events
}

func mintedOf(b *block.Block) uint64 {
	if len(b.Txs) > 0 && b.Txs[0].IsCoinbase {
		return b.Txs[0].Minted
	}
	return 0
}

func hexID(b [32]byte) string { return hex.EncodeToString(b[:]) }

func short(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return hex.EncodeToString(b)
}
