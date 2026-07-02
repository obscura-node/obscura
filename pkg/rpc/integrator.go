package rpc

// Third-party-integrator endpoints (from docs/NODE_API_AUDIT.md): a stable node
// identity (/version), a machine-readable parameter surface so clients stop
// hardcoding decimals/fees/terms (/params), and transaction-by-hash lookup so a
// client can tell whether/where a tx confirmed (/tx). Plus a CORS middleware so a
// browser client can talk to a node directly. All CORS-enabled + JSON.

import (
	"net/http"
	"strings"

	"obscura/pkg/config"
	"obscura/pkg/p2p"
)

// ProtocolVersion is the wire/RPC protocol revision integrators can branch on. Bump
// it on a breaking RPC/consensus change.
const ProtocolVersion = 1

// txScanWindow bounds the /tx and block-by-hash backward scan so a single request
// can't walk an unbounded chain (there is no persisted tx index yet). Recent txs —
// the confirmation-tracking case — are found immediately near the tip.
const txScanWindow = 200_000

// txFallbackScanWindow bounds the /tx fallback scan (audit:SECURITY_AUDIT_2026-07-01,
// Finding 1). The persisted TxHeight index consulted first in handleTx is COMPLETE
// for a db-backed chain (built on open + maintained on every apply/reorg), so it
// already resolves every confirmed txid in O(1); this fallback only covers the
// stale-reorg / db-less (test) edge and therefore need not walk the whole chain.
// Bounding it turns a non-existent-txid request from a ~txScanWindow amplified disk
// scan into a small bounded one.
const txFallbackScanWindow = 4_000

// findBlockHeightByHash resolves a block hash (lowercase 64-hex of Header.ID()) to
// its active-chain height via a bounded backward scan from the tip (reusing the
// txScanWindow bound — recent blocks, the explorer-search case, resolve
// immediately). Returns false if the hash is not found within the window. There is
// no persisted hash→height index yet; the scan keeps this O(window) and DoS-bounded.
func (s *Server) findBlockHeightByHash(hash string) (uint64, bool) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	tip := s.chain.Height()

	// audit:SECURITY_AUDIT_2026-07-01 (Finding 1) — resolve via the in-memory index
	// instead of a per-request full-chain disk scan. The index is built once (the
	// first lookup) and afterwards only folds in blocks added since the previous
	// call, so a lookup for an arbitrary/non-existent hash is an O(1) map probe. The
	// fold runs under the mutex so a flood of concurrent first-callers triggers at
	// most one build rather than N parallel full scans.
	s.hashIdxMu.Lock()
	if s.blockHashIdx == nil {
		s.blockHashIdx = make(map[string]uint64)
		s.hashIdxNext = 0
	}
	for h := s.hashIdxNext; h <= tip; h++ {
		if b, ok := s.chain.BlockByHeight(h); ok {
			s.blockHashIdx[hexID(b.Header.ID())] = h
		}
		if h == tip { // guard against uint64 wrap when tip is unchanged
			break
		}
	}
	if tip+1 > s.hashIdxNext { // advance only (a reorg-shrunk tip self-heals below)
		s.hashIdxNext = tip + 1
	}
	h, ok := s.blockHashIdx[hash]
	s.hashIdxMu.Unlock()
	if !ok {
		return 0, false
	}
	// Reorg self-heal: the active block at the indexed height must still carry this
	// hash; on mismatch drop the stale entry and report not found.
	if b, ok := s.chain.BlockByHeight(h); ok && hexID(b.Header.ID()) == hash {
		return h, true
	}
	s.hashIdxMu.Lock()
	if cur, ok := s.blockHashIdx[hash]; ok && cur == h {
		delete(s.blockHashIdx, hash)
	}
	s.hashIdxMu.Unlock()
	return 0, false
}

// handleVersion returns the node + NETWORK identity. An exchange/integrator needs
// this to verify which chain it is talking to (coin/ticker are identical on
// testnet and mainnet — network + genesis_hash disambiguate).
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	cors(w)
	genesis := ""
	if b, ok := s.chain.BlockByHeight(0); ok {
		genesis = hexID(b.Header.ID())
	}
	writeJSON(w, map[string]any{
		"coin":                config.CoinName,
		"ticker":              config.Ticker,
		"software_version":    p2p.SoftwareVersion,
		"protocol_version":    ProtocolVersion,
		"network":             config.Network,
		"genesis_hash":        genesis,
		"accumulator_backend": config.AccumulatorBackend,
	})
}

// handleParams exposes the consensus/economic constants a client would otherwise
// hardcode (audit + UI-decoupling: wallet/explorer hardcode DEC/fees/terms "to
// match pkg/config"). Reading this at boot keeps every client in lock-step with
// the node and removes silent drift.
func (s *Server) handleParams(w http.ResponseWriter, r *http.Request) {
	cors(w)
	terms := make([]map[string]any, 0, len(config.VaultTerms))
	for i, t := range config.VaultTerms {
		var bps uint64
		if i < len(config.VaultRatesBps) {
			bps = config.VaultRatesBps[i]
		}
		terms = append(terms, map[string]any{"term": t, "rate_bps": bps})
	}
	writeJSON(w, map[string]any{
		"decimals":              config.AutoLiquidityDecimals, // {OBX:12, XNO:12} — offer/display scale
		"obx_atomic_per_coin":   config.AtomicPerCoin,         // 1 OBX = 1e12 atomic
		"min_fee_per_byte":      config.MinFeePerByte,
		"swap_fee_atomic":       s.swapFee, // 0 until the swap engine is wired
		"vault_terms":           terms,
		"vault_flex_rate_bps":   config.VaultFlexRateBps, // flexible-staking ANNUAL yield (basis points)
		"coinbase_maturity":     config.CoinbaseMaturity,
		"target_block_time_sec": config.TargetBlockTime,
		"network":               config.Network,
		"money_supply_cap":      config.MoneySupplyCap,     // atomic units; ~18.4M OBX before tail emission
		"tail_emission_atomic":  config.TailEmissionAtomic, // 0.6 OBX/block forever, once the cap is hit
	})
}

// TxLookup is the /tx?hash= response: where a transaction is + how confirmed it is.
type TxLookup struct {
	Found         bool   `json:"found"`
	Status        string `json:"status"` // "confirmed" | "pending" | "unknown"
	TxID          string `json:"txid"`
	BlockHeight   uint64 `json:"block_height,omitempty"`
	BlockHash     string `json:"block_hash,omitempty"` // hex ID of the containing block (confirmed only)
	Index         int    `json:"index,omitempty"`      // position within the block
	Confirmations uint64 `json:"confirmations"`
	Coinbase      bool   `json:"coinbase,omitempty"`
	Note          string `json:"note,omitempty"`
}

// handleTx looks a transaction up by its hex txid: first the mempool (pending),
// then the persisted txid->height index (chain.TxHeight, O(1)), falling back to a
// bounded backward scan (txScanWindow) if the index has no entry. Returns
// confirmations so a client can credit a deposit safely.
func (s *Server) handleTx(w http.ResponseWriter, r *http.Request) {
	cors(w)
	hash := r.URL.Query().Get("hash")
	if !validNanoHash(hash) { // reuse: a 64-hex check (not nano-specific)
		httpErr(w, http.StatusBadRequest, "hash required (64-hex txid)")
		return
	}
	// pending in the mempool?
	if s.mp != nil {
		for _, t := range s.mp.Select(1 << 20) {
			if t.HashHex() == hash {
				writeJSON(w, TxLookup{Found: true, Status: "pending", TxID: hash, Confirmations: 0})
				return
			}
		}
	}
	tip := s.chain.Height()
	// FAST PATH: the persisted txid->height index (O(1)). Re-verify the txid is
	// actually present at the indexed height before trusting it, so a stale entry
	// left by a reorg self-heals into the bounded-scan fallback below.
	if h, ok := s.chain.TxHeight(hash); ok {
		if b, ok2 := s.chain.BlockByHeight(h); ok2 {
			for idx, t := range b.Txs {
				if t.HashHex() == hash {
					writeJSON(w, TxLookup{
						Found: true, Status: "confirmed", TxID: hash,
						BlockHeight: h, BlockHash: hexID(b.Header.ID()),
						Index: idx, Confirmations: tip - h + 1,
						Coinbase: t.IsCoinbase,
					})
					return
				}
			}
		}
	}
	limit := uint64(0)
	if tip > txFallbackScanWindow {
		limit = tip - txFallbackScanWindow
	}
	for h := tip; ; h-- {
		if b, ok := s.chain.BlockByHeight(h); ok {
			for idx, t := range b.Txs {
				if t.HashHex() == hash {
					writeJSON(w, TxLookup{
						Found: true, Status: "confirmed", TxID: hash,
						BlockHeight: h, BlockHash: hexID(b.Header.ID()),
						Index: idx, Confirmations: tip - h + 1,
						Coinbase: t.IsCoinbase,
					})
					return
				}
			}
		}
		if h == 0 || h == limit {
			break
		}
	}
	note := ""
	if limit > 0 {
		note = "not found in the most recent blocks; a full tx index is not yet maintained"
	}
	writeJSON(w, TxLookup{Found: false, Status: "unknown", TxID: hash, Note: note})
}

// corsMiddleware adds permissive CORS to EVERY response and answers OPTIONS
// preflight, so a browser-based client can call a node directly (audit: core
// routes had no ACAO and /submittx/etc. had no preflight). It is header-only — it
// does NOT relax the loopback/token gating on operator endpoints (a cross-origin
// browser still cannot satisfy those), so opening CORS is safe. Disable with
// OBX_RPC_NO_CORS=1.
func corsMiddleware(next http.Handler) http.Handler {
	if envTrue("OBX_RPC_NO_CORS") {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// SENSITIVE OPERATOR ROUTES ARE NEVER CORS-ENABLED (audit CRITICAL): operator
		// trust is loopback-OR-bearer, so a malicious page open in the operator's
		// browser could otherwise CSRF a same-machine POST to /xno/withdraw (drain) or
		// /xno/recovery (secret exfil) — a wildcard ACAO is exactly what lets the browser
		// send + read that cross-origin request. Withholding the CORS headers makes the
		// browser block the preflight; non-browser CLI callers (no CORS) are unaffected.
		if corsDeniedPath(r.URL.Path) {
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "600")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// corsDeniedPath reports whether a route must NOT receive CORS headers — the
// state-changing/secret-revealing operator endpoints (see corsMiddleware).
func corsDeniedPath(p string) bool {
	switch p {
	case "/xno/withdraw", "/xno/recovery":
		return true
	}
	return false
}
