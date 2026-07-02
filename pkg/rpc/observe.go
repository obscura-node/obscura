package rpc

// Observability + API-hygiene layer for the RPC surface (additive; no handler
// behavior changes):
//
//   - GET /health   — machine-readable readiness (status/tip/synced/peers/uptime)
//   - GET /healthz  — plain-text liveness ("ok")
//   - GET /metrics  — Prometheus text exposition (v0.0.4), hand-written, stdlib only
//   - httpErr       — the unified JSON error envelope {"error":..., "code":...}
//   - observe()     — middleware wrapping the whole mux: per-route request/duration
//     counters (labels normalized to the REGISTERED route pattern, so cardinality
//     is bounded), the X-OBX-Api-Version header on every response, and an opt-in
//     access log (env OBX_RPC_LOG=1).

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"obscura/pkg/chain"
)

// APIVersion is the RPC surface revision emitted as the X-OBX-Api-Version
// header on EVERY response. Versioning policy: additive changes (new endpoints,
// new response fields) do NOT bump it; a breaking change (removed/renamed field
// or endpoint, changed semantics) bumps it, and the previous behavior is kept
// for at least one release wherever feasible. Clients should read the header
// and warn when it exceeds the version they were built against.
const APIVersion = "1"

// procStart anchors uptime for Server values constructed without NewServer
// (some tests build a bare &Server{}).
var procStart = time.Now()

// routeMux wraps http.ServeMux, recording every registered pattern so (a) the
// observe middleware can normalize metric labels to the registered route
// pattern (bounded cardinality) and (b) the OpenAPI spec/tests can enumerate
// the real route table instead of drifting from it.
type routeMux struct {
	*http.ServeMux
	patterns []string
}

func newRouteMux() *routeMux { return &routeMux{ServeMux: http.NewServeMux()} }

func (m *routeMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	m.patterns = append(m.patterns, pattern)
	m.ServeMux.HandleFunc(pattern, handler)
}

// reqKey is one {route pattern, status code} counter bucket.
type reqKey struct {
	path string
	code int
}

// durAgg is the sum/count pair backing the per-route duration summary.
type durAgg struct {
	sum   float64 // seconds
	count uint64
}

// observeFields holds the observability state. Embedded in Server.
type observeFields struct {
	started  time.Time
	routes   []string // registered route patterns (set by Handler())
	obsMu    sync.Mutex
	httpReqs map[reqKey]uint64
	httpDur  map[string]*durAgg

	// tipLive tracks when the chain tip was last observed to ADVANCE (stall
	// detection for /health degraded + /status). Lazily created (bare test
	// Servers work); poll-driven from fillSyncStatus.
	liveMu  sync.Mutex
	tipLive *chain.TipLiveness
}

// observeTip feeds the current tip height to the liveness tracker and returns
// how long the tip has been observed unchanged (0 on first observation/advance).
func (s *Server) observeTip(height uint64) time.Duration {
	s.liveMu.Lock()
	if s.tipLive == nil {
		s.tipLive = chain.NewTipLiveness()
	}
	tl := s.tipLive
	s.liveMu.Unlock()
	return tl.Observe(height)
}

// startTime returns when this server was constructed (falling back to process
// start for bare test values).
func (s *Server) startTime() time.Time {
	if s.started.IsZero() {
		return procStart
	}
	return s.started
}

// httpErr writes the UNIFIED JSON error envelope with the correct HTTP status:
//
//	{"error": "<message>", "code": <status>}
//
// Every error path on the RPC surface uses this (or writeErr, which delegates
// here) so clients can branch on the status code and read one stable `.error`
// field regardless of route. The former plain-text http.Error bodies are gone;
// consumers that displayed the raw body now show compact JSON instead (all
// in-repo consumers parse `.error` or wrap the body opaquely, so nothing
// breaks — see docs/API.md "Errors").
func httpErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg, "code": code})
}

// statusRecorder captures the response status for metrics/logging. It forwards
// Flush so long-poll/SSE handlers (which type-assert http.Flusher) keep working.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// observe wraps the full RPC surface: X-OBX-Api-Version on every response,
// per-route request counters + duration sums (route pattern resolved via the
// mux so unknown paths collapse into "other" — bounded label cardinality), and
// an opt-in access log (OBX_RPC_LOG=1, read once at Handler() build).
func (s *Server) observe(mux *routeMux, next http.Handler) http.Handler {
	logOn := envTrue("OBX_RPC_LOG")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-OBX-Api-Version", APIVersion)
		rec := &statusRecorder{ResponseWriter: w}
		start := time.Now()
		next.ServeHTTP(rec, r)
		dur := time.Since(start)
		code := rec.status
		if code == 0 {
			code = http.StatusOK
		}
		// Normalize the metric label to the REGISTERED route pattern (strips the
		// query string by construction; "/order/<id>" collapses to "/order/").
		// Unmatched paths become "other" so an attacker cannot inflate cardinality.
		_, pattern := mux.Handler(r)
		if pattern == "" || pattern == "/" { // "/" is the JSON-404 catch-all, not a route
			pattern = "other"
		}
		s.obsMu.Lock()
		if s.httpReqs == nil {
			s.httpReqs = make(map[reqKey]uint64)
			s.httpDur = make(map[string]*durAgg)
		}
		s.httpReqs[reqKey{path: pattern, code: code}]++
		d := s.httpDur[pattern]
		if d == nil {
			d = &durAgg{}
			s.httpDur[pattern] = d
		}
		d.sum += dur.Seconds()
		d.count++
		s.obsMu.Unlock()
		if logOn {
			log.Printf("rpc: %s %s -> %d (%s) remote=%s", r.Method, r.URL.Path, code,
				dur.Round(time.Millisecond), remoteIPOf(r))
		}
	})
}

// remoteIPOf extracts the peer IP (no port) for the access log. It reports the
// DIRECT peer only — X-Forwarded-For is forgeable and deliberately ignored.
func remoteIPOf(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// HealthResponse is the /health payload.
type HealthResponse struct {
	Status              string `json:"status"`           // "ok" | "degraded"
	Reason              string `json:"reason,omitempty"` // names WHY status is degraded (e.g. sync stall)
	TipHeight           uint64 `json:"tip_height"`
	Synced              bool   `json:"synced"`
	PeerCount           int    `json:"peer_count"`
	BlocksBehind        uint64 `json:"blocks_behind"`
	LastBlockAgeSeconds int64  `json:"last_block_age_seconds"`
	UptimeSeconds       uint64 `json:"uptime_seconds"`
}

// handleHealth is the readiness probe: 200 {"status":"ok",...} while the chain
// backend is serving and not stalled; 503 {"status":"degraded",...} when the
// chain backend is missing OR the stall-detection rule fires (peers connected,
// blocks_behind > MaxReorgDepth, and no tip advance for > 20×TargetBlockTime —
// see fillSyncStatus), with `reason` naming the cause. A still-syncing node
// whose tip IS advancing stays "ok" (sync state is informational; branch on
// `synced` client-side if you need stricter readiness). Detection only — the
// node takes no self-heal action.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	cors(w)
	up := uint64(time.Since(s.startTime()).Seconds())
	if s.chain == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(HealthResponse{Status: "degraded", Reason: "no chain backend", UptimeSeconds: up})
		return
	}
	var st StatusResponse
	st.TipHeight = s.chain.Height()
	s.fillSyncStatus(&st)
	resp := HealthResponse{
		Status:              "ok",
		TipHeight:           st.TipHeight,
		Synced:              st.Synced,
		PeerCount:           st.PeerCount,
		BlocksBehind:        st.BlocksBehind,
		LastBlockAgeSeconds: st.LastBlockAgeSeconds,
		UptimeSeconds:       up,
	}
	if st.stallReason != "" {
		resp.Status = "degraded"
		resp.Reason = st.stallReason
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}
	writeJSON(w, resp)
}

// handleHealthz is the plain-text liveness probe: "ok", always 200 while the
// HTTP server answers at all (load balancers / container orchestrators).
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

// escapeLabel escapes a Prometheus label VALUE per the text exposition format
// (backslash, double-quote, newline).
func escapeLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return strings.ReplaceAll(v, `"`, `\"`)
}

// handlePromMetrics emits Prometheus text exposition format v0.0.4, written by
// hand (stdlib only — this project takes no client_golang dependency). Gauges
// come from the same live providers /status uses; the request counters/durations
// are recorded by the observe middleware with route-pattern labels.
func (s *Server) handlePromMetrics(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	gauge := func(name, help string, val string) {
		b.WriteString("# HELP " + name + " " + help + "\n")
		b.WriteString("# TYPE " + name + " gauge\n")
		b.WriteString(name + " " + val + "\n")
	}
	if s.chain != nil {
		gauge("obx_tip_height", "Height of the active chain tip.",
			strconv.FormatUint(s.chain.Height(), 10))
	}
	peerCount := 0
	if s.peers != nil {
		peerCount = s.peers.PeerCount()
	}
	gauge("obx_peer_count", "Connected p2p peers.", strconv.Itoa(peerCount))
	if s.mp != nil {
		gauge("obx_mempool_size", "Pending transactions in the mempool.",
			strconv.Itoa(s.mp.Size()))
	}
	if s.chain != nil {
		var st StatusResponse
		st.TipHeight = s.chain.Height()
		s.fillSyncStatus(&st)
		synced := "0"
		if st.Synced {
			synced = "1"
		}
		gauge("obx_synced", "1 when the node believes it is synced (see /status sync_basis).", synced)
		gauge("obx_blocks_behind", "Blocks behind the best height advertised by connected peers (0 when synced or no peer height known).",
			strconv.FormatUint(st.BlocksBehind, 10))
		gauge("obx_last_block_age_seconds", "Seconds since the tip block's header timestamp.",
			strconv.FormatInt(st.LastBlockAgeSeconds, 10))
	}
	gauge("obx_uptime_seconds", "Seconds since this RPC server started.",
		strconv.FormatFloat(time.Since(s.startTime()).Seconds(), 'f', 3, 64))

	// HTTP request counters + per-route duration summary (sum/count), recorded by
	// the observe middleware. Snapshot under the lock, emit sorted (deterministic).
	s.obsMu.Lock()
	reqs := make([]reqKey, 0, len(s.httpReqs))
	for k := range s.httpReqs {
		reqs = append(reqs, k)
	}
	reqVals := make(map[reqKey]uint64, len(s.httpReqs))
	for k, v := range s.httpReqs {
		reqVals[k] = v
	}
	durPaths := make([]string, 0, len(s.httpDur))
	durVals := make(map[string]durAgg, len(s.httpDur))
	for p, d := range s.httpDur {
		durPaths = append(durPaths, p)
		durVals[p] = *d
	}
	s.obsMu.Unlock()
	sort.Slice(reqs, func(i, j int) bool {
		if reqs[i].path != reqs[j].path {
			return reqs[i].path < reqs[j].path
		}
		return reqs[i].code < reqs[j].code
	})
	sort.Strings(durPaths)

	b.WriteString("# HELP obx_http_requests_total RPC requests served, by registered route pattern and status code.\n")
	b.WriteString("# TYPE obx_http_requests_total counter\n")
	for _, k := range reqs {
		fmt.Fprintf(&b, "obx_http_requests_total{path=%q,code=\"%d\"} %d\n",
			escapeLabel(k.path), k.code, reqVals[k])
	}
	b.WriteString("# HELP obx_http_request_duration_seconds RPC request duration, by registered route pattern.\n")
	b.WriteString("# TYPE obx_http_request_duration_seconds summary\n")
	for _, p := range durPaths {
		d := durVals[p]
		fmt.Fprintf(&b, "obx_http_request_duration_seconds_sum{path=%q} %s\n",
			escapeLabel(p), strconv.FormatFloat(d.sum, 'f', 6, 64))
		fmt.Fprintf(&b, "obx_http_request_duration_seconds_count{path=%q} %d\n",
			escapeLabel(p), d.count)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
