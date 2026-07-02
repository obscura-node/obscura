package rpc

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"obscura/pkg/config"
)

// Network-metrics time series for the explorer's sparkline cards (supply, difficulty,
// hashrate, nodes-seen) PLUS all-time swap volume. This is ADDITIVE and per-node: a
// bounded ring sampled every metricsSampleInterval, persisted to disk so the charts
// survive restarts. Swap volume is accumulated by reading the order book's trade tape
// (NOT by modifying pkg/swapbook — the proven core stays untouched).
const (
	metricsCap            = 2880 // 24h at 30s
	metricsSampleInterval = 30 * time.Second
)

type metricPoint struct {
	T          int64  `json:"t"`
	Supply     uint64 `json:"supply"`     // emitted atomic
	Difficulty uint64 `json:"difficulty"` // tip difficulty
	Hashrate   uint64 `json:"hashrate"`   // estimated H/s (difficulty / target block time)
	Peers      int    `json:"peers"`      // connected peers
}

// metricsFields holds the sampler state. Embedded in Server.
type metricsFields struct {
	metricsMu      sync.Mutex
	metrics        []metricPoint
	volCum         map[string]uint64 // cumulative swap volume per asset ("OBX","XNO")
	volSeen        int64             // last trade Time watermark (no double-count)
	metricsPath    string
	metricsStarted sync.Once
}

// SetMetricsPath persists the metrics series + cumulative swap volume to p (loaded on
// the first sample, saved after each), so the explorer charts survive restarts. Call
// before Handler(). Empty = in-memory only.
func (s *Server) SetMetricsPath(p string) { s.metricsPath = p }

type metricsState struct {
	Points  []metricPoint     `json:"points"`
	VolCum  map[string]uint64 `json:"vol_cum"`
	VolSeen int64             `json:"vol_seen"`
}

func (s *Server) loadMetrics() {
	if s.metricsPath == "" {
		return
	}
	b, err := os.ReadFile(s.metricsPath)
	if err != nil {
		return
	}
	var st metricsState
	if json.Unmarshal(b, &st) != nil {
		return
	}
	if len(st.Points) > metricsCap {
		st.Points = st.Points[len(st.Points)-metricsCap:]
	}
	s.metricsMu.Lock()
	if len(s.metrics) == 0 {
		s.metrics = st.Points
		s.volCum = st.VolCum
		s.volSeen = st.VolSeen
	}
	if s.volCum == nil {
		s.volCum = map[string]uint64{}
	}
	s.metricsMu.Unlock()
}

func (s *Server) saveMetrics() {
	if s.metricsPath == "" {
		return
	}
	s.metricsMu.Lock()
	st := metricsState{Points: s.metrics, VolCum: s.volCum, VolSeen: s.volSeen}
	b, err := json.Marshal(st)
	s.metricsMu.Unlock()
	if err != nil {
		return
	}
	tmp := s.metricsPath + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, s.metricsPath)
	}
}

// accumulateVolume folds NEW trades (Time strictly after the watermark) from the order
// book tape into the cumulative per-asset volume. Watermark dedup means no trade is
// counted twice; the rare same-second-as-watermark trade is the only one that can slip.
func (s *Server) accumulateVolume() {
	if s.offers == nil {
		return
	}
	s.metricsMu.Lock()
	if s.volCum == nil {
		s.volCum = map[string]uint64{}
	}
	watermark := s.volSeen
	s.metricsMu.Unlock()

	maxT := watermark
	add := map[string]uint64{}
	for _, pair := range []string{"OBX/XNO", "XNO/OBX"} {
		for _, t := range s.offers.Trades(pair, 4000) {
			if t.Time <= watermark {
				continue
			}
			if t.Time > maxT {
				maxT = t.Time
			}
			if p := strings.SplitN(t.Pair, "/", 2); len(p) == 2 {
				add[p[0]] += t.Give
				add[p[1]] += t.Get
			}
		}
	}
	s.metricsMu.Lock()
	for k, v := range add {
		s.volCum[k] += v
	}
	s.volSeen = maxT
	s.metricsMu.Unlock()
}

func (s *Server) recordMetrics() {
	s.accumulateVolume()
	diff := s.chain.ExpectedDifficulty()
	peers := 0
	if s.peers != nil {
		peers = s.peers.PeerCount()
	}
	var hr uint64
	if config.TargetBlockTime > 0 {
		hr = diff * 1000 / uint64(config.TargetBlockTime) // milli-H/s (avoids flooring to 0 at low difficulty)
	}
	s.metricsMu.Lock()
	s.metrics = append(s.metrics, metricPoint{
		T: time.Now().Unix(), Supply: s.chain.Emitted(), Difficulty: diff, Hashrate: hr, Peers: peers,
	})
	if len(s.metrics) > metricsCap {
		s.metrics = s.metrics[len(s.metrics)-metricsCap:]
	}
	s.metricsMu.Unlock()
}

// runMetricsSampler restores persisted history, samples immediately, then every
// metricsSampleInterval, saving after each. Launched once from Handler().
func (s *Server) runMetricsSampler() {
	s.loadMetrics()
	s.recordMetrics()
	s.saveMetrics()
	t := time.NewTicker(metricsSampleInterval)
	defer t.Stop()
	for range t.C {
		s.recordMetrics()
		s.saveMetrics()
	}
}

// MetricsResponse is the /explorer/metrics payload: a per-node time series for the
// explorer sparklines + all-time swap volume (human strings, decimals applied).
type MetricsResponse struct {
	Points     []metricPoint `json:"points"`
	VolumeOBX  string        `json:"volume_obx"`
	VolumeXNO  string        `json:"volume_xno"`
	Decimals   int           `json:"decimals"`
	SampleSecs int           `json:"sample_secs"`
}

func (s *Server) handleExplorerMetrics(w http.ResponseWriter, r *http.Request) {
	cors(w)
	s.metricsMu.Lock()
	pts := make([]metricPoint, len(s.metrics))
	copy(pts, s.metrics)
	volOBX := s.volCum["OBX"]
	volXNO := s.volCum["XNO"]
	s.metricsMu.Unlock()
	writeJSON(w, MetricsResponse{
		Points:     pts,
		VolumeOBX:  config.FormatAmount(volOBX),
		VolumeXNO:  formatXNOVol(volXNO),
		Decimals:   config.AutoLiquidityDecimals["OBX"],
		SampleSecs: int(metricsSampleInterval / time.Second),
	})
}

// formatXNOVol renders cumulative XNO swap volume. Order-book XNO legs are in the
// book's offer units (12-dec display scale, matching the wallet/quote path), so it
// uses the same FormatAmount as OBX rather than Nano's 30-dec raw.
func formatXNOVol(v uint64) string { return config.FormatAmount(v) }
