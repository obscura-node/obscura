package rpc

// GET /mining — the node's OWN built-in-miner status, for the wallet's Mine tab
// and any operator dashboard. Read-only and public-proxy-safe: it exposes the
// node's payout address (which the node operator already knows) plus live
// counters; it never exposes seeds or keys, and it never fabricates numbers —
// every figure comes from the chain or the in-process miner telemetry.
//
// The node binary wires its miner telemetry in via SetMiningInfo (the same
// setter pattern as SetXNO / SetOfferBook). File-ownership note: the provider
// is stored in a package-level per-Server map rather than a new Server struct
// field so this feature stays entirely in mining.go (server.go's only change is
// the one /mining route registration line).

import (
	"net/http"
	"sync"

	"obscura/pkg/config"
)

// MiningInfoProvider reports the node binary's own built-in miner state.
// Implemented in cmd/obscura-node (mineLoop telemetry). All methods must be
// safe for concurrent use; a node that is not mining reports zeros/false.
type MiningInfoProvider interface {
	// MiningEnabled reports whether the built-in miner is running (--mine).
	MiningEnabled() bool
	// MineAddress is the node's ACTUAL coinbase payout address (human Base58
	// form): the --mine-address override, or the node's own miner wallet.
	MineAddress() string
	// BlocksFoundSession is how many blocks this node mined since it started.
	BlocksFoundSession() uint64
	// SessionEarnedAtomic is the total coinbase (atomic units) those blocks minted.
	SessionEarnedAtomic() uint64
	// Hashrate is the node's own live PoW hashrate in H/s (from the 20s
	// mining-progress reporter); 0 when not mining or not yet measured.
	Hashrate() float64
}

// miningProviders holds each Server's wired MiningInfoProvider. A per-Server
// map (instead of a Server field) keeps this feature additive to mining.go —
// see the file header. Servers are per-process singletons in production, so
// the map stays tiny; test servers are garbage after the test either way.
var (
	miningMu        sync.RWMutex
	miningProviders = map[*Server]MiningInfoProvider{}
)

// SetMiningInfo wires the node's own miner telemetry so GET /mining reports the
// real payout address, session blocks/earnings, and live hashrate. Optional:
// without it /mining still serves chain-derived fields (difficulty, block
// reward, sync state) with enabled=false.
func (s *Server) SetMiningInfo(p MiningInfoProvider) {
	miningMu.Lock()
	miningProviders[s] = p
	miningMu.Unlock()
}

// miningProvider returns the wired provider, or nil.
func (s *Server) miningProvider() MiningInfoProvider {
	miningMu.RLock()
	defer miningMu.RUnlock()
	return miningProviders[s]
}

// MiningResponse is the GET /mining payload. Amount fields are raw atomic
// uint64 plus a human OBX string; hashrate is H/s. block_reward_atomic is the
// NEXT block's expected coinbase (subsidy from the real emission state, zero
// fees) — what one solved empty block pays right now.
type MiningResponse struct {
	Enabled             bool    `json:"enabled"`
	MineAddress         string  `json:"mine_address"`
	BlocksFoundSession  uint64  `json:"blocks_found_session"`
	SessionEarnedAtomic uint64  `json:"session_earned_atomic"`
	SessionEarnedOBX    string  `json:"session_earned_obx"`
	Hashrate            float64 `json:"hashrate"`
	Difficulty          uint64  `json:"difficulty"`
	BlockRewardAtomic   uint64  `json:"block_reward_atomic"`
	BlockRewardOBX      string  `json:"block_reward_obx"`
	Synced              bool    `json:"synced"`
	PeerCount           int     `json:"peer_count"`
	CoinbaseMaturity    uint64  `json:"coinbase_maturity"`
}

// handleMining serves the node's own miner status. Public read-only: safe on
// loopback, via the --ui proxy, and via the hosted proxy.
func (s *Server) handleMining(w http.ResponseWriter, r *http.Request) {
	resp := MiningResponse{
		Difficulty:        s.chain.ExpectedDifficulty(),
		BlockRewardAtomic: s.chain.ExpectedCoinbaseMinted(0, nil),
		CoinbaseMaturity:  config.CoinbaseMaturity,
	}
	if p := s.miningProvider(); p != nil {
		resp.Enabled = p.MiningEnabled()
		resp.MineAddress = p.MineAddress()
		resp.BlocksFoundSession = p.BlocksFoundSession()
		resp.SessionEarnedAtomic = p.SessionEarnedAtomic()
		resp.Hashrate = p.Hashrate()
	}
	resp.SessionEarnedOBX = config.FormatAmount(resp.SessionEarnedAtomic)
	resp.BlockRewardOBX = config.FormatAmount(resp.BlockRewardAtomic)
	// Reuse the /status sync derivation (real peer-height comparison when the
	// p2p layer can report it; documented heuristic otherwise).
	var st StatusResponse
	st.TipHeight = s.chain.Height()
	s.fillSyncStatus(&st)
	resp.Synced, resp.PeerCount = st.Synced, st.PeerCount
	writeJSON(w, resp)
}
