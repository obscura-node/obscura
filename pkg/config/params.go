// Package config holds the consensus parameters and network configuration for
// Obscura (OBX).
package config

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// MaxAnchorWindow bounds the rolling window of CURRENT-epoch commitment-root snapshots
// a node retains as spend anchors (pruning design #4). FINALIZED epoch roots are kept
// permanently (separately, bounded by epoch count), so this only limits how stale a
// current-epoch witness may be — it does NOT strand old coins. A var so tests can
// lower it to exercise window eviction.
var MaxAnchorWindow = 100_000

// PoRWindow is the PROTOCOL block-BODY retention window (in blocks) and, by the
// SAME constant, the span Proof-of-Retrievability challenges are drawn from.
//
// Pruning is INTRINSIC to the protocol — there is no archive/full-history mode to
// toggle. Every node, MINERS INCLUDED, keeps block BODIES only for the most recent
// PoRWindow heights and prunes older bodies (state pruning — snapshots, disk-backed
// spent/tag/prime/coin sets, the bounded RAM body cache — is separate and always
// on). PoR challenges for a block at height H are drawn UNIFORMLY from
// [H-PoRWindow, H) (clamped at genesis): exactly the heights the protocol
// guarantees are retained. So "what a miner must prove it holds" == "what the
// protocol guarantees every node retains" — pruning and PoR are consistent BY
// DESIGN, not by a node-local flag.
//
// PoR soundness over the window is UNCHANGED: a miner must still prove retrievability
// of the entire challengeable (retained) set, and a node that has dropped any body in
// [H-PoRWindow, H) cannot mine. Only un-retained ancient history (pruned for everyone)
// is no longer challengeable — it is provably unavailable to all, so challenging it
// would be unsatisfiable rather than a security check.
//
// INVARIANT: the body pruner (pkg/chain/snapshot.go) retains every body in
// [tip-PoRWindow, tip]; the PoR derivation (pkg/block/por.go) never challenges below
// H-PoRWindow. Both uses MUST stay tied to this constant. A var only so tests can
// shrink it; it is a CONSENSUS parameter (all nodes must agree). Default ~2 weeks of
// history at 120s blocks.
var PoRWindow uint64 = 10_000

const (
	// CoinName / ticker.
	CoinName = "Obscura"
	Ticker   = "OBX"

	// AtomicPerCoin: 1 OBX = 10^12 atomic units (12 decimals, like Monero).
	AtomicPerCoin uint64 = 1_000_000_000_000

	// ConfidentialBits is the range-proof width for confidential ZK amounts (CZKSpend):
	// hidden a_in, a_out and the public fee must each lie in [0, 2^ConfidentialBits).
	// Capped at stark.MaxRangeBits=60 so 2^bits < the Goldilocks modulus (no field
	// wraparound — the anti-inflation guard). This bounds a single confidential coin to
	// 2^60 atomic units (< MoneySupplyCap); larger coins remain spendable via the
	// public-amount ZKInput path. The consensus fee range-check uses this (FINDING 5).
	ConfidentialBits = 60

	// PoRChallenges: number of proof-of-retrievability challenges a miner must answer per
	// block (must hold those historical bodies). 0 disables. See pkg/block/por.go.
	//
	// audit fix (partial-data miner evasion): a miner withholding fraction f of the
	// retained window passes all k challenges with probability (1-f)^k, so a small k lets
	// a partial-data miner mine with non-negligible probability (k=4: a 50%-withholder
	// passes 6.25% of blocks; a 10%-withholder 66%). Raised 4→8 to tighten the evasion
	// margin (50%-withholder → 0.39%; 25%-withholder → 10%) at the cost of a few extra
	// header-only PoR entries per block. A consensus parameter (all nodes agree); part of
	// the genesis reset.
	PoRChallenges = 8

	// Difficulty retarget window (LWMA), in blocks.
	DifficultyWindow = 60

	// Emission: smooth decreasing reward = (remainingSupply >> EmissionShift),
	// with a perpetual tail emission floor for security funding.
	EmissionShift      uint   = 19
	MoneySupplyCap     uint64 = 18_400_000 * 1_000_000_000_000 // ~18.4M OBX before tail
	TailEmissionAtomic uint64 = 600_000_000_000                // 0.6 OBX/block forever

	// Incentive split (basis points of each block's base reward):
	//   - IncentivePoolBps funds the holding bonus pool.
	//   - ReferralMaxBps caps the referral (sharing) bonus minted per block.
	IncentivePoolBps uint64 = 500 // 5% of reward -> holding incentive pool
	// ReferralMaxBps is the cap on the freshly-minted referral bonus. It is set
	// to 0 by DEFAULT for safety: a freshly-minted referral reward keyed on an
	// arbitrary tag is sybil-exploitable (a miner can self-refer with throwaway
	// tags to mint extra coins). Enabling it (>0) REQUIRES a sybil-resistant
	// identity binding for the referrer (see docs/TOKENOMICS.md). The mechanism
	// remains implemented and tested behind this flag.
	ReferralMaxBps uint64 = 0

	// Referral anti-abuse: a referrer can earn the bonus on at most this many
	// distinct referred coinbases, and the bonus decays with count.
	ReferralMaxClaims uint64 = 1000

	// Holding bonus: outputs locked for at least HoldingMinLock blocks become
	// eligible; bonus weight scales with min(lockDuration, HoldingMaxLock).
	HoldingMinLock uint64 = 10_000  // ~2 weeks at 120s blocks
	HoldingMaxLock uint64 = 525_600 // ~2 years

	// Maximum block weight (bytes). Raised 2MB→4MB for the recipient-secret ZK spend:
	// the unlinkable nf-spend / cnf-spend STARK proofs (extra nk/rho columns + the full
	// membership path at ZKDepth) are ~1.8–2MB each, so a single confidential spend tx
	// plus the coinbase no longer reliably fit under a 2MB cap. 4MB guarantees a
	// confidential spend always fits, with headroom for the coinbase + a second tx. A
	// consensus parameter (all nodes agree); changed as part of the nf genesis reset.
	MaxBlockBytes = 4_000_000

	// MaxFutureDriftSeconds bounds how far ahead of local time a block timestamp
	// may be (standard practice; too-future blocks are temporarily rejected).
	MaxFutureDriftSeconds int64 = 7200

	// P2P default port and RPC default port.
	DefaultP2PPort = 18080
	DefaultRPCPort = 18081
)

// DefaultSeeds is the embedded bootstrap seed list. A fresh node started with no
// --seeds (the "download and run" desktop-app path) falls back to these so it can
// find the network with zero configuration. Once connected, PEX (msgGetAddr/msgAddr)
// teaches the node the rest of the network from any one reachable seed.
//
// These are the CURRENT public TEST-NET seed nodes (DigitalOcean, port 18080). They
// replace the old RFC5737 placeholder (192.0.2.1) which never routed, so a fresh
// desktop app used to mine an isolated, worthless fork (audit S2).
//
// Override at runtime with OBX_SEEDS="host1:port,host2:port" (replaces the list) or
// OBX_SEEDS_APPEND (adds without replacing — see init below), or the --seeds flag.
//
// DNS-SEED SUPPORT: entries may be HOSTNAMES, not just raw IPs — e.g.
// "seed1.obscura.network:18080". Seeds flow through the stack as host:port strings
// and are resolved at DIAL time (net.DialTimeout for clearnet; the Tor SOCKS proxy
// resolves for -tor nodes, so no local DNS leak). A hostname that stops resolving
// simply fails like an unreachable IP (backoff + address-book failure eviction, no
// log spam); repointing the DNS record re-seeds every stock binary without a
// rebuild. For a MAINNET launch, replace the raw droplet IPs below with stable DNS
// seed hostnames — see the go-live checklist (docs/GO_LIVE_CHECKLIST.md).
var DefaultSeeds = []string{
	"139.59.183.15:18080",  // obx-g (miner/seed, also the hosted-wallet RPC target)
	"188.166.153.86:18080", // obx-h (follower)
}

func init() {
	// OBX_SEEDS overrides the embedded bootstrap list with a comma-separated
	// host:port set (hostnames or IPs — see the DefaultSeeds comment), so an
	// operator can repoint a stock binary at a different network
	// (mainnet/testnet/devnet) without a rebuild.
	if v := os.Getenv("OBX_SEEDS"); v != "" {
		var seeds []string
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				seeds = append(seeds, s)
			}
		}
		if len(seeds) > 0 {
			DefaultSeeds = seeds
		}
	}
	// OBX_SEEDS_APPEND ADDS extra seeds (comma-separated host:port, hostnames OK)
	// WITHOUT replacing the embedded/OBX_SEEDS list — e.g. an operator adds their
	// own node as a preferred bootstrap while keeping the network defaults as
	// fallback. Duplicates are dropped.
	if v := os.Getenv("OBX_SEEDS_APPEND"); v != "" {
		have := make(map[string]bool, len(DefaultSeeds))
		for _, s := range DefaultSeeds {
			have[s] = true
		}
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" && !have[s] {
				have[s] = true
				DefaultSeeds = append(DefaultSeeds, s)
			}
		}
	}
}

// GenesisDifficulty: starting PoW difficulty target. Low for the prototype
// testnet so blocks are found quickly on a single CPU; LWMA raises it
// automatically as hashrate grows. A var so a devnet/load-test can set it near
// the equilibrium for its hardware (OBX_GENESIS_DIFFICULTY) to avoid the
// genesis difficulty-overshoot oscillation. Mainnet default 64, unchanged.
var GenesisDifficulty uint64 = 64

// FixedDifficulty, when > 0 (set via OBX_FIXED_DIFFICULTY), pegs the PoW
// difficulty to a constant — disabling LWMA retargeting. This is ONLY for
// devnets/load-tests on a contended host, where a single-thread RandomX miner's
// hashrate is too variable for LWMA to converge (causing difficulty
// oscillation). Mainnet leaves this 0 (full LWMA). All nodes must agree.
var FixedDifficulty uint64 = 0

// TargetBlockTime in seconds. A var (not const) so a devnet/load-test can lower
// it via the OBX_TARGET_BLOCK_TIME env var (all nodes must agree — it is a
// consensus parameter). Mainnet default is 120s, unchanged.
var TargetBlockTime int64 = 120

// Network is the consensus network mode: "mainnet" (default), "testnet", or
// "devnet". It is read from OBX_NETWORK at startup. On MAINNET the emission-critical
// timing knobs are LOCKED to their safe defaults: the devnet env overrides
// (OBX_TARGET_BLOCK_TIME / OBX_FIXED_DIFFICULTY / OBX_GENESIS_DIFFICULTY) are IGNORED.
//
// This is the distribution-safety guard (go-live): with 120s blocks the ~18.4M supply
// emits over ~8 years (50% in 1.4yr) — a multi-year, Monero-style schedule. With the
// devnet 1–2s block time the WHOLE supply emits in ~weeks, so those overrides must NOT
// take effect on a real launch. Devnet/testnet keep the overrides for fast iteration.
// MAINNET BUILD: this tree is permanently mainnet. The testnet/devnet escape hatches
// were removed so a production node can never be downgraded to test timing or a test
// genesis identity. The separate testnet/ tree keeps the OBX_NETWORK switch.
var Network = "mainnet"

// IsMainnet reports whether consensus timing is locked to the mainnet schedule.
func IsMainnet() bool { return Network == "mainnet" }

func init() {
	// MAINNET LOCK: ignore the devnet timing/difficulty overrides so a production
	// build always uses 120s blocks and the full multi-year emission curve. Only
	// devnet/testnet may accelerate blocks (which compresses emission — see Network).
	if IsMainnet() {
		return
	}
	if v := os.Getenv("OBX_TARGET_BLOCK_TIME"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			TargetBlockTime = n
		}
	}
	if v := os.Getenv("OBX_GENESIS_DIFFICULTY"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			GenesisDifficulty = n
		}
	}
	if v := os.Getenv("OBX_FIXED_DIFFICULTY"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			FixedDifficulty = n
			GenesisDifficulty = n
		}
	}
}

// RandomX-style PoW epoch seed rotation. The PoW cache is keyed by a seed that
// rotates every PoWEpochLen blocks, taken from a block PoWSeedLag blocks in the
// past — so the seed is from confirmed history (a miner cannot grind it) and is
// known to every validator. These are CONSENSUS parameters: all nodes must agree.
//
// INVARIANT: PoWSeedLag MUST be >= the deepest reorg the chain will ever accept, so
// the seed block always lies in the unreorganizable common prefix and every node
// derives the same seed regardless of branch. The chain's deepest accepted reorg is
// exactly the PARTITION-RECOVERY bound (pkg/chain/forkchoice.go caps a deep recovery
// reorg at config.PoWSeedLag for precisely this reason), so PoWSeedLag IS the recovery
// window: a partition up to PoWSeedLag blocks long can self-heal, and no reorg may ever
// rewrite a seed block (which would let an attacker grind the seed across an epoch).
// Therefore: MaxReorgDepth (100) <= PoWSeedLag <= PoWEpochLen (clean single-epoch lag)
// and PoWSeedLag <= PoRWindow (bodies for the whole recovery window stay retained).
// Epoch 0 (PoWSeedHeight == 0) uses the fixed PoWGenesisSeed constant, so early blocks
// need no chain lookup.
var (
	PoWEpochLen uint64 = 2048 // blocks per seed epoch
	PoWSeedLag  uint64 = 512  // seed taken this many blocks back == partition-recovery window (MaxReorgDepth <= this <= PoWEpochLen, <= PoRWindow)
)

// --- Auto-liquid mining rewards (NON-CONSENSUS, node-local) --------------------
//
// When AutoSwapLiquidity is on, a mining node automatically posts cross-chain swap
// OFFERS (sell its spendable OBX for XNO) into the off-chain P2P swap order book
// (pkg/swapbook), so mining itself bootstraps liquidity and price discovery. These
// are gossiped P2P offers — NOT a consensus change, NOT a chain transaction — so
// the values here are node-local policy knobs (NOT consensus parameters): different
// nodes may use different settings without forking. All are env-overridable.
var (
	// AutoSwapLiquidity enables the auto-liquidity loop. DEFAULT true (maintainer
	// choice, reaffirmed after a brief default-off period per audit ROUND2 [73]): a
	// mining node bootstraps real OBX→XNO liquidity out of the box — otherwise a new
	// user's first "buy OBX" hits an empty order book. TRADE-OFF: auto-selling
	// freshly-mined OBX for XNO publishes a miner→XNO link on the public Nano ledger,
	// which can deanonymize the miner. This is NOT silent: a startup log line + an
	// in-product notice both call it out, and OPT OUT is one flag/env var away
	// (--no-auto-liquidity or OBX_AUTO_LIQUIDITY=0). Bounded: never offers more than
	// AutoLiquidityMaxFraction of spendable, capped at AutoLiquidityMaxOffers.
	AutoSwapLiquidity = true

	// AutoLiquiditySeedRateXNO is the SEED price used only when the order book has
	// no EXTERNAL OBX→XNO offer to anchor to: how many XNO a maker asks per 1 OBX
	// (human units). It is a real, executable quote (a fill runs a real atomic swap
	// at it), held STEADY — not a synthetic/moving price. Once genuine third-party
	// offers exist the loop eases toward the external book's best rate (real price
	// discovery). Operators SHOULD set this to a sensible bootstrap value for their
	// market. Default 1.0 XNO/OBX. Override: OBX_AUTO_LIQUIDITY_RATE.
	AutoLiquiditySeedRateXNO = 1.0

	// AutoLiquidityMaxFraction caps the fraction of the miner's spendable OBX that
	// may be tied up in outstanding auto-offers at once (0<f<=1), so the loop never
	// offers the whole balance. Override: OBX_AUTO_LIQUIDITY_MAX_FRACTION.
	AutoLiquidityMaxFraction = 0.5

	// AutoLiquidityChunkOBX is the target size of a single auto-offer in whole OBX,
	// so the loop posts a few sensible chunks rather than one giant offer or many
	// dust offers. Override: OBX_AUTO_LIQUIDITY_CHUNK_OBX.
	AutoLiquidityChunkOBX = 5.0

	// AutoLiquidityMaxOffers caps how many auto-offers this node keeps outstanding
	// at once (anti-spam on our own book share). Override: OBX_AUTO_LIQUIDITY_MAX_OFFERS.
	// Default 16 so the book holds a real LADDER of competing price levels (depth),
	// not one flat price.
	AutoLiquidityMaxOffers = 16

	// AutoLiquidityPriceStepPct is DEPRECATED and UNUSED. It formerly drove a
	// per-tick RANDOM WALK of the maker's mid price "so the price chart moves" —
	// that manufactured synthetic market data and was removed (live-only rule): the
	// mid now holds the seed rate steady and eases only toward the REAL external
	// book. Retained (with its env override) solely for config compatibility.
	AutoLiquidityPriceStepPct = 0.05

	// AutoLiquidityLadderStepPct is the price gap between adjacent ladder rungs
	// (fraction, e.g. 0.012 = 1.2%). Each tick the loop posts a LADDER around the
	// mid so there is competitive depth; the most aggressive (best-for-taker) rung
	// is filled first. Override: OBX_AUTO_LIQUIDITY_LADDER_STEP.
	AutoLiquidityLadderStepPct = 0.012

	// AutoLiquidityIntervalSec is how often the loop re-evaluates spendable balance
	// and tops up offers (slow — offer PoW is cheap but we are not a spammer).
	// Override: OBX_AUTO_LIQUIDITY_INTERVAL_SEC.
	AutoLiquidityIntervalSec int64 = 60
)

// AutoLiquidityDecimals are the UINT64-SAFE display/offer decimal scales the Obscura
// swap ecosystem (web wallet, explorer, auto-liquidity) uses for offer amounts + rates.
// OBX:12 = its on-chain atomic scale (AtomicPerCoin=10^12, fits uint64). XNO's NATIVE
// raw is 10^30, which OVERFLOWS a uint64 offer amount (a 5-XNO get-amount = 5e30 > 2^64),
// so offers/quotes express XNO with 12 decimals (1 XNO = 10^12 offer-units). The live
// XNO leg still moves real raw (10^30) via raw strings (cmd/obscura-swap, NanoRPC) — those
// are separate from these presentation/offer units. All UI DEC maps MUST match these.
var AutoLiquidityDecimals = map[string]int{"OBX": 12, "XNO": 12}

func init() {
	if v := os.Getenv("OBX_AUTO_LIQUIDITY"); v != "" {
		// "1"/"true"/"yes"/"on" force-enable; anything else (incl. "0"/"false") force-
		// DISABLE. Default is now ON; set OBX_AUTO_LIQUIDITY=0 to opt out (miner privacy).
		switch v {
		case "1", "true", "yes", "on", "TRUE", "YES", "ON":
			AutoSwapLiquidity = true
		default:
			AutoSwapLiquidity = false
		}
	}
	if v := os.Getenv("OBX_AUTO_LIQUIDITY_RATE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			AutoLiquiditySeedRateXNO = f
		}
	}
	if v := os.Getenv("OBX_AUTO_LIQUIDITY_MAX_FRACTION"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f <= 1 {
			AutoLiquidityMaxFraction = f
		}
	}
	if v := os.Getenv("OBX_AUTO_LIQUIDITY_CHUNK_OBX"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			AutoLiquidityChunkOBX = f
		}
	}
	if v := os.Getenv("OBX_AUTO_LIQUIDITY_MAX_OFFERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			AutoLiquidityMaxOffers = n
		}
	}
	if v := os.Getenv("OBX_AUTO_LIQUIDITY_PRICE_STEP"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f < 0.5 {
			AutoLiquidityPriceStepPct = f
		}
	}
	if v := os.Getenv("OBX_AUTO_LIQUIDITY_LADDER_STEP"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f < 0.2 {
			AutoLiquidityLadderStepPct = f
		}
	}
	if v := os.Getenv("OBX_AUTO_LIQUIDITY_INTERVAL_SEC"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			AutoLiquidityIntervalSec = n
		}
	}
	// OBX_SWAP_REORG_MARGIN lowers the atomic-swap reorg grace margin (blocks) for
	// FAST devnets: claim/sweep confirmation waits SwapReorgMargin blocks, which at
	// 1s block time would otherwise be ~100s. Kept < SwapTimelockWindow so the claim
	// window stays non-empty (the invariant the default 100/200 guarantees).
	//
	// audit fix: SwapReorgMargin is a CONSENSUS parameter (the on-chain swap fund/claim
	// path in pkg/chain/validate.go enforces it), so a per-node env override on mainnet
	// would let nodes disagree on swap validity — a silent fork. Lock it on mainnet like
	// the other consensus timing overrides; only devnet/testnet may lower it.
	if !IsMainnet() {
		if v := os.Getenv("OBX_SWAP_REORG_MARGIN"); v != "" {
			if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 && n < SwapTimelockWindow {
				SwapReorgMargin = n
			}
		}
	}
}

// SettleableAssets is the allowlist of swap assets that currently have a real,
// settleable leg. An offer may only be admitted to the swap order book if BOTH
// of its sides are in this set (see swapbook.IsSettleableAsset / Offer.Verify).
//
// BTC is INTENTIONALLY EXCLUDED: the Bitcoin leg has no real orchestrator yet
// (the HTLC script + mock exist in pkg/swapd/bitcoin.go, but the trustless
// redeem/refund signer needs a pure-Go secp256k1 dependency — see
// docs/SWAP_IMPLEMENTATION_PROGRESS.md "P3"). A BTC offer is therefore
// unsettleable and must not be postable/takeable/gossiped. The BTC code is left
// intact, only gated off here.
//
// RE-ENABLE BTC: add "BTC" to this slice once the BTC leg + secp256k1 dep land.
// A var (not const) so it can be toggled for tests or a future relaunch without
// a code change to every call site.
var SettleableAssets = []string{"OBX", "XNO"}

// IsSettleableAsset reports whether asset a has a real, settleable swap leg —
// i.e. it is in the SettleableAssets allowlist. Comparison is exact (the swap
// surface uses canonical uppercase tickers like "OBX"/"XNO").
func IsSettleableAsset(a string) bool {
	for _, s := range SettleableAssets {
		if s == a {
			return true
		}
	}
	return false
}

// PoWGenesisSeed keys epoch 0 of the PoW (a fixed protocol constant).
var PoWGenesisSeed = []byte("Obscura/RandomX/epoch0/v1")

// PoWSeedHeight returns the height of the block whose id seeds the PoW cache for
// a block at the given height. Returns 0 for epoch 0 (use PoWGenesisSeed).
func PoWSeedHeight(height uint64) uint64 {
	if height < PoWSeedLag {
		return 0
	}
	return ((height - PoWSeedLag) / PoWEpochLen) * PoWEpochLen
}

// AccumulatorBackend selects the group of unknown order.
//   - "classgroup": trustless, no setup (production target)
//   - "rsa2048":    RSA-2048 challenge modulus (fast, needs unknown factoring)
const AccumulatorBackend = "classgroup"

// ClassGroupDiscriminantBits for the production class-group backend.
const ClassGroupDiscriminantBits = 2048

// NetworkSeed is mixed into the genesis / nothing-up-my-sleeve derivations.
// Bumped to -sr1 with the header StateRoot field (state-root precursor): the header
// format changed, so this is a fresh, incompatible network (test chain — reset is free).
const NetworkSeed = "obscura-mainnet-sr1"

// netID is the 32-byte network/instance identifier bound into every proof,
// signature, and Fiat-Shamir transcript so that an anon-spend STARK, a swap
// claim/refund signature, or any Schnorr/DLEQ proof produced on one instance
// CANNOT replay verbatim on a sibling instance that re-minted the same coins
// (post genesis-reset relaunch, testnet, fork). SECURITY_AUDIT (cross-instance
// replay): without this binding the Fiat-Shamir challenges/transcripts are
// independent of which chain a proof was made for, so a verbatim copy verifies
// anywhere the same coin exists.
//
// It is derived (nothing-up-my-sleeve) from the consensus-distinguishing
// parameters that uniquely identify an instance: the NetworkSeed (the operator's
// genesis-reset lever — a new launch picks a fresh seed), the accumulator group
// backend and its discriminant width (the accumulator modulus is itself a
// deterministic function of NetworkSeed‖bits, so these pin the modulus), and the
// coin identity. Two instances differ in netID iff they differ in any of these.
var netID = func() [32]byte {
	var w [10]byte
	binary.BigEndian.PutUint64(w[:8], AtomicPerCoin)
	binary.BigEndian.PutUint16(w[8:], uint16(ClassGroupDiscriminantBits))
	h, _ := blake2b.New256([]byte(nil))
	h.Write([]byte("Obscura/netID/v1"))
	h.Write([]byte(NetworkSeed))
	h.Write([]byte(AccumulatorBackend))
	h.Write([]byte(CoinName))
	h.Write([]byte(Ticker))
	h.Write(w[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}()

// NetID returns the 32-byte network/instance identifier (see netID). Callers
// bind it into their proof/signature/transcript domain so proofs cannot replay
// across sibling instances.
func NetID() [32]byte { return netID }

// NetIDHex returns netID as a 64-char lowercase hex string, for use as a
// transcript/domain-separation label component.
func NetIDHex() string { return toHexLower(netID[:]) }

func toHexLower(b []byte) string {
	const hexdig = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdig[c>>4]
		out[i*2+1] = hexdig[c&0xf]
	}
	return string(out)
}

// MinFeePerByte is the minimum fee rate accepted into the mempool.
const MinFeePerByte uint64 = 1000 // atomic units per byte

// CoinbaseMaturity is the number of blocks a coinbase output must age before it
// can be spent (reorg safety). A var (not const) so tests can use a small value.
// Lowered from 60 to 6 (2026-07-02, operator decision): this chain is test-only
// (no live OBX value — see docs/CLAUDE.md), and 6 blocks still gives auto-
// liquidity's OBX funding a real reorg-safety margin before a taker can lock
// live XNO against it, while cutting the wait for fresh liquidity from ~20min
// to ~2min at the observed block rate. main.go's --coinbase-maturity override
// is still locked/ignored on mainnet builds; this changes the CANONICAL value
// itself, so it applies uniformly without needing the flag.
var CoinbaseMaturity uint64 = 6

// SwapReorgMargin is the reorg GRACE MARGIN (in blocks) separating an atomic-swap
// output's claim and refund windows (#11). It MUST be >= the DEEPEST reorg the chain
// will ever accept at the claim/refund boundary.
//
// AUDIT FIX (swap atomicity vs deep partition-recovery reorg): the deepest accepted
// reorg is NOT the normal-finality bound MaxReorgDepth (100) — the fork-choice accepts
// PARTITION-RECOVERY reorgs up to config.PoWSeedLag (512) deep (pkg/chain/forkchoice.go
// rejects only depth > PoWSeedLag). A swap straddling a 100–512-deep partition-recovery
// reorg could have its claim (one fork) and refund (other fork) BOTH become valid — a
// double-settle where the funder refunds while the counterparty already extracted the
// adaptor secret. So the margin is tied to PoWSeedLag, the true deepest accepted reorg,
// not MaxReorgDepth. The cost is paid only on the ABANDONED-swap refund path (the maker's
// OBX is reclaimable ~PoWSeedLag blocks later); the HAPPY path is unaffected (the taker
// still claims within the claim window right after funding).
//
// It lives here (not in pkg/chain) so BOTH the consensus call site (pkg/chain/validate.go)
// AND the helper (pkg/swap.SwapOutput.VerifyClaim/VerifyRefund) can use the SAME bound
// without pkg/swap importing pkg/chain (which would cycle: chain imports swap).
//
// REORG-SAFETY INVARIANT (the whole point of #11):
//
//	CLAIM  is valid  iff  height + SwapReorgMargin <= UnlockHeight  (height <= UnlockHeight - margin)
//	REFUND is valid  iff  height                  >= UnlockHeight
//
// The two valid height-sets are DISJOINT and separated by a dead-zone
// [UnlockHeight - margin, UnlockHeight) of exactly `margin` heights where NEITHER path
// is valid. A reorg of depth d <= margin shifts a transaction's confirmed height by at
// most `margin`, so it can never carry a claim-valid height (<= UnlockHeight - margin)
// up into the refund-valid region (>= UnlockHeight), nor vice versa. Hence a claim
// (valid on one fork) and a refund (valid on the other) can NEVER both be valid for the
// same swap across any single accepted reorg — closing the window where a funder could
// refund while the counterparty has already extracted the adaptor secret.
//
// Default == PoWSeedLag (the deepest accepted reorg). A var so tests can use a small
// value (real reorgs never happen in the test harness).
var SwapReorgMargin uint64 = PoWSeedLag

// SwapTimelockWindow is how many blocks after funding an atomic-swap output's refund
// branch opens (claim valid before it minus the reorg margin, refund valid at/after).
// Previously hardcoded as a magic "height+200" in the executor (#10); a var so it can
// be negotiated per swap and so tests can use a small value. Must comfortably exceed
// SwapReorgMargin (so the claim window [fund, fund+window-margin] is non-empty) PLUS
// claim-propagation headroom, so a claim cannot race a refund across a reorg (#11).
//
// GUARD: SwapTimelockWindow MUST be > SwapReorgMargin (and >= margin + SwapMinClaimWindow).
// With SwapReorgMargin now tied to PoWSeedLag (512), the default is PoWSeedLag + 100 = 612,
// leaving a 100-block claim window after the margin. The taker still claims within that
// window right after funding (happy path unchanged); only an ABANDONED swap's refund waits
// the full window. If you shrink either, keep the invariant.
var SwapTimelockWindow uint64 = PoWSeedLag + 100

// SwapMinClaimWindow is the MINIMUM number of blocks of OPEN claim window an
// atomic-swap output must leave ABOVE the reorg margin, measured at the height a
// counterparty observes the funded SwapOut. It is the headroom a taker needs to:
// confirm the off-chain XNO lock, obtain the maker's co-signature, and get the
// claim spend mined — all while the claim path is still valid (height + margin <=
// UnlockHeight). A var so tests can shrink it.
//
// FUND-SAFETY INVARIANT (F-1, the fund-freeze fix). Recall the claim-validity rule:
//
//	a claim is valid iff  height + SwapReorgMargin <= UnlockHeight.
//
// A SwapOut whose UnlockHeight is too close to the current height has a claim
// window that is already (or imminently) DEAD. If a taker locks XNO into such a
// swap it can NEVER claim the OBX, yet the maker can refund risk-free at/after
// UnlockHeight — the taker's XNO freezes. To close this, every party that commits
// value into a swap requires, at its OWN current height H:
//
//	UnlockHeight >= H + SwapReorgMargin + SwapMinClaimWindow
//
// enforced at THREE layers: (1) the TAKER (swapsession.checkSwapOut) refuses to
// lock XNO unless its current height leaves this window; (2) the MAKER
// (swapsession.Maker.Fund) refuses to fund an unclaimable unlock height; and
// (3) CONSENSUS (pkg/chain/validate.go swap-output fund path) rejects any SwapOut
// funded with UnlockHeight < fundHeight + SwapReorgMargin — a provably-dead claim
// window never gets on-chain (defense-in-depth; uses only the margin since the
// off-chain SwapMinClaimWindow headroom is a per-counterparty concern).
//
// DEFAULTS MUST COMPOSE: SwapTimelockWindow >= SwapReorgMargin + SwapMinClaimWindow,
// so the legacy executor (unlock = height + SwapTimelockWindow) and an honest
// session maker both satisfy the invariant. Default 612 (= PoWSeedLag+100) >= 512 + 50
// holds with a 50-block honest margin to spare. If you shrink any of the three, preserve this.
var SwapMinClaimWindow uint64 = 50

// AssertSwapTimingInvariant verifies the swap claim/refund windows are still disjoint.
// audit: ROUND2 [100] — SwapReorgMargin/SwapTimelockWindow are one-time value copies of
// PoWSeedLag, not live derivations, so a future PoWSeedLag change (or a bad devnet override)
// could silently reopen the claim/refund double-settle race. Called once at node startup so
// a broken invariant fails loudly instead of silently forking on swap validity.
func AssertSwapTimingInvariant() error {
	if SwapTimelockWindow <= SwapReorgMargin {
		return fmt.Errorf("swap timing invariant broken: SwapTimelockWindow(%d) must exceed SwapReorgMargin(%d) — the claim/refund windows are not disjoint", SwapTimelockWindow, SwapReorgMargin)
	}
	if SwapTimelockWindow < SwapReorgMargin+SwapMinClaimWindow {
		return fmt.Errorf("swap timing invariant broken: SwapTimelockWindow(%d) < SwapReorgMargin(%d)+SwapMinClaimWindow(%d) — an honest claim window cannot compose", SwapTimelockWindow, SwapReorgMargin, SwapMinClaimWindow)
	}
	if IsMainnet() && SwapReorgMargin != PoWSeedLag {
		return fmt.Errorf("swap timing invariant broken: on mainnet SwapReorgMargin(%d) must equal PoWSeedLag(%d) — a PoWSeedLag change did not propagate to the one-time copy", SwapReorgMargin, PoWSeedLag)
	}
	return nil
}

// MinOrderSize is the per-asset minimum GIVE size (in the asset's offer units —
// the AutoLiquidityDecimals scale) the matching engine will reserve/fill for a
// taker on a directed leg, keyed by the asset the TAKER gives. A reserve request
// smaller than this is rejected as dust (and a per-rung partial fill that would
// leave or take less than this is skipped), so the executed-trade tape and the
// on-chain settlement legs are never asked to move uneconomic crumbs. Assets not
// present here default to MinOrderSizeDefault. A var so tests can tune it.
var MinOrderSize = map[string]uint64{
	"OBX": 1, // 1 offer-unit OBX (10^-12 OBX in offer scale) — effectively no floor in tests
	"XNO": 1, // 1 offer-unit XNO
}

// MinOrderSizeDefault is the dust floor applied to any asset absent from the
// MinOrderSize map.
var MinOrderSizeDefault uint64 = 1

// MinOrderSizeFor returns the dust floor for a taker giving `asset`, falling back
// to MinOrderSizeDefault when the asset has no explicit entry.
func MinOrderSizeFor(asset string) uint64 {
	if v, ok := MinOrderSize[asset]; ok {
		return v
	}
	return MinOrderSizeDefault
}

// SwapMaxSessions caps the TOTAL number of concurrent in-flight swap sessions a
// single node's swap coordinator (pkg/swapnet) will hold at once, across BOTH
// roles and ALL peers. It bounds the coordinator's `sessions` map and the
// per-session goroutines so a flood of swap openings cannot exhaust memory or
// goroutines. Reaching the cap rejects new sessions (a taker's Take errors; an
// inbound maker-opening Init is dropped) until live ones finish/refund. A var so
// tests can use a small value.
var SwapMaxSessions int = 256

// SwapMaxSessionsPerPeer caps the number of concurrent in-flight swap sessions a
// node will run with ANY SINGLE counterparty (keyed by the peer routing handle).
// It blunts the F-A griefing vector where one peer floods Init envelopes to spin
// up many maker sessions on a victim (each of which funds OBX), by bounding how
// many a single peer can hold open at once. A var so tests can use a small value.
var SwapMaxSessionsPerPeer int = 8

// PoolSize is the fixed anonymity-pool size: coins are grouped into pools of
// this many by creation order, and an anonymous spend's ring is one complete
// pool (canonical, so verification cost is bounded by PoolSize and there is no
// decoy-selection heuristic). MUST be a power of two (one-out-of-many requires
// it). A var so tests can use a small pool; production uses 64–256.
var PoolSize uint64 = 16

// MaxMoney is a sanity bound for amounts (supply cap plus tail headroom).
var MaxMoney = new(big.Int).Add(
	new(big.Int).SetUint64(MoneySupplyCap),
	new(big.Int).SetUint64(1_000_000*AtomicPerCoin),
)

// BlockReward returns the base PoW reward at the given already-emitted supply.
// Smooth emission until the tail floor takes over.
func BlockReward(alreadyEmitted uint64) uint64 {
	if alreadyEmitted >= MoneySupplyCap {
		return TailEmissionAtomic
	}
	remaining := MoneySupplyCap - alreadyEmitted
	reward := remaining >> EmissionShift
	if reward < TailEmissionAtomic {
		return TailEmissionAtomic
	}
	return reward
}

// FormatAmount renders atomic units as a decimal OBX string.
func FormatAmount(atomic uint64) string {
	whole := atomic / AtomicPerCoin
	frac := atomic % AtomicPerCoin
	return formatUint(whole) + "." + padFrac(frac)
}

func formatUint(n uint64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func padFrac(frac uint64) string {
	s := formatUint(frac)
	for len(s) < 12 {
		s = "0" + s
	}
	return s
}
