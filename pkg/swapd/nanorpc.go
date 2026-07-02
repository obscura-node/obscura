package swapd

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/blake2b"
)

// NanoRPC is the PRODUCTION NanoClient: it talks to a real Nano (XNO) node's JSON-RPC
// over HTTP. It is constructed ONLY from a node-maintainer-provided endpoint — there is
// NO hardcoded URL anywhere in Obscura. If a maintainer does not configure a Nano RPC,
// the swap order book still works; only the XNO execution leg is disabled. This is the
// design the user requested: zero hardcoding of other networks' infrastructure.
//
// LIVE GATE: the deterministic pieces here (address codec, block hashing, the
// ed25519-blake2b signature) are unit-tested against Nano's published constants, but the
// end-to-end Lock/Sweep/work/process flow handles real funds and can only be FINAL-
// validated against a live/testnet Nano node — which only the maintainer who supplies the
// RPC endpoint has. Treat as ready-for-testnet, not audited-for-mainnet, until then.
type NanoRPC struct {
	cfg NanoRPCConfig
	hc  *http.Client
	// fundSecret is the parsed FundSecretHex (raw ed25519 scalar of the taker's
	// funding XNO account), or nil if none was configured. It NEVER leaves this
	// struct: Lock uses it to sign the funding send locally, and it is never logged,
	// returned, or included in any error message.
	fundSecret *edwards25519.Scalar
}

// NanoRPCConfig is everything a node maintainer must supply to enable the XNO swap leg.
// All of it comes from the operator (flags / env / config) — never hardcoded.
type NanoRPCConfig struct {
	URL string // REQUIRED: the maintainer's Nano node RPC endpoint, e.g. http://127.0.0.1:7076
	// Fallbacks are additional read/process RPC endpoints tried IN ORDER when URL is
	// unreachable (transport error / non-2xx) — resilience when the primary public node
	// is down or rate-limiting. NOT used for work_generate (only WorkURL does work). A
	// Nano {"error":...} envelope from the primary is a real answer and is NOT retried.
	Fallbacks  []string
	AuthHeader string // optional: value for an Authorization header (hosted nodes)
	WalletID   string // optional: node wallet id used as the funding source for Lock (send)
	Source     string // optional: funding account (nano_...) inside WalletID for Lock
	WorkURL    string // optional: separate work-generation endpoint; defaults to URL
	Timeout    time.Duration

	// FundSecretHex is an OPTIONAL raw 32-byte ed25519 scalar (hex) of a TAKER's
	// funding XNO account. It is the LOCAL-KEY alternative to WalletID/Source: when a
	// public Nano RPC (e.g. rainstorm) gives no node-managed wallet, Lock signs the
	// funding send LOCALLY with this scalar (the same partial-send path as Send).
	// SECURITY: this is a SECRET. It is parsed once at construction into an in-memory
	// scalar (fundSecret) and is NEVER logged, returned, or echoed in any error. Only
	// the TAKER (the buyer who pays XNO) needs it; makers only sweep and do not.
	FundSecretHex string
}

// NewNanoRPC builds a production Nano client from a maintainer-provided config. It
// REQUIRES a non-empty URL — refusing to invent a default is the whole point (no
// hardcoded third-party infrastructure).
func NewNanoRPC(cfg NanoRPCConfig) (*NanoRPC, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("swapd: nano RPC URL is required (set it via the node operator config; Obscura never hardcodes a Nano endpoint)")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 20 * time.Second
	}
	if cfg.WorkURL == "" {
		cfg.WorkURL = cfg.URL
	}
	n := &NanoRPC{cfg: cfg, hc: &http.Client{Timeout: cfg.Timeout}}
	// Parse the optional local-key funding secret ONCE, at construction, so a bad hex
	// fails fast (startup) and the raw hex string is never carried into Lock. The
	// secret lives only as the in-memory scalar n.fundSecret from here on.
	if strings.TrimSpace(cfg.FundSecretHex) != "" {
		sec, err := parseFundSecret(cfg.FundSecretHex)
		if err != nil {
			// NOTE: parseFundSecret's error NEVER includes the secret bytes.
			return nil, err
		}
		n.fundSecret = sec
		n.cfg.FundSecretHex = "" // drop the raw hex; keep only the parsed scalar
	}
	return n, nil
}

// parseFundSecret decodes a raw 32-byte ed25519 scalar from hex into an
// *edwards25519.Scalar, requiring CANONICAL bytes (the same check the test wallet
// uses). It is the single validation point for --nano-fund-secret. Its errors are
// deliberately content-free about the secret: they report the failure CLASS (bad
// hex / wrong length / non-canonical) but never echo the secret value, so a bad
// secret cannot leak into a startup log.
func parseFundSecret(hexStr string) (*edwards25519.Scalar, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(hexStr))
	if err != nil {
		return nil, errors.New("swapd: nano fund secret is not valid hex")
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("swapd: nano fund secret must be 32 bytes, got %d", len(raw))
	}
	sec, err := new(edwards25519.Scalar).SetCanonicalBytes(raw)
	if err != nil {
		return nil, errors.New("swapd: nano fund secret is not a canonical ed25519 scalar")
	}
	return sec, nil
}

var _ NanoClient = (*NanoRPC)(nil)

// NanoRPCFundAddress returns the canonical nano_ address of the configured LOCAL-KEY
// funding account (derived from the funding scalar), for a startup confirmation log.
// It exposes only the PUBLIC address — the secret scalar never leaves the struct. If
// no funding secret is configured it returns an error.
func NanoRPCFundAddress(n *NanoRPC) (string, error) {
	if n == nil || n.fundSecret == nil {
		return "", errors.New("swapd: no local funding secret configured")
	}
	pub := new(edwards25519.Point).ScalarBaseMult(n.fundSecret).Bytes()
	return EncodeNanoAddress(pub)
}

// Version pings the configured Nano node (the `version` RPC) and returns its node-vendor
// string. Used as a startup connectivity check so a maintainer learns immediately whether
// the endpoint they supplied actually works — without any hardcoded fallback.
func (n *NanoRPC) Version() (string, error) {
	var res struct {
		NodeVendor string `json:"node_vendor"`
		RPCVersion string `json:"rpc_version"`
	}
	if err := n.call(n.cfg.URL, map[string]any{"action": "version"}, &res); err != nil {
		return "", err
	}
	v := strings.TrimSpace(res.NodeVendor + " " + res.RPCVersion)
	if v == "" {
		v = "unknown"
	}
	return v, nil
}

// ---- JSON-RPC plumbing -----------------------------------------------------

// call wraps callOnce with up to 3 attempts, riding out the transient timeouts that public
// Nano RPCs (incl. rainstorm/nano.to) hit under load — the reference XNO template does the
// same. A Nano {"error":...} envelope is a real answer, not transient, so it is not retried.
func (n *NanoRPC) call(url string, req map[string]any, out any) error {
	// Endpoint list: the requested url first, then the configured fallbacks — but only
	// for the PRIMARY read/process endpoint (work_generate is sent to WorkURL and has no
	// read fallback). Each endpoint gets up to 3 attempts; a dead/erroring endpoint
	// (transport error or non-2xx) advances to the next fallback, while a Nano
	// {"error":...} envelope is a real answer and returns immediately.
	urls := []string{url}
	if url == n.cfg.URL {
		urls = append(urls, n.cfg.Fallbacks...)
	}
	var lastErr error
	for _, u := range urls {
		for attempt := 0; attempt < 3; attempt++ {
			lastErr = n.callOnce(u, req, out)
			if lastErr == nil {
				return nil
			}
			if strings.Contains(lastErr.Error(), "nano rpc error:") {
				return lastErr // node answered with an error envelope — not a dead node
			}
		}
		// this endpoint is unreachable/5xx at the transport level — fall back to the next
	}
	return lastErr
}

func (n *NanoRPC) callOnce(url string, req map[string]any, out any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if n.cfg.AuthHeader != "" {
		httpReq.Header.Set("Authorization", n.cfg.AuthHeader)
	}
	resp, err := n.hc.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// AUDIT FIX: reject non-2xx responses (a misbehaving/hostile endpoint could return
	// an HTML error page that we'd otherwise try to JSON-decode), and cap the body we
	// read with an io.LimitReader so an unbounded/streaming response cannot exhaust
	// memory. 1 MiB is far larger than any legitimate Nano RPC reply.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("swapd: nano rpc http status %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, 1<<20)
	// Read the body once into a generic map so we can surface Nano's {"error":"..."}
	// envelope, then re-decode into the typed out.
	var generic map[string]json.RawMessage
	if err := json.NewDecoder(limited).Decode(&generic); err != nil {
		return err
	}
	if e, ok := generic["error"]; ok {
		var msg string
		_ = json.Unmarshal(e, &msg)
		return fmt.Errorf("swapd: nano rpc error: %s", msg)
	}
	if out != nil {
		b, _ := json.Marshal(generic)
		return json.Unmarshal(b, out)
	}
	return nil
}

// ---- NanoClient interface --------------------------------------------------

// Lock sends `amount` raw XNO from the maintainer's configured funding source to the joint
// account derived from accountPub (= (s_a+s_b)·G). Returns the send block hash as lockID.
//
// TWO FUNDING MODES (mutually exclusive at use time):
//
//   - NODE-WALLET path (cfg.WalletID + cfg.Source set): the funding key lives inside a
//     node-managed Nano wallet and the node's `send` RPC signs the block. This is the
//     original path and is preferred when a private node wallet is configured.
//   - LOCAL-KEY path (n.fundSecret set, WalletID empty): a public Nano RPC (e.g.
//     rainstorm) has NO node wallet, so we sign the funding send OURSELVES from the raw
//     ed25519 scalar of the taker's funding account — the SAME receive-pending →
//     partial-send pattern as Send. This is what lets an in-node taker pay REAL XNO
//     through a public RPC. The funding secret is never logged or returned.
//
// AMOUNT PRECISION: `amount` is a *big.Int raw value (1 XNO = 1e30 raw, a 128-bit
// quantity that does NOT fit in uint64). It is formatted as a faithful decimal raw
// string into the `send` RPC — no truncation — so the on-ledger amount matches the
// agreed amount exactly.
func (n *NanoRPC) Lock(amount *big.Int, accountPub []byte) (string, error) {
	if amount == nil || amount.Sign() < 0 {
		return "", errors.New("swapd: nano lock amount must be non-negative")
	}
	// LOCAL-KEY path: a funding secret is configured and no node wallet is. Derive the
	// funding account from the secret, receive any pending into it, then sign+publish a
	// send of EXACTLY `amount` raw to the joint account locally.
	if n.cfg.WalletID == "" && n.fundSecret != nil {
		return n.lockLocalKey(amount, accountPub)
	}
	if n.cfg.WalletID == "" || n.cfg.Source == "" {
		return "", errors.New("swapd: Lock needs a funding wallet+source OR a local funding secret in the Nano config (operator-provided)")
	}
	dest, err := EncodeNanoAddress(accountPub)
	if err != nil {
		return "", err
	}
	var res struct {
		Block string `json:"block"`
	}
	err = n.call(n.cfg.URL, map[string]any{
		"action":      "send",
		"wallet":      n.cfg.WalletID,
		"source":      n.cfg.Source,
		"destination": dest,
		"amount":      amount.String(),
	}, &res)
	if err != nil {
		return "", err
	}
	if res.Block == "" {
		return "", errors.New("swapd: nano send returned no block hash")
	}
	return res.Block, nil
}

// lockLocalKey is the LOCAL-KEY Lock: it RECEIVES any pending into the funding account
// (derived from n.fundSecret) until the balance covers `amount`, then SIGNS and
// publishes a send of EXACTLY `amount` raw to the joint account (accountPub), KEEPING
// the change. It reuses the EXACT receive→send→work→process flow of Send/publishState,
// signing every block with the raw funding scalar. It returns the send block hash as the
// lockID. The funding secret is NEVER logged, returned, or embedded in any error.
func (n *NanoRPC) lockLocalKey(amount *big.Int, accountPub []byte) (string, error) {
	if len(accountPub) != 32 {
		return "", errors.New("swapd: bad nano account pubkey")
	}
	// AUDIT FIX (defense in depth): reject an amount wider than 128 bits before we touch
	// the ledger, mirroring publishState's balance guard.
	if len(amount.Bytes()) > 16 {
		return "", errors.New("swapd: nano lock amount exceeds 128 bits")
	}
	fromSecret := n.fundSecret
	fromPub := new(edwards25519.Point).ScalarBaseMult(fromSecret).Bytes()
	fromAddr, err := EncodeNanoAddress(fromPub)
	if err != nil {
		return "", err
	}
	// the joint account (s_a+s_b)·G is the destination of the funding send.
	destAddr, err := EncodeNanoAddress(accountPub)
	if err != nil {
		return "", err
	}
	destPub, err := DecodeNanoAddress(destAddr)
	if err != nil {
		return "", err
	}

	var info struct {
		Frontier       string `json:"frontier"`
		Representative string `json:"representative"`
		Balance        string `json:"balance"`
	}
	_ = n.call(n.cfg.URL, map[string]any{"action": "account_info", "account": fromAddr, "representative": "true"}, &info)
	zero := strings.Repeat("0", 64)
	prev := info.Frontier
	if prev == "" {
		prev = zero
	}
	rep := info.Representative
	if rep == "" {
		rep = defaultNanoRep
	}
	bal := big.NewInt(0)
	if info.Balance != "" {
		bal, _ = new(big.Int).SetString(info.Balance, 10)
	}
	// Receive pending blocks until the spendable balance covers `amount`.
	for bal.Cmp(amount) < 0 {
		hash, amtStr, ok := n.Receivable(fromAddr)
		if !ok {
			break
		}
		amt, ok2 := new(big.Int).SetString(amtStr, 10)
		if !ok2 {
			return "", errors.New("swapd: bad receivable amount")
		}
		bal = new(big.Int).Add(bal, amt)
		h, perr := n.publishState(fromPub, prev, rep, bal, hash, fromSecret, prev == zero, "receive")
		if perr != nil {
			return "", fmt.Errorf("swapd: lock receive: %w", perr)
		}
		prev = h
	}
	if bal.Cmp(amount) < 0 {
		return "", fmt.Errorf("swapd: insufficient funding balance %s < %s raw to lock", bal, amount)
	}
	newBal := new(big.Int).Sub(bal, amount)
	lockID, err := n.publishState(fromPub, prev, rep, newBal, hex.EncodeToString(destPub), fromSecret, false, "send")
	if err != nil {
		return "", fmt.Errorf("swapd: lock send: %w", err)
	}
	if lockID == "" {
		return "", errors.New("swapd: nano lock send returned no block hash")
	}
	return lockID, nil
}

// Confirmed reports whether the lock's send block is cemented (irreversible). Nano has no
// reorgs once a block is confirmed by quorum.
func (n *NanoRPC) Confirmed(lockID string) bool {
	var res struct {
		Confirmed string `json:"confirmed"`
	}
	if err := n.call(n.cfg.URL, map[string]any{
		"action":     "block_info",
		"hash":       lockID,
		"json_block": "true",
	}, &res); err != nil {
		return false
	}
	return res.Confirmed == "true"
}

// LockInfo reads the AUTHORITATIVE destination account and amount of the lock send block
// (lockID is its hash) straight from the Nano ledger, so the maker can verify the taker
// locked the agreed XNO to the JOINT account BEFORE co-signing. It returns the 32-byte
// destination public key (the receiver of the send) and the send amount.
//
// The send's destination is carried as the block's `link` (a 64-hex value that is the
// receiver's public key for a send subtype). `block_info` with json_block also surfaces
// `amount` (the value transferred) and `contents.link` / `contents.link_as_account`.
//
// AMOUNT PRECISION: the amount is returned as the full 128-bit raw *big.Int parsed
// straight from the ledger's decimal string — no truncation — so the maker's
// exact-equality check against the agreed amount is correct. If the node does not return
// a usable link/amount the swap safely aborts (error) rather than trusting blindly.
func (n *NanoRPC) LockInfo(lockID string) (*big.Int, []byte, error) {
	var res struct {
		Amount   string `json:"amount"`
		Subtype  string `json:"subtype"`
		Contents struct {
			Link          string `json:"link"`
			LinkAsAccount string `json:"link_as_account"`
			Type          string `json:"type"`
		} `json:"contents"`
	}
	if err := n.call(n.cfg.URL, map[string]any{
		"action":     "block_info",
		"hash":       lockID,
		"json_block": "true",
	}, &res); err != nil {
		return nil, nil, err
	}
	// the destination public key: prefer the raw hex `link`; fall back to decoding the
	// nano_ account form. A send's link IS the receiver's public key.
	var pub []byte
	if l := strings.TrimSpace(res.Contents.Link); l != "" {
		b, err := hex.DecodeString(l)
		if err != nil || len(b) != 32 {
			return nil, nil, errors.New("swapd: lock block has an unreadable link (destination)")
		}
		pub = b
	} else if a := strings.TrimSpace(res.Contents.LinkAsAccount); a != "" {
		b, err := DecodeNanoAddress(a)
		if err != nil {
			return nil, nil, fmt.Errorf("swapd: lock block link_as_account undecodable: %w", err)
		}
		pub = b
	} else {
		return nil, nil, errors.New("swapd: lock block has no destination link — cannot verify XNO account")
	}
	// amount transferred by the send block, FULL 128-bit raw (no truncation).
	v, ok := new(big.Int).SetString(strings.TrimSpace(res.Amount), 10)
	if !ok {
		return nil, nil, errors.New("swapd: lock block has no readable amount")
	}
	if v.Sign() < 0 {
		return nil, nil, errors.New("swapd: lock block amount is negative")
	}
	return v, pub, nil
}

// Receivable returns the newest pending (receivable) block sending funds TO account, with
// its raw amount as a decimal string (full 128-bit precision, unlike the uint64 interface).
// This is how the executor detects a manually-sent lock without needing a funding wallet.
func (n *NanoRPC) Receivable(account string) (blockHash, amountRaw string, ok bool) {
	var res struct {
		Blocks map[string]string `json:"blocks"`
	}
	// NOTE: use "threshold" (not "source") — with source:true the node returns nested
	// {hash:{amount,source}} objects that don't decode into map[string]string; threshold
	// returns the {hash: amountRaw} map this expects. (Found by the first live run.)
	if err := n.call(n.cfg.URL, map[string]any{
		"action":    "receivable",
		"account":   account,
		"count":     "10",
		"threshold": "1",
	}, &res); err != nil {
		return "", "", false
	}
	// pick the largest receivable (the lock), returning hash + raw amount.
	best := new(big.Int)
	for h, amt := range res.Blocks {
		v, good := new(big.Int).SetString(amt, 10)
		if !good {
			continue
		}
		if v.Cmp(best) > 0 {
			best = v
			blockHash, amountRaw = h, amt
		}
	}
	return blockHash, amountRaw, blockHash != ""
}

// Balance returns the confirmed balance (full 128-bit raw) of dest. Used for
// settlement checks. A missing account / unreadable balance returns 0.
func (n *NanoRPC) Balance(dest string) *big.Int {
	var res struct {
		Balance string `json:"balance"`
	}
	if err := n.call(n.cfg.URL, map[string]any{
		"action":  "account_info",
		"account": dest,
	}, &res); err != nil {
		return new(big.Int)
	}
	v, ok := new(big.Int).SetString(res.Balance, 10)
	if !ok {
		return new(big.Int)
	}
	return v
}

// Sweep moves the locked XNO out of the joint account to dest, proving knowledge of the
// joint secret s = s_a+s_b. The joint account is unopened (the Lock only created a
// *receivable*), so sweeping is two signed state blocks: (1) receive the pending Lock send
// into the joint account, then (2) send the full balance to dest. Both are signed with the
// joint scalar using Nano's ed25519-blake2b scheme and published via `process`.
//
// LIVE GATE: exercised against MockNano in tests; the real receive→send→work→process path
// must be validated against a live/testnet Nano node before mainnet use.
func (n *NanoRPC) Sweep(lockID string, accountSecret *edwards25519.Scalar, dest string) error {
	jointPub := new(edwards25519.Point).ScalarBaseMult(accountSecret).Bytes()
	jointAddr, err := EncodeNanoAddress(jointPub)
	if err != nil {
		return err
	}
	destPub, err := DecodeNanoAddress(dest)
	if err != nil {
		return fmt.Errorf("swapd: bad nano dest: %w", err)
	}

	// Idempotency: a prior Sweep call may have published the receive (step 1) and then
	// failed before the send (step 2) — e.g. a transient RPC error. Retrying blindly would
	// try to receive lockID a second time, which Nano rejects (the link is no longer
	// pending), so every retry would fail identically and the payout would stall forever
	// with the OBX side already funded. Check whether lockID is still an outstanding
	// receivable for the joint account before deciding whether step 1 needs to run again.
	var pending struct {
		Blocks map[string]string `json:"blocks"`
	}
	if err := n.call(n.cfg.URL, map[string]any{
		"action":    "receivable",
		"account":   jointAddr,
		"count":     "10",
		"threshold": "1",
	}, &pending); err != nil {
		return fmt.Errorf("swapd: nano sweep: checking receivable status: %w", err)
	}
	_, lockStillPending := pending.Blocks[lockID]

	// (1) Receive the pending Lock send (skipped if a prior attempt already did this).
	// Determine the receivable amount + the joint account's current frontier/representative
	// (frontier is zero if still unopened).
	var info struct {
		Frontier       string `json:"frontier"`
		Representative string `json:"representative"`
		Balance        string `json:"balance"`
	}
	_ = n.call(n.cfg.URL, map[string]any{"action": "account_info", "account": jointAddr, "representative": "true"}, &info)
	prev := info.Frontier
	if prev == "" {
		prev = strings.Repeat("0", 64) // unopened account
	}
	rep := info.Representative
	if rep == "" {
		rep = defaultNanoRep // a known online representative for the open block (per the XNO template)
	}

	recvHash := prev
	if lockStillPending {
		curBal := big.NewInt(0)
		if info.Balance != "" {
			curBal, _ = new(big.Int).SetString(info.Balance, 10)
		}
		// amount of the receivable (the Lock send)
		var binfo struct {
			Amount string `json:"amount"`
		}
		if err := n.call(n.cfg.URL, map[string]any{"action": "block_info", "hash": lockID, "json_block": "true"}, &binfo); err != nil {
			return err
		}
		recvAmt, ok := new(big.Int).SetString(binfo.Amount, 10)
		if !ok {
			return errors.New("swapd: cannot read receivable amount")
		}
		afterRecv := new(big.Int).Add(curBal, recvAmt)

		// build + publish the receive block (link = the Lock send hash)
		recvHash, err = n.publishState(jointPub, prev, rep, afterRecv, lockID, accountSecret, prev == strings.Repeat("0", 64), "receive")
		if err != nil {
			return fmt.Errorf("swapd: nano receive: %w", err)
		}
	} else if prev == strings.Repeat("0", 64) {
		// lockID isn't pending, yet the joint account never opened — a joint account's
		// only ever receivable is this one lock, so this is an inconsistent read (e.g. a
		// transient node-lag between the two RPC calls above); fail closed rather than
		// risk sending from an account that never actually received the lock.
		return errors.New("swapd: nano sweep: lock not pending but joint account unopened — unexpected state, retry")
	}

	// (2) send the whole balance to dest (balance 0, link = dest pubkey)
	if _, err := n.publishState(jointPub, recvHash, rep, big.NewInt(0), hex.EncodeToString(destPub), accountSecret, false, "send"); err != nil {
		return fmt.Errorf("swapd: nano send: %w", err)
	}
	return nil
}

// publishState builds, signs (ed25519-blake2b), works, and processes one Nano state block.
// linkHex is a 64-hex value: the source block hash for a receive, or the destination
// pubkey for a send. opened=true means this is the account's first (open) block.
// Send receives pending into the account controlled by fromSecret (until it can cover
// amountRaw), then sends EXACTLY amountRaw to dest, KEEPING the change. Unlike Sweep
// (which sends the whole balance), this moves a capped amount — used to drive a funded
// account as a swap sender in testing without spending more than intended. Real funds.
func (n *NanoRPC) Send(fromSecret *edwards25519.Scalar, amountRaw *big.Int, dest string) error {
	fromPub := new(edwards25519.Point).ScalarBaseMult(fromSecret).Bytes()
	fromAddr, err := EncodeNanoAddress(fromPub)
	if err != nil {
		return err
	}
	destPub, err := DecodeNanoAddress(dest)
	if err != nil {
		return fmt.Errorf("swapd: bad nano dest: %w", err)
	}
	var info struct {
		Frontier       string `json:"frontier"`
		Representative string `json:"representative"`
		Balance        string `json:"balance"`
	}
	_ = n.call(n.cfg.URL, map[string]any{"action": "account_info", "account": fromAddr, "representative": "true"}, &info)
	zero := strings.Repeat("0", 64)
	prev := info.Frontier
	if prev == "" {
		prev = zero
	}
	rep := info.Representative
	if rep == "" {
		rep = defaultNanoRep
	}
	bal := big.NewInt(0)
	if info.Balance != "" {
		bal, _ = new(big.Int).SetString(info.Balance, 10)
	}
	// Receive pending blocks until the spendable balance covers amountRaw.
	for bal.Cmp(amountRaw) < 0 {
		hash, amtStr, ok := n.Receivable(fromAddr)
		if !ok {
			break
		}
		amt, ok2 := new(big.Int).SetString(amtStr, 10)
		if !ok2 {
			return errors.New("swapd: bad receivable amount")
		}
		bal = new(big.Int).Add(bal, amt)
		h, perr := n.publishState(fromPub, prev, rep, bal, hash, fromSecret, prev == zero, "receive")
		if perr != nil {
			return fmt.Errorf("swapd: receive: %w", perr)
		}
		prev = h
	}
	if bal.Cmp(amountRaw) < 0 {
		return fmt.Errorf("swapd: insufficient balance %s < %s raw", bal, amountRaw)
	}
	newBal := new(big.Int).Sub(bal, amountRaw)
	if _, err := n.publishState(fromPub, prev, rep, newBal, hex.EncodeToString(destPub), fromSecret, false, "send"); err != nil {
		return fmt.Errorf("swapd: send: %w", err)
	}
	return nil
}

func (n *NanoRPC) publishState(accountPub []byte, previousHex, repAddr string, balance *big.Int, linkHex string, secret *edwards25519.Scalar, opened bool, subtype string) (string, error) {
	repPub, err := DecodeNanoAddress(repAddr)
	if err != nil {
		return "", err
	}
	prev, err := hex.DecodeString(previousHex)
	if err != nil || len(prev) != 32 {
		return "", errors.New("swapd: bad previous hash")
	}
	link, err := hex.DecodeString(linkHex)
	if err != nil || len(link) != 32 {
		return "", errors.New("swapd: bad link")
	}
	// AUDIT FIX: a Nano raw balance is a 128-bit value, so it must fit in 16 bytes.
	// Reject anything wider (negative or >128 bits) here instead of letting
	// nanoStateHash compute make([]byte, 16-len(bal)) with a negative length, which
	// would PANIC. Guarding at the source keeps nanoStateHash's hashing path total.
	if balance.Sign() < 0 || len(balance.Bytes()) > 16 {
		return "", errors.New("swapd: nano balance exceeds 128 bits")
	}
	hash := nanoStateHash(accountPub, prev, repPub, balance, link)
	sig := nanoSign(secret, hash)

	// work is generated on the previous hash (or the account pubkey for an open block).
	workRoot := previousHex
	if opened {
		workRoot = hex.EncodeToString(accountPub)
	}
	work, err := n.generateWork(workRoot, subtype)
	if err != nil {
		return "", err
	}

	acct, _ := EncodeNanoAddress(accountPub)
	block := map[string]any{
		"type":           "state",
		"account":        acct,
		"previous":       strings.ToUpper(previousHex),
		"representative": repAddr,
		"balance":        balance.String(),
		"link":           strings.ToUpper(linkHex),
		"signature":      strings.ToUpper(hex.EncodeToString(sig)),
		"work":           work,
	}
	var res struct {
		Hash string `json:"hash"`
	}
	if err := n.call(n.cfg.URL, map[string]any{"action": "process", "json_block": "true", "subtype": subtype, "block": block}, &res); err != nil {
		return "", err
	}
	if res.Hash == "" {
		return "", errors.New("swapd: process returned no hash")
	}
	return res.Hash, nil
}

// Nano v2 work thresholds: a send/change needs the HIGHER difficulty, a receive/open the
// LOWER one. Passing the wrong (or no) difficulty makes the node return work that `process`
// then rejects as insufficient. (Confirmed against the XNO reference template.)
const (
	nanoSendDifficulty    = "fffffff800000000"
	nanoReceiveDifficulty = "fffffe0000000000"
	// defaultNanoRep is a well-known online representative used when opening an account
	// (matches the XNO template's DEFAULT_REP).
	defaultNanoRep = "nano_3arg3asgtigae3xckabaaewkx3bzsh7nwz7jkmjos79ihyaxwphhm6qgjps4"
)

func (n *NanoRPC) generateWork(rootHex, subtype string) (string, error) {
	difficulty := nanoReceiveDifficulty
	if subtype == "send" || subtype == "change" || subtype == "epoch" {
		difficulty = nanoSendDifficulty
	}
	var res struct {
		Work string `json:"work"`
	}
	if err := n.call(n.cfg.WorkURL, map[string]any{"action": "work_generate", "hash": strings.ToUpper(rootHex), "difficulty": difficulty}, &res); err != nil {
		return "", err
	}
	if res.Work == "" {
		return "", errors.New("swapd: work_generate returned nothing")
	}
	return res.Work, nil
}

// ---- Nano state-block hashing + ed25519-blake2b signature ------------------

// statePreamble is the 32-byte domain separator Nano prepends to every state block hash.
var statePreamble = func() []byte { b := make([]byte, 32); b[31] = 0x06; return b }()

// nanoStateHash computes the 32-byte blake2b hash that a Nano state block is identified and
// signed by: blake2b256(preamble || account || previous || representative || balance16 || link).
func nanoStateHash(account, previous, representative []byte, balance *big.Int, link []byte) []byte {
	h, _ := blake2b.New256(nil)
	h.Write(statePreamble)
	h.Write(account)
	h.Write(previous)
	h.Write(representative)
	// AUDIT FIX: clamp the big-endian balance to its low 16 bytes so 16-len(bal) can
	// never go negative and panic in make(). Callers (publishState) already reject
	// over-128-bit balances; this keeps the hashing primitive itself panic-free.
	bal := balance.Bytes()
	if len(bal) > 16 {
		bal = bal[len(bal)-16:]
	}
	pad := make([]byte, 16-len(bal)) // 128-bit big-endian balance
	h.Write(pad)
	h.Write(bal)
	h.Write(link)
	return h.Sum(nil)
}

// nanoSign produces a Nano ed25519-blake2b signature over msg (the 32-byte block hash) with
// a RAW scalar private key (the joint key s_a+s_b — not a seed-derived expanded key, which
// is why we derive the nonce ourselves). Verifiable by nanoVerify and by Nano nodes, which
// use blake2b as the EdDSA hash. R = r·G; k = blake2b512(R||A||msg) mod L; s = r + k·secret.
func nanoSign(secret *edwards25519.Scalar, msg []byte) []byte {
	A := new(edwards25519.Point).ScalarBaseMult(secret)
	// nonce: blake2b512 over secret || msg || 32 fresh random bytes (hedged determinism),
	// reduced mod L. Randomness avoids catastrophic nonce reuse across two sweep blocks.
	var rnd [32]byte
	_, _ = rand.Read(rnd[:])
	nh, _ := blake2b.New512(nil)
	nh.Write([]byte("obscura/nano-sweep/nonce"))
	nh.Write(secret.Bytes())
	nh.Write(msg)
	nh.Write(rnd[:])
	r, _ := new(edwards25519.Scalar).SetUniformBytes(nh.Sum(nil))
	R := new(edwards25519.Point).ScalarBaseMult(r)

	k := nanoChallenge(R.Bytes(), A.Bytes(), msg)
	s := new(edwards25519.Scalar).Add(r, new(edwards25519.Scalar).Multiply(k, secret))

	out := make([]byte, 64)
	copy(out[:32], R.Bytes())
	copy(out[32:], s.Bytes())
	return out
}

// nanoChallenge = blake2b512(R || A || msg) reduced mod L — Nano's EdDSA hash.
func nanoChallenge(R, A, msg []byte) *edwards25519.Scalar {
	h, _ := blake2b.New512(nil)
	h.Write(R)
	h.Write(A)
	h.Write(msg)
	k, _ := new(edwards25519.Scalar).SetUniformBytes(h.Sum(nil))
	return k
}

// nanoVerify checks a signature as a Nano node would: s·G == R + k·A.
func nanoVerify(pub, msg, sig []byte) bool {
	if len(sig) != 64 || len(pub) != 32 {
		return false
	}
	R, err := new(edwards25519.Point).SetBytes(sig[:32])
	if err != nil {
		return false
	}
	A, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return false
	}
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}
	k := nanoChallenge(sig[:32], pub, msg)
	// s·G - k·A == R   ⇔  VarTimeDoubleScalarBaseMult(-k, A, s) == R
	negK := new(edwards25519.Scalar).Negate(k)
	lhs := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(negK, A, s)
	return lhs.Equal(R) == 1
}

// ---- Nano address codec ----------------------------------------------------

const nanoAlphabet = "13456789abcdefghijkmnopqrstuwxyz"

func nanoDecodeRune(r byte) (int, bool) {
	i := strings.IndexByte(nanoAlphabet, r)
	return i, i >= 0
}

// EncodeNanoAddress turns a 32-byte ed25519 public key into a nano_ address (account +
// 5-byte blake2b checksum), the canonical Nano account encoding.
func EncodeNanoAddress(pub []byte) (string, error) {
	if len(pub) != 32 {
		return "", errors.New("swapd: nano pubkey must be 32 bytes")
	}
	// account: 256 bits padded to 260 (4 leading zero bits) → 52 base32 chars.
	acct := encodeBase32Bits(pub, 52)
	// checksum: blake2b(pub, 5) reversed → 40 bits → 8 base32 chars.
	ck, _ := blake2b.New(5, nil)
	ck.Write(pub)
	cs := ck.Sum(nil)
	for i, j := 0, len(cs)-1; i < j; i, j = i+1, j-1 {
		cs[i], cs[j] = cs[j], cs[i]
	}
	check := encodeBase32Bits(cs, 8)
	return "nano_" + acct + check, nil
}

// DecodeNanoAddress parses a nano_/xrb_ address back to its 32-byte public key, verifying
// the checksum.
func DecodeNanoAddress(addr string) ([]byte, error) {
	a := addr
	switch {
	case strings.HasPrefix(a, "nano_"):
		a = a[5:]
	case strings.HasPrefix(a, "xrb_"):
		a = a[4:]
	default:
		return nil, errors.New("swapd: address must start with nano_ or xrb_")
	}
	if len(a) != 60 {
		return nil, errors.New("swapd: bad nano address length")
	}
	pub, err := decodeBase32Bits(a[:52], 32)
	if err != nil {
		return nil, err
	}
	csBytes, err := decodeBase32Bits(a[52:], 5)
	if err != nil {
		return nil, err
	}
	ck, _ := blake2b.New(5, nil)
	ck.Write(pub)
	want := ck.Sum(nil)
	for i, j := 0, len(want)-1; i < j; i, j = i+1, j-1 {
		want[i], want[j] = want[j], want[i]
	}
	if !bytes.Equal(csBytes, want) {
		return nil, errors.New("swapd: nano address checksum mismatch")
	}
	return pub, nil
}

// encodeBase32Bits encodes data as `chars` Nano-base32 characters, MSB-first, left-padding
// with zero bits to fill the leading characters (Nano pads the 256-bit account to 260 bits).
func encodeBase32Bits(data []byte, chars int) string {
	v := new(big.Int).SetBytes(data)
	out := make([]byte, chars)
	mask := big.NewInt(31)
	tmp := new(big.Int)
	for i := chars - 1; i >= 0; i-- {
		idx := new(big.Int).And(v, mask).Int64()
		out[i] = nanoAlphabet[idx]
		v.Rsh(v, 5)
		_ = tmp
	}
	return string(out)
}

// decodeBase32Bits reverses encodeBase32Bits into a big-endian byte slice of length `byteLen`.
func decodeBase32Bits(s string, byteLen int) ([]byte, error) {
	v := new(big.Int)
	for i := 0; i < len(s); i++ {
		d, ok := nanoDecodeRune(s[i])
		if !ok {
			return nil, fmt.Errorf("swapd: invalid base32 char %q", s[i])
		}
		v.Lsh(v, 5)
		v.Or(v, big.NewInt(int64(d)))
	}
	b := v.Bytes()
	if len(b) > byteLen {
		b = b[len(b)-byteLen:] // drop the leading pad bits
	}
	out := make([]byte, byteLen)
	copy(out[byteLen-len(b):], b)
	return out, nil
}
