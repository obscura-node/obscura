// Package nanorpc is the ISOLATED, SECRET-FREE layer that communicates with a
// Nano (XNO) node's JSON-RPC for the swap path. It is the single place the node
// talks to the Nano network: read account/block state, generate work, and
// PUBLISH already-signed blocks.
//
// It deliberately holds NO private keys and performs NO signing. Signing happens
// elsewhere — for the non-custodial swap, in the browser (WASM) via pkg/nanocrypto
// — and a fully-formed signature is handed to PublishState, which only assembles
// the wire block, attaches proof-of-work, and submits it via `process`. This
// keeps custody out of the backend entirely: the node relays, it never spends.
//
// This package is additive. It does NOT replace pkg/swapd's in-tree NanoRPC (the
// proven node-operator client stays exactly as-is); it exists so the browser's
// signed blocks have a clean, key-free path onto the Nano ledger.
package nanorpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"obscura/pkg/nanocrypto"
)

// Config is everything needed to reach a Nano RPC. All of it is operator-provided
// (flag/env) — nanorpc never invents an endpoint.
type Config struct {
	URL        string        // REQUIRED: the Nano node RPC endpoint
	AuthHeader string        // optional: Authorization header value (hosted nodes)
	WorkURL    string        // optional: separate work_generate endpoint (defaults to URL)
	Timeout    time.Duration // optional: per-request timeout for READS (account_info/pending/block_info/process), default 20s
	// WorkTimeout is the per-request timeout for work_generate specifically.
	// work_generate is genuinely compute-bound (real proof-of-work), not just a
	// network round trip, so it needs materially more slack than a read — a
	// real incident: a single shared short timeout (tuned for "reads answer in
	// well under a second") made ordinary, successful work_generate calls fail
	// with "context deadline exceeded", killing real swaps that would otherwise
	// have completed a few seconds later. Defaults to Timeout if unset (so
	// existing single-timeout callers keep their prior behavior).
	WorkTimeout time.Duration
}

// endpoint is one resolved Nano RPC in the failover chain.
type endpoint struct {
	url     string
	workURL string
	auth    string
}

// Client is a secret-free Nano RPC client with ORDERED FAILOVER across a list of
// endpoints: a read/process call tries each endpoint's URL in turn, and
// work_generate tries each endpoint's work URL in turn. A transport failure
// (timeout, unreachable, 5xx) advances to the next endpoint; a Nano
// {"error":...} envelope is a real answer and is returned immediately (no
// failover). Safe to share across goroutines.
//
// The endpoint LIST is supplied by the caller — nanorpc hardcodes no third-party
// URL. The node passes the SAME list it uses itself (swapd.PublicNanoRPCs:
// rainstorm → somenano → nanoto, with work routed to rainstorm), so the browser
// swap relay fails over across exactly the node's curated Nano endpoints.
type Client struct {
	eps    []endpoint
	hc     *http.Client // reads: account_info/pending/block_info/process
	hcWork *http.Client // work_generate — genuinely compute-bound, needs more slack
}

// New builds a single-endpoint client. A non-empty URL is REQUIRED.
func New(cfg Config) (*Client, error) { return NewMulti([]Config{cfg}) }

// NewMulti builds a client that fails over across cfgs IN ORDER (first = primary).
// Empty-URL configs are skipped; at least one usable URL is REQUIRED.
func NewMulti(cfgs []Config) (*Client, error) {
	timeout := 20 * time.Second
	workTimeout := timeout
	var eps []endpoint
	for _, cfg := range cfgs {
		if strings.TrimSpace(cfg.URL) == "" {
			continue
		}
		work := cfg.WorkURL
		if work == "" {
			work = cfg.URL
		}
		eps = append(eps, endpoint{url: cfg.URL, workURL: work, auth: cfg.AuthHeader})
		if cfg.Timeout > 0 {
			timeout = cfg.Timeout
			workTimeout = cfg.Timeout // default: same as reads unless WorkTimeout overrides below
		}
		if cfg.WorkTimeout > 0 {
			workTimeout = cfg.WorkTimeout
		}
	}
	if len(eps) == 0 {
		return nil, errors.New("nanorpc: at least one endpoint URL is required (operator-provided; never hardcoded)")
	}
	return &Client{eps: eps, hc: &http.Client{Timeout: timeout}, hcWork: &http.Client{Timeout: workTimeout}}, nil
}

// ---- JSON-RPC plumbing (secret-free, with failover) ------------------------

// attemptsPerEndpoint rides out a transient flake before failing over (public
// Nano RPCs time out under load). With multiple endpoints this is kept low since
// failover provides the redundancy; a lone endpoint still gets a few tries.
func (c *Client) attemptsPerEndpoint() int {
	if len(c.eps) == 1 {
		return 3
	}
	return 2
}

// callRead issues a read/process call, trying each endpoint URL in order.
func (c *Client) callRead(req map[string]any, out any) error {
	var lastErr error
	for _, ep := range c.eps {
		for attempt := 0; attempt < c.attemptsPerEndpoint(); attempt++ {
			err := c.callOnce(c.hc, ep.url, ep.auth, req, out)
			if err == nil {
				return nil
			}
			if strings.Contains(err.Error(), "nano rpc error:") {
				return err // node answered with an error envelope — real, not transient
			}
			lastErr = err
		}
	}
	return lastErr
}

// callWork issues a work_generate call, trying each endpoint's work URL in order
// (deduplicated — several endpoints often share one work provider, e.g.
// rainstorm). Uses hcWork (a longer timeout): work_generate is genuine
// proof-of-work computation, not just a network round trip, so it needs more
// slack than a plain read before being judged dead.
func (c *Client) callWork(req map[string]any, out any) error {
	var lastErr error
	seen := make(map[string]bool)
	for _, ep := range c.eps {
		if seen[ep.workURL] {
			continue
		}
		seen[ep.workURL] = true
		for attempt := 0; attempt < c.attemptsPerEndpoint(); attempt++ {
			err := c.callOnce(c.hcWork, ep.workURL, ep.auth, req, out)
			if err == nil {
				return nil
			}
			if strings.Contains(err.Error(), "nano rpc error:") {
				return err
			}
			lastErr = err
		}
	}
	return lastErr
}

func (c *Client) callOnce(hc *http.Client, url, auth string, req map[string]any, out any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if auth != "" {
		httpReq.Header.Set("Authorization", auth)
	}
	resp, err := hc.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("nanorpc: http status %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, 1<<20) // 1 MiB cap — far larger than any real reply
	var generic map[string]json.RawMessage
	if err := json.NewDecoder(limited).Decode(&generic); err != nil {
		return err
	}
	if e, ok := generic["error"]; ok {
		var msg string
		_ = json.Unmarshal(e, &msg)
		return fmt.Errorf("nanorpc: nano rpc error: %s", msg)
	}
	if out != nil {
		b, _ := json.Marshal(generic)
		return json.Unmarshal(b, out)
	}
	return nil
}

// ---- reads -----------------------------------------------------------------

// Version pings the node (connectivity check at startup). Returns the vendor string.
func (c *Client) Version() (string, error) {
	var res struct {
		NodeVendor string `json:"node_vendor"`
		RPCVersion string `json:"rpc_version"`
	}
	if err := c.callRead(map[string]any{"action": "version"}, &res); err != nil {
		return "", err
	}
	v := strings.TrimSpace(res.NodeVendor + " " + res.RPCVersion)
	if v == "" {
		v = "unknown"
	}
	return v, nil
}

// AccountInfo is the subset of `account_info` the swap path needs to build the
// next state block for an account. Opened is false for an account that has no
// blocks yet (Nano returns "Account not found").
type AccountInfo struct {
	Frontier       string   // 64-hex hash of the head block ("" if unopened)
	Representative string   // nano_ representative ("" if unopened)
	Balance        *big.Int // confirmed balance, full 128-bit raw (0 if unopened)
	Opened         bool
}

// AccountInfo reads an account's frontier/representative/balance. A not-found
// account returns Opened=false with zero balance and NO error (it is the normal
// state of an account that has only receivables).
func (c *Client) AccountInfo(account string) (AccountInfo, error) {
	var res struct {
		Frontier       string `json:"frontier"`
		Representative string `json:"representative"`
		Balance        string `json:"balance"`
		Error          string `json:"error"`
	}
	err := c.callRead(map[string]any{"action": "account_info", "account": account, "representative": "true"}, &res)
	if err != nil {
		// "Account not found" is surfaced by call() as an error envelope; treat it
		// as the unopened state, not a transport failure.
		if strings.Contains(err.Error(), "Account not found") {
			return AccountInfo{Balance: new(big.Int)}, nil
		}
		return AccountInfo{Balance: new(big.Int)}, err
	}
	bal := new(big.Int)
	if res.Balance != "" {
		bal, _ = new(big.Int).SetString(res.Balance, 10)
	}
	return AccountInfo{
		Frontier:       res.Frontier,
		Representative: res.Representative,
		Balance:        bal,
		Opened:         res.Frontier != "",
	}, nil
}

// BlockInfo is the authoritative on-ledger view of a block, used to verify a lock.
type BlockInfo struct {
	Amount        *big.Int // value transferred, full 128-bit raw
	Subtype       string
	LinkHex       string // raw 64-hex link (destination pubkey for a send)
	LinkAsAccount string // nano_ form of the link
	Confirmed     bool
}

// BlockInfo reads a block by hash.
func (c *Client) BlockInfo(hash string) (BlockInfo, error) {
	var res struct {
		Amount    string `json:"amount"`
		Subtype   string `json:"subtype"`
		Confirmed string `json:"confirmed"`
		Contents  struct {
			Link          string `json:"link"`
			LinkAsAccount string `json:"link_as_account"`
		} `json:"contents"`
	}
	if err := c.callRead(map[string]any{"action": "block_info", "hash": hash, "json_block": "true"}, &res); err != nil {
		return BlockInfo{}, err
	}
	amt := new(big.Int)
	if res.Amount != "" {
		amt, _ = new(big.Int).SetString(strings.TrimSpace(res.Amount), 10)
		if amt == nil {
			amt = new(big.Int)
		}
	}
	return BlockInfo{
		Amount:        amt,
		Subtype:       res.Subtype,
		LinkHex:       strings.TrimSpace(res.Contents.Link),
		LinkAsAccount: strings.TrimSpace(res.Contents.LinkAsAccount),
		Confirmed:     res.Confirmed == "true",
	}, nil
}

// Confirmed reports whether a block is cemented (irreversible).
func (c *Client) Confirmed(hash string) bool {
	bi, err := c.BlockInfo(hash)
	return err == nil && bi.Confirmed
}

// Receivable returns the LARGEST pending block sending funds to account, with its
// raw amount as a decimal string (full 128-bit precision). ok=false if none.
func (c *Client) Receivable(account string) (blockHash, amountRaw string, ok bool) {
	var res struct {
		Blocks map[string]string `json:"blocks"`
	}
	// "threshold" (not "source") so the node returns a {hash: amountRaw} map.
	// threshold "1" raw = detect ANY non-zero amount (down to 1e-30 XNO, so dust
	// like 0.000000001 XNO is surfaced). include_only_confirmed=false so a deposit
	// is detected the instant the network sees it, not only after confirmation
	// (small XNO sends confirm slower) — the funding box updates immediately.
	if err := c.callRead(map[string]any{
		"action":                 "receivable",
		"account":                account,
		"count":                  "10",
		"threshold":              "1",
		"include_only_confirmed": "false",
	}, &res); err != nil {
		return "", "", false
	}
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

// Balance returns the confirmed balance (full 128-bit raw) of an account; 0 if
// missing/unreadable.
func (c *Client) Balance(account string) *big.Int {
	info, err := c.AccountInfo(account)
	if err != nil || info.Balance == nil {
		return new(big.Int)
	}
	return info.Balance
}

// WorkGenerate asks the (work) endpoint for proof-of-work over rootHex at the
// difficulty appropriate for subtype. No secret involved.
func (c *Client) WorkGenerate(rootHex, subtype string) (string, error) {
	difficulty := nanocrypto.ReceiveDifficulty
	if subtype == "send" || subtype == "change" || subtype == "epoch" {
		difficulty = nanocrypto.SendDifficulty
	}
	var res struct {
		Work string `json:"work"`
	}
	if err := c.callWork(map[string]any{"action": "work_generate", "hash": strings.ToUpper(rootHex), "difficulty": difficulty}, &res); err != nil {
		return "", err
	}
	if res.Work == "" {
		return "", errors.New("nanorpc: work_generate returned nothing")
	}
	return res.Work, nil
}

// ---- publish (the secret-free half of a send/receive) ----------------------

// StateBlock carries all the fields of a Nano state block plus an EXTERNALLY
// COMPUTED signature. nanorpc NEVER signs: the caller (the browser, via
// nanocrypto.StateHash + nanocrypto.Sign) computes Signature over the canonical
// block hash and hands it here only to be worked and published.
type StateBlock struct {
	AccountPub  []byte   // 32B account public key
	PreviousHex string   // 64-hex frontier, or 64 zeros for an open block
	RepAddr     string   // nano_ representative
	Balance     *big.Int // resulting balance, raw (≤128 bits)
	LinkHex     string   // 64-hex: source hash (receive) or dest pubkey (send)
	Signature   []byte   // 64B ed25519-blake2b signature over the block hash
	Subtype     string   // send | receive | open | change
	Opened      bool     // true ⇒ this is the account's first block (work root = account pub)
}

// PublishState assembles the wire block from a StateBlock + its provided
// signature, generates work, and submits it via `process`. It validates only
// shapes (lengths, balance width) — it does NOT re-derive or verify the
// signature; that is the signer's responsibility, and a wrong signature is
// rejected by the Nano node itself. Returns the published block hash.
func (c *Client) PublishState(b StateBlock) (string, error) {
	if len(b.AccountPub) != 32 {
		return "", errors.New("nanorpc: account pub must be 32 bytes")
	}
	if len(b.Signature) != 64 {
		return "", errors.New("nanorpc: signature must be 64 bytes")
	}
	if b.Balance == nil || b.Balance.Sign() < 0 || len(b.Balance.Bytes()) > 16 {
		return "", errors.New("nanorpc: balance must be a non-negative ≤128-bit raw value")
	}
	if prev, err := hex.DecodeString(b.PreviousHex); err != nil || len(prev) != 32 {
		return "", errors.New("nanorpc: previous must be 64 hex chars")
	}
	if link, err := hex.DecodeString(b.LinkHex); err != nil || len(link) != 32 {
		return "", errors.New("nanorpc: link must be 64 hex chars")
	}
	acct, err := nanocrypto.EncodeAddress(b.AccountPub)
	if err != nil {
		return "", err
	}
	// validate the representative address up front (a bad rep would be rejected by
	// the node anyway, but failing here gives a clearer error).
	if _, err := nanocrypto.DecodeAddress(b.RepAddr); err != nil {
		return "", fmt.Errorf("nanorpc: bad representative: %w", err)
	}

	workRoot := b.PreviousHex
	if b.Opened {
		workRoot = hex.EncodeToString(b.AccountPub)
	}
	work, err := c.WorkGenerate(workRoot, b.Subtype)
	if err != nil {
		return "", err
	}

	block := map[string]any{
		"type":           "state",
		"account":        acct,
		"previous":       strings.ToUpper(b.PreviousHex),
		"representative": b.RepAddr,
		"balance":        b.Balance.String(),
		"link":           strings.ToUpper(b.LinkHex),
		"signature":      strings.ToUpper(hex.EncodeToString(b.Signature)),
		"work":           work,
	}
	var res struct {
		Hash string `json:"hash"`
	}
	if err := c.callRead(map[string]any{"action": "process", "json_block": "true", "subtype": b.Subtype, "block": block}, &res); err != nil {
		return "", err
	}
	if res.Hash == "" {
		return "", errors.New("nanorpc: process returned no hash")
	}
	return res.Hash, nil
}
