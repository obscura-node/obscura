package rpc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"obscura/pkg/block"
	"obscura/pkg/chain"
	"obscura/pkg/group"
	"obscura/pkg/mempool"
	"obscura/pkg/stark"
	"obscura/pkg/swapbook"
	"obscura/pkg/tx"
)

// maxRespBytes bounds how much of a node's HTTP response the client will read,
// so a malicious/compromised node cannot OOM a wallet with a huge body.
const maxRespBytes = 64 << 20 // 64 MiB

// Client talks to a remote node and implements wallet.ChainView.
type Client struct {
	base  string
	http  *http.Client
	g     group.Group
	token string // optional operator bearer token (sent as Authorization: Bearer)
}

// NewClient connects to a node at baseURL (e.g. http://127.0.0.1:18081).
func NewClient(baseURL string) (*Client, error) {
	g, err := chain.NewConfiguredGroup()
	if err != nil {
		return nil, err
	}
	return &Client{
		base: baseURL,
		http: &http.Client{Timeout: 30 * time.Second},
		g:    g,
	}, nil
}

// SetToken arms an operator bearer token, sent as "Authorization: Bearer <tok>"
// on every request. The node's operator endpoints (/blocktemplate, /submitblock,
// ...) admit loopback callers unconditionally but require this token from any
// REMOTE caller (the node's OBX_RPC_TOKEN) — without it a remote miner gets 403.
// Empty tok keeps the old unauthenticated behavior.
func (c *Client) SetToken(tok string) { c.token = tok }

// do sends req with the optional bearer token attached.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return c.http.Do(req)
}

// post issues an authenticated JSON POST to path.
func (c *Client) post(path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

// Group implements wallet.ChainView.
func (c *Client) Group() group.Group { return c.g }

// Height implements wallet.ChainView.
func (c *Client) Height() uint64 {
	var resp struct {
		Height uint64 `json:"height"`
	}
	_ = c.get("/height", &resp)
	return resp.Height
}

// AccValue implements wallet.ChainView.
func (c *Client) AccValue() []byte {
	var resp struct {
		AccValue string `json:"accvalue"`
	}
	if err := c.get("/accvalue", &resp); err != nil {
		return nil
	}
	b, _ := hex.DecodeString(resp.AccValue)
	return b
}

// WitnessFor implements wallet.ChainView.
func (c *Client) WitnessFor(prime []byte) ([]byte, bool) {
	var resp struct {
		Witness string `json:"witness"`
	}
	if err := c.get("/witness?prime="+hex.EncodeToString(prime), &resp); err != nil {
		return nil, false
	}
	b, err := hex.DecodeString(resp.Witness)
	if err != nil || len(b) == 0 {
		return nil, false
	}
	return b, true
}

// Status fetches node status.
func (c *Client) Status() (*StatusResponse, error) {
	var resp StatusResponse
	if err := c.get("/status", &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// BlockTemplate fetches an unmined block (coinbase to `address` + mempool txs)
// for an external miner to grind, plus its difficulty and the per-epoch PoW seed
// to grind under.
func (c *Client) BlockTemplate(address string) (*block.Block, []byte, uint64, error) {
	var resp BlockTemplateResponse
	if err := c.get("/blocktemplate?address="+address, &resp); err != nil {
		return nil, nil, 0, err
	}
	raw, err := hex.DecodeString(resp.Block)
	if err != nil {
		return nil, nil, 0, err
	}
	b, err := block.DeserializeBlock(raw)
	if err != nil {
		return nil, nil, 0, err
	}
	seed, err := hex.DecodeString(resp.Seed)
	if err != nil {
		return nil, nil, 0, err
	}
	return b, seed, resp.Difficulty, nil
}

// SubmitBlock posts a mined block to the node, returning the accepted height.
func (c *Client) SubmitBlock(b *block.Block) (uint64, error) {
	body, _ := json.Marshal(map[string]string{"block": hex.EncodeToString(b.Serialize())})
	r, err := c.post("/submitblock", body)
	if err != nil {
		return 0, err
	}
	defer r.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(r.Body, maxRespBytes))
	if r.StatusCode != 200 {
		return 0, fmt.Errorf("submitblock: %s", string(data))
	}
	var resp struct {
		Height uint64 `json:"height"`
	}
	_ = json.Unmarshal(data, &resp)
	return resp.Height, nil
}

// Peers fetches the node's connected-peer list.
func (c *Client) Peers() (*PeersResponse, error) {
	var resp PeersResponse
	if err := c.get("/peers", &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Mempool fetches a snapshot of the node's pending-transaction pool.
func (c *Client) Mempool() (*mempool.Stats, error) {
	var st mempool.Stats
	if err := c.get("/mempool", &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// FeeRate asks the node for a suggested fee-per-byte to confirm within `target`
// blocks (dynamic fee estimation, Block 20).
func (c *Client) FeeRate(target int) (*FeeRateResponse, error) {
	var resp FeeRateResponse
	if err := c.get(fmt.Sprintf("/feerate?target=%d", target), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// BlockByHeight fetches a block.
func (c *Client) BlockByHeight(h uint64) ([]byte, error) {
	var resp struct {
		Block string `json:"block"`
	}
	if err := c.get(fmt.Sprintf("/block?height=%d", h), &resp); err != nil {
		return nil, err
	}
	return hex.DecodeString(resp.Block)
}

// Headers fetches a range of block headers (parsed) for SPV verification.
func (c *Client) Headers(from, count uint64) ([]block.Header, error) {
	var resp struct {
		Headers []string `json:"headers"`
	}
	if err := c.get(fmt.Sprintf("/headers?from=%d&count=%d", from, count), &resp); err != nil {
		return nil, err
	}
	out := make([]block.Header, 0, len(resp.Headers))
	for _, hh := range resp.Headers {
		raw, err := hex.DecodeString(hh)
		if err != nil {
			return nil, err
		}
		hdr, err := block.ParseHeader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		out = append(out, *hdr)
	}
	return out, nil
}

// SubmitTx sends a transaction to the node.
func (c *Client) SubmitTx(t *tx.Transaction) (string, error) {
	body, _ := json.Marshal(map[string]string{"tx": hex.EncodeToString(t.Serialize())})
	r, err := c.post("/submittx", body)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(r.Body, maxRespBytes))
	if r.StatusCode != 200 {
		return "", fmt.Errorf("submit failed: %s", string(data))
	}
	var resp struct {
		TxID string `json:"txid"`
	}
	_ = json.Unmarshal(data, &resp)
	return resp.TxID, nil
}

// ZKWitnessFor fetches the membership witness for a ZK coin leaf: the epoch anchor,
// the reconstructed authentication path, and the tree depth. ok=false means the leaf
// is not yet in the commitment tree (the mint is unconfirmed or unknown to this node).
func (c *Client) ZKWitnessFor(leaf []byte) (anchor []byte, path stark.MerklePath256, depth int, ok bool) {
	var resp ZKWitnessResponse
	if err := c.get("/zkwitness?leaf="+hex.EncodeToString(leaf), &resp); err != nil {
		return nil, stark.MerklePath256{}, 0, false
	}
	depth = resp.Depth
	if !resp.OK {
		return nil, stark.MerklePath256{}, depth, false
	}
	a, err := hex.DecodeString(resp.Anchor)
	if err != nil {
		return nil, stark.MerklePath256{}, depth, false
	}
	sibs := make([]stark.Node256, 0, len(resp.Path))
	for _, h := range resp.Path {
		nb, err := hex.DecodeString(h)
		if err != nil || len(nb) != 32 {
			return nil, stark.MerklePath256{}, depth, false
		}
		sibs = append(sibs, stark.NodeFromBytes(nb))
	}
	return a, stark.MerklePath256{Index: resp.Index, Siblings: sibs}, depth, true
}

// Offers fetches the swap order book.
func (c *Client) Offers() ([]*swapbook.Offer, error) {
	var resp struct {
		Offers []string `json:"offers"`
	}
	if err := c.get("/offers", &resp); err != nil {
		return nil, err
	}
	out := make([]*swapbook.Offer, 0, len(resp.Offers))
	for _, hh := range resp.Offers {
		raw, err := hex.DecodeString(hh)
		if err != nil {
			return nil, err
		}
		o, err := swapbook.ParseOffer(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

// PostOffer publishes a swap offer to the network.
func (c *Client) PostOffer(o *swapbook.Offer) error {
	body, _ := json.Marshal(map[string]string{"offer": hex.EncodeToString(o.Serialize())})
	r, err := c.post("/offer", body)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		data, _ := io.ReadAll(io.LimitReader(r.Body, maxRespBytes))
		return fmt.Errorf("post offer: %s", string(data))
	}
	return nil
}

func (c *Client) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	r, err := c.do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		data, _ := io.ReadAll(io.LimitReader(r.Body, maxRespBytes))
		return fmt.Errorf("rpc %s: %s", path, string(data))
	}
	return json.NewDecoder(io.LimitReader(r.Body, maxRespBytes)).Decode(out)
}
