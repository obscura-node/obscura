package p2p

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// Dialer abstracts how the node makes OUTBOUND connections, so the same gossip
// logic runs over clearnet TCP or over Tor (a local SOCKS5 proxy). This gives
// optional network-layer anonymity (hiding the node's IP) on top of the
// Dandelion++ transaction-origin privacy.
type Dialer interface {
	Dial(addr string) (net.Conn, error)
}

// clearnetDialer is the default: plain TCP with a timeout.
type clearnetDialer struct{ timeout time.Duration }

func (d clearnetDialer) Dial(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, d.timeout)
}

// torDialer routes every outbound connection through a local Tor SOCKS5 proxy
// (so peers and observers never see the node's real IP, and .onion peers are
// reachable).
//
// STREAM ISOLATION (P2P robustness / privacy hardening): every Dial presents a
// FRESH, random SOCKS5 username/password. Tor's default IsolateSOCKSAuth flag
// puts streams with different SOCKS credentials on DIFFERENT circuits, so each
// peer connection gets its own Tor circuit — one hostile/observed exit or a
// single circuit-level adversary can no longer correlate all of this node's
// peer links (the standard per-peer isolation technique, e.g. Bitcoin Core's
// -proxyrandomize). Tor daemons ignore unneeded auth, so this is a no-op where
// isolation is off. The credentials are never reused and carry no identity.
type torDialer struct {
	socksAddr string
	timeout   time.Duration
}

// isolationAuth mints single-use random SOCKS5 credentials for one dial.
func isolationAuth() (*proxy.Auth, error) {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		return nil, fmt.Errorf("p2p: tor isolation auth: %w", err)
	}
	return &proxy.Auth{
		User:     hex.EncodeToString(b[:8]),
		Password: hex.EncodeToString(b[8:]),
	}, nil
}

func (t torDialer) Dial(addr string) (net.Conn, error) {
	auth, err := isolationAuth()
	if err != nil {
		return nil, err
	}
	// A per-dial SOCKS5 client: hostname resolution is delegated to Tor
	// (proxy.SOCKS5 sends the host to the proxy), so there is no local DNS leak.
	d, err := proxy.SOCKS5("tcp", t.socksAddr, auth, &net.Dialer{Timeout: t.timeout})
	if err != nil {
		return nil, err
	}
	return d.Dial("tcp", addr)
}

// NewTorDialer builds a Dialer that connects through the Tor SOCKS5 proxy at
// socksAddr (typically 127.0.0.1:9050), with per-peer stream isolation (see
// torDialer).
func NewTorDialer(socksAddr string) (Dialer, error) {
	if _, _, err := net.SplitHostPort(socksAddr); err != nil {
		return nil, fmt.Errorf("p2p: bad tor socks address %q: %w", socksAddr, err)
	}
	return torDialer{socksAddr: socksAddr, timeout: 20 * time.Second}, nil
}

// SetTransport configures the outbound dialer and the address this node
// advertises to peers (for Tor, the node's .onion address; for clearnet, its
// reachable host:port). Call before Start. Passing dialer=nil keeps clearnet.
// When onionOnly is true (Tor mode), the node FAILS CLOSED on the address layer:
// it only stores/relays .onion peer addresses, never mixing clearnet peers into
// the anonymity set (per the engine's pitfall #2).
func (n *Node) SetTransport(dialer Dialer, advertiseAddr string, onionOnly bool) {
	if dialer != nil {
		n.dialer = dialer
	}
	n.advMu.Lock()
	n.advertiseAddr = advertiseAddr
	n.advertiseFixed = true // a Tor .onion address is fixed — never auto-overridden
	n.advMu.Unlock()
	n.onionOnly = onionOnly
}

// isOnion reports whether addr is a Tor hidden-service address.
func isOnion(addr string) bool {
	h := addr
	if host, _, err := net.SplitHostPort(addr); err == nil {
		h = host
	}
	return strings.HasSuffix(h, ".onion")
}

// maybeAddAddr records a learned peer address, dropping clearnet addresses when
// the node is in onion-only (Tor) mode.
func (n *Node) maybeAddAddr(addr string) {
	if n.onionOnly && !isOnion(addr) {
		return // fail closed: never mix clearnet peers into the Tor anonymity set
	}
	if !n.onionOnly && !isRoutable(addr) {
		return // never store/share an undialable address (0.0.0.0 etc.) via PEX
	}
	// Never store OUR OWN public address: it echoes back via PEX, and keeping it in the
	// book leads to self-dials (slots/sync wasted on a self-loop instead of real peers).
	n.advMu.RLock()
	self := n.advertiseAddr
	n.advMu.RUnlock()
	if addr == self || addr == n.addr {
		return
	}
	// A loopback address on OUR OWN listen port is US: dialing it SUCCEEDS (we accept
	// our own connection), so the book's dial-failure eviction never fires and the node
	// wedges itself in a self-gossip loop (live incident 2026-07-04: a peer PEX-gossiped
	// "127.0.0.1:18080" and every network node began dialing itself). Loopback on OTHER
	// ports stays permitted so multi-node local devnets keep working.
	if n.isSelfLoopback(addr) {
		return
	}
	n.book.Add(addr)
}

// isSelfLoopback reports whether addr is a loopback host with our own listen port —
// an address that can only ever reach ourselves (see maybeAddAddr).
func (n *Node) isSelfLoopback(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return false
	}
	_, ownPort, err := net.SplitHostPort(n.addr)
	return err == nil && port == ownPort
}

// KnownAddresses returns the addresses currently in the peer address book
// (primarily for tests / introspection).
func (n *Node) KnownAddresses() []string { return n.book.Sample(1 << 16) }
