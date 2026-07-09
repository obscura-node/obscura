package p2p

import (
	"encoding/json"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"
)

// AddrBook is a simple peer-address store enabling auto-discovery (no manual
// seeds needed after the first contact). Addresses are learned via PEX
// (getaddr/addr) and persisted so a node can reconnect after restart without
// depending solely on bootstrap seeds. It tracks last-seen and failure counts
// and enforces per-IP-group (/16) caps + group-diverse peer selection to resist
// ECLIPSE attacks (an attacker flooding the book with one IP range to monopolize a
// victim's connections, isolate it, and feed it a false chain). See maxPerGroup / Sample.
type AddrBook struct {
	mu     sync.Mutex
	addrs  map[string]*addrInfo
	groups map[string]int   // count of addresses per IP group (/16) — eclipse defense
	sticky map[string]bool  // bootstrap addrs that must never be evicted (seeds + known peers)
	path   string
}

// Size returns the number of distinct known addresses (the PEX view of network
// breadth). Used by the explorer's node-count widget.
func (ab *AddrBook) Size() int {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	return len(ab.addrs)
}

// AllUnreachable reports whether the book holds NO address that was ever
// successfully contacted or is still untried — i.e. every known address
// (including all configured seeds) has only ever failed, or the book is empty.
// Drives the operator "cannot bootstrap" warning; an untried address (Fails==0,
// LastSeen==0) keeps this false so the warning never fires before the first
// dial attempts have actually failed.
func (ab *AddrBook) AllUnreachable() bool {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	for _, a := range ab.addrs {
		if a.LastSeen > 0 || a.Fails == 0 {
			return false
		}
	}
	return true
}

// ipGroup returns the network group an address belongs to (/16 for IPv4, /32 for
// IPv6), so the book can bound how many addresses any single network contributes —
// the core defense against an attacker who floods the book with one IP range to
// eclipse a node. Non-IP hosts (e.g. .onion) group by host string.
func ipGroup(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host // .onion / hostname — its own group
	}
	if v4 := ip.To4(); v4 != nil {
		return "4:" + string([]byte{v4[0], v4[1]}) // /16
	}
	return "6:" + string(ip[:4]) // IPv6 /32
}

type addrInfo struct {
	Addr     string `json:"addr"`
	LastSeen int64  `json:"last_seen"`
	Fails    int    `json:"fails"`
}

// NewAddrBook loads (or creates) an address book persisted at path. An empty
// path keeps it in memory only.
func NewAddrBook(path string) *AddrBook {
	ab := &AddrBook{addrs: make(map[string]*addrInfo), groups: make(map[string]int), sticky: make(map[string]bool), path: path}
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			var list []*addrInfo
			if json.Unmarshal(data, &list) == nil {
				for _, a := range list {
					// re-apply the per-group cap on load (a persisted book could have been
					// poisoned by an older version without the cap).
					if g := ipGroup(a.Addr); ab.groups[g] < maxPerGroup {
						ab.addrs[a.Addr] = a
						ab.groups[g]++
					}
				}
			}
		}
	}
	return ab
}

// Add records a peer address (deduplicated). Invalid host:port strings are
// ignored. Caps the book to bound memory (anti-poisoning).
func (ab *AddrBook) Add(addr string) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return
	}
	ab.mu.Lock()
	defer ab.mu.Unlock()
	if len(ab.addrs) >= maxAddrBook {
		return
	}
	if _, ok := ab.addrs[addr]; ok {
		return
	}
	g := ipGroup(addr)
	if ab.groups[g] >= maxPerGroup {
		return // ECLIPSE DEFENSE: one network can't flood the book with addresses
	}
	ab.addrs[addr] = &addrInfo{Addr: addr}
	ab.groups[g]++
}

// AddSticky records a BOOTSTRAP address that must never be evicted by the failure
// counter — configured seeds and known old/community peers. Effect: the node keeps
// these in its address book across restarts AND runtime failures, so it re-dials them
// on every start and after a partition instead of forgetting them once they fail
// maxAddrFails times. Sticky addrs bypass the size/group caps because they are
// operator-provided bootstrap (not attacker-gossiped), so they cannot be abused for
// eclipse flooding; group-diverse Sample() still governs the actual dial set.
func (ab *AddrBook) AddSticky(addr string) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return
	}
	ab.mu.Lock()
	defer ab.mu.Unlock()
	ab.sticky[addr] = true
	if _, ok := ab.addrs[addr]; !ok {
		ab.addrs[addr] = &addrInfo{Addr: addr}
		ab.groups[ipGroup(addr)]++
	}
}

// Seen marks an address as successfully contacted.
func (ab *AddrBook) Seen(addr string) {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	if a, ok := ab.addrs[addr]; ok {
		a.LastSeen = time.Now().Unix()
		a.Fails = 0
		return
	}
	g := ipGroup(addr)
	if len(ab.addrs) >= maxAddrBook || ab.groups[g] >= maxPerGroup {
		return
	}
	ab.addrs[addr] = &addrInfo{Addr: addr, LastSeen: time.Now().Unix()}
	ab.groups[g]++
}

// Failed increments an address's failure count and evicts after too many.
func (ab *AddrBook) Failed(addr string) {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	if a, ok := ab.addrs[addr]; ok {
		a.Fails++
		// Sticky bootstrap addresses (seeds + known old/community peers) are NEVER
		// evicted — the node keeps retrying them so it can rejoin after a partition.
		if a.Fails > maxAddrFails && !ab.sticky[addr] {
			delete(ab.addrs, addr)
			if g := ipGroup(addr); ab.groups[g] > 0 {
				ab.groups[g]--
			}
		}
	}
}

// Sample returns up to n known addresses chosen with IP-GROUP DIVERSITY: it buckets
// by network group and round-robins across groups, so the returned set spans many
// networks. This is the decisive eclipse defense — applied where it matters most (peer
// selection) — so an attacker controlling a few IP ranges cannot dominate a node's dial
// set even if it managed to seed several addresses into the book.
func (ab *AddrBook) Sample(n int) []string {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	byGroup := make(map[string][]string)
	order := make([]string, 0)
	for a := range ab.addrs {
		g := ipGroup(a)
		if _, ok := byGroup[g]; !ok {
			order = append(order, g)
		}
		byGroup[g] = append(byGroup[g], a)
	}
	rand.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	for g := range byGroup {
		l := byGroup[g]
		rand.Shuffle(len(l), func(i, j int) { l[i], l[j] = l[j], l[i] })
	}
	out := make([]string, 0, n)
	for round := 0; len(out) < n; round++ {
		progressed := false
		for _, g := range order {
			if round < len(byGroup[g]) {
				out = append(out, byGroup[g][round])
				progressed = true
				if len(out) >= n {
					return out
				}
			}
		}
		if !progressed {
			break
		}
	}
	return out
}

// RecentlySeen returns addresses that were SUCCESSFULLY contacted within the last
// withinSec seconds — the "latest connected" peers. The reconnect sweep uses this to
// proactively re-dial peers that dropped or went offline, so the node rejoins its
// last-known-good set after a transient partition or a peer restart, without waiting
// for the peer-count target.
func (ab *AddrBook) RecentlySeen(withinSec int64) []string {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	cutoff := time.Now().Unix() - withinSec
	out := make([]string, 0)
	for a, info := range ab.addrs {
		if info.LastSeen >= cutoff {
			out = append(out, a)
		}
	}
	return out
}

// Save persists the address book.
func (ab *AddrBook) Save() {
	if ab.path == "" {
		return
	}
	ab.mu.Lock()
	list := make([]*addrInfo, 0, len(ab.addrs))
	for _, a := range ab.addrs {
		list = append(list, a)
	}
	ab.mu.Unlock()
	if data, err := json.Marshal(list); err == nil {
		_ = os.WriteFile(ab.path, data, 0600)
	}
}

const (
	maxAddrBook  = 4096
	maxAddrFails = 10
	// maxPerGroup bounds how many addresses a single IP group (/16) may contribute to
	// the book, so one attacker network cannot fill it (eclipse defense). Combined with
	// group-diverse Sample(), an attacker's few groups can occupy at most a small,
	// bounded share of a node's dial set.
	maxPerGroup = 32
)
