//go:build !protopow

// Canonical RandomX PoW backend (Monero-compatible), wired via the pure-Go
// P2Pool port git.gammaspectra.live/P2Pool/go-randomx (no cgo, so cross-compiles
// to a static .exe like the rest of Obscura). This is the DEFAULT backend (built
// when no tags are given); pass `-tags protopow` only to select the insecure
// prototype VM for fast dev/test.
//
// The per-epoch consensus seed (config.PoWSeedHeight / chain.PoWSeed) is used
// directly as the RandomX cache KEY, so Obscura's epoch seed rotation IS RandomX's
// reseed. Output is byte-identical to reference RandomX (verified by the official
// known-answer vectors in randomx_kat_test.go).
package pow

import (
	"sync"

	rx "git.gammaspectra.live/P2Pool/go-randomx/v3"
)

// BackendName identifies the active PoW backend (logged at node startup).
const BackendName = "randomx-canonical"

// maxRxCaches bounds how many seed-keyed RandomX caches are kept live (epoch
// rotation only needs the current + adjacent epochs around a boundary). Each
// cache is ~256 MiB; evicted caches are dropped and reclaimed by the GC (we do
// NOT Close() them, so a cache still in use by a VM on another goroutine is never
// freed out from under it).
const maxRxCaches = 3

type rxCacheEntry struct {
	key   string
	cache *rx.Cache
}

var (
	rxbMu     sync.Mutex
	rxbCaches []*rxCacheEntry
)

// rxCacheFor returns the RandomX cache keyed by the per-epoch seed, building it
// (a ~256 MiB Argon2d fill) on first use and memoizing it for the epoch. The
// cache is read-only after Init, so many VMs across goroutines share it safely.
func rxCacheFor(seed []byte) *rx.Cache {
	key := string(seed)
	rxbMu.Lock()
	defer rxbMu.Unlock()
	for i, e := range rxbCaches {
		if e.key == key {
			rxbCaches = append(rxbCaches[:i], rxbCaches[i+1:]...)
			rxbCaches = append([]*rxCacheEntry{e}, rxbCaches...)
			return e.cache
		}
	}
	c, err := rx.NewCache(rx.Flags(0)) // interpreter, light mode (portable, deterministic)
	if err != nil {
		panic("randomx: NewCache: " + err.Error())
	}
	c.Init(seed)
	e := &rxCacheEntry{key: key, cache: c}
	rxbCaches = append([]*rxCacheEntry{e}, rxbCaches...)
	if len(rxbCaches) > maxRxCaches {
		rxbCaches = rxbCaches[:maxRxCaches] // drop LRU tail; GC reclaims it
	}
	return c
}

// backendHash computes a canonical RandomX hash under the given seed. A fresh VM
// (light mode, shared cache) is created per call, so it is safe for concurrent
// use without locking the hot path.
func backendHash(seed, input []byte) [32]byte {
	cache := rxCacheFor(seed)
	vm, err := rx.NewVM(rx.Flags(0), cache, nil)
	if err != nil {
		panic("randomx: NewVM: " + err.Error())
	}
	defer vm.Close()
	var out [32]byte
	vm.CalculateHash(input, &out)
	return out
}
