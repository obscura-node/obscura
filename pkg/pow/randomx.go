// RandomX-style virtual-machine proof-of-work (pure Go, deterministic).
//
// This implements the ARCHITECTURE that gives RandomX its ASIC resistance —
// a memory-hard seeded cache, a per-nonce random-access scratchpad, and a
// randomized register VM mixing integer, floating-point, and memory operations —
// rather than a byte-for-byte reimplementation of Monero's RandomX (which is a
// large, consensus-critical spec with its own dataset/AES/test-vector
// requirements). It is NOT interchange-compatible with Monero RandomX; it is a
// self-contained, dependency-light PoW for Obscura whose properties (latency-
// bound memory access + branchy float/int code that differs every nonce) deny
// ASICs and GPUs the efficiency edge that simple hashes give them.
//
// Determinism: only IEEE-754 +,-,*,/ and correctly-rounded sqrt are used (no FMA,
// no transcendentals), and all values are bit-masked to stay finite, so the hash
// is identical across amd64/arm64 and every node.
//
// To adopt canonical Monero-compatible RandomX later, replace Hash()'s body with
// a binding to a vetted RandomX implementation; the consensus interface
// (Hash/Meets/Target) is unchanged.
package pow

import (
	"encoding/binary"
	"math"
	"math/bits"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
)

// RandomX VM parameters (vars so tests/regtest can shrink them for speed).
// Production should raise these via a network upgrade (e.g. scratchpad 2 MiB,
// cache 256 MiB, iterations 2048) for strong ASIC resistance.
var (
	RxScratchKiB  = 64  // per-nonce random-access scratchpad (prototype)
	RxCacheKiB    = 256 // shared seed-derived cache (Argon2d-hard to build)
	RxProgramSize = 64  // instructions per generated program
	RxIterations  = 256 // VM execution rounds per hash
)

// SeedKey is the default cache seed used by Hash() (and the standalone pow tests).
// Consensus PoW passes an explicit per-epoch seed via HashSeed(); see
// config.PoWSeedHeight and chain.PoWSeed for the epoch-rotation derivation.
var SeedKey = []byte("Obscura/RandomX/seed/v1")

// MaxCachedSeeds bounds how many seed-keyed caches are kept (epoch rotation only
// ever needs the current and adjacent epochs around a boundary).
const MaxCachedSeeds = 4

// memoized caches keyed by seed+size. Each cache is read-only after build, so it
// is safe to share across mining/validation goroutines.
type cacheEntry struct {
	sig string
	buf []uint64
}

var (
	rxMu     sync.Mutex
	rxCaches []*cacheEntry
)

// cache returns the seed-derived cache for `seed`, building it on first use. The
// build runs Argon2d over RxCacheKiB of memory, so producing the cache is itself
// memory-hard (an ASIC must also pay that cost). Caches rotate with the epoch
// seed; a small LRU keeps the few that are live around a boundary.
func cache(seed []byte) []uint64 {
	sig := string(seed) + "|" + string(rune(RxCacheKiB))
	rxMu.Lock()
	defer rxMu.Unlock()
	for i, e := range rxCaches {
		if e.sig == sig {
			// move to front (most-recently-used)
			rxCaches = append(rxCaches[:i], rxCaches[i+1:]...)
			rxCaches = append([]*cacheEntry{e}, rxCaches...)
			return e.buf
		}
	}
	n := RxCacheKiB * 1024 / 8
	if n < 8 {
		n = 8
	}
	buf := make([]uint64, n)
	kdf := argon2.IDKey(seed, []byte("Obscura/RandomX/cache"), 1, uint32(RxCacheKiB), 1, 64)
	fillU64(buf, kdf)
	e := &cacheEntry{sig: sig, buf: buf}
	rxCaches = append([]*cacheEntry{e}, rxCaches...)
	if len(rxCaches) > MaxCachedSeeds {
		rxCaches = rxCaches[:MaxCachedSeeds]
	}
	return buf
}

// fillU64 deterministically fills dst with a BLAKE2b counter keystream from seed.
func fillU64(dst []uint64, seed []byte) {
	var ctr [8]byte
	i := 0
	var c uint64
	for i < len(dst) {
		binary.LittleEndian.PutUint64(ctr[:], c)
		c++
		h := blake2b.Sum512(append(append([]byte(nil), seed...), ctr[:]...))
		for j := 0; j+8 <= len(h) && i < len(dst); j += 8 {
			dst[i] = binary.LittleEndian.Uint64(h[j : j+8])
			i++
		}
	}
}

// toFloat maps 64 bits to a finite double in [1,2): never NaN/Inf.
func toFloat(u uint64) float64 {
	return math.Float64frombits((u & 0x000FFFFFFFFFFFFF) | 0x3FF0000000000000)
}

// sanitize keeps a float finite and exponent-bounded (deterministic bit ops).
func sanitize(x float64) float64 {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return 1.0
	}
	b := math.Float64bits(x)
	if (b>>52)&0x7FF > 1023+48 { // clamp magnitude to avoid runaway growth
		b = (b &^ (uint64(0x7FF) << 52)) | (uint64(1023+48) << 52)
	}
	return math.Float64frombits(b)
}

// vmHash runs the RandomX-style VM over the input under the given cache seed and
// returns the 32-byte PoW.
func vmHash(cacheSeed, input []byte) [32]byte {
	cc := cache(cacheSeed)
	ccN := uint64(len(cc))
	seed := blake2b.Sum512(input)

	// per-nonce scratchpad
	sn := RxScratchKiB * 1024 / 8
	if sn < 8 {
		sn = 8
	}
	sp := make([]uint64, sn)
	fillU64(sp, append([]byte("Obscura/RandomX/sp\x00"), seed[:]...))
	spN := uint64(sn)

	// register file: 8 integer, 8 float
	var r [8]uint64
	var f [8]float64
	for i := 0; i < 8; i++ {
		r[i] = binary.LittleEndian.Uint64(seed[i*8 : i*8+8])
		f[i] = toFloat(r[i])
	}

	// generated program
	prog := make([]uint64, RxProgramSize)
	fillU64(prog, append([]byte("Obscura/RandomX/prog\x00"), seed[:]...))

	for it := 0; it < RxIterations; it++ {
		for _, w := range prog {
			op := w & 15
			d := (w >> 4) & 7
			s := (w >> 7) & 7
			imm := w
			switch op {
			case 0:
				r[d] += r[s] + imm
			case 1:
				r[d] -= r[s]
			case 2:
				r[d] *= r[s] | 1
			case 3:
				r[d] ^= r[s] + imm
			case 4:
				r[d] = bits.RotateLeft64(r[d], -int(r[s]&63))
			case 5:
				hi, _ := bits.Mul64(r[d], r[s])
				r[d] = hi
			case 6:
				f[d] += f[s]
			case 7:
				f[d] -= f[s]
			case 8:
				f[d] *= f[s]
			case 9:
				den := f[s]
				if den == 0 || math.IsNaN(den) || math.IsInf(den, 0) {
					den = 1
				}
				f[d] /= den
			case 10:
				f[d] = math.Sqrt(math.Float64frombits(math.Float64bits(f[d]) &^ (uint64(1) << 63)))
			case 11:
				sp[(r[s]^imm)%spN] ^= r[d] // scratchpad store
			case 12:
				r[d] ^= sp[(r[s]+imm)%spN] // scratchpad load
			case 13:
				r[d] += cc[(r[s]+imm)%ccN] // cache (dataset) load
			case 14:
				f[d] += toFloat(sp[r[s]%spN]) // float from scratchpad
			default:
				if r[d]&0x3F == 0 { // data-dependent branch
					r[d] += imm | 1
				}
			}
		}
		// per-round scratchpad write keeps memory in the critical path
		sp[r[it&7]%spN] ^= r[(it+1)&7] + uint64(it)
		for i := 0; i < 8; i++ {
			f[i] = sanitize(f[i])
		}
	}

	// fold the whole scratchpad into the result so memory must be materialized
	var fold uint64 = 1469598103934665603
	for i := 0; i < sn; i++ {
		fold = (fold ^ sp[i]) * 1099511628211
	}

	var out [8*8 + 8*8 + 8]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], r[i])
		binary.LittleEndian.PutUint64(out[64+i*8:], math.Float64bits(f[i]))
	}
	binary.LittleEndian.PutUint64(out[128:], fold)
	return blake2b.Sum256(out[:])
}
