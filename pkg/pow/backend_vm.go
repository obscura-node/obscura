//go:build protopow

package pow

// OPT-IN prototype PoW backend: the self-contained, pure-Go RandomX-STYLE VM
// (randomx.go). Light and fast, for quick dev/test iteration ONLY. It has
// near-zero memory-hardness and must NEVER back a value-bearing or public node;
// guardPrototypePoW refuses to start on it without OBX_ALLOW_PROTOTYPE_POW=1.
// Build with `-tags protopow` to select it. The DEFAULT build (no tags) is the
// KAT-verified canonical RandomX (backend_randomx.go).
const BackendName = "vm-randomx-style"

func backendHash(seed, input []byte) [32]byte { return vmHash(seed, input) }
