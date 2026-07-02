package swapd

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"filippo.io/edwards25519"

	"obscura/pkg/commit"
)

// NanoClient is the Nano (XNO) side of an XNO↔Obscura atomic swap. Nano is an
// ed25519, feeless, block-lattice chain with NO script and NO timelock — but it
// shares Obscura's curve, so the swap is the SAME scriptless construction as the
// Monero swap (no cross-curve cryptography), and the REFUND is anchored on the
// Obscura leg's on-chain timelock (Nano needs none of its own). The joint account
// is an ordinary Nano account whose secret key is s_a + s_b; whoever knows that
// scalar can sign the send block that sweeps the funds. See
// docs/INVENTION_CROSSCHAIN_SWAPS.md.
//
// A production build talks to a Nano node RPC (account_create from the joint
// pubkey, receive/send blocks); tests use MockNano, which enforces the real spend
// rule (sweeping requires the scalar whose point equals the locked account key).
//
// AMOUNT PRECISION: Nano raw is a 128-bit value (1 XNO = 1e30 raw), which OVERFLOWS
// uint64 (~1.8e19 raw) even at sub-cent scale (0.00001 XNO = 1e25 raw). So every
// amount that crosses this interface is a *big.Int (formatted as a decimal string
// at the JSON edges). The previous uint64 interface SATURATED real amounts; the
// amount-equality checks only passed by coincident saturation. *big.Int makes the
// agreed XNO amount round-trip exactly through Lock/LockInfo/Balance.
type NanoClient interface {
	// Lock sends `amount` raw XNO to the account whose public key is
	// accountPub = (s_a + s_b)·G, returning a lock id. Movable only by s_a + s_b.
	Lock(amount *big.Int, accountPub []byte) (lockID string, err error)
	// Confirmed reports whether the send block is cemented (production: confirmed
	// by quorum — Nano has no reorgs once cemented).
	Confirmed(lockID string) bool
	// Sweep signs a send block moving the locked funds to `dest`, proving knowledge
	// of the account secret s_a + s_b. Fails if the secret is wrong or spent.
	Sweep(lockID string, accountSecret *edwards25519.Scalar, dest string) error
	// LockInfo returns the AUTHORITATIVE on-ledger amount (raw, full 128-bit) and
	// 32-byte destination account public key that the lock pays to. The maker uses
	// this to verify, BEFORE co-signing, that the taker really locked the agreed XNO
	// to the JOINT account (s_a+s_b)·G — not to some attacker-controlled account. An
	// error means the lock could not be read (the swap then safely aborts rather than
	// trusting blindly).
	LockInfo(lockID string) (amount *big.Int, accountPub []byte, err error)
	// Balance returns funds credited to a destination, raw (full 128-bit, for tests).
	Balance(dest string) *big.Int
}

// XNOOfferUnitsToRaw converts an XNO amount expressed in the swapbook OFFER UNITS
// (config.AutoLiquidityDecimals["XNO"] = 12 decimals, i.e. 1e12-scale) into Nano
// RAW (1 XNO = 1e30 raw). Offer units are 10^12 per XNO, raw is 10^30 per XNO, so
// raw = offerUnits × 10^(30-12) = offerUnits × 10^18. This is the conversion the
// in-node settlement leg MUST apply before calling Lock — the offer book trades in
// 1e12 units, but the on-ledger Nano lock is denominated in raw. (Previously the
// 1e12-unit value was fed straight into Lock as raw, under-paying by 10^18×.)
func XNOOfferUnitsToRaw(offerUnits *big.Int) *big.Int {
	if offerUnits == nil {
		return big.NewInt(0)
	}
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil) // 10^(30-12)
	return new(big.Int).Mul(offerUnits, scale)
}

// XNORawToOfferUnits is the inverse of XNOOfferUnitsToRaw: it converts a RAW XNO
// amount (1 XNO = 1e30 raw) back to the swapbook OFFER UNITS (1e12-scale) used to
// size an order-book reservation, i.e. offerUnits = raw / 10^18 (floor). The maker
// side uses it to reserve the matching XNO capacity for an inbound Init (whose
// XNOAmount is raw). A raw amount below 10^18 floors to 0 offer-units. nil → 0.
func XNORawToOfferUnits(raw *big.Int) uint64 {
	if raw == nil || raw.Sign() <= 0 {
		return 0
	}
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil) // 10^(30-12)
	units := new(big.Int).Quo(raw, scale)
	if !units.IsUint64() {
		return 0 // absurdly large; refuse rather than truncate
	}
	return units.Uint64()
}

// NanoAccountPub returns the joint Nano account public key the XNO is locked to:
// S_a + S_b (sum of the two parties' shares) on ed25519 — no cross-curve DLEQ
// because Obscura and Nano share the curve.
func NanoAccountPub(Sa, Sb []byte) ([]byte, error) {
	A, err := new(edwards25519.Point).SetBytes(Sa)
	if err != nil {
		return nil, err
	}
	B, err := new(edwards25519.Point).SetBytes(Sb)
	if err != nil {
		return nil, err
	}
	return new(edwards25519.Point).Add(A, B).Bytes(), nil
}

// MinerXNOAccount derives a node's XNO PROCEEDS account from its miner seed with a
// DISTINCT domain tag, so the OBX→XNO swap sweep can pay swept XNO to an address the
// operator actually controls (recoverable from the same seed) instead of a
// placeholder string. The domain tag "Obscura/xno-proceeds/v1" keeps this key
// SEPARATE from any other key derived from the same seed (the miner's OBX key, the
// swap maker key, etc.). Returns the receive secret scalar, its public key, and the
// canonical nano_ address. The secret is exported (alongside the address) for the
// wallet/recovery follow-up that will let the operator spend the swept XNO.
func MinerXNOAccount(minerSeed []byte) (sec *edwards25519.Scalar, pub []byte, addr string, err error) {
	sec = commit.HashToScalar([]byte("Obscura/xno-proceeds/v1"), minerSeed)
	pub = new(edwards25519.Point).ScalarBaseMult(sec).Bytes()
	addr, err = EncodeNanoAddress(pub)
	if err != nil {
		return nil, nil, "", err
	}
	return sec, pub, addr, nil
}

// MockNano is an in-memory Nano stand-in for tests: a ledger of locked accounts
// and destination balances, enforcing the real spend rule. Amounts are *big.Int so
// the mock matches real 128-bit raw precision (a 0.00001-XNO = 1e25-raw lock is
// stored EXACTLY, not saturated).
type MockNano struct {
	mu    sync.Mutex
	seq   int
	locks map[string]*nLock
	bal   map[string]*big.Int
}

type nLock struct {
	amount *big.Int
	pub    []byte
	spent  bool
}

// NewMockNano creates an empty mock Nano ledger.
func NewMockNano() *MockNano {
	return &MockNano{locks: make(map[string]*nLock), bal: make(map[string]*big.Int)}
}

func (m *MockNano) Lock(amount *big.Int, accountPub []byte) (string, error) {
	if len(accountPub) != 32 {
		return "", errors.New("swapd: bad nano account pubkey")
	}
	if amount == nil || amount.Sign() < 0 {
		return "", errors.New("swapd: nano lock amount must be non-negative")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	id := fmt.Sprintf("xnolock-%d", m.seq)
	m.locks[id] = &nLock{amount: new(big.Int).Set(amount), pub: append([]byte(nil), accountPub...)}
	return id, nil
}

func (m *MockNano) Confirmed(lockID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.locks[lockID]
	return ok
}

func (m *MockNano) Sweep(lockID string, accountSecret *edwards25519.Scalar, dest string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.locks[lockID]
	if !ok {
		return errors.New("swapd: unknown lock")
	}
	if l.spent {
		return errors.New("swapd: lock already spent")
	}
	// the real Nano rule: you must know s with s·G == the locked account key
	got := new(edwards25519.Point).ScalarBaseMult(accountSecret).Bytes()
	if string(got) != string(l.pub) {
		return errors.New("swapd: wrong account key — cannot sweep")
	}
	l.spent = true
	cur := m.bal[dest]
	if cur == nil {
		cur = new(big.Int)
	}
	m.bal[dest] = new(big.Int).Add(cur, l.amount)
	return nil
}

// LockInfo returns the amount and joint-account public key recorded for the lock,
// exactly as a real ledger lookup would. Unknown lock → error (swap aborts).
func (m *MockNano) LockInfo(lockID string) (*big.Int, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.locks[lockID]
	if !ok {
		return nil, nil, errors.New("swapd: unknown lock")
	}
	return new(big.Int).Set(l.amount), append([]byte(nil), l.pub...), nil
}

func (m *MockNano) Balance(dest string) *big.Int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v := m.bal[dest]; v != nil {
		return new(big.Int).Set(v)
	}
	return new(big.Int)
}

var _ NanoClient = (*MockNano)(nil)
