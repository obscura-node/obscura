package accumulator

import (
	"errors"
	"math/big"
	"sort"

	"obscura/pkg/group"
)

// Accumulator is the node-side ("manager") view of the dynamic accumulator. It
// tracks the live set of prime representatives so it can compute witnesses and
// accumulator updates. Light clients only need the single accumulator element
// plus a per-output witness.
//
// The accumulator value is acc = g^(∏ members) in the group of unknown order.
//
// Two modes:
//   - default (New): retains the member-prime set, so it can build membership
//     WITNESSES (MembershipWitness) and answer Contains. RAM is O(n).
//   - value-only (NewValueOnly): keeps ONLY the O(1) accumulator value + a size
//     counter — it can Add and report Value/Size with byte-identical results, but
//     cannot build witnesses or answer Contains. This is sound for a node on the
//     ring-based spend path: the accumulator value is only a header COMMITMENT
//     (spends use rings, not accumulator witnesses), and duplicate-prime rejection
//     is authoritative in chain validation (outPrimes), not here. Drops the ~O(n)
//     member set (the dominant accumulator RAM cost at scale). See
//     docs/SCALING_100M.md (Track A).
type Accumulator struct {
	G         group.Group
	acc       group.Element
	members   map[string]*big.Int // hex(prime) -> prime (nil in value-only mode)
	valueOnly bool
	count     int // number of adds (value-only mode)
}

// New creates an empty accumulator seeded at the generator g (the empty
// product). The genesis accumulator value is therefore g.
func New(G group.Group) *Accumulator {
	return &Accumulator{
		G:       G,
		acc:     G.Generator(),
		members: make(map[string]*big.Int),
	}
}

// NewValueOnly creates an O(1)-memory accumulator (value + size counter, no member
// set). Its Value/Size are byte-identical to New's for the same add sequence, but
// it cannot build witnesses or answer Contains.
func NewValueOnly(G group.Group) *Accumulator {
	return &Accumulator{G: G, acc: G.Generator(), valueOnly: true}
}

// Value returns the current accumulator element.
func (a *Accumulator) Value() group.Element { return a.acc }

// Clone returns a deep copy of the accumulator (used for chain state snapshots
// during reorgs). The group is shared (immutable); the member set is copied.
func (a *Accumulator) Clone() *Accumulator {
	if a.valueOnly {
		return &Accumulator{G: a.G, acc: a.acc, valueOnly: true, count: a.count}
	}
	m := make(map[string]*big.Int, len(a.members))
	for k, v := range a.members {
		m[k] = new(big.Int).Set(v)
	}
	return &Accumulator{G: a.G, acc: a.acc, members: m}
}

// Size returns the number of accumulated members.
func (a *Accumulator) Size() int {
	if a.valueOnly {
		return a.count
	}
	return len(a.members)
}

// Contains reports whether prime p is currently accumulated. Always false in
// value-only mode (no member set; dup-detection is enforced by chain validation).
func (a *Accumulator) Contains(p *big.Int) bool {
	if a.valueOnly {
		return false
	}
	_, ok := a.members[p.Text(16)]
	return ok
}

// Add inserts prime p: acc' = acc^p. Idempotent guards prevent double-insert
// (member mode only; value-only mode trusts the caller's prior dup check).
func (a *Accumulator) Add(p *big.Int) error {
	if a.valueOnly {
		a.acc = a.G.Exp(a.acc, p)
		a.count++
		return nil
	}
	k := p.Text(16)
	if _, ok := a.members[k]; ok {
		return errors.New("accumulator: element already present")
	}
	a.acc = a.G.Exp(a.acc, p)
	a.members[k] = new(big.Int).Set(p)
	return nil
}

// AddBatch folds n already-validated primes, supplied as their product, into the
// accumulator in ONE exponentiation: acc' = acc^product. Because acc^p1^p2..^pn =
// acc^(p1*p2*..*pn), this is byte-identical to calling Add for each prime (and to the
// value the block template predicts, pkg/chain/template.go), but it does a single Exp
// instead of n, removing the per-output exponentiation overhead. Value-only mode only;
// the caller MUST have already verified each prime's uniqueness (the apply path relies on
// validation's per-block seenPrime set). No-op when n == 0.
func (a *Accumulator) AddBatch(product *big.Int, n int) {
	if n == 0 {
		return
	}
	a.acc = a.G.Exp(a.acc, product)
	a.count += n
}

// Remove deletes prime p. The new accumulator equals the membership witness of
// p (acc^(1/p) = g^(∏ others)). Returns error if p is absent.
func (a *Accumulator) Remove(p *big.Int) error {
	k := p.Text(16)
	if _, ok := a.members[k]; !ok {
		return errors.New("accumulator: element not present")
	}
	delete(a.members, k)
	a.acc = a.recompute()
	return nil
}

// recompute rebuilds the accumulator from the current member set: g^(∏ members).
// O(n) exponent build; correct and simple. Production uses BBF batch updates.
func (a *Accumulator) recompute() group.Element {
	prod := big.NewInt(1)
	for _, p := range a.sortedMembers() {
		prod.Mul(prod, p)
	}
	return a.G.Exp(a.G.Generator(), prod)
}

func (a *Accumulator) sortedMembers() []*big.Int {
	out := make([]*big.Int, 0, len(a.members))
	for _, p := range a.members {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Cmp(out[j]) < 0 })
	return out
}

// productExcept returns ∏ members except p.
func (a *Accumulator) productExcept(p *big.Int) *big.Int {
	prod := big.NewInt(1)
	pk := p.Text(16)
	for k, m := range a.members {
		if k == pk {
			continue
		}
		prod.Mul(prod, m)
	}
	return prod
}

// MembershipWitness returns w = g^(∏ others) so that w^p = acc.
func (a *Accumulator) MembershipWitness(p *big.Int) (group.Element, error) {
	if a.valueOnly {
		return nil, errors.New("accumulator: value-only node cannot build witnesses (archive node required)")
	}
	if !a.Contains(p) {
		return nil, errors.New("accumulator: cannot witness absent element")
	}
	return a.G.Exp(a.G.Generator(), a.productExcept(p)), nil
}

// product returns ∏ all members (the accumulator's exponent over g).
func (a *Accumulator) product() *big.Int {
	prod := big.NewInt(1)
	for _, m := range a.members {
		prod.Mul(prod, m)
	}
	return prod
}

// VerifyMembership checks w^p == acc (witness w proves p is accumulated).
func VerifyMembership(G group.Group, acc, w group.Element, p *big.Int) bool {
	return G.Equal(G.Exp(w, p), acc)
}

// ---------------------------------------------------------------------------
// Wesolowski Proof of Exponentiation (PoE) — succinct, non-interactive.
//
// Proves acc = base^exp without the verifier recomputing the full exponent.
// Verifier work is O(log exp) instead of O(exp bits) group ops.
// ---------------------------------------------------------------------------

// PoE is a proof that acc = base^exp.
type PoE struct {
	Q group.Element // base^floor(exp/ℓ)
}

// ProvePoE produces a PoE for acc = base^exp.
func ProvePoE(G group.Group, base, acc group.Element, exp *big.Int) *PoE {
	ell := poeChallenge(G, base, acc, exp)
	q := new(big.Int).Div(exp, ell)
	return &PoE{Q: G.Exp(base, q)}
}

// VerifyPoE checks a PoE: Q^ℓ · base^(exp mod ℓ) == acc.
func VerifyPoE(G group.Group, base, acc group.Element, exp *big.Int, pf *PoE) bool {
	ell := poeChallenge(G, base, acc, exp)
	r := new(big.Int).Mod(exp, ell)
	lhs := G.Op(G.Exp(pf.Q, ell), G.Exp(base, r))
	return G.Equal(lhs, acc)
}

func poeChallenge(G group.Group, base, acc group.Element, exp *big.Int) *big.Int {
	var t []byte
	t = append(t, []byte(G.Name())...)
	t = append(t, G.Marshal(base)...)
	t = append(t, G.Marshal(acc)...)
	t = append(t, exp.Bytes()...)
	return HashToPrimeChallenge(t)
}

// ---------------------------------------------------------------------------
// NI-PoKE2 — Non-Interactive Proof of Knowledge of Exponent (BBF).
//
// Proves knowledge of x such that base^x = target, WITHOUT transmitting x.
// Only z = g^x (a hard-to-invert commitment) and r = x mod ℓ are revealed,
// so x — and therefore the accumulated prime — stays hidden. This is the
// building block for hiding *which* output is being spent.
// ---------------------------------------------------------------------------

// PoKE2 is a non-interactive proof of knowledge of exponent.
type PoKE2 struct {
	Z group.Element // g^x  (commitment to the secret exponent)
	Q group.Element // (base · g^α)^q
	R *big.Int      // x mod ℓ
}

// ProvePoKE2 proves knowledge of x with base^x = target. g is an independent
// generator (we use G.Generator()); base is typically the membership witness.
func ProvePoKE2(G group.Group, base, target group.Element, x *big.Int) *PoKE2 {
	g := G.Generator()
	z := G.Exp(g, x)
	ell := poke2Challenge(G, base, target, z)
	alpha := poke2Alpha(G, base, target, z, ell)

	q := new(big.Int).Div(x, ell)
	r := new(big.Int).Mod(x, ell)

	// Q = (base · g^α)^q
	bg := G.Op(base, G.Exp(g, alpha))
	Q := G.Exp(bg, q)
	return &PoKE2{Z: z, Q: Q, R: r}
}

// VerifyPoKE2 checks: Q^ℓ · (base · g^α)^r == target · z^α.
func VerifyPoKE2(G group.Group, base, target group.Element, pf *PoKE2) bool {
	g := G.Generator()
	ell := poke2Challenge(G, base, target, pf.Z)
	alpha := poke2Alpha(G, base, target, pf.Z, ell)
	if pf.R.Sign() < 0 || pf.R.Cmp(ell) >= 0 {
		return false
	}
	bg := G.Op(base, G.Exp(g, alpha))
	lhs := G.Op(G.Exp(pf.Q, ell), G.Exp(bg, pf.R))
	rhs := G.Op(target, G.Exp(pf.Z, alpha))
	return G.Equal(lhs, rhs)
}

func poke2Challenge(G group.Group, base, target, z group.Element) *big.Int {
	var t []byte
	t = append(t, []byte("PoKE2-ell")...)
	t = append(t, []byte(G.Name())...)
	t = append(t, G.Marshal(base)...)
	t = append(t, G.Marshal(target)...)
	t = append(t, G.Marshal(z)...)
	return HashToPrimeChallenge(t)
}

func poke2Alpha(G group.Group, base, target, z group.Element, ell *big.Int) *big.Int {
	var t []byte
	t = append(t, []byte("PoKE2-alpha")...)
	t = append(t, G.Marshal(base)...)
	t = append(t, G.Marshal(target)...)
	t = append(t, G.Marshal(z)...)
	t = append(t, ell.Bytes()...)
	return HashToInt(t, 256)
}

// ---------------------------------------------------------------------------
// Non-membership proof (BBF).
//
// Proves prime x is NOT accumulated: gcd(x, s) = 1 where acc = g^s. Witness is
// (a, D = g^b) for Bezout coefficients a·s + b·x = 1. Verified by
// acc^a · D^x == g.
// ---------------------------------------------------------------------------

// NonMembership is a non-membership witness/proof for a prime x.
type NonMembership struct {
	A *big.Int      // Bezout coefficient on s
	D group.Element // g^b
}

// ProveNonMembership builds a non-membership proof for prime x against this
// accumulator. Requires x to be coprime to the accumulated product (i.e. x is
// genuinely absent).
func (a *Accumulator) ProveNonMembership(x *big.Int) (*NonMembership, error) {
	s := a.product()
	g := new(big.Int)
	bezA := new(big.Int)
	bezB := new(big.Int)
	g.GCD(bezA, bezB, s, x) // bezA*s + bezB*x = gcd
	if g.Cmp(big.NewInt(1)) != 0 {
		return nil, errors.New("accumulator: element is a member (gcd != 1)")
	}
	return &NonMembership{
		A: bezA,
		D: a.G.Exp(a.G.Generator(), bezB),
	}, nil
}

// VerifyNonMembership checks acc^a · D^x == g.
func VerifyNonMembership(G group.Group, acc group.Element, x *big.Int, pf *NonMembership) bool {
	lhs := G.Op(G.Exp(acc, pf.A), G.Exp(pf.D, x))
	return G.Equal(lhs, G.Generator())
}
