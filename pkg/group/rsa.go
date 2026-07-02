package group

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// rsaElement wraps a residue in (Z/NZ)^*. We always keep 1 <= x < N and, by
// convention, identify x with N-x is NOT applied here (full multiplicative
// group). For accumulator soundness we work in the quotient by {+-1} when
// needed; callers use Equal which compares canonical residues.
type rsaElement struct {
	x *big.Int
}

func (e rsaElement) String() string { return e.x.String() }

// RSAGroup implements Group over (Z/NZ)^* for a fixed modulus N of unknown
// factorization. The generator is a fixed small base mapped into the group.
type RSAGroup struct {
	N    *big.Int
	g    *big.Int
	name string
}

// RSA2048Challenge is the modulus from the RSA Factoring Challenge (RSA-2048),
// whose factorization has never been published and is widely believed unknown.
// Using it as a nothing-up-my-sleeve group of unknown order is standard in the
// VDF / accumulator literature (e.g. Chia, Boneh-Bunz-Fisch reference impls).
const RSA2048Challenge = "25195908475657893494027183240048398571429282126204032027777" +
	"137836043662020707595556264018525880784406918290641249515082" +
	"189298559149176184502808489120072844992687392807287776735971" +
	"418347270261896375014971824691165077613379859095700097330459" +
	"748808428401797429100642458691817195118746121515172654632282" +
	"216869987549182422433637259085141865462043576798423387184774" +
	"447920739934236584823824281198163815010674810451660377306056" +
	"201619676256133844143603833904414952634432190114657544454178" +
	"424020924616515723350778707749817125772467962926386356373289" +
	"912154831438167899885040445364023527381951378636564391212010" +
	"397122822120720357"

// NewRSA2048Group returns the canonical RSA-2048-challenge group of unknown
// order with generator 2.
func NewRSA2048Group() *RSAGroup {
	N, ok := new(big.Int).SetString(RSA2048Challenge, 10)
	if !ok {
		panic("group: invalid RSA-2048 challenge constant")
	}
	return &RSAGroup{N: N, g: big.NewInt(2), name: "rsa2048"}
}

// NewRSAGroup builds an RSA group from an explicit modulus and generator.
// Intended for tests (small moduli) and for deployments that ran their own
// modulus ceremony.
func NewRSAGroup(N, g *big.Int, name string) *RSAGroup {
	return &RSAGroup{N: new(big.Int).Set(N), g: new(big.Int).Set(g), name: name}
}

func (G *RSAGroup) Name() string { return G.name }

func (G *RSAGroup) Identity() Element { return rsaElement{big.NewInt(1)} }

func (G *RSAGroup) Generator() Element { return rsaElement{new(big.Int).Set(G.g)} }

// canon returns the canonical representative min(x, N-x). Working modulo {±1}
// removes the sign ambiguity (x and N-x both satisfy w^p = acc) that would
// otherwise let a prover present a non-canonical element, and keeps elements in
// a well-defined quotient where the accumulator soundness assumptions hold.
func (G *RSAGroup) canon(x *big.Int) *big.Int {
	negx := new(big.Int).Sub(G.N, x)
	if negx.Cmp(x) < 0 {
		return negx
	}
	return x
}

func (G *RSAGroup) Op(a, b Element) Element {
	ae := a.(rsaElement)
	be := b.(rsaElement)
	r := new(big.Int).Mul(ae.x, be.x)
	r.Mod(r, G.N)
	return rsaElement{G.canon(r)}
}

func (G *RSAGroup) Exp(a Element, e *big.Int) Element {
	ae := a.(rsaElement)
	if e.Sign() < 0 {
		inv := G.Inverse(a).(rsaElement)
		pe := new(big.Int).Neg(e)
		return rsaElement{G.canon(new(big.Int).Exp(inv.x, pe, G.N))}
	}
	return rsaElement{G.canon(new(big.Int).Exp(ae.x, e, G.N))}
}

func (G *RSAGroup) Inverse(a Element) Element {
	ae := a.(rsaElement)
	inv := new(big.Int).ModInverse(ae.x, G.N)
	if inv == nil {
		// Element not invertible mod N (shares a factor with N). Canonicalized,
		// honestly-derived elements are always invertible; return identity to
		// avoid a panic-based DoS on crafted input (the caller's verification
		// will then fail).
		return G.Identity()
	}
	return rsaElement{G.canon(inv)}
}

func (G *RSAGroup) Equal(a, b Element) bool {
	return a.(rsaElement).x.Cmp(b.(rsaElement).x) == 0
}

// MarshalSize returns the byte length of the modulus, the max element size.
func (G *RSAGroup) MarshalSize() int { return (G.N.BitLen() + 7) / 8 }

func (G *RSAGroup) Marshal(a Element) []byte {
	sz := G.MarshalSize()
	buf := make([]byte, sz)
	a.(rsaElement).x.FillBytes(buf)
	return buf
}

func (G *RSAGroup) Unmarshal(b []byte) (Element, error) {
	// audit: ROUND2 [95] enforce the exact canonical wire length. Marshal()
	// FillBytes-pads to MarshalSize(); without this bound a leading-zero-padded
	// (or oversized) buffer decodes to the same residue — malleability — and an
	// unbounded input forces unbounded big.Int allocation.
	if len(b) != G.MarshalSize() {
		return nil, errors.New("group: rsa element wrong length")
	}
	x := new(big.Int).SetBytes(b)
	if x.Sign() <= 0 || x.Cmp(G.N) >= 0 {
		return nil, errors.New("group: rsa element out of range")
	}
	// reject the trivial/degenerate elements and canonicalize the sign.
	if x.Cmp(big.NewInt(1)) == 0 || new(big.Int).Sub(G.N, x).Cmp(big.NewInt(1)) == 0 {
		return nil, errors.New("group: degenerate rsa element")
	}
	return rsaElement{G.canon(x)}, nil
}

// HashToRSAGroup deterministically maps arbitrary bytes to a group element by
// hashing into [2, N-1]. Used to derive independent generators for commitments
// inside proofs (e.g. the PoKE Fiat-Shamir base) without trusted setup.
func (G *RSAGroup) HashToRSAGroup(data []byte) Element {
	// Expand with a counter until we land in range; squaring removes the +-1
	// ambiguity and keeps us in the group of quadratic residues.
	for ctr := 0; ; ctr++ {
		h := sha256.Sum256(append(data, byte(ctr)))
		x := new(big.Int).SetBytes(h[:])
		x.Mod(x, G.N)
		if x.Sign() == 0 {
			continue
		}
		// square to ensure membership in QR_N (a cyclic-ish subgroup) and
		// avoid the trivial element.
		x.Mul(x, x)
		x.Mod(x, G.N)
		if x.Cmp(big.NewInt(1)) == 0 {
			continue
		}
		return rsaElement{G.canon(x)}
	}
}

var _ Group = (*RSAGroup)(nil)

func (G *RSAGroup) GoString() string {
	return fmt.Sprintf("RSAGroup(%s, bits=%d)", G.name, G.N.BitLen())
}
