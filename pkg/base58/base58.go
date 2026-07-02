// Package base58 implements Bitcoin-style Base58 encoding (big-integer variant)
// for human-facing identifiers such as wallet addresses. Base58 omits the
// visually ambiguous characters 0/O and I/l, so hand-copied strings are less
// error-prone than hex.
package base58

import (
	"errors"
	"math/big"
	"strings"
)

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var bigBase = big.NewInt(58)

// Encode returns the Base58 encoding of b. Leading zero bytes are preserved as
// leading '1' characters.
func Encode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	x := new(big.Int).SetBytes(b)
	mod := new(big.Int)
	var out []byte
	for x.Sign() > 0 {
		x.DivMod(x, bigBase, mod)
		out = append(out, alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// Decode parses a Base58 string back to bytes.
func Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("base58: empty string")
	}
	// audit: ROUND2 [123] cap input length BEFORE any big.Int work. Decode is
	// O(n²) in the input length and is reachable from live RPC (e.g.
	// /blocktemplate?address=); an unbounded string is a CPU-DoS vector. Real
	// addresses are well under this bound (a 32-byte payload Base58s to ~44 chars).
	if len(s) > 200 {
		return nil, errors.New("base58: input too long")
	}
	x := new(big.Int)
	for i := 0; i < len(s); i++ {
		idx := strings.IndexByte(alphabet, s[i])
		if idx < 0 {
			return nil, errors.New("base58: invalid character")
		}
		x.Mul(x, bigBase)
		x.Add(x, big.NewInt(int64(idx)))
	}
	zeros := 0
	for zeros < len(s) && s[zeros] == alphabet[0] {
		zeros++
	}
	dec := x.Bytes()
	out := make([]byte, zeros+len(dec))
	copy(out[zeros:], dec)
	return out, nil
}
