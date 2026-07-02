// Package mnemonic encodes a wallet seed as a human-readable, checksummed word
// phrase (Block 26 — see docs/INVENTION_MNEMONIC.md). A 64-hex-char seed is easy
// to mistype or lose; a word phrase is far easier to write down and read back, and
// the built-in checksum catches typos before they silently produce the wrong
// wallet.
//
// The scheme is the BIP39 *entropy encoding* (entropy || checksum, split into
// 11-bit groups indexing a 2048-word list) with an Obscura-specific wordlist that
// is generated deterministically from pronounceable CVCV syllables. It is NOT
// compatible with BIP39 English phrases — it is a self-contained, dependency-free
// codec for THIS wallet. The cryptographic seed is unchanged; this is only an
// encoding of it.
package mnemonic

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// The wordlist is 2048 entries (11 bits each), generated as C V C V syllables
// over 16 consonants and 5 vowels (16*5*16*5 = 6400 ≥ 2048 distinct combos).
var (
	consonants = []byte("bdfghklmnprstvwz") // 16
	vowels     = []byte("aeiou")            // 5

	wordsOnce sync.Once
	wordList  []string
	wordIdx   map[string]int
)

func build() {
	wordList = make([]string, 2048)
	wordIdx = make(map[string]int, 2048)
	for i := 0; i < 2048; i++ {
		x := i
		d := x % 5
		x /= 5
		c := x % 16
		x /= 16
		b := x % 5
		x /= 5
		a := x % 16
		w := string([]byte{consonants[a], vowels[b], consonants[c], vowels[d]})
		wordList[i] = w
		wordIdx[w] = i
	}
}

// Words returns the deterministic 2048-word list.
func Words() []string {
	wordsOnce.Do(build)
	out := make([]string, len(wordList))
	copy(out, wordList)
	return out
}

// Encode turns entropy (the seed) into a word phrase. Entropy must be 16–32 bytes
// in 4-byte steps (128–256 bits); a 32-byte seed yields 24 words.
func Encode(entropy []byte) (string, error) {
	wordsOnce.Do(build)
	if len(entropy) < 16 || len(entropy) > 32 || len(entropy)%4 != 0 {
		return "", errors.New("mnemonic: entropy must be 16–32 bytes in 4-byte steps")
	}
	csBits := len(entropy) * 8 / 32
	h := sha256.Sum256(entropy)
	totalBits := len(entropy)*8 + csBits
	getBit := func(i int) int {
		if i < len(entropy)*8 {
			return int((entropy[i/8] >> (7 - uint(i%8))) & 1)
		}
		j := i - len(entropy)*8
		return int((h[j/8] >> (7 - uint(j%8))) & 1)
	}
	n := totalBits / 11
	parts := make([]string, n)
	for w := 0; w < n; w++ {
		idx := 0
		for b := 0; b < 11; b++ {
			idx = idx<<1 | getBit(w*11+b)
		}
		parts[w] = wordList[idx]
	}
	return strings.Join(parts, " "), nil
}

// Decode parses a word phrase back to the seed, verifying the checksum. A typo in
// any single word almost always fails the checksum rather than returning a wrong
// (but valid-looking) seed.
func Decode(phrase string) ([]byte, error) {
	wordsOnce.Do(build)
	parts := strings.Fields(strings.ToLower(strings.TrimSpace(phrase)))
	n := len(parts)
	if n < 12 || n > 24 || n%3 != 0 {
		return nil, errors.New("mnemonic: word count must be 12, 15, 18, 21, or 24")
	}
	totalBits := n * 11
	csBits := totalBits / 33 // total = entropy*33/32 → checksum = total/33
	entBits := totalBits - csBits
	if entBits%8 != 0 {
		return nil, errors.New("mnemonic: invalid phrase length")
	}
	bits := make([]int, 0, totalBits)
	for _, p := range parts {
		idx, ok := wordIdx[p]
		if !ok {
			return nil, fmt.Errorf("mnemonic: unknown word %q", p)
		}
		for b := 10; b >= 0; b-- {
			bits = append(bits, (idx>>uint(b))&1)
		}
	}
	entropy := make([]byte, entBits/8)
	for i := 0; i < entBits; i++ {
		if bits[i] == 1 {
			entropy[i/8] |= 1 << (7 - uint(i%8))
		}
	}
	h := sha256.Sum256(entropy)
	for i := 0; i < csBits; i++ {
		exp := int((h[i/8] >> (7 - uint(i%8))) & 1)
		if bits[entBits+i] != exp {
			return nil, errors.New("mnemonic: checksum mismatch (a word is likely mistyped)")
		}
	}
	return entropy, nil
}
