package chain

import (
	"obscura/pkg/accumulator"
)

// accPrime derives an output's accumulator prime from its one-time key + nonce.
func accPrime(oneTimeKey []byte, nonce uint64) ([]byte, bool) {
	return accumulator.HashToPrimeVerifyableData(oneTimeKey, nonce)
}
