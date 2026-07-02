// Package light implements SPV light-client verification: it validates a chain
// of block HEADERS (proof-of-work, linkage, difficulty retargeting, timestamps,
// cumulative work) WITHOUT downloading or executing full blocks, and verifies
// transaction inclusion via Merkle proofs. This lets wallets confirm the best
// chain and that a transaction is in it at a tiny fraction of full-node cost.
//
// Trust model (standard SPV): a light client trusts that the most-work valid
// header chain reflects the honest majority; it does NOT re-validate
// transactions (no inflation/double-spend checking) — that is the full node's
// job. Wallet output scanning still needs per-output data (view-tags, a
// documented refinement, speed that up).
package light

import (
	"errors"
	"math/big"
	"sort"
	"time"

	"obscura/pkg/block"
	"obscura/pkg/config"
	"obscura/pkg/consensus"
	"obscura/pkg/pow"
)

// VerifyHeaderChain checks an ordered slice of headers (genesis first) and
// returns the tip hash, height, and cumulative work. It verifies, for each
// non-genesis header: linkage to its parent, the LWMA-expected difficulty, that
// the PoW meets that difficulty, and timestamp sanity (median-time-past +
// bounded future drift). The genesis header must match expectGenesisID (the
// light client's hardcoded trust root).
func VerifyHeaderChain(headers []block.Header, expectGenesisID [32]byte) (tip [32]byte, height uint64, work *big.Int, err error) {
	if len(headers) == 0 {
		return tip, 0, nil, errors.New("light: empty header chain")
	}
	if headers[0].Height != 0 || headers[0].ID() != expectGenesisID {
		return tip, 0, nil, errors.New("light: genesis mismatch")
	}
	work = new(big.Int)
	now := time.Now().Unix()
	for i := range headers {
		if i > 0 {
			// audit: SECURITY_AUDIT_2026-07-01 #4 — per-header PoW/linkage/difficulty
			// /timestamp checks live in the shared helper (also used by
			// VerifyHeaderExtension) so the two verifiers stay behavior-identical.
			if err := verifyHeaderAt(headers, i, now); err != nil {
				return tip, 0, nil, err
			}
		} else if headers[i].Height != uint64(i) {
			return tip, 0, nil, errors.New("light: non-contiguous height")
		}
		work.Add(work, new(big.Int).SetUint64(headers[i].Difficulty))
	}
	last := headers[len(headers)-1]
	return last.ID(), last.Height, work, nil
}

// verifyHeaderAt verifies the single non-genesis header at index i within a
// genesis-first slice. `headers[:i]` supplies the difficulty window / MTP
// context and the per-epoch PoW seed lookup (headers[PoWSeedHeight(h)]), so the
// slice MUST be genesis-first and contiguous up to i. Shared by
// VerifyHeaderChain and VerifyHeaderExtension.
//
// audit: SECURITY_AUDIT_2026-07-01 #4
func verifyHeaderAt(headers []block.Header, i int, now int64) error {
	h := headers[i]
	if h.Height != uint64(i) {
		return errors.New("light: non-contiguous height")
	}
	if h.PrevHash != headers[i-1].ID() {
		return errors.New("light: broken parent link")
	}
	if h.Difficulty == 0 {
		return errors.New("light: zero difficulty")
	}
	ts, df := window(headers[:i])
	if h.Difficulty != consensus.NextDifficulty(ts, df) {
		return errors.New("light: wrong difficulty")
	}
	if h.Timestamp <= medianTimePast(headers[:i]) {
		return errors.New("light: timestamp <= MTP")
	}
	if h.Timestamp > now+config.MaxFutureDriftSeconds {
		return errors.New("light: timestamp too far in future")
	}
	// per-epoch PoW seed: epoch 0 uses the constant, later epochs use the
	// id of the seed-height header (present in this genesis-first slice).
	seed := config.PoWGenesisSeed
	if sh := config.PoWSeedHeight(h.Height); sh > 0 && sh < uint64(len(headers)) {
		id := headers[sh].ID()
		seed = id[:]
	}
	if !pow.Meets(h.PoWHashSeed(seed), h.Difficulty) {
		return errors.New("light: insufficient proof of work")
	}
	return nil
}

// VerifyHeaderExtension incrementally verifies new headers appended to an
// already-verified prefix, so a light client verifies each header's (expensive)
// PoW exactly once and never re-verifies the whole chain on every sync.
//
// `prefix` is genesis-first and already verified (prefix[0].Height==0), with
// cumulative work `prefixWork` (sum of Difficulty over prefix, matching how
// VerifyHeaderChain counts genesis). `next` is contiguous, starting at the
// prefix tip's height+1. Each new header is verified via verifyHeaderAt against
// the combined genesis-first chain (so difficulty-window, MTP, and per-epoch
// PoW-seed lookups have correct context), and its work is accumulated onto a
// copy of prefixWork. Returns the new tip/height/cumulative-work.
//
// audit: SECURITY_AUDIT_2026-07-01 #4
func VerifyHeaderExtension(prefix, next []block.Header, prefixWork *big.Int) (tip [32]byte, height uint64, work *big.Int, err error) {
	if len(prefix) == 0 || prefix[0].Height != 0 {
		return tip, 0, nil, errors.New("light: prefix must be genesis-first")
	}
	if prefixWork == nil {
		return tip, 0, nil, errors.New("light: nil prefix work")
	}
	work = new(big.Int).Set(prefixWork)
	if len(next) == 0 {
		last := prefix[len(prefix)-1]
		return last.ID(), last.Height, work, nil
	}
	combined := make([]block.Header, 0, len(prefix)+len(next))
	combined = append(combined, prefix...)
	combined = append(combined, next...)
	now := time.Now().Unix()
	for i := len(prefix); i < len(combined); i++ {
		if err := verifyHeaderAt(combined, i, now); err != nil {
			return tip, 0, nil, err
		}
		work.Add(work, new(big.Int).SetUint64(combined[i].Difficulty))
	}
	last := combined[len(combined)-1]
	return last.ID(), last.Height, work, nil
}

// VerifyInclusion confirms a transaction (by txid) is committed by a verified
// header's MerkleRoot via its inclusion branch.
func VerifyInclusion(header block.Header, txid [32]byte, steps []block.MerkleStep) bool {
	return block.VerifyMerkleProof(txid, steps, header.MerkleRoot)
}

func window(prev []block.Header) ([]int64, []uint64) {
	n := config.DifficultyWindow + 1
	start := 0
	if len(prev) > n {
		start = len(prev) - n
	}
	var ts []int64
	var df []uint64
	for _, h := range prev[start:] {
		ts = append(ts, h.Timestamp)
		df = append(df, h.Difficulty)
	}
	return ts, df
}

func medianTimePast(prev []block.Header) int64 {
	const n = 11
	start := 0
	if len(prev) > n {
		start = len(prev) - n
	}
	var tsv []int64
	for _, h := range prev[start:] {
		tsv = append(tsv, h.Timestamp)
	}
	if len(tsv) == 0 {
		return 0
	}
	sort.Slice(tsv, func(i, j int) bool { return tsv[i] < tsv[j] })
	return tsv[len(tsv)/2]
}
