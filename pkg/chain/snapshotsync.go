package chain

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"math/big"
	"sort"

	"obscura/pkg/accumulator"
	"obscura/pkg/block"
	"obscura/pkg/config"
	"obscura/pkg/consensus"
	"obscura/pkg/pow"
	"obscura/pkg/pqaccum"
	"obscura/pkg/stark"
)

// Snapshot AUTHENTICITY verification (audit: fresh-node bootstrap past PoRWindow). A fresh
// node cannot sync from genesis once the chain exceeds PoRWindow, because bodies below
// tip-PoRWindow are pruned network-wide. The eventual fix is to fast-forward via a
// peer-supplied snapshot — but ONLY after verifying it against PROOF OF WORK, never trusting
// the peer.
//
// WHAT IS PROVEN AND SHIPPED HERE: VerifySnapshotAuthenticity verifies the part that IS
// soundly checkable against PoW today — the genesis binds to OUR network, every header
// carries real cumulative PoW under the correct LWMA difficulty + seed, and the four
// header-committed roots (AccValue, NullRoot, CMRoot, PQAccRoot) match the restored
// accumulators. A peer cannot forge any of that. This is the reusable verification core.
//
// WHAT IS DELIBERATELY NOT DONE — and WHY (a deep review, not a shortcut): actually IMPORTING
// the state (adopting it as the live ledger) is NOT sound with the current architecture, for
// two independent, proven reasons:
//
//  1. UNCOMMITTED SCALARS/SETS. The snapshot carries Emitted, IncentivePool, AccValues
//     (spend anchors), and the Referral/swap/vault/PQ/ZK maps — none bound by any header
//     root (cf. audit PQACC-1, which generalizes). A peer could tamper them undetectably.
//     (Emitted/IncentivePool ARE deterministically recomputable for a classical-only chain,
//     but AccValues/anchors and the per-feature maps are not, in general.)
//  2. STRUCTURALLY OMITTED DISK-BACKED SETS. The classical double-spend set `tags`
//     (consulted at validate.go for key-image/tag reuse), `outPrimes`, and the coin set are
//     disk-backed; the snapshot stores only their COUNT, not their members (the format is
//     built for LOCAL crash-resume, which trusts the intact local bolt). A fresh node
//     importing a snapshot has an EMPTY bolt, so it would have NO double-spend set and NO
//     coin set, and could not validate any post-snapshot transaction. Importing it would
//     produce a BROKEN node — strictly worse than the availability gap it tries to close.
//
// Sound network bootstrap requires a PRECURSOR: (a) a header state-root committing ALL residual
// consensus state, and (b) transferring the disk-backed member sets, not just counts. BOTH ARE
// NOW DONE: (a) Header.StateRoot (pkg/chain/stateroot.go) and (b) the transfer format + verified
// import below (VerifyAndImportSnapshot). VerifySnapshotAuthenticity remains the lighter
// read-only check; VerifyAndImportSnapshot is the full verify-then-adopt path. The one remaining
// gap (the coin/anonymity set) is documented at VerifyAndImportSnapshot. See docs/SNAPSHOT_SYNC_DESIGN.md.

// maxSnapshotHeaders bounds a peer-supplied header count (anti decode-bomb).
const maxSnapshotHeaders = 50_000_000

// --- slice-based replays of the chain's header-validation helpers, so verification uses the
// SAME consensus rules as live block validation but over a candidate header slice. ---

func recentTSDiffsAt(headers []block.Header, upto int) ([]int64, []uint64) {
	n := config.DifficultyWindow + 1
	start := 0
	if upto > n {
		start = upto - n
	}
	ts := make([]int64, 0, upto-start)
	df := make([]uint64, 0, upto-start)
	for _, h := range headers[start:upto] {
		ts = append(ts, h.Timestamp)
		df = append(df, h.Difficulty)
	}
	return ts, df
}

func medianTimePastAt(headers []block.Header, upto int) int64 {
	const n = 11
	start := 0
	if upto > n {
		start = upto - n
	}
	tsv := make([]int64, 0, upto-start)
	for _, h := range headers[start:upto] {
		tsv = append(tsv, h.Timestamp)
	}
	sort.Slice(tsv, func(i, j int) bool { return tsv[i] < tsv[j] })
	return tsv[len(tsv)/2]
}

func powSeedAt(headers []block.Header, height uint64) ([]byte, bool) {
	sh := config.PoWSeedHeight(height)
	if sh == 0 {
		return config.PoWGenesisSeed, true
	}
	if sh >= uint64(len(headers)) {
		return nil, false
	}
	id := headers[sh].ID()
	return id[:], true
}

// verifyHeaderChain replays the consensus header checks (linkage, LWMA difficulty, PoW
// seed-epoch, PoW threshold, median-time-past) over a candidate chain. A chain that does not
// carry real cumulative PoW from a valid genesis is rejected. The FUTURE-time bound is
// intentionally skipped (historical headers are legitimately in the past). Mirrors the header
// section of validateBlockLocked so there is one rule set, not a divergent re-implementation.
func verifyHeaderChain(headers []block.Header) error {
	if len(headers) == 0 {
		return fmt.Errorf("%w: empty snapshot header chain", errValidation)
	}
	g := headers[0]
	if g.Height != 0 || g.PrevHash != ([32]byte{}) || g.Timestamp != GenesisTimestamp {
		return fmt.Errorf("%w: malformed snapshot genesis header", errValidation)
	}
	for i := 1; i < len(headers); i++ {
		h := headers[i]
		prev := headers[i-1]
		if h.Height != prev.Height+1 {
			return fmt.Errorf("%w: snapshot header %d non-sequential height", errValidation, i)
		}
		if h.PrevHash != prev.ID() {
			return fmt.Errorf("%w: snapshot header %d prevhash mismatch", errValidation, i)
		}
		if h.Difficulty == 0 {
			return fmt.Errorf("%w: snapshot header %d zero difficulty", errValidation, i)
		}
		if h.Timestamp <= medianTimePastAt(headers, i) {
			return fmt.Errorf("%w: snapshot header %d timestamp <= median-time-past", errValidation, i)
		}
		ts, df := recentTSDiffsAt(headers, i)
		if exp := consensus.NextDifficulty(ts, df); h.Difficulty != exp {
			return fmt.Errorf("%w: snapshot header %d difficulty %d, expected %d", errValidation, i, h.Difficulty, exp)
		}
		seed, ok := powSeedAt(headers, h.Height)
		if !ok {
			return fmt.Errorf("%w: snapshot header %d missing PoW seed", errValidation, i)
		}
		if !pow.Meets(h.PoWHashSeed(seed), h.Difficulty) {
			return fmt.Errorf("%w: snapshot header %d insufficient PoW", errValidation, i)
		}
	}
	return nil
}

// VerifySnapshotAuthenticity returns nil iff the peer-supplied snapshot is authentic against
// proof of work: its genesis is OUR genesis, every header carries real cumulative PoW under
// the correct LWMA difficulty + seed, and the four header-committed roots match the restored
// accumulators. A malicious peer cannot forge any of these. It does NOT import/adopt the
// state — see this file's header for the two proven reasons sound network import additionally
// requires a state-root precursor + disk-backed-set transfer. This is the sound, reusable
// verification core a future bootstrap path builds on (and a useful light-client check today).
//
// It is read-only: it never mutates chain state.
func (c *Chain) VerifySnapshotAuthenticity(data []byte) error {
	c.mu.RLock()
	ourGenesis := c.headers[0].ID()
	haveGenesis := len(c.headers) > 0
	c.mu.RUnlock()
	if !haveGenesis {
		return fmt.Errorf("%w: local chain not initialized", errValidation)
	}

	var s chainSnapshot
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&s); err != nil {
		return fmt.Errorf("%w: snapshot decode: %v", errValidation, err)
	}
	if n := len(s.Headers); n == 0 || n > maxSnapshotHeaders {
		return fmt.Errorf("%w: snapshot header count out of range", errValidation)
	}
	// genesis binding: ID() hashes the WHOLE header, so equal IDs == identical genesis.
	if s.Headers[0].ID() != ourGenesis {
		return fmt.Errorf("%w: snapshot genesis mismatch (foreign network)", errValidation)
	}
	tip := s.Headers[len(s.Headers)-1]
	if tip.Height != s.Height {
		return fmt.Errorf("%w: snapshot tip height != declared height", errValidation)
	}
	// PoW + difficulty + seed + linkage over the whole header chain.
	if err := verifyHeaderChain(s.Headers); err != nil {
		return err
	}
	// the four header-committed roots must match the restored accumulators (so tampered
	// committed state is rejected — the roots are PoW-bound via the verified tip header).
	acc, err := accumulator.RestoreState(c.G, s.Acc)
	if err != nil {
		return fmt.Errorf("%w: snapshot acc restore", errValidation)
	}
	nullAcc, err := pqaccum.RestoreState(s.NullAcc)
	if err != nil {
		return fmt.Errorf("%w: snapshot nullAcc restore", errValidation)
	}
	pqAcc, err := pqaccum.RestoreState(s.PQAcc)
	if err != nil {
		return fmt.Errorf("%w: snapshot pqAcc restore", errValidation)
	}
	cmTree, ok := stark.LoadEpochIMTState(s.CMTree)
	if !ok {
		return fmt.Errorf("%w: snapshot cmTree restore failed", errValidation)
	}
	if !bytes.Equal(c.G.Marshal(acc.Value()), tip.AccValue) {
		return fmt.Errorf("%w: snapshot AccValue != tip header (tampered state)", errValidation)
	}
	if !bytes.Equal(nullAcc.Root(), tip.NullRoot[:]) {
		return fmt.Errorf("%w: snapshot NullRoot != tip header (tampered state)", errValidation)
	}
	if !bytes.Equal(pqAcc.Root(), tip.PQAccRoot[:]) {
		return fmt.Errorf("%w: snapshot PQAccRoot != tip header (tampered state)", errValidation)
	}
	if cmRootBytes(cmTree.CurrentRoot()) != tip.CMRoot {
		return fmt.Errorf("%w: snapshot CMRoot != tip header (tampered state)", errValidation)
	}
	return nil
}

// --- Verified network snapshot IMPORT (docs/SNAPSHOT_SYNC_DESIGN.md Stages 1–3) ---
//
// A fresh node fast-forwards past the body-pruning boundary by importing a peer's snapshot, but
// ONLY after verifying every part against PROOF OF WORK. State at height H is verified two ways,
// both PoW-bound:
//   - the four POST-state accumulator roots against header[H] (AccValue/NullRoot/PQAccRoot/CMRoot);
//   - the residual PRE-state root (emitted, incentivePool, the disk-set commitments, and ALL
//     in-RAM maps incl. pqUtxo amounts) against header[H+1].StateRoot.
// The disk-set MEMBERS (spent/tags/outPrimes) are transferred so the imported node can detect
// double-spends + output reuse; they are verified because their multiset commitments feed the
// residual StateRoot — a tampered/dropped/added member changes a commitment and is REJECTED.
//
// DOCUMENTED SCOPE GAP: the COIN set (anonymity set) is NOT transferred here, because CoinInfo
// does not persist the PrimeNonce needed to re-derive each coin's accumulator prime, so a
// transferred coin set could not be verified against AccValue (a peer could inject phantom
// spendable coins). Closing it needs a coin-set commitment / nonce persistence — a further
// precursor. So an imported node can validate double-spends and apply blocks that do NOT spend
// pre-snapshot coins (e.g. coinbase blocks); spending a pre-snapshot coin needs the coin set.

const maxSnapshotMembers = 200_000_000 // anti decode-bomb on each transferred member list

type transferSnapshot struct {
	State           []byte         // gob(chainSnapshot) at height H
	Headers         []block.Header // current chain 0..tip (tip ≥ H+1): PoW + post/pre-state roots
	SpentMembers    [][]byte
	TagsMembers     [][]byte
	OutPrimeMembers [][]byte
}

// encodeTransferSnapshotLocked builds a verifiable transfer snapshot from the newest SAVED
// snapshot at height ≤ tip-1 (so header[H+1] exists for the pre-state StateRoot check). Returns
// the bytes and the state height H. Caller holds the lock.
func (c *Chain) encodeTransferSnapshotLocked() ([]byte, uint64, error) {
	tip := c.headers[len(c.headers)-1].Height
	if tip == 0 {
		return nil, 0, fmt.Errorf("%w: chain too short to serve a transfer snapshot", errValidation)
	}
	stateBytes, h, ok := c.readSnapshotAtMostLocked(tip - 1)
	if !ok {
		return nil, 0, fmt.Errorf("%w: no saved snapshot at/below tip-1 to serve", errValidation)
	}
	var s chainSnapshot
	if err := gob.NewDecoder(bytes.NewReader(stateBytes)).Decode(&s); err != nil {
		return nil, 0, err
	}
	t := transferSnapshot{
		State:           stateBytes,
		Headers:         append([]block.Header(nil), c.headers...),
		SpentMembers:    c.spent.members(s.SpentCount),
		TagsMembers:     c.tags.members(s.TagsCount),
		OutPrimeMembers: c.outPrimes.members(s.OutPrimesCount),
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(&t); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), h, nil
}

// ExportTransferSnapshot produces a verifiable transfer snapshot for a peer (the serving side of
// network snapshot sync). Returns the bytes + the state height H. Takes the lock. Errors if the
// chain is too short / has no saved snapshot at/below tip-1 yet.
func (c *Chain) ExportTransferSnapshot() ([]byte, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.encodeTransferSnapshotLocked()
}

// VerifyAndImportSnapshot verifies a peer transfer snapshot against proof of work and, only if
// every check passes, adopts it as this (fresh) node's state. Returns the imported height. See
// the section header for the trust argument and the documented coin-set scope gap.
func (c *Chain) VerifyAndImportSnapshot(data []byte) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.headers) == 0 {
		return 0, fmt.Errorf("%w: local chain not initialized", errValidation)
	}
	ourGenesis := c.headers[0].ID()

	var t transferSnapshot
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&t); err != nil {
		return 0, fmt.Errorf("%w: transfer decode: %v", errValidation, err)
	}
	if n := len(t.Headers); n == 0 || n > maxSnapshotHeaders {
		return 0, fmt.Errorf("%w: transfer header count out of range", errValidation)
	}
	if len(t.SpentMembers) > maxSnapshotMembers || len(t.TagsMembers) > maxSnapshotMembers || len(t.OutPrimeMembers) > maxSnapshotMembers {
		return 0, fmt.Errorf("%w: transfer member list too large", errValidation)
	}
	var s chainSnapshot
	if err := gob.NewDecoder(bytes.NewReader(t.State)).Decode(&s); err != nil {
		return 0, fmt.Errorf("%w: transfer state decode: %v", errValidation, err)
	}
	H := s.Height

	// (1) genesis binding + full PoW header chain; require header[H+1] for the pre-state check.
	if t.Headers[0].ID() != ourGenesis {
		return 0, fmt.Errorf("%w: snapshot genesis mismatch (foreign network)", errValidation)
	}
	if uint64(len(t.Headers)) <= H+1 {
		return 0, fmt.Errorf("%w: transfer headers must extend past H+1 for the pre-state root check", errValidation)
	}
	if t.Headers[H].Height != H {
		return 0, fmt.Errorf("%w: transfer header index/height mismatch", errValidation)
	}
	if err := verifyHeaderChain(t.Headers); err != nil {
		return 0, err
	}

	// (1b) most-cumulative-work gate. verifyHeaderChain above proved every header's PoW and the
	// retarget schedule, so the summed difficulty below is REAL work, not a peer assertion. But a
	// valid-PoW chain can still be a minority / lower-work fork that merely happens to be TALLER
	// (e.g. a long run of low-difficulty blocks). Without comparing against our own tip, a peer
	// that advertises such a taller tip induces maybeRequestSnapshot to pull it and we would
	// overwrite a HEAVIER local chain — a remote ledger-replacement DoS (audit
	// SECURITY_AUDIT_2026-07-01 #2). Adopt only when the snapshot carries STRICTLY MORE cumulative
	// work than our current best tip (same Σ-difficulty metric forkchoice uses).
	snapWork := new(big.Int)
	for i := range t.Headers {
		snapWork.Add(snapWork, new(big.Int).SetUint64(t.Headers[i].Difficulty))
	}
	if local, ok := c.nodes[c.bestHash]; ok && local.work != nil && snapWork.Cmp(local.work) <= 0 {
		return 0, fmt.Errorf("%w: snapshot cumulative work %s ≤ local %s — refusing to adopt a non-heavier chain", errValidation, snapWork, local.work)
	}

	// (2) the four POST-state accumulator roots vs header[H].
	hH := t.Headers[H]
	acc, err := accumulator.RestoreState(c.G, s.Acc)
	if err != nil {
		return 0, fmt.Errorf("%w: snapshot acc restore", errValidation)
	}
	nullAcc, err := pqaccum.RestoreState(s.NullAcc)
	if err != nil {
		return 0, fmt.Errorf("%w: snapshot nullAcc restore", errValidation)
	}
	pqAcc, err := pqaccum.RestoreState(s.PQAcc)
	if err != nil {
		return 0, fmt.Errorf("%w: snapshot pqAcc restore", errValidation)
	}
	cmTree, ok := stark.LoadEpochIMTState(s.CMTree)
	if !ok {
		return 0, fmt.Errorf("%w: snapshot cmTree restore failed", errValidation)
	}
	if !bytes.Equal(c.G.Marshal(acc.Value()), hH.AccValue) {
		return 0, fmt.Errorf("%w: snapshot AccValue != header[H] (tampered state)", errValidation)
	}
	if !bytes.Equal(nullAcc.Root(), hH.NullRoot[:]) {
		return 0, fmt.Errorf("%w: snapshot NullRoot != header[H] (tampered state)", errValidation)
	}
	if !bytes.Equal(pqAcc.Root(), hH.PQAccRoot[:]) {
		return 0, fmt.Errorf("%w: snapshot PQAccRoot != header[H] (tampered state)", errValidation)
	}
	if cmRootBytes(cmTree.CurrentRoot()) != hH.CMRoot {
		return 0, fmt.Errorf("%w: snapshot CMRoot != header[H] (tampered state)", errValidation)
	}

	// (3) disk-set member counts match + residual PRE-state root vs header[H+1].
	if uint64(len(t.SpentMembers)) != s.SpentCount || uint64(len(t.TagsMembers)) != s.TagsCount || uint64(len(t.OutPrimeMembers)) != s.OutPrimesCount {
		return 0, fmt.Errorf("%w: transfer member count != snapshot count", errValidation)
	}
	rs := residualState{
		emitted: s.Emitted, incentivePool: s.IncentivePool,
		spentCommit: commitOfMembers(t.SpentMembers), tagsCommit: commitOfMembers(t.TagsMembers), outPrimeCommit: commitOfMembers(t.OutPrimeMembers),
		swapNonces: nzBool(s.SwapNonces), accValues: nzBool(s.AccValues), pqNull: nzBool(s.PQNull), pqWots: nzBool(s.PQWots), pqRoots: nzBool(s.PQRoots),
		cmRoots: nzBool(s.CMRoots), cmFinal: nzBool(s.CMFinal), zkNull: nzBool(s.ZKNull),
		referral: nzU64(s.Referral), pqIndex: nzInt(s.PQIndex), cmRootOrder: s.CMRootOrder,
		swaps: nzMap(s.Swaps), vaults: nzMap(s.Vaults), pqUtxo: nzMap(s.PQUtxo),
	}
	if stateRootOf(rs) != t.Headers[H+1].StateRoot {
		return 0, fmt.Errorf("%w: residual state-root != header[H+1] (tampered uncommitted state)", errValidation)
	}

	// ALL VERIFIED — commit. Import disk-set members FIRST (rebuilds commits + per-count records
	// + counts in bolt), then restore the rest; restoreSnapshotLocked's setCount then reads the
	// per-count commit the imports just recorded.
	//
	// The sets must be RESET first: importMembers requires a fresh set, and a node that
	// already applied blocks before adopting this (heavier, fully verified) snapshot has
	// members whose duplicate Adds would shift the per-count commit records, wedging the
	// node on "state-root mismatch" for every later block (see disksetreset.go). Safe
	// here — every verification above has already passed.
	c.spent.resetForImport()
	c.tags.resetForImport()
	c.outPrimes.resetForImport()
	c.spent.importMembers(t.SpentMembers)
	c.tags.importMembers(t.TagsMembers)
	c.outPrimes.importMembers(t.OutPrimeMembers)
	if err := c.restoreSnapshotLocked(t.State); err != nil {
		return 0, fmt.Errorf("%w: snapshot commit: %v", errValidation, err)
	}
	c.indexActiveChain() // rebuild the fork-choice node tree from the restored headers so the
	// imported tip is recognized and the next block (H+1) can extend it (mirrors New()/replay()).
	return H, nil
}
