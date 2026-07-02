package p2p

import (
	"encoding/binary"
	"os"
	"strconv"
	"time"
)

// Snapshot fast-sync (P2P transport for the chain's verified snapshot import). A node that is
// FAR behind a peer (e.g. fresh or long-restarted) fast-forwards by downloading the peer's
// verified transfer snapshot instead of re-verifying every historical block (which is ~1 block/s
// dominated by the class-group accumulator). The chain side is already built + tested:
// chain.ExportTransferSnapshot (serve) and chain.VerifyAndImportSnapshot (receive, PoW-verified,
// adversarial reject-tests green). This file only adds the wire transport + a bounded trigger.
//
// SAFETY: this is a SEPARATE code path from steady-state block sync (msgTip/msgGetBlk/msgBlock),
// which is unchanged. It fires ONLY when a node is > snapSyncGap behind, at most one transfer in
// flight, with a hard byte cap + timeout (anti-DoS), and the import itself rejects any tampered/
// fake-PoW/foreign snapshot. On import failure it simply falls back to normal block sync.
//
// RESILIENCE (P2P robustness): the transfer now SURVIVES chunk loss. A watcher goroutine
// monitors progress; when no chunk has arrived for snapStallAfter it RE-REQUESTS only the
// missing chunk indexes from the pinned peer (msgGetSnapshot with a targeted payload:
// [8B height][4B count][count × 4B seq]) up to snapMaxRetries times before abandoning the
// transfer (block sync then resumes as before). Old peers ignore the payload and re-serve the
// full snapshot; the receiver deduplicates already-held chunks, so the retry remains
// backward-compatible.

const snapMaxChunks = 8192 // bound on chunk count (anti-DoS)

// Tunables. Vars (not consts) so the chunking/retry/abandon paths are
// unit-testable with small sizes and tight timings; production defaults here.
var (
	snapChunkSize   = maxMsgBytes - 64 // payload bytes per chunk (room for the 16B header)
	snapMaxBytes    = 1 << 30          // 1 GiB hard cap on a reassembled snapshot (anti-DoS)
	snapXferTimeout = 90 * time.Second // a stalled transfer is abandoned (then block-sync resumes)
	snapStallAfter  = 10 * time.Second // no chunk for this long → targeted re-request of the gaps
	snapWatchTick   = time.Second      // watcher poll interval
	snapMaxRetries  = 3                // targeted re-requests before the transfer is abandoned
)

// snapSyncGap: trigger snapshot fast-sync when this many blocks behind a peer. Env-overridable
// (OBX_SNAP_SYNC_GAP) for devnet/testing; default 200 (below that, block-sync is fine).
var snapSyncGap uint64 = 200

func init() {
	if v := os.Getenv("OBX_SNAP_SYNC_GAP"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			snapSyncGap = n
		}
	}
}

// snapXfer is the in-flight INBOUND snapshot reassembly state (one at a time per node).
type snapXfer struct {
	from      string   // peer remote addr we requested from (only this peer's chunks are accepted)
	peer      *peer    // pinned peer handle for targeted re-requests
	total     uint32   // total chunks (0 until the first chunk sets it)
	height    uint64   // snapshot height (pinned by the first chunk; mismatching chunks are ignored)
	chunks    [][]byte // received chunks indexed by seq
	got       int      // distinct chunks received
	bytes     int      // bytes accumulated (bounded by snapMaxBytes)
	deadline  time.Time
	lastChunk time.Time // when the last NEW chunk arrived (stall detection)
	retries   int       // targeted re-requests issued so far
}

// missingLocked returns the chunk indexes not yet received. nil when total is
// still unknown (no chunk arrived at all — the retry then re-requests the full
// snapshot). Caller holds n.snapMu.
func (x *snapXfer) missingLocked() []uint32 {
	if x.total == 0 {
		return nil
	}
	out := make([]uint32, 0, int(x.total)-x.got)
	for i := uint32(0); i < x.total; i++ {
		if x.chunks[i] == nil {
			out = append(out, i)
		}
	}
	return out
}

// encodeSnapReq builds the targeted re-request payload: [8B height][4B count][count × 4B seq].
// A nil/empty seq list yields a nil payload (= "send everything", the original request form).
func encodeSnapReq(height uint64, seqs []uint32) []byte {
	if len(seqs) == 0 {
		return nil
	}
	b := make([]byte, 12+4*len(seqs))
	binary.BigEndian.PutUint64(b[0:], height)
	binary.BigEndian.PutUint32(b[8:], uint32(len(seqs)))
	for i, s := range seqs {
		binary.BigEndian.PutUint32(b[12+4*i:], s)
	}
	return b
}

// decodeSnapReq parses a targeted re-request payload. ok=false means the payload
// is absent/malformed and the serve should fall back to the full snapshot.
func decodeSnapReq(payload []byte) (height uint64, seqs []uint32, ok bool) {
	if len(payload) < 12 {
		return 0, nil, false
	}
	height = binary.BigEndian.Uint64(payload[0:])
	cnt := binary.BigEndian.Uint32(payload[8:])
	if cnt == 0 || cnt > snapMaxChunks || len(payload) != 12+4*int(cnt) {
		return 0, nil, false
	}
	seqs = make([]uint32, cnt)
	for i := range seqs {
		seqs[i] = binary.BigEndian.Uint32(payload[12+4*i:])
	}
	return height, seqs, true
}

// maybeRequestSnapshot starts a snapshot fast-sync from p if we are far behind and none is in
// flight. Called from the msgTip handler.
func (n *Node) maybeRequestSnapshot(p *peer, peerH, ourH uint64) {
	if peerH <= ourH+snapSyncGap {
		return
	}
	n.snapMu.Lock()
	if n.snapXfer != nil && time.Now().Before(n.snapXfer.deadline) {
		n.snapMu.Unlock()
		return // a transfer is already in progress
	}
	now := time.Now()
	x := &snapXfer{from: p.conn.RemoteAddr().String(), peer: p,
		deadline: now.Add(snapXferTimeout), lastChunk: now}
	n.snapXfer = x
	n.snapMu.Unlock()
	p2pLog("snapshot fast-sync: %d behind %s (peer %d / ours %d), requesting snapshot", peerH-ourH, p.conn.RemoteAddr(), peerH, ourH)
	_ = n.send(p, msgGetSnapshot, nil)
	go n.snapWatch(x)
}

// snapWatch monitors one inbound transfer: on a chunk gap (no new chunk for
// snapStallAfter) it re-requests ONLY the missing chunk indexes from the pinned
// peer, up to snapMaxRetries times; on timeout / exhausted retries it abandons
// the transfer so normal block sync (and a later fresh snapshot attempt) resume.
func (n *Node) snapWatch(x *snapXfer) {
	t := time.NewTicker(snapWatchTick)
	defer t.Stop()
	for {
		select {
		case <-n.done:
			return
		case <-t.C:
		}
		n.snapMu.Lock()
		if n.snapXfer != x {
			n.snapMu.Unlock()
			return // completed, abandoned, or replaced — nothing to watch
		}
		now := time.Now()
		if now.After(x.deadline) {
			n.snapXfer = nil
			n.snapMu.Unlock()
			p2pLog("snapshot fast-sync: transfer from %s timed out (%d/%d chunks) — abandoned, block sync resumes", x.from, x.got, x.total)
			return
		}
		if now.Sub(x.lastChunk) < snapStallAfter {
			n.snapMu.Unlock()
			continue // still flowing
		}
		if x.retries >= snapMaxRetries {
			n.snapXfer = nil
			n.snapMu.Unlock()
			p2pLog("snapshot fast-sync: transfer from %s still incomplete after %d re-requests (%d/%d chunks) — abandoned, block sync resumes", x.from, x.retries, x.got, x.total)
			return
		}
		x.retries++
		x.lastChunk = now                     // restart the stall clock for this retry
		x.deadline = now.Add(snapXferTimeout) // a live retry earns a fresh window
		missing := x.missingLocked()
		req := encodeSnapReq(x.height, missing)
		p, retry := x.peer, x.retries
		n.snapMu.Unlock()
		if req == nil {
			p2pLog("snapshot fast-sync: no chunks from %s yet — re-requesting full snapshot (retry %d/%d)", x.from, retry, snapMaxRetries)
		} else {
			p2pLog("snapshot fast-sync: stalled at %d/%d chunks from %s — re-requesting %d missing (retry %d/%d)", x.got, x.total, x.from, len(missing), retry, snapMaxRetries)
		}
		_ = n.send(p, msgGetSnapshot, req)
	}
}

// SnapshotSyncState reports the inbound snapshot-transfer state for /status:
// "idle" when nothing is in flight, "receiving" with chunk progress otherwise.
// Aggregate only (never reveals the serving peer).
func (n *Node) SnapshotSyncState() (state string, receivedChunks, totalChunks int) {
	n.snapMu.Lock()
	defer n.snapMu.Unlock()
	x := n.snapXfer
	if x == nil || time.Now().After(x.deadline) {
		return "idle", 0, 0
	}
	return "receiving", x.got, int(x.total)
}

// serveSnapshot answers a peer's msgGetSnapshot by streaming the verified transfer snapshot in
// chunks. Run in its own goroutine (the export can be large); msgGetSnapshot is rate-limited so a
// peer cannot spam expensive exports. An optional targeted payload ([8B height][4B count][seqs])
// re-serves ONLY the listed chunks of the snapshot at that height (the receiver's gap retry);
// if our current snapshot height has moved past the requested one, nothing is served — the
// receiver's retry/abandon logic then restarts cleanly on a fresh snapshot.
func (n *Node) serveSnapshot(p *peer, req []byte) {
	// This runs in a DETACHED goroutine (go n.serveSnapshot(p, req)); the per-connection
	// recover() does NOT cover it, so a panic here would crash the whole node. Guard it.
	defer func() {
		if r := recover(); r != nil {
			p2pLog("serveSnapshot panic recovered: %v", r)
		}
	}()
	data, h, err := n.chain.ExportTransferSnapshot()
	if err != nil || len(data) == 0 {
		p2pLog("serve snapshot to %s -> none (%v)", p.conn.RemoteAddr(), err)
		return
	}
	total := (len(data) + snapChunkSize - 1) / snapChunkSize
	if total == 0 || total > snapMaxChunks {
		return
	}
	// Targeted re-request: serve only the listed chunks, and only if the snapshot
	// height still matches (a moved snapshot would send chunks the receiver must
	// ignore — cheaper to send nothing and let it restart fresh).
	var want []uint32
	if reqH, seqs, ok := decodeSnapReq(req); ok {
		if reqH != h {
			p2pLog("serve snapshot to %s -> targeted request for h=%d but snapshot is h=%d; not serving", p.conn.RemoteAddr(), reqH, h)
			return
		}
		for _, s := range seqs {
			if int(s) < total {
				want = append(want, s)
			}
		}
		if len(want) == 0 {
			return
		}
	} else {
		want = make([]uint32, total)
		for i := range want {
			want[i] = uint32(i)
		}
	}
	p2pLog("serve snapshot h=%d (%d bytes, %d/%d chunks) to %s", h, len(data), len(want), total, p.conn.RemoteAddr())
	for _, i := range want {
		lo := int(i) * snapChunkSize
		hi := lo + snapChunkSize
		if hi > len(data) {
			hi = len(data)
		}
		hdr := make([]byte, 16)
		binary.BigEndian.PutUint32(hdr[0:], i)
		binary.BigEndian.PutUint32(hdr[4:], uint32(total))
		binary.BigEndian.PutUint64(hdr[8:], h)
		if err := n.send(p, msgSnapshot, append(hdr, data[lo:hi]...)); err != nil {
			return // peer gone; abandon
		}
	}
}

// recvSnapshotChunk reassembles inbound snapshot chunks; on completion it verifies+imports.
func (n *Node) recvSnapshotChunk(p *peer, payload []byte) {
	if len(payload) < 16 {
		return
	}
	seq := binary.BigEndian.Uint32(payload[0:])
	total := binary.BigEndian.Uint32(payload[4:])
	height := binary.BigEndian.Uint64(payload[8:])
	chunk := payload[16:]
	remote := p.conn.RemoteAddr().String()

	n.snapMu.Lock()
	x := n.snapXfer
	// only accept chunks for an in-flight transfer we requested from THIS peer, not expired.
	if x == nil || x.from != remote || time.Now().After(x.deadline) {
		n.snapMu.Unlock()
		return
	}
	if total == 0 || total > snapMaxChunks || seq >= total {
		n.snapMu.Unlock()
		return
	}
	if x.total == 0 {
		x.total = total
		x.height = height
		x.chunks = make([][]byte, total)
	}
	if x.total != total || x.height != height {
		n.snapMu.Unlock()
		return // total/height changed mid-transfer: malformed or a moved snapshot — ignore
	}
	if x.chunks[seq] == nil {
		x.bytes += len(chunk)
		if x.bytes > snapMaxBytes {
			n.snapXfer = nil // anti-DoS: abandon an over-large transfer
			n.snapMu.Unlock()
			return
		}
		x.chunks[seq] = append([]byte(nil), chunk...)
		x.got++
		x.lastChunk = time.Now() // progress: reset the stall clock
	}
	complete := x.got == int(x.total)
	var full []byte
	if complete {
		for _, c := range x.chunks {
			full = append(full, c...)
		}
		n.snapXfer = nil
	}
	n.snapMu.Unlock()

	if !complete {
		return
	}
	h, err := n.chain.VerifyAndImportSnapshot(full)
	if err != nil {
		p2pLog("snapshot import from %s REJECTED: %v (falling back to block sync)", remote, err)
		return
	}
	p2pLog("snapshot IMPORTED from %s -> tip now %d", remote, h)
	// Blocks that arrived DURING the transfer were buffered as parent-unknown
	// orphans; the import just made their parents known without AddBlock ever
	// running, so trigger the normal orphan-connect sweep or sync wedges one
	// block short of the tip (re-sent copies dedupe against the buffer).
	n.chain.ResumeOrphans()
	_ = n.send(p, msgGetTip, nil) // resume normal block sync for the recent tail
}
