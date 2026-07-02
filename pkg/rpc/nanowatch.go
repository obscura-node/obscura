package rpc

import (
	"fmt"
	"math/big"
	"net/http"
	"time"
)

// handleNanoWatch streams a Server-Sent Events feed that pushes a "deposit" event
// the instant new XNO (confirmed balance + still-pending receivable) arrives for an
// account. A funding notification is one-way (server→client), so SSE — plain HTTP,
// no framing, no dependency, with EventSource auto-reconnect on the client — is the
// right primitive (vs a full websocket).
//
// The node polls the Nano backend SERVER-SIDE, so the browser never connects to the
// Nano node (no IP leak; same privacy model as the rest of the relay) and one poll
// loop serves the client. Same-origin only (CSP connect-src 'self'). Where a stream
// cannot be held end-to-end (a serverless proxy in front of the node), the client
// detects the missing "ready" and falls back to plain polling.
func (s *Server) handleNanoWatch(w http.ResponseWriter, r *http.Request) {
	cors(w)
	acct := r.URL.Query().Get("account")
	if !validNanoAccount(acct) {
		httpErr(w, http.StatusBadRequest, "valid nano_ account required")
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok || s.nanoPub == nil {
		httpErr(w, http.StatusServiceUnavailable, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // ask any reverse proxy not to buffer

	// total = confirmed balance + pending receivable (both raw). A pending deposit
	// already means "funded" because the buy flow pockets receivables.
	total := func() *big.Int {
		t := new(big.Int)
		if info, err := s.nanoPub.AccountInfo(acct); err == nil && info.Balance != nil {
			t.Add(t, info.Balance)
		}
		if _, amt, ok := s.nanoPub.Receivable(acct); ok && amt != "" {
			if v, good := new(big.Int).SetString(amt, 10); good {
				t.Add(t, v)
			}
		}
		return t
	}

	baseline := total()
	fmt.Fprintf(w, "event: ready\ndata: {\"account\":%q,\"total\":%q}\n\n", acct, baseline.String())
	fl.Flush()

	poll := time.NewTicker(3 * time.Second)
	defer poll.Stop()
	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()
	stop := time.NewTimer(15 * time.Minute) // bound the stream; client reconnects
	defer stop.Stop()
	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stop.C:
			fmt.Fprint(w, "event: bye\ndata: {}\n\n")
			fl.Flush()
			return
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			fl.Flush()
		case <-poll.C:
			cur := total()
			if cur.Cmp(baseline) > 0 {
				delta := new(big.Int).Sub(cur, baseline)
				fmt.Fprintf(w, "event: deposit\ndata: {\"account\":%q,\"total\":%q,\"delta\":%q}\n\n",
					acct, cur.String(), delta.String())
				fl.Flush()
				baseline = cur
			}
		}
	}
}
