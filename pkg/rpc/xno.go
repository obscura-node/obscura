package rpc

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"

	"filippo.io/edwards25519"

	"obscura/pkg/swapd"
)

// XNO PROCEEDS WALLET
//
// The miner auto-sells OBX for XNO; the XNO it receives is swept to a Nano
// account derived from the miner seed (swapd.MinerXNOAccount, domain
// "Obscura/xno-proceeds/v1"). These handlers give the operator a real,
// recoverable view of those proceeds:
//
//   - GET  /xno/account   PUBLIC, read-only, NO secret. Returns the nano_
//     address + live balance/receivable (via the real NanoRPC when configured,
//     else zeros + "backend":"mock"). Safe to proxy from the public website.
//
//   - GET  /xno/recovery  OPERATOR-GATED (loopback / OBX_RPC_TOKEN). Reveals the
//     seed-derived XNO secret hex for local backup. The ONLY way to read the
//     secret, and it is NEVER public-proxied.
//
//   - POST /xno/withdraw  OPERATOR-GATED. Moves XNO to an external nano_ dest.
//     The secret is derived in-process and used to sign; it is NEVER returned.
//
// The miner seed and Nano client are injected by the node via SetXNO. With no
// real Nano, /xno/account still returns the derived address (mock backend) and
// withdraw fails loudly; recovery still works (local backup of the secret).

// xnoLedger is the subset of the Nano client the XNO proceeds wallet needs:
// read balance/receivable and send. Satisfied by *swapd.NanoRPC. Kept narrow so
// the mock-backend path (nil ledger) is unambiguous.
type xnoLedger interface {
	Balance(dest string) *big.Int
	Receivable(account string) (blockHash, amountRaw string, ok bool)
	Send(fromSecret *edwards25519.Scalar, amountRaw *big.Int, dest string) error
}

// SetXNO injects the miner seed (to derive the XNO proceeds account + sign
// withdrawals in-process) and the Nano ledger client. A nil ledger keeps
// /xno/account working with the derived address and "backend":"mock"; recovery
// still works; withdraw refuses. The seed is held only in-process and is never
// emitted over the public proxy — only /xno/recovery (operator-gated) reveals it.
func (s *Server) SetXNO(seed []byte, ledger xnoLedger) {
	s.xnoSeed = append([]byte(nil), seed...)
	// A typed-nil concrete client passed through an interface would be non-nil;
	// guard against that so NanoEnabled-style checks stay honest.
	s.xnoLedger = ledger
}

// xnoAccount derives the proceeds account (secret, pubkey, nano_ address) from
// the injected miner seed. Returns ok=false when no seed has been injected.
func (s *Server) xnoAccount() (sec *edwards25519.Scalar, pub []byte, addr string, ok bool) {
	if len(s.xnoSeed) == 0 {
		return nil, nil, "", false
	}
	sec, pub, addr, err := swapd.MinerXNOAccount(s.xnoSeed)
	if err != nil {
		return nil, nil, "", false
	}
	return sec, pub, addr, true
}

// XNOAccountResponse is the PUBLIC read-only proceeds view. No secret material.
type XNOAccountResponse struct {
	Address       string `json:"address"`
	BalanceRaw    string `json:"balance_raw"`
	ReceivableRaw string `json:"receivable_raw"`
	Backend       string `json:"backend"` // "real" when a Nano RPC is wired, else "mock"
}

// handleXNOAccount serves the miner's XNO proceeds account: the derived nano_
// address plus live balance + receivable. PUBLIC and read-only — it never
// touches the secret. When no real Nano client is wired the balances are zero
// and backend is "mock" (so the UI never presents simulated proceeds as real).
func (s *Server) handleXNOAccount(w http.ResponseWriter, r *http.Request) {
	// audit BUG-1: do not expose the operator's XNO proceeds account (address + balance) to a
	// public web visitor arriving through the hosted UI proxy — that links the operator's node
	// to a traceable Nano account. Direct callers (local operator, or a node that deliberately
	// exposes its RPC) are unaffected; only the hosted-proxy public path is refused.
	if proxiedPublic(r) && !s.hasBearer(r) {
		httpErr(w, http.StatusForbidden, "forbidden: the XNO proceeds account is operator-only on a public node")
		return
	}
	_, _, addr, ok := s.xnoAccount()
	if !ok {
		httpErr(w, http.StatusServiceUnavailable, "xno proceeds account unavailable (no miner seed wired)")
		return
	}
	resp := XNOAccountResponse{Address: addr, BalanceRaw: "0", ReceivableRaw: "0", Backend: "mock"}
	if s.xnoLedger != nil {
		resp.Backend = "real"
		if bal := s.xnoLedger.Balance(addr); bal != nil {
			resp.BalanceRaw = bal.String()
		}
		if _, amtRaw, got := s.xnoLedger.Receivable(addr); got && amtRaw != "" {
			resp.ReceivableRaw = amtRaw
		}
	}
	writeJSON(w, resp)
}

// XNORecoveryResponse reveals the seed-derived XNO secret for LOCAL backup.
// OPERATOR-GATED and never public-proxied.
type XNORecoveryResponse struct {
	Address   string `json:"address"`
	SecretHex string `json:"secret_hex"` // 32-byte ed25519 scalar (the XNO spend key)
	PubHex    string `json:"pub_hex"`
	Note      string `json:"note"`
}

// handleXNORecovery reveals the XNO proceeds secret so the operator can back it
// up / import it into a Nano wallet and recover the funds anywhere. This is the
// ONLY endpoint that exposes the secret; it is operator-gated (loopback / token)
// and MUST NOT be added to the public proxy whitelist.
func (s *Server) handleXNORecovery(w http.ResponseWriter, r *http.Request) {
	sec, pub, addr, ok := s.xnoAccount()
	if !ok {
		httpErr(w, http.StatusServiceUnavailable, "xno proceeds account unavailable (no miner seed wired)")
		return
	}
	writeJSON(w, XNORecoveryResponse{
		Address:   addr,
		SecretHex: hex.EncodeToString(sec.Bytes()),
		PubHex:    hex.EncodeToString(pub),
		Note:      "This is the spend key for your XNO proceeds account. Back it up offline. Anyone with it can spend these funds. Domain: Obscura/xno-proceeds/v1.",
	})
}

// handleXNOWithdraw sends XNO from the proceeds account to an external nano_
// destination. OPERATOR-GATED. The secret is derived in-process and used to
// sign; it is NEVER returned. Requires a real Nano client (no withdraw on the
// mock backend).
func (s *Server) handleXNOWithdraw(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	sec, _, _, ok := s.xnoAccount()
	if !ok {
		httpErr(w, http.StatusServiceUnavailable, "xno proceeds account unavailable (no miner seed wired)")
		return
	}
	if s.xnoLedger == nil {
		httpErr(w, http.StatusServiceUnavailable, "xno withdraw unavailable: no Nano RPC configured (mock backend); set --nano-rpc")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req struct {
		AmountRaw string `json:"amount_raw"`
		Dest      string `json:"dest"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, "bad json")
		return
	}
	amount, good := new(big.Int).SetString(req.AmountRaw, 10)
	if !good || amount.Sign() <= 0 {
		httpErr(w, http.StatusBadRequest, "bad amount_raw (want a positive decimal raw string)")
		return
	}
	if _, err := swapd.DecodeNanoAddress(req.Dest); err != nil {
		httpErr(w, http.StatusBadRequest, "bad dest: "+err.Error())
		return
	}
	if err := s.xnoLedger.Send(sec, amount, req.Dest); err != nil {
		httpErr(w, http.StatusBadGateway, "send failed: "+err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "sent", "amount_raw": amount.String(), "dest": req.Dest})
}
