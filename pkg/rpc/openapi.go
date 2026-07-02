package rpc

// GET /openapi.json — a machine-readable OpenAPI 3.0 description of the WHOLE
// RPC surface, built as plain Go data (stdlib only) and kept in lockstep with
// the real route table: the drift test asserts every mux-registered route has
// a spec entry and vice versa. Response schemas are loosely typed (objects
// with their key properties) — the prose contract remains docs/API.md.

import (
	"encoding/json"
	"net/http"
	"strings"
)

// oaExtraPaths are spec paths that are NOT registered on the pkg/rpc mux but
// belong to the node's public HTTP surface (added by cmd/obscura-node's wrapper
// mux in front of the RPC handler). The drift test allowlists them.
var oaExtraPaths = map[string]bool{
	"/auto-liquidity": true,
}

// specPathFor maps a mux route pattern to its OpenAPI path (prefix routes gain
// a path parameter).
func specPathFor(route string) string {
	if route == "/order/" {
		return "/order/{id}"
	}
	return route
}

// ---- tiny schema builders ----------------------------------------------------

func oaSchema(typ, desc string) map[string]any {
	m := map[string]any{"type": typ}
	if desc != "" {
		m["description"] = desc
	}
	return m
}

func oaStr(desc string) map[string]any  { return oaSchema("string", desc) }
func oaInt(desc string) map[string]any  { return oaSchema("integer", desc) }
func oaBool(desc string) map[string]any { return oaSchema("boolean", desc) }

func oaObj(desc string, props map[string]any) map[string]any {
	m := map[string]any{"type": "object"}
	if desc != "" {
		m["description"] = desc
	}
	if props != nil {
		m["properties"] = props
	}
	return m
}

func oaArr(desc string, items map[string]any) map[string]any {
	m := map[string]any{"type": "array", "items": items}
	if desc != "" {
		m["description"] = desc
	}
	return m
}

// oaQ builds one query parameter.
func oaQ(name, typ, desc string, required bool) map[string]any {
	return map[string]any{
		"name": name, "in": "query", "required": required,
		"description": desc, "schema": map[string]any{"type": typ},
	}
}

// oaErrSchema is the unified error envelope every error response carries.
func oaErrSchema() map[string]any {
	return oaObj("unified error envelope", map[string]any{
		"error": oaStr("human-readable message"),
		"code":  oaInt("HTTP status code (mirrors the response status)"),
	})
}

// oaOp assembles one operation. contentType "" means application/json.
func oaOp(tag, summary string, params []map[string]any, reqBody map[string]any,
	respSchema map[string]any, contentType string, operatorGated bool) map[string]any {
	if contentType == "" {
		contentType = "application/json"
	}
	if respSchema == nil {
		respSchema = oaObj("", nil)
	}
	op := map[string]any{
		"tags":    []string{tag},
		"summary": summary,
		"responses": map[string]any{
			"200": map[string]any{
				"description": "OK",
				"content":     map[string]any{contentType: map[string]any{"schema": respSchema}},
			},
			"default": map[string]any{
				"description": "Error ({\"error\":...,\"code\":...} with the matching HTTP status)",
				"content":     map[string]any{"application/json": map[string]any{"schema": oaErrSchema()}},
			},
		},
	}
	if len(params) > 0 {
		op["parameters"] = params
	}
	if reqBody != nil {
		op["requestBody"] = map[string]any{
			"required": true,
			"content":  map[string]any{"application/json": map[string]any{"schema": reqBody}},
		}
	}
	if operatorGated {
		op["security"] = []map[string]any{{"bearerAuth": []string{}}}
		op["description"] = "OPERATOR endpoint: loopback callers always allowed; remote callers need Authorization: Bearer <OBX_RPC_TOKEN>."
	}
	return op
}

func oaGet(op map[string]any) map[string]any  { return map[string]any{"get": op} }
func oaPost(op map[string]any) map[string]any { return map[string]any{"post": op} }

// pagination params shared by the list endpoints.
func oaPageParams(defLimit, capLimit string) []map[string]any {
	return []map[string]any{
		oaQ("limit", "integer", "max rows returned (default "+defLimit+", cap "+capLimit+")", false),
		oaQ("offset", "integer", "rows to skip before returning (default 0)", false),
	}
}

// openAPISpec builds the full document. Kept as one function so the paths map
// reads top-to-bottom like the route table in Handler().
func openAPISpec() map[string]any {
	hexAmount := oaStr("raw atomic amount as a decimal string (never a float)")

	statusSchema := oaObj("node status", map[string]any{
		"coin": oaStr(""), "ticker": oaStr(""), "height": oaInt(""),
		"difficulty": oaInt(""), "emitted_atomic": oaInt(""), "emitted_obx": oaStr(""),
		"incentive_pool_atomic": oaInt(""), "accumulator_size": oaInt(""),
		"accumulator_backend": oaStr(""), "pow_backend": oaStr(""),
		"mempool_size": oaInt(""), "tip_height": oaInt(""), "peer_count": oaInt(""),
		"best_known_height": oaInt("omitted when no peer advertises a height"),
		"synced":            oaBool(""), "sync_basis": oaStr("how `synced` was derived"),
		"blocks_behind":          oaInt("max(best_known_height - tip_height, 0); 0 when no peer height is known"),
		"last_block_age_seconds": oaInt("now - tip block header timestamp"),
		"snapshot_sync": oaObj("p2p snapshot fast-sync receiver state (omitted when the peer layer can't report it)", map[string]any{
			"state":           oaStr("idle|receiving"),
			"received_chunks": oaInt("chunks received so far (receiving only)"),
			"total_chunks":    oaInt("total chunks expected; 0 until the first chunk arrives"),
		}),
	})
	offerSchema := oaObj("decoded order-book offer", map[string]any{
		"id": oaStr("hex offer id"), "maker": oaStr("hex maker pubkey"),
		"give_asset": oaStr(""), "get_asset": oaStr(""),
		"give_amount": oaInt(""), "get_amount": oaInt(""),
		"rate": oaStr("get/give decimal string"), "expiry": oaInt("unix seconds"),
	})
	tradeSchema := oaObj("one executed fill", map[string]any{
		"pair": oaStr(""), "price": oaStr("raw atomic get/give"),
		"give": hexAmount, "get": hexAmount,
		"maker": oaStr("hex pubkey"), "taker": oaStr("hex pubkey"),
		"swap_key": oaStr("on-chain settlement join key"), "time": oaInt("unix seconds"),
	})
	orderSchema := oaObj("one maker order + fill state", map[string]any{
		"id": oaStr(""), "give_asset": oaStr(""), "get_asset": oaStr(""),
		"give_amount": oaInt(""), "get_amount": oaInt(""),
		"remaining_give": hexAmount, "remaining_get": hexAmount,
		"status": oaStr("open|partial|filled|..."), "expiry": oaInt(""),
	})
	swapEventSchema := oaObj("one on-chain swap lifecycle event", map[string]any{
		"kind": oaStr("funded|claimed|refunded"), "swap_key": oaStr(""),
		"amount_obx": oaStr(""), "height": oaInt(""), "unlock_height": oaInt(""),
		"time": oaInt(""), "txid": oaStr(""),
	})
	sessionSchema := oaObj("one in-flight swap session", map[string]any{
		"id": oaStr("display-only hashed id"), "role": oaStr("maker|taker"),
		"phase": oaStr(""), "obx_amount": hexAmount, "xno_amount": hexAmount,
		"steps":   oaArr("", oaObj("", map[string]any{"name": oaStr(""), "done": oaBool("")})),
		"updated": oaInt("unix seconds"),
	})

	accountParam := oaQ("account", "string", "nano_ address (validated shape + checksum)", true)
	pairParam := oaQ("pair", "string", "taker-orientation GIVE/GET, e.g. XNO/OBX", false)

	paths := map[string]any{
		// --- core/chain -------------------------------------------------------
		"/status": oaGet(oaOp("core/chain", "Node status + sync/health verdict", nil, nil, statusSchema, "", false)),
		"/health": oaGet(oaOp("core/chain", "Readiness probe: 200 ok while the chain backend serves; 503 degraded when it is missing OR sync is stalled (peers connected, blocks_behind > reorg-finality depth, no tip advance for > 20×target block time) — `reason` names the cause", nil, nil,
			oaObj("", map[string]any{
				"status": oaStr("ok|degraded"), "reason": oaStr("why status is degraded (omitted when ok)"),
				"tip_height": oaInt(""), "synced": oaBool(""),
				"peer_count": oaInt(""), "blocks_behind": oaInt(""),
				"last_block_age_seconds": oaInt(""), "uptime_seconds": oaInt(""),
			}), "", false)),
		"/healthz": oaGet(oaOp("core/chain", "Liveness probe (plain text \"ok\")", nil, nil, oaStr("ok"), "text/plain", false)),
		"/metrics": oaGet(oaOp("core/chain", "Prometheus text exposition v0.0.4 (obx_tip_height, obx_peer_count, obx_mempool_size, obx_synced, obx_blocks_behind, obx_last_block_age_seconds, obx_uptime_seconds, obx_http_requests_total, obx_http_request_duration_seconds)",
			nil, nil, oaStr("Prometheus exposition text"), "text/plain", false)),
		"/openapi.json": oaGet(oaOp("core/chain", "This document", nil, nil, oaObj("OpenAPI 3.0 document", nil), "", false)),
		"/version": oaGet(oaOp("core/chain", "Node + network identity (use network+genesis_hash to confirm the chain)", nil, nil,
			oaObj("", map[string]any{
				"coin": oaStr(""), "ticker": oaStr(""), "software_version": oaStr(""),
				"protocol_version": oaInt(""), "network": oaStr(""), "genesis_hash": oaStr(""),
				"accumulator_backend": oaStr(""),
			}), "", false)),
		"/params": oaGet(oaOp("core/chain", "Machine-readable consensus/economic constants (read at boot; do not hardcode)", nil, nil,
			oaObj("", map[string]any{
				"decimals": oaObj("per-asset display decimals", nil), "obx_atomic_per_coin": oaInt(""),
				"min_fee_per_byte": oaInt(""), "swap_fee_atomic": oaInt(""),
				"vault_terms":       oaArr("", oaObj("", map[string]any{"term": oaInt(""), "rate_bps": oaInt("")})),
				"coinbase_maturity": oaInt(""), "target_block_time_sec": oaInt(""), "network": oaStr(""),
				"money_supply_cap": oaInt(""), "tail_emission_atomic": oaInt(""),
			}), "", false)),
		"/tx": oaGet(oaOp("core/chain", "Transaction lookup by txid (mempool, then persisted txid->height index, then bounded scan)",
			[]map[string]any{oaQ("hash", "string", "64-hex txid", true)}, nil,
			oaObj("", map[string]any{
				"found": oaBool(""), "status": oaStr("confirmed|pending|unknown"), "txid": oaStr(""),
				"block_height": oaInt(""), "block_hash": oaStr("hex ID of the containing block (confirmed only)"),
				"index": oaInt(""), "confirmations": oaInt(""),
				"coinbase": oaBool(""), "note": oaStr(""),
			}), "", false)),
		"/height":   oaGet(oaOp("core/chain", "Chain tip height", nil, nil, oaObj("", map[string]any{"height": oaInt("")}), "", false)),
		"/accvalue": oaGet(oaOp("core/chain", "Current accumulator value (hex)", nil, nil, oaObj("", map[string]any{"accvalue": oaStr("hex")}), "", false)),
		"/block": oaGet(oaOp("core/chain", "Full serialized block by height or hash",
			[]map[string]any{oaQ("height", "integer", "block height (or use hash)", false), oaQ("hash", "string", "64-hex block hash", false)},
			nil, oaObj("", map[string]any{"block": oaStr("hex-serialized block")}), "", false)),
		"/blocks": oaGet(oaOp("core/chain", "Range of serialized blocks (batch wallet scan; stops at the tip)",
			[]map[string]any{oaQ("from", "integer", "first height (inclusive)", true), oaQ("count", "integer", "blocks to return (cap 256)", false)},
			nil, oaObj("", map[string]any{"blocks": oaArr("", oaStr("hex block"))}), "", false)),
		"/headers": oaGet(oaOp("core/chain", "Range of block headers (SPV light clients)",
			[]map[string]any{oaQ("from", "integer", "first height (inclusive)", true), oaQ("count", "integer", "headers to return (cap 2000)", false)},
			nil, oaObj("", map[string]any{"headers": oaArr("", oaStr("hex header"))}), "", false)),
		"/submittx": oaPost(oaOp("core/chain", "Submit a signed transaction (hex)", nil,
			oaObj("", map[string]any{"tx": oaStr("hex-serialized signed tx")}),
			oaObj("", map[string]any{"txid": oaStr("")}), "", false)),
		"/zkwitness": oaGet(oaOp("core/chain", "ZK anonymous-spend membership witness (anchor + auth path; proof built offline)",
			[]map[string]any{oaQ("leaf", "string", "32-byte hex note commitment", true)}, nil,
			oaObj("", map[string]any{
				"anchor": oaStr("hex"), "path": oaArr("", oaStr("hex sibling")),
				"index": oaInt(""), "depth": oaInt(""), "ok": oaBool(""),
			}), "", false)),
		"/feerate": oaGet(oaOp("core/chain", "Dynamic fee estimate (fee-per-byte)",
			[]map[string]any{oaQ("target", "integer", "confirm-within blocks (default 2)", false)}, nil,
			oaObj("", map[string]any{
				"target_blocks": oaInt(""), "fee_per_byte": oaInt(""),
				"floor_per_byte": oaInt(""), "window_blocks": oaInt(""),
			}), "", false)),
		"/mempool": oaGet(oaOp("core/chain", "Mempool statistics", nil, nil, oaObj("mempool.Stats", nil), "", false)),
		"/mining": oaGet(oaOp("core/chain", "This node's own built-in-miner status: payout address, session blocks/earnings, live hashrate, difficulty + next block reward (read-only; enabled=false with zeros when the node is not mining)", nil, nil,
			oaObj("", map[string]any{
				"enabled":               oaBool("is the built-in miner (--mine) running"),
				"mine_address":          oaStr("the node's ACTUAL coinbase payout address (Base58)"),
				"blocks_found_session":  oaInt("blocks this node mined since it started"),
				"session_earned_atomic": oaInt("total coinbase those blocks minted (atomic)"),
				"session_earned_obx":    oaStr(""),
				"hashrate":              oaSchema("number", "node's own live H/s (20s reporter window); 0 when not mining"),
				"difficulty":            oaInt("current expected difficulty"),
				"block_reward_atomic":   oaInt("next block's expected coinbase (real emission state, zero fees)"),
				"block_reward_obx":      oaStr(""),
				"synced":                oaBool(""), "peer_count": oaInt(""),
				"coinbase_maturity": oaInt("blocks a coinbase must age before spending"),
			}), "", false)),
		"/peers": oaGet(oaOp("core/chain", "Connected peers (full address list only for loopback/token callers; count-only otherwise)",
			nil, nil, oaObj("", map[string]any{"count": oaInt(""), "peers": oaArr("", oaStr(""))}), "", false)),

		// --- dex (order book / market data) ------------------------------------
		"/offers": oaGet(oaOp("dex", "Live signed offers (hex-serialized)", nil, nil,
			oaObj("", map[string]any{"offers": oaArr("", oaStr("hex offer"))}), "", false)),
		"/offers/json": oaGet(oaOp("dex", "Live offers decoded to JSON, rate-sorted, paginated", oaPageParams("2000", "5000"), nil,
			oaObj("", map[string]any{
				"offers": oaArr("", offerSchema), "total": oaInt("full live-book size"),
				"offset": oaInt(""), "truncated": oaBool("more rows exist beyond offset+len(offers)"),
			}), "", false)),
		"/offer": oaPost(oaOp("dex", "Publish a signed swap offer (gossiped)", nil,
			oaObj("", map[string]any{"offer": oaStr("hex-serialized signed offer")}),
			oaObj("", map[string]any{"offer_id": oaStr("hex")}), "", false)),
		"/offer/cancel": oaPost(oaOp("dex", "Cancel a live offer (maker-signed; local to this node, gossiped copies expire by TTL)", nil,
			oaObj("", map[string]any{"offer_id": oaStr("hex"), "sig": oaStr("hex maker cancellation signature")}),
			oaObj("", map[string]any{"ok": oaBool("")}), "", false)),
		"/quote": oaGet(oaOp("dex", "Depth-aware VWAP quote for a taker size",
			[]map[string]any{
				oaQ("give", "string", "asset the taker gives", true),
				oaQ("get", "string", "asset the taker receives", true),
				oaQ("size", "integer", "give size in atomic units (>0)", true),
			}, nil,
			oaObj("", map[string]any{
				"give": oaStr(""), "get": oaStr(""), "size": hexAmount, "filled": hexAmount,
				"get_out": hexAmount, "vwap": oaStr(""), "offers_used": oaInt(""), "full": oaBool(""),
			}), "", false)),
		"/depth": oaGet(oaOp("dex", "Cumulative order-book depth ladder (best-rate-first)",
			[]map[string]any{oaQ("give", "string", "", true), oaQ("get", "string", "", true)}, nil,
			oaObj("", map[string]any{
				"give": oaStr(""), "get": oaStr(""),
				"rungs": oaArr("", oaObj("", map[string]any{
					"rate": oaStr(""), "give": hexAmount, "get": hexAmount,
					"cum_give": hexAmount, "cum_get": hexAmount, "offer_id": oaStr("hex"),
				})),
			}), "", false)),
		"/liquidity": oaGet(oaOp("dex", "Per-pair aggregate liquidity (Σ give/get, counts, best rate)", nil, nil,
			oaObj("", map[string]any{
				"pairs": oaArr("", oaObj("", map[string]any{
					"pair": oaStr(""), "give_asset": oaStr(""), "get_asset": oaStr(""),
					"total_give": hexAmount, "total_get": hexAmount,
					"offers": oaInt(""), "best_rate": oaStr(""),
				})),
				"total_offers": oaInt(""), "total_makers": oaInt(""),
			}), "", false)),
		"/trades": oaGet(oaOp("dex", "Executed-trade tape (newest first; empty pair = all pairs)",
			append([]map[string]any{pairParam}, oaPageParams("100", "5000")...), nil,
			oaObj("", map[string]any{
				"pair": oaStr(""), "last_price": oaStr(""), "trades": oaArr("", tradeSchema),
				"limit": oaInt(""), "offset": oaInt(""), "total": oaInt("full tape rows matching pair"),
				"truncated": oaBool(""),
			}), "", false)),
		"/candles": oaGet(oaOp("dex", "OHLCV candles aggregated from the tape",
			[]map[string]any{
				oaQ("pair", "string", "GIVE/GET (required)", true),
				oaQ("interval", "integer", "bucket seconds (default 3600)", false),
				oaQ("limit", "integer", "buckets (default 200, cap 5000)", false),
			}, nil,
			oaObj("", map[string]any{"pair": oaStr(""), "interval_sec": oaInt(""), "candles": oaArr("", oaObj("OHLCV bucket", nil))}), "", false)),
		"/stats": oaGet(oaOp("dex", "Trailing-24h OHLC + volume summary",
			[]map[string]any{oaQ("pair", "string", "GIVE/GET (required)", true)}, nil,
			oaObj("", map[string]any{
				"pair": oaStr(""), "volume": hexAmount, "volume_get": hexAmount,
				"high": oaStr(""), "low": oaStr(""), "open": oaStr(""), "last": oaStr(""),
				"change": oaStr(""), "trades": oaInt(""),
			}), "", false)),
		"/orders": oaGet(oaOp("dex", "A maker's live orders + fill state",
			append([]map[string]any{oaQ("maker", "string", "32-byte hex maker pubkey", true)}, oaPageParams("500", "5000")...), nil,
			oaObj("", map[string]any{
				"orders": oaArr("", orderSchema), "total": oaInt(""),
				"offset": oaInt(""), "truncated": oaBool(""),
			}), "", false)),
		"/order/{id}": map[string]any{"get": func() map[string]any {
			op := oaOp("dex", "One order's fill state", nil, nil,
				oaObj("", map[string]any{
					"id": oaStr(""), "remaining_give": hexAmount, "remaining_get": hexAmount,
					"status": oaStr(""),
				}), "", false)
			op["parameters"] = []map[string]any{{
				"name": "id", "in": "path", "required": true,
				"description": "32-byte hex order id", "schema": map[string]any{"type": "string"},
			}}
			return op
		}()},
		"/my": oaGet(oaOp("dex", "Joined view: a maker's live orders + their trade history (as maker OR taker)",
			[]map[string]any{
				oaQ("maker", "string", "32-byte hex pubkey", true),
				oaQ("limit", "integer", "max trades returned (default 200, cap 5000)", false),
			}, nil,
			oaObj("", map[string]any{"orders": oaArr("", orderSchema), "trades": oaArr("", tradeSchema)}), "", false)),

		// --- swaps (in-flight sessions + non-custodial browser relay) -----------
		"/swaps/active": oaGet(oaOp("swaps", "In-flight swap sessions (display-only ids, phase + step checklist)", nil, nil,
			oaObj("", map[string]any{"sessions": oaArr("", sessionSchema)}), "", false)),
		"/swaps/take": oaPost(oaOp("swaps", "Start a taker swap (OPERATOR-FUNDED — gated to loopback/token unless OBX_PUBLIC_SWAPS=1; browsers use the relay instead)", nil,
			oaObj("", map[string]any{
				"offer_id": oaStr("hex (or use size+type)"), "peer": oaStr("optional maker peer override"),
				"type": oaStr("market|ioc|fok"), "size": oaInt("XNO offer-units to fill"),
				"taker_pub": oaStr("optional 32-byte hex taker pubkey"),
			}),
			oaObj("", map[string]any{
				"swap_id": oaStr(""), "reserved": hexAmount, "get_out": hexAmount,
				"settling": hexAmount, "obx_atomic": hexAmount,
				"order_type": oaStr(""), "rungs_total": oaStr(""),
			}), "", false)),
		"/swaps/relay/open": oaPost(oaOp("swaps", "Open a browser-taker relay session for a swap id", nil,
			oaObj("", map[string]any{"swap_id": oaStr("hex32")}),
			oaObj("", map[string]any{"ok": oaBool(""), "token": oaStr("per-session secret for send/recv")}), "", false)),
		"/swaps/relay/send": oaPost(oaOp("swaps", "Relay a browser-signed swap envelope to the local maker session", nil,
			oaObj("", map[string]any{
				"swap_id": oaStr(""), "token": oaStr(""), "kind": oaInt("0..255"), "payload": oaStr("hex"),
			}),
			oaObj("", map[string]any{"ok": oaBool("")}), "", false)),
		"/swaps/relay/recv": oaGet(oaOp("swaps", "Long-poll the next maker->browser envelope ({\"empty\":true} on timeout)",
			[]map[string]any{oaQ("swap_id", "string", "hex32", true), oaQ("token", "string", "session token from open", true)}, nil,
			oaObj("", map[string]any{"kind": oaInt(""), "payload": oaStr("hex"), "empty": oaBool("")}), "", false)),
		"/swaps/relay/status": oaGet(oaOp("swaps", "Is this relay session still alive?",
			[]map[string]any{oaQ("swap_id", "string", "hex32", true), oaQ("token", "string", "", true)}, nil,
			oaObj("", map[string]any{"alive": oaBool("")}), "", false)),
		"/swaps/swapout": oaGet(oaOp("swaps", "On-chain SwapOutput the taker verifies before locking XNO",
			[]map[string]any{oaQ("key", "string", "hex swap key", true)}, nil,
			oaObj("", map[string]any{
				"found": oaBool(""), "claim_key": oaStr("hex"), "refund_key": oaStr("hex"),
				"unlock_height": oaInt(""), "claim_r": oaStr("hex"), "claim_t": oaStr("hex"),
				"amount": hexAmount,
			}), "", false)),

		// --- nano (secret-free XNO reads/publish for the browser swap) ----------
		"/swaps/nano/account": oaGet(oaOp("nano", "Nano account info (frontier, representative, balance, opened)",
			[]map[string]any{accountParam}, nil,
			oaObj("", map[string]any{
				"frontier": oaStr(""), "representative": oaStr(""),
				"balance": oaStr("raw decimal string"), "opened": oaBool(""),
			}), "", false)),
		"/swaps/nano/receivable": oaGet(oaOp("nano", "Oldest pending receivable for an account",
			[]map[string]any{accountParam}, nil,
			oaObj("", map[string]any{"found": oaBool(""), "hash": oaStr(""), "amount": oaStr("raw")}), "", false)),
		"/swaps/nano/receivable_status": oaGet(oaOp("nano", "Receivable + its confirmation state in ONE round trip",
			[]map[string]any{accountParam}, nil,
			oaObj("", map[string]any{"found": oaBool(""), "hash": oaStr(""), "amount": oaStr("raw"), "confirmed": oaBool("")}), "", false)),
		"/swaps/nano/watch": oaGet(oaOp("nano", "Server-Sent Events deposit watch: `ready` on connect, `deposit` when confirmed+receivable total grows, `bye` at the 15m bound (client reconnects)",
			[]map[string]any{accountParam}, nil, oaStr("SSE stream (event: ready|deposit|bye)"), "text/event-stream", false)),
		"/swaps/nano/block": oaGet(oaOp("nano", "Nano block info (confirmation, amount, link, subtype)",
			[]map[string]any{oaQ("hash", "string", "64-hex Nano block hash", true)}, nil,
			oaObj("", map[string]any{
				"confirmed": oaBool(""), "amount": oaStr("raw"), "link_hex": oaStr(""),
				"link_as_account": oaStr(""), "subtype": oaStr(""),
			}), "", false)),
		"/swaps/nano/publish": oaPost(oaOp("nano", "Publish a BROWSER-SIGNED Nano state block (signature verified locally before PoW is spent; the node never signs)", nil,
			oaObj("", map[string]any{
				"account_pub": oaStr("hex32"), "previous": oaStr("hex32"),
				"representative": oaStr("nano_ address"), "balance": oaStr("raw decimal"),
				"link": oaStr("hex32"), "signature": oaStr("hex64"), "subtype": oaStr("send|receive|open|change"),
			}),
			oaObj("", map[string]any{"hash": oaStr("published block hash")}), "", false)),

		// --- explorer ------------------------------------------------------------
		"/explorer/summary": oaGet(oaOp("explorer", "Explorer landing payload: network stats, network panel (peers/known nodes/versions), vault stats, best prices, latest blocks", nil, nil,
			oaObj("", map[string]any{
				"coin": oaStr(""), "ticker": oaStr(""), "height": oaInt(""), "difficulty": oaInt(""),
				"target_block_time": oaInt(""), "emitted_obx": oaStr(""), "mempool": oaInt(""),
				"anonymity_set": oaInt(""), "pow_backend": oaStr(""),
				// mainnet-specific network panel: connected peers + PEX-known address
				// count + version distribution (counts only, never addresses).
				"connected_peers": oaInt(""), "known_nodes": oaInt("PEX-known addresses"),
				"version_counts": oaObj("software-version distribution across connected peers + self (counts only)", nil),
				"tvl_obx":        oaStr(""), "tvl_atomic": oaInt(""), "vaults": oaInt(""), "yield_pool_obx": oaStr(""),
				"prices": oaArr("", oaObj("", map[string]any{"pair": oaStr(""), "rate": oaStr("raw atomic get/give"), "give_asset": oaStr(""), "get_asset": oaStr(""), "offers": oaInt("")})),
				"latest": oaArr("", oaObj("", map[string]any{"height": oaInt(""), "hash": oaStr(""), "time": oaInt(""), "txs": oaInt(""), "minted_obx": oaStr("")})),
			}), "", false)),
		"/explorer/block": oaGet(oaOp("explorer", "Privacy-redacted block view (structure, fees, key images, stealth keys — never amounts)",
			[]map[string]any{oaQ("height", "integer", "block height (or use hash)", false), oaQ("hash", "string", "64-hex block hash", false)}, nil,
			oaObj("", map[string]any{
				"height": oaInt(""), "hash": oaStr(""), "prev": oaStr(""), "time": oaInt(""),
				"merkle": oaStr(""), "minted_obx": oaStr(""), "fees_obx": oaStr(""),
				"txs": oaArr("", oaObj("privacy-redacted tx", nil)),
			}), "", false)),
		"/explorer/blocks": oaGet(oaOp("explorer", "Paged privacy-redacted block summaries, DESCENDING from `from` (default/clamp: tip), plus the tip height",
			[]map[string]any{oaQ("from", "integer", "highest height in the page (default & past-tip clamp: tip)", false), oaQ("count", "integer", "rows (default 20, max 50)", false)}, nil,
			oaObj("", map[string]any{
				"tip": oaInt("current chain tip height"), "from": oaInt("first (highest) height in blocks"), "count": oaInt(""),
				"blocks": oaArr("", oaObj("", map[string]any{"height": oaInt(""), "hash": oaStr(""), "time": oaInt(""), "txs": oaInt(""), "minted_obx": oaStr("")})),
			}), "", false)),
		"/explorer/mempool": oaGet(oaOp("explorer", "Privacy-redacted pending pool (fee-prioritized, capped at 80 rows)", nil, nil,
			oaObj("", map[string]any{
				"count": oaInt(""), "bytes": oaInt(""), "total_fees_obx": oaStr(""),
				"min_fee_rate": oaInt(""), "median_fee_rate": oaInt(""), "max_fee_rate": oaInt(""),
				"pending": oaArr("", oaObj("privacy-redacted tx", nil)),
			}), "", false)),
		"/explorer/vaults": oaGet(oaOp("explorer", "Staking vaults: TVL, count, yield pool, per-vault term/rate/maturity", nil, nil,
			oaObj("", map[string]any{
				"tvl_obx": oaStr(""), "count": oaInt(""), "yield_pool_obx": oaStr(""),
				"vaults": oaArr("", oaObj("", map[string]any{
					"key": oaStr("hex vault id"), "amount_obx": oaStr(""), "term_blocks": oaInt(""),
					"rate_bps": oaInt(""), "deposit_height": oaInt(""), "maturity_height": oaInt(""),
				})),
			}), "", false)),
		"/explorer/pricehistory": oaGet(oaOp("explorer", "OBX/XNO best-taker-rate time series (per-node ring buffer sampled from the live book)", nil, nil,
			oaObj("", map[string]any{
				"pair": oaStr(""), "give_asset": oaStr(""), "get_asset": oaStr(""),
				"dec_give": oaInt(""), "dec_get": oaInt(""),
				"points": oaArr("", oaObj("", map[string]any{"t": oaInt("unix seconds"), "rate": oaStr("raw atomic get/give")})),
			}), "", false)),
		"/explorer/metrics": oaGet(oaOp("explorer", "Sparkline time series (supply/difficulty/hashrate/peers) + cumulative swap volume", nil, nil,
			oaObj("", map[string]any{
				"points": oaArr("", oaObj("", map[string]any{
					"t": oaInt(""), "supply": oaInt(""), "difficulty": oaInt(""),
					"hashrate": oaInt("milli-H/s"), "peers": oaInt(""),
				})),
				"volume_obx": oaStr(""), "volume_xno": oaStr(""), "decimals": oaInt(""), "sample_secs": oaInt(""),
			}), "", false)),
		"/explorer/swaps": oaGet(oaOp("explorer", "Recent on-chain swap lifecycle events (funded/claimed/refunded; OBX leg only, 1000-block scan window)",
			oaPageParams("200", "1000"), nil,
			oaObj("", map[string]any{
				"window_blocks": oaInt(""), "events": oaArr("", swapEventSchema),
				"total": oaInt(""), "offset": oaInt(""), "truncated": oaBool(""),
			}), "", false)),

		// --- operator -------------------------------------------------------------
		"/xno/account": oaGet(oaOp("operator", "Miner XNO proceeds account: derived nano_ address + live balance/receivable (read-only, no secret; refused to hosted-proxy public callers)", nil, nil,
			oaObj("", map[string]any{
				"address": oaStr(""), "balance_raw": oaStr(""), "receivable_raw": oaStr(""),
				"backend": oaStr("real|mock"),
			}), "", false)),
		"/blocktemplate": oaGet(oaOp("operator", "Unmined block template for an external miner (short-TTL cached per address)",
			[]map[string]any{oaQ("address", "string", "coinbase destination (Base58 or hex)", true)}, nil,
			oaObj("", map[string]any{
				"height": oaInt(""), "difficulty": oaInt(""),
				"block": oaStr("hex serialized block, nonce=0"), "seed": oaStr("hex PoW epoch seed"),
			}), "", true)),
		"/submitblock": oaPost(oaOp("operator", "Submit a mined block (added to the chain, txs evicted from mempool, relayed to peers)", nil,
			oaObj("", map[string]any{"block": oaStr("hex serialized mined block")}),
			oaObj("", map[string]any{"height": oaInt("")}), "", true)),
		"/xno/recovery": oaGet(oaOp("operator", "Reveal the seed-derived XNO proceeds SECRET for local backup (never CORS-enabled, never proxied)",
			nil, nil,
			oaObj("", map[string]any{
				"address": oaStr(""), "secret_hex": oaStr("XNO spend key — guard it"),
				"pub_hex": oaStr(""), "note": oaStr(""),
			}), "", true)),
		"/xno/withdraw": oaPost(oaOp("operator", "Send XNO from the proceeds account to an external nano_ destination (signs in-process; secret never returned)", nil,
			oaObj("", map[string]any{"amount_raw": oaStr("positive raw decimal"), "dest": oaStr("nano_ address")}),
			oaObj("", map[string]any{"status": oaStr(""), "amount_raw": oaStr(""), "dest": oaStr("")}), "", true)),

		// --- node-binary extras (cmd/obscura-node wrapper mux, not pkg/rpc) --------
		"/auto-liquidity": oaGet(oaOp("operator", "Auto-liquidity loop status counters (registered by the node binary in front of the RPC handler, not by pkg/rpc itself)",
			nil, nil, oaObj("auto-liquidity status", nil), "", false)),
	}

	return map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       "Obscura node RPC",
			"version":     APIVersion,
			"description": "JSON-over-HTTP API of an Obscura (OBX) node: chain reads, DEX order book + market data, non-custodial cross-chain swap relay, explorer views, and operator endpoints. Amounts are raw atomic decimal STRINGS (never floats). Every response carries X-OBX-Api-Version. Errors are {\"error\":...,\"code\":...} with the matching HTTP status. Prose contract: docs/API.md.",
		},
		"servers": []map[string]any{{"url": "/", "description": "the node's --rpc address"}},
		"tags": []map[string]any{
			{"name": "core/chain", "description": "node identity, chain + tx reads, mempool, mining-facing meta"},
			{"name": "dex", "description": "order book, quotes, depth, trade tape, per-maker orders"},
			{"name": "swaps", "description": "in-flight swap sessions + the non-custodial browser relay"},
			{"name": "nano", "description": "secret-free Nano (XNO) reads / browser-signed publish"},
			{"name": "explorer", "description": "privacy-redacted explorer views + per-node time series"},
			{"name": "operator", "description": "state-changing / sensitive endpoints (loopback or bearer token)"},
		},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{
					"type": "http", "scheme": "bearer",
					"description": "OBX_RPC_TOKEN operator token. Loopback callers are exempt.",
				},
			},
		},
		"paths": paths,
	}
}

// handleOpenAPI serves the OpenAPI 3.0 document.
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	cors(w)
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(openAPISpec())
}

// openAPIPathSet returns the spec's path keys (used by the drift test).
func openAPIPathSet() map[string]bool {
	out := map[string]bool{}
	for p := range openAPISpec()["paths"].(map[string]any) {
		out[p] = true
	}
	return out
}

// specCoversRoute reports whether a mux route pattern has a spec entry.
func specCoversRoute(specPaths map[string]bool, route string) bool {
	return specPaths[specPathFor(strings.TrimSpace(route))]
}
