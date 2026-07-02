# Obscura (OBX) — build & test
#
# Test targets (full test map: docs/TESTING.md):
#   make test       fast default: prototype PoW (-tags protopow), whole module incl.
#                   ./tests/... — the everyday / CI gate path. -timeout 1500s: the
#                   heaviest packages (pkg/chain, pkg/stark, pkg/swapnet) need >300s
#                   when the whole module runs in parallel on a laptop.
#   make test-full  canonical RandomX PoW (no tags) — KAT-verified backend, SLOW:
#                   ~31 mining-heavy packages redo real PoW (-timeout 3600s).
#   make check      gofmt gate + go vet + make test (the pre-merge gate).
#   make e2e        prints the Playwright web-wallet e2e runbook (needs a LIVE node).
#
# NOTE on tags (AUDIT FIX): the DEFAULT BUILD (no tags) ships the KAT-verified
# canonical RandomX PoW backend. The pure-Go `vm-randomx-style` prototype has
# near-zero memory-hardness and must never back a value-bearing node; select it
# ONLY with the explicit opt-in `-tags protopow` for fast prototype/dev/test runs.
VERSION ?= 0.1.0-prototype
BUILDTAGS ?=
GOFLAGS := -trimpath -tags "$(BUILDTAGS)"
LDFLAGS := -s -w -X main.version=$(VERSION)

# gofmt gate exclusions (keep in sync with docs/TESTING.md).
# This identical Makefile ships in BOTH the root (dev) and mainnet (release)
# trees, so patterns are UNANCHORED: `pkg/swapd/` matches both `pkg/swapd/...`
# (run from within a tree) AND `mainnet/pkg/swapd/...` (run from the root tree).
# That means `make check` from root now GATES mainnet/ too; only testnet/ stays
# fully excluded. The release tree's protected-core skip list (documented below)
# is exactly: swap core, class-group core, and the TEMP other-agent files.
#   - testnet/            FROZEN mirror — never reformat (see testnet/DEPRECATED.md)
#   - node_modules        vendored JS deps (tests/e2e)
#   - pkg/swapsession|swapnet|swapbook|swapd  PROTECTED swap core: even formatting-
#     only changes alarm the audit mtime sweeps — deliberately left unformatted.
#   - pkg/group, pkg/accumulator  class-group core owned by another agent — do not
#     reformat (their tree divergence is tracked by tests/critical/parity instead).
# TEMP exclusions (other agents own these files right now — remove after the
# post-merge gofmt sweep): pkg/p2p/**, pkg/chain non-test files,
# pkg/rpc/swaprelay.go, cmd/obscura-dashboard/** (dashboard agent).
GOFMT_SKIP := -e '^testnet/' -e 'node_modules/' \
	-e 'pkg/swapsession/' -e 'pkg/swapnet/' -e 'pkg/swapbook/' -e 'pkg/swapd/' \
	-e 'pkg/group/' -e 'pkg/accumulator/' \
	-e 'pkg/p2p/' -e 'cmd/obscura-dashboard/' \
	-e 'pkg/chain/diskset\.go' -e 'pkg/chain/incentives\.go' -e 'pkg/chain/snapshot\.go' \
	-e 'pkg/chain/stateroot\.go' -e 'pkg/chain/validate\.go' \
	-e 'pkg/rpc/swaprelay\.go'

.PHONY: all build node wallet test test-full test-short test-proto check e2e bench release run-node clean clean-all fmt vet tidy

all: build

build: node wallet ## build both binaries into bin/

node: ## build the full node + miner
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/obscura-node ./cmd/obscura-node

wallet: ## build the CLI wallet
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/obscura-wallet ./cmd/obscura-wallet

test: ## fast default suite: prototype PoW (-tags protopow), incl. ./tests/...
	go test -tags protopow ./... -timeout 1500s

test-full: ## FULL suite on the canonical RandomX PoW backend — SLOW (real PoW; ~1h)
	go test -tags "$(BUILDTAGS)" ./... -timeout 3600s

test-short: ## faster test run (skips heavy class-group tests)
	go test -tags protopow ./... -short -timeout 180s

test-proto: ## alias of test-short (kept for muscle memory / older docs)
	go test -tags protopow ./... -short -timeout 180s

check: ## pre-merge gate: gofmt (fail on unformatted) + go vet + make test
	@bad=$$(gofmt -l . 2>/dev/null | grep -v $(GOFMT_SKIP) || true); \
	if [ -n "$$bad" ]; then echo "gofmt needed on:"; echo "$$bad"; exit 1; fi; \
	echo "gofmt: clean"
	go vet -tags protopow ./...
	$(MAKE) test

e2e: ## print the web-wallet Playwright e2e runbook (LIVE node required — never mocked)
	@echo "Web-wallet e2e (Playwright) — needs a LIVE obscura-node serving the UI:"
	@echo "  1. make node                                # build bin/obscura-node"
	@echo "  2. ./bin/obscura-node --ui --ui-addr 127.0.0.1:18099 --datadir <scratch-dir>"
	@echo "                                              # keep it running in another terminal"
	@echo "  3. cd tests/e2e && npm install && npx playwright install chromium   # first time only"
	@echo "  4. cd tests/e2e && npx playwright test      # BASE_URL overrides 127.0.0.1:18099"
	@echo "Funded / real-XNO specs are gated behind env secrets (OBX_NANO_*) and stay"
	@echo "skipped without them. See tests/e2e/README.md and docs/TESTING.md."

bench: ## run benchmarks
	go test -tags "$(BUILDTAGS)" ./pkg/... -run x -bench . -benchmem

release: ## cross-compile release archives into dist/
	VERSION=$(VERSION) ./build.sh

run-node: node ## build and run a mining node (testnet)
	./bin/obscura-node --mine

fmt: ; go fmt ./...
vet: ; go vet ./...
tidy: ; go mod tidy

clean: ## remove build outputs: bin/, dist/, and loose top-level obscura-* binaries
	rm -rf bin dist
	rm -f obscura-node obscura-wallet obscura-miner obscura-swap obscura-wasm \
		obscura-dashboard obscura-dexsim obscura-loadgen obscura-testwallet
	# NOTE: website/releases/ is a DEPLOY artifact served by the live site — never removed here.

clean-all: clean ## clean + regenerable deps (node_modules via `npm ci`); keeps website/releases/
	rm -rf tests/e2e/node_modules
	rm -rf scripts/*/node_modules

help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

devnet: ## run the one-command 2-node devnet demo
	./scripts/devnet.sh

testnet: ## run an N-node local testnet (make testnet N=5)
	./scripts/testnet.sh $(N)
