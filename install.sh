#!/usr/bin/env sh
# Obscura (OBX) installer / upgrader — Linux & macOS.
#
# Run it once to install + start a full node + miner. Run the SAME command again
# any time to upgrade: it notices a node is already running, checks the published
# release for a newer build, ASKS before doing anything, replaces the binary, and
# restarts it. Your wallet/miner keys live in ~/.obscura and are NEVER touched by
# an upgrade — only the program binary is replaced.
#
#   curl -fsSL https://obscura-protocol.space/install.sh | sh
#
# Pass node flags after `-s --` (defaults: --mine --seeds <mainnet seeds>):
#   curl -fsSL https://obscura-protocol.space/install.sh | sh -s -- --mine --seeds 139.59.183.15:18080,188.166.153.86:18080
#
# PRIVACY: the node hides your real IP by default — it auto-starts Tor and routes
# all P2P over a hidden service (no setup needed). This installer best-effort
# installs `tor` for that. Public/seed operators opt out by passing --clearnet.
#
# Env: OBX_DATADIR overrides the key/data directory (default ~/.obscura).
set -eu

# Ensure `tor` is present: the node's default privacy mode auto-launches it. This
# is best-effort — if the package manager is unknown or unprivileged, the node
# still prints clear install instructions (and --clearnet always works without tor).
ensure_tor() {
  command -v tor >/dev/null 2>&1 && return 0
  echo "Installing tor (for default IP privacy)…"
  if command -v brew >/dev/null 2>&1; then brew install tor || true
  elif command -v apt-get >/dev/null 2>&1; then sudo apt-get update -y && sudo apt-get install -y tor || true
  elif command -v dnf >/dev/null 2>&1; then sudo dnf install -y tor || true
  elif command -v pacman >/dev/null 2>&1; then sudo pacman -S --noconfirm tor || true
  elif command -v apk >/dev/null 2>&1; then sudo apk add tor || true
  fi
  command -v tor >/dev/null 2>&1 || \
    echo "  note: could not auto-install tor — install it manually for IP privacy, or run with --clearnet." >&2
}

# Release files are served from the website's own /releases/ directory — they are
# part of the Vercel deploy, so they always exist alongside this script.
# Mirror: the GitHub release at github.com/obscura-node/obscura
# (https://github.com/obscura-node/obscura/releases/download/v1.0.0). Only point
# BASE there once that release actually EXISTS at the obscura-node org.
TAG="v1.0.0"
BASE="https://obscura-protocol.space/releases"
DATADIR="${OBX_DATADIR:-$HOME/.obscura}"
MARKER="$DATADIR/.installed-sha"
DEFAULT_ARGS="--mine --seeds 139.59.183.15:18080,188.166.153.86:18080"

os="$(uname -s)"; arch="$(uname -m)"
case "$os-$arch" in
  Linux-x86_64|Linux-amd64)  ASSET="Obscura-linux-amd64.tar.gz"; DIR="Obscura-linux-amd64";      BIN="$DIR/obscura-node";                KIND=tar ;;
  Linux-aarch64|Linux-arm64) ASSET="Obscura-linux-arm64.tar.gz"; DIR="Obscura-linux-arm64";      BIN="$DIR/obscura-node";                KIND=tar ;;
  Darwin-arm64)              ASSET="Obscura-darwin-arm64.zip";   DIR="Obscura-darwin-arm64.app"; BIN="$DIR/Contents/MacOS/obscura-node"; KIND=zip ;;
  Darwin-x86_64)             ASSET="Obscura-darwin-amd64.zip";   DIR="Obscura-darwin-amd64.app"; BIN="$DIR/Contents/MacOS/obscura-node"; KIND=zip ;;
  *) echo "Obscura: unsupported platform $os-$arch" >&2; exit 1 ;;
esac

# Published SHA-256 of this asset — the source of truth for "is a new build out?".
pub_sha() { curl -fsSL "$BASE/SHA256SUMS.txt" 2>/dev/null | awk -v a="$ASSET" '$2==a{print $1}'; }
sha_of()  { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
short()   { printf '%.12s' "$1"; }

# Ask y/N on the controlling terminal, even when this script is piped into `sh`.
# If there is no usable terminal to confirm on (CI / cron / no tty) we DO NOT
# auto-replace a running node unattended — we skip and ask the user to re-run
# interactively. A real `curl ... | sh` in a terminal can still reach /dev/tty.
ask() {
  a=""
  if { true >/dev/tty; } 2>/dev/null; then
    printf '%s [y/N] ' "$1" > /dev/tty
    read -r a < /dev/tty 2>/dev/null || a=""
  else
    echo "  (no terminal available to confirm — re-run in an interactive shell to upgrade)" >&2
  fi
  case "$a" in y*|Y*) return 0 ;; *) return 1 ;; esac
}

PUB="$(pub_sha || true)"
PID="$(pgrep -x obscura-node 2>/dev/null | head -n1 || true)"
HAVE="$( [ -f "$MARKER" ] && cat "$MARKER" || true )"

if [ -n "$PID" ]; then
  echo "Obscura node already running (pid $PID), keys in $DATADIR."
  if [ -n "$PUB" ] && [ "$PUB" = "$HAVE" ]; then
    echo "Already on the latest published build ($(short "$PUB")…). Nothing to do."
    exit 0
  fi
  echo "A newer published build is available."
  ask "Upgrade now? Your keys in $DATADIR are preserved (only the binary is replaced)." \
    || { echo "Upgrade skipped — the running node is untouched."; exit 0; }
  echo "Stopping the running node (keys untouched)…"
  kill "$PID" 2>/dev/null || true
  i=0; while kill -0 "$PID" 2>/dev/null && [ "$i" -lt 24 ]; do sleep 0.5; i=$((i+1)); done
  kill -9 "$PID" 2>/dev/null || true
fi

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
echo "Downloading $ASSET …"
curl -fL "$BASE/$ASSET" -o "$tmp/$ASSET"
# FAIL-CLOSED checksum (audit): if the published checksum can't be fetched, REFUSE to
# run an unverified binary rather than silently skipping verification + auto-running it.
if [ -z "$PUB" ]; then
  if [ "${OBX_INSTALL_ALLOW_UNVERIFIED:-}" = "1" ]; then
    echo "Obscura: WARNING — no published checksum reachable; running UNVERIFIED (OBX_INSTALL_ALLOW_UNVERIFIED=1)." >&2
  else
    echo "Obscura: could not fetch the published checksum — refusing to run an unverified binary." >&2
    echo "         (set OBX_INSTALL_ALLOW_UNVERIFIED=1 to override at your own risk)." >&2
    exit 1
  fi
else
  got="$(sha_of "$tmp/$ASSET")"
  [ "$got" = "$PUB" ] || { echo "Obscura: checksum mismatch (got $(short "$got")…, want $(short "$PUB")…) — aborting." >&2; exit 1; }
  echo "Checksum verified ($(short "$PUB")…)."
fi
echo "Unpacking into $(pwd)/$DIR …"
rm -rf "$DIR"
case "$KIND" in
  tar) tar xzf "$tmp/$ASSET" ;;
  zip) unzip -oq "$tmp/$ASSET" ;;
esac
chmod +x "$BIN" 2>/dev/null || true
[ "$os" = Darwin ] && { xattr -dr com.apple.quarantine "$DIR" 2>/dev/null || true; }

mkdir -p "$DATADIR"
[ -n "$PUB" ] && printf '%s\n' "$PUB" > "$MARKER" || true

ARGS="$*"; [ -n "$ARGS" ] || ARGS="$DEFAULT_ARGS"
# Default privacy mode auto-starts Tor; make sure it's installed unless the
# operator opted out with --clearnet (seed/public nodes).
case " $ARGS " in *" --clearnet "*) : ;; *) ensure_tor ;; esac
echo "Starting: ./$BIN $ARGS"
case " $ARGS " in
  *" --clearnet "*) echo "Privacy: --clearnet — running as a PUBLIC clearnet node (your IP is visible)." ;;
  *) echo "Privacy: Tor is ON by default — your real IP is hidden (auto hidden service). Use --clearnet to opt out." ;;
esac
if command -v setsid >/dev/null 2>&1; then
  setsid "./$BIN" $ARGS > obscura.log 2>&1 < /dev/null &
else
  nohup "./$BIN" $ARGS > obscura.log 2>&1 < /dev/null &
fi
echo "Obscura node started (pid $!). Logs: $(pwd)/obscura.log"
echo "Watch it:  tail -f $(pwd)/obscura.log"
