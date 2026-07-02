#!/usr/bin/env bash
# Cross-compile Obscura node + wallet into dist/ for all major platforms.
# Pure-Go (CGO disabled) => single static binaries, including real Windows .exe.
set -euo pipefail

cd "$(dirname "$0")"

VERSION="${VERSION:-0.1.0-prototype}"
# AUDIT FIX: release binaries ship the KAT-verified canonical RandomX PoW backend
# by DEFAULT (no build tags). The pure-Go `vm-randomx-style` prototype has near-
# zero memory-hardness and must never back a value-bearing node; select it ONLY
# with the explicit opt-in `BUILDTAGS=protopow ./build.sh` for non-value builds.
BUILDTAGS="${BUILDTAGS:-}"
OUT="dist"
rm -rf "$OUT"
mkdir -p "$OUT"

# platform list: GOOS/GOARCH
PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
)

BINARIES=("obscura-node" "obscura-wallet" "obscura-miner")

echo "Building Obscura $VERSION"
for platform in "${PLATFORMS[@]}"; do
  GOOS="${platform%/*}"
  GOARCH="${platform#*/}"
  tag="${GOOS}-${GOARCH}"
  dir="$OUT/obscura-$VERSION-$tag"
  mkdir -p "$dir"
  ext=""
  if [ "$GOOS" = "windows" ]; then ext=".exe"; fi
  for bin in "${BINARIES[@]}"; do
    echo "  -> $tag/$bin$ext"
    CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
      go build -trimpath -tags "$BUILDTAGS" -ldflags "-s -w -X main.version=$VERSION" \
      -o "$dir/$bin$ext" "./cmd/$bin"
  done
  # bundle docs
  cp README.md WHITEPAPER.md "$dir/" 2>/dev/null || true
  cp -r docs "$dir/docs" 2>/dev/null || true
  # archive
  if [ "$GOOS" = "windows" ]; then
    ( cd "$OUT" && zip -qr "obscura-$VERSION-$tag.zip" "obscura-$VERSION-$tag" )
  else
    ( cd "$OUT" && tar czf "obscura-$VERSION-$tag.tar.gz" "obscura-$VERSION-$tag" )
  fi
done

echo
echo "Artifacts in $OUT/:"
ls -1 "$OUT"/*.tar.gz "$OUT"/*.zip 2>/dev/null || true
