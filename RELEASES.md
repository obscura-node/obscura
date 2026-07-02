# Obscura releases

**Version 1.0.0** — single static binaries, pure Go, no runtime dependencies.
Canonical (KAT-verified) RandomX PoW. Built from this repository.

## Downloads

Download the binaries from the website: <https://obscura-blush.vercel.app/download>
(direct files under `https://obscura-blush.vercel.app/releases/…` — they deploy with
the site, so they always exist). Mirror: the
[GitHub release v1.0.0](https://github.com/obscura-node/obscura/releases/tag/v1.0.0)
at the public `obscura-node` org (use it only once that release is actually published there).

**One command — install a node + miner that joins mainnet, and re-run to upgrade.**
Re-running the same command detects the running node, checks for a newer published
build, asks to confirm, verifies its SHA-256, replaces **only** the binary, and
restarts — your keys in `~/.obscura` (Windows: `%USERPROFILE%\.obscura`) are untouched.

```sh
# Linux / macOS
curl -fsSL https://obscura-blush.vercel.app/install.sh | sh

# Windows (PowerShell)
iwr -useb https://obscura-blush.vercel.app/install.ps1 | iex
```

Manual alternative (no upgrade logic):

```sh
curl -fL https://obscura-blush.vercel.app/releases/Obscura-linux-amd64.tar.gz | tar xz \
  && ./Obscura-linux-amd64/obscura-node --mine --seeds 139.59.183.15:18080,188.166.153.86:18080
```

| Platform | File |
| --- | --- |
| macOS (Apple Silicon) | [`Obscura-darwin-arm64.zip`](https://obscura-blush.vercel.app/releases/Obscura-darwin-arm64.zip) |
| macOS (Intel) | [`Obscura-darwin-amd64.zip`](https://obscura-blush.vercel.app/releases/Obscura-darwin-amd64.zip) |
| Linux (x86-64) | [`Obscura-linux-amd64.tar.gz`](https://obscura-blush.vercel.app/releases/Obscura-linux-amd64.tar.gz) |
| Linux (ARM64) | [`Obscura-linux-arm64.tar.gz`](https://obscura-blush.vercel.app/releases/Obscura-linux-arm64.tar.gz) |
| Windows (x86-64) | [`Obscura-windows-amd64.zip`](https://obscura-blush.vercel.app/releases/Obscura-windows-amd64.zip) |
| Windows (ARM64) | [`Obscura-windows-arm64.zip`](https://obscura-blush.vercel.app/releases/Obscura-windows-arm64.zip) |

## SHA-256 checksums

Verify your download before running it (`shasum -a 256 -c SHA256SUMS.txt`; also
published at <https://obscura-blush.vercel.app/releases/SHA256SUMS.txt>):

```
281dedbc5ec6806f1a4ebab0d65bf5e8a6acd00470e562d3469134b074340e4d  Obscura-darwin-amd64.zip
cfbb10eee8a9d29c0e4cd849612e48fd9865a2eb14c37e4799498e0204f0d805  Obscura-darwin-arm64.zip
3a832cb8c39385cf1ae96e19d1f6aa758ef6d8a8cbc66fa9d2cf146928a514a6  Obscura-windows-amd64.zip
6e7f14fabd0dd7801606536bae4217ea372b4d4d78ad97e837f1e42cb6cf9fc0  Obscura-windows-arm64.zip
6947db3dce4cbc060dbb16b8185c87e87a325459478d0d40b3a7f5d6435a16f3  Obscura-linux-amd64.tar.gz
4ed59dd92b9fe83a29ab609ecee8fd7890efbdddaee148636da923f667ed73ae  Obscura-linux-arm64.tar.gz
```

_macOS:_ the build isn't Apple-signed; clear the quarantine flag after download —
`xattr -dr com.apple.quarantine Obscura-darwin-arm64.app` — then open it.
