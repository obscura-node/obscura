# Obscura (OBX) installer / upgrader — Windows (PowerShell).
#
# Run it once to install + start a full node + miner. Run the SAME command again
# any time to upgrade: it notices a node is already running, checks the published
# release for a newer build, ASKS before doing anything, replaces the binary, and
# restarts it. Your wallet/miner keys live in %USERPROFILE%\.obscura and are NEVER
# touched by an upgrade — only the program binary is replaced.
#
#   iwr -useb https://obscura-protocol.space/install.ps1 | iex
#
# Pass node flags via $NodeArgs (defaults: --mine --seeds <mainnet seeds>):
#   & ([scriptblock]::Create((iwr -useb https://obscura-protocol.space/install.ps1))) --mine --seeds 139.59.183.15:18080,188.166.153.86:18080
#
# PRIVACY: the node hides your real IP by default — it auto-starts Tor and routes
# all P2P over a hidden service (no setup needed). This installer best-effort
# installs `tor` for that. Public/seed operators opt out by passing --clearnet.
#
# Env: OBX_DATADIR overrides the key/data directory (default %USERPROFILE%\.obscura).
param([Parameter(ValueFromRemainingArguments=$true)][string[]]$NodeArgs)
$ErrorActionPreference = 'Stop'

# Ensure `tor` is present: the node's default privacy mode auto-launches it.
# Best-effort via winget/choco; if neither is available (or it's already present)
# we move on — the node prints clear instructions, and --clearnet needs no tor.
function Ensure-Tor {
  if (Get-Command tor -ErrorAction SilentlyContinue) { return }
  Write-Host "Installing tor (for default IP privacy)..."
  try {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
      winget install --id TheTorProject.TorExpertBundle -e --silent --accept-package-agreements --accept-source-agreements 2>$null
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
      choco install tor -y 2>$null
    }
  } catch {}
  if (-not (Get-Command tor -ErrorAction SilentlyContinue)) {
    Write-Host "  note: could not auto-install tor — install it manually for IP privacy, or run with --clearnet."
  }
}

# Release files are served from the website's own /releases/ directory (part of the
# Vercel deploy, so they always exist alongside this script). Mirror: the GitHub
# release at github.com/obscura-node/obscura — only point $Base there once that
# release actually EXISTS at the obscura-node org.
$Tag  = 'v1.0.0'
$Base = 'https://obscura-protocol.space/releases'
$Arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$Asset = "Obscura-windows-$Arch.zip"
$Dir   = "Obscura-windows-$Arch"
$Bin   = Join-Path $Dir 'obscura-node.exe'
$DataDir = if ($env:OBX_DATADIR) { $env:OBX_DATADIR } else { Join-Path $env:USERPROFILE '.obscura' }
$Marker  = Join-Path $DataDir '.installed-sha'
$DefaultArgs = @('--mine', '--seeds', '139.59.183.15:18080,188.166.153.86:18080')

function Get-PubSha {
  try {
    ((iwr -useb "$Base/SHA256SUMS.txt").Content -split "`n") |
      Where-Object { $_ -match [regex]::Escape($Asset) } |
      ForEach-Object { ($_ -split '\s+')[0] } | Select-Object -First 1
  } catch { $null }
}

$pub  = Get-PubSha
$proc = Get-Process obscura-node -ErrorAction SilentlyContinue | Select-Object -First 1
$have = if (Test-Path $Marker) { (Get-Content $Marker -Raw).Trim() } else { '' }

if ($proc) {
  Write-Host "Obscura node already running (pid $($proc.Id)), keys in $DataDir."
  if ($pub -and ($pub -eq $have)) {
    Write-Host "Already on the latest published build ($($pub.Substring(0,12))...). Nothing to do."
    return
  }
  Write-Host "A newer published build is available."
  if (-not [Environment]::UserInteractive) {
    Write-Host "  (no interactive console to confirm — re-run in an interactive PowerShell to upgrade)"
    return
  }
  $ans = Read-Host "Upgrade now? Your keys in $DataDir are preserved (only the binary is replaced) [y/N]"
  if ($ans -notmatch '^[yY]') { Write-Host "Upgrade skipped — the running node is untouched."; return }
  Write-Host "Stopping the running node (keys untouched)..."
  $proc | Stop-Process -Force
  Start-Sleep -Seconds 2
}

$tmp = Join-Path $env:TEMP $Asset
Write-Host "Downloading $Asset ..."
iwr -useb "$Base/$Asset" -OutFile $tmp
# FAIL-CLOSED checksum (audit): refuse to run an unverified binary if the published
# checksum can't be fetched, rather than silently skipping verification.
if (-not $pub) {
  if ($env:OBX_INSTALL_ALLOW_UNVERIFIED -eq "1") {
    Write-Host "Obscura: WARNING - no published checksum reachable; running UNVERIFIED (OBX_INSTALL_ALLOW_UNVERIFIED=1)."
  } else {
    throw "Obscura: could not fetch the published checksum - refusing to run an unverified binary (set OBX_INSTALL_ALLOW_UNVERIFIED=1 to override)."
  }
} else {
  $got = (Get-FileHash $tmp -Algorithm SHA256).Hash.ToLower()
  if ($got -ne $pub.ToLower()) { throw "checksum mismatch (got $got, want $pub)" }
  Write-Host "Checksum verified ($($pub.Substring(0,12))...)."
}
Write-Host "Unpacking into $(Resolve-Path .)\$Dir ..."
if (Test-Path $Dir) { Remove-Item $Dir -Recurse -Force }
Expand-Archive -Path $tmp -DestinationPath . -Force

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
if ($pub) { Set-Content -Path $Marker -Value $pub }

$argv = if ($NodeArgs -and $NodeArgs.Count -gt 0) { $NodeArgs } else { $DefaultArgs }
# Default privacy mode auto-starts Tor; ensure it's installed unless the operator
# opted out with --clearnet (seed/public nodes).
if ($argv -contains '--clearnet') {
  Write-Host "Privacy: --clearnet - running as a PUBLIC clearnet node (your IP is visible)."
} else {
  Ensure-Tor
  Write-Host "Privacy: Tor is ON by default - your real IP is hidden (auto hidden service). Use --clearnet to opt out."
}
Write-Host "Starting: $Bin $($argv -join ' ')"
Start-Process -FilePath (Resolve-Path $Bin) -ArgumentList $argv `
  -RedirectStandardOutput 'obscura.log' -RedirectStandardError 'obscura.err.log' -WindowStyle Hidden
Write-Host "Obscura node started. Logs: $(Resolve-Path .)\obscura.log"
