# Obscura (OBX)

**A privacy cryptocurrency with a *global* anonymity set — no decoys, no trusted setup.**

Obscura hides every spend among the **entire** unspent-output set: a zero-knowledge proof shows the spent coin is a member of a trustless cryptographic accumulator over *all* outputs. The anonymity set is global and grows with adoption, while membership proofs stay **constant-size** and fast to verify. Amounts are hidden with Pedersen commitments + range proofs; recipients with dual-key stealth addresses. Pure Go, single static binary per platform, canonical RandomX PoW.

- **Global anonymity set** — every spend hides among all outputs, not a ring of ~16 decoys.
- **No trusted setup** — class-group accumulator (no ceremony) + transparent, post-quantum-friendly zk-STARKs.
- **Confidential amounts & hidden recipients** — Pedersen commitments, range proofs, stealth addresses.
- **Constant-size proofs** regardless of chain size · **fair launch** (no premine, no dev fund).
- **Batteries included** — full node, CPU miner, CLI/desktop wallet, private staking vaults, and trustless OBX↔XNO atomic swaps.

## Protocol at a glance

```mermaid
flowchart TB

subgraph WAL["WALLET · build and prove"]
  direction LR
  W1["Transparent<br/>Pedersen + Schnorr"]:::wal
  W2["Confidential ZK<br/>hidden amounts"]:::wal
  W3["Unlinkable<br/>recipient-secret nullifier"]:::wal
  W4["zk-STARK anon spend<br/>transparent · no trusted setup"]:::wal
  W5["Vault<br/>private staking"]:::wal
  W6["Cross-chain swaps<br/>XNO scriptless"]:::wal
  W7["Post-quantum<br/>ML-KEM-768 stealth"]:::wal
end

subgraph P2P["P2P MESH · censorship-resistant"]
  direction LR
  N1["Self-discovering<br/>PEX + addr-me"]:::net
  N2["Eclipse-resistant<br/>/16 group caps"]:::net
  N3["Tor · .onion<br/>Dandelion++"]:::net
end

subgraph MIN["MINER · full node by protocol"]
  direction LR
  R1["Proof-of-Retrievability"]:::min
  R2["Memory-hard RandomX PoW"]:::min
end

subgraph ST["STATE · constant-size, committed"]
  direction LR
  S1[("Class-group accumulator<br/>all coins · constant-size")]:::sta
  S2[("Nullifier set")]:::sta
  S3[("Epoch-sharded Poseidon tree")]:::sta
  S5[("Vaults · swaps · incentive pool")]:::sta
end

CH[("CANONICAL CHAIN")]:::sta

WAL ==>|"signed tx + STARK proof"| P2P
P2P ==>|"Dandelion++ gossip"| MIN
MIN ==>|"mined block"| ST
ST ==>|"5 roots, PoW-bound header"| CH
CH -.->|"broadcast"| P2P
S3 -.->|"spend anchor"| W2

classDef wal fill:#08313a,stroke:#00e6c3,color:#dffbf5;
classDef net fill:#1e1640,stroke:#8b6cff,color:#ece7ff;
classDef min fill:#3a1426,stroke:#ff7ad9,color:#ffe6f6;
classDef sta fill:#3a2e0b,stroke:#ffc15e,color:#fff3dc;
```

## Download & run

Get a build for your platform from the **[v1.0.0 release](https://github.com/dhyabi2/obscura/releases/tag/v1.0.0)** (verify against [RELEASES.md](RELEASES.md) checksums). Or install + run a full node + miner in one command — **re-run the same line any time to upgrade** (it verifies the new build's SHA-256, replaces only the binary, and keeps your keys in `~/.obscura`):

```sh
# Linux / macOS
curl -fsSL https://obscura-blush.vercel.app/install.sh | sh

# Windows (PowerShell)
iwr -useb https://obscura-blush.vercel.app/install.ps1 | iex
```

For a desktop wallet + swaps + mining in a window, unzip the macOS/Windows/Linux build and open it.

## Links

- **Website** — https://obscura-blush.vercel.app
- **Whitepaper** — https://obscura-blush.vercel.app/whitepaper
- **Docs** — [docs/](docs/) · https://obscura-blush.vercel.app/docs.html

## Status & disclaimer

New, novel software running a **live mainnet**. An in-house four-track security review (~100 findings remediated) was performed; there is **no external third-party audit yet**, and the accumulator-based sender-anonymity ZK spend is an experimental layer still being hardened. Understand the software before committing value to it.

## License

See [LICENSE](LICENSE).
