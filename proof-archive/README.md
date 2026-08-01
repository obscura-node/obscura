# Public proof archive

This directory is auto-populated by [`.github/workflows/proof-archive.yml`](../.github/workflows/proof-archive.yml),
which runs daily and commits one new block here: the **full serialized block**
(hex) plus a small manifest, straight off the live mainnet node.

## What's actually in these files

`<height>.hex` is the complete raw block, unredacted at the *structural*
level — every transaction in it, including the full **zk-STARK proof bytes**
for each confidential spend (membership-in-the-global-accumulator, the
nullifier/range/conservation proofs — see `pkg/stark/`). This is exactly the
data every full node downloads and independently verifies before extending
its chain; nothing here is curated or cherry-picked for presentation.

`<height>.json` is a small human-readable manifest for the same block (height,
hash, timestamp, tx count) — for orientation, not for verification.

## What is NOT in these files

**Amounts.** Obscura hides transaction amounts with Pedersen commitments and
range proofs — the whole point of a confidential-amount privacy coin. The
STARK proofs in these blocks prove the transaction is well-formed (inputs
exist in the accumulator, nothing is double-spent, outputs sum correctly)
*without* revealing what those amounts are, including in this archive. If you
verify a block from this archive, you will confirm the proofs check out — you
will not learn who paid whom or how much.

## How to actually verify one of these yourself

This is aimed at people who want to check the claim rather than take it on
faith. You'll need Go and this repo:

```sh
git clone https://github.com/obscura-node/obscura.git
cd obscura
go build ./...
```

The verification entry points are ordinary exported Go functions, not a
separate tool — call them from a short `main.go` or a test:

- `(*chain.Chain).ValidateBlock(b *block.Block) error` — full block validation
  (PoW, header roots, every transaction) — [`pkg/chain/validate.go`](../pkg/chain/validate.go)
- `(*chain.Chain).ValidateStandaloneTx(t *tx.Transaction) error` — validate one
  transaction on its own — [`pkg/chain/validate.go`](../pkg/chain/validate.go)
- The individual STARK circuits each proof is checked against live in
  [`pkg/stark/`](../pkg/stark/) (`VerifyMembership`, `VerifyNfSpend`,
  `VerifyRange`, `VerifyFRI`, and friends) if you want to go a layer deeper
  than block-level validation.

Deserialize `<height>.hex` with `block.DeserializeBlock` (see
[`pkg/block/block.go`](../pkg/block/block.go)), then call `ValidateBlock` against your own
chain state (or `ValidateStandaloneTx` per-transaction if you just want to
check proof validity without replaying full chain state). A `nil` error means
every proof in the block checked out.

## Why bother

Anyone can claim a coin is "private." This archive exists so a Tor/zk-literate
reader doesn't have to take that on faith — the actual bytes are here,
updated daily, and the verifier is the same open-source code a real node
runs, not a demo.
