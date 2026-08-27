# xmxx-companion

Box-side relay for the **xmxx** KeyOS app (Monero cold storage on the Passport Prime).

The Prime is offline — it never touches the network. This companion is the
online half of the QR pipe:

```
[ Monero daemon RPC ] <---> [ xmxx-companion (box) ] <---> [ xmxx app (Prime) ]
                                    QR (raw bytes / binary)
```

The device keeps the **spend key**. The box only ever holds the **view key**
(the `xmxx-viewkey.txt` the app exports to the Airlock) — it can see incoming
outputs and build unsigned transactions, but can never sign.

## Build

Requires the nightly-2026-04-11 toolchain (same as the KeyOS SDK shell):

```bash
cargo build --release
```

The binary must be a **Linux ELF** to run on the box — build it there with the
SDK's cargo (the Mac's SDK env produces Mach-O):

```bash
nix develop ~/.foundation/sdk/current -c cargo build --release
```

## Run

```bash
xmxx-companion serve \
  --view-key xmxx-viewkey.txt \
  --rpc http://127.0.0.1:18081 \
  [--from 3500000] \
  [--port 8789]
```

- `--view-key` — the `address=...` / `view_key=...` file exported from the app
- `--rpc` — any standard Monero daemon JSON-RPC endpoint (remote or local)
- `--from` — block height to start scanning from (defaults to the chain tip)

### Node choice: run your own pruned daemon

As of Aug 2026 the public "nodes" that respond (`xmr.support:18089`,
`xmr-node.cakewallet.com:18081`) are **restricted whitelist gateways** — they
answer `get_block_count` / `get_block` / `get_output_distribution` /
`get_fee_estimate` but return `Method not found` for `get_transactions`,
`get_blocks_by_height`, `get_o_indexes`, `get_outs`, and
`send_raw_transaction`. The companion's sync/spend path needs all of those, so
these gateways cannot drive it.

The box therefore runs its own **pruned** `monerod` (≈60 GB, fits the box's
free space; `--prune-blockchain --sync-pruned-blocks` only downloads pruned
data). A pruned daemon serves every method the companion calls, keeps queries
off third parties, and has no public-node dependency. One-shot setup:

```bash
# on the Mac, copy the view key exported from the Prime:
scp /Volumes/AIRLOCK/xmxx-viewkey.txt mikegotbtc@<box>:~/xmxx-viewkey.txt

# on the box:
bash deploy/deploy-box.sh ~/xmxx-viewkey.txt
```

That installs the **official current monerod** (downloaded from
getmonero.org — apt's monero package is an ancient snapshot that lacks the
modern RPC methods), builds the companion (native ELF), installs the units
in `deploy/`, and starts `monerod` + `xmxx-companion`. The pruned sync runs
unattended in the background; the companion page comes up immediately and
re-syncs on every load. (On this box, 8787/8788 are taken by `surf-relay`,
so the companion uses **8789**.)

Note: while the node is still syncing toward the RingCT hardfork height
(~1,009,827), `get_output_distribution` for amount 0 legitimately errors
(`-5 Failed to get output distribution`) — the companion logs it as a
non-fatal initial-sync warning and succeeds automatically once the node
passes that height.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /` | Sync page: owned outputs, balance, `xmr-output` QR (raw bytes) |
| `GET /send?a=..&p=..` | Build unsigned tx → view-key-authenticated envelope → binary QR |
| `POST /broadcast` | `xmr-txsigned` hex → publish via the daemon |

The unsigned tx is a `monero-wallet` `SignableTransaction` wrapped in the
xmxx-core view-key-authenticated envelope (Schnorr signature keyed by the view
key — tampered or foreign-wallet sets are rejected before parsing). The device
verifies the envelope, reviews on-device (amount + fee + payload fingerprint),
signs with its spend key, and the box broadcasts the result.

## Status

- [x] Sync (scan, owned outputs, balance, key-image export)
- [x] Send (envelope build → device sign → broadcast)
- [x] Binary-QR transport for large payloads
- [ ] **Not yet exercised against a live daemon** — blocked on the box being
      back online with its pruned node synced; the deploy bundle is staged in
      `deploy/` and the binary + view-key parse are smoke-tested
- [ ] wallet2 `unsigned_tx_set` interop (Cake/Feather import) — tracked in
      [xmxx-core](https://github.com/OZARUMOTO/xmxx-core), needs CryptoNight-v0
      + portable_storage parsing

Crypto lives in [OZARUMOTO/xmxx-core](https://github.com/OZARUMOTO/xmxx-core)
(monero-oxide / monero-wallet, audited stack) — vendored here as a path dep.
