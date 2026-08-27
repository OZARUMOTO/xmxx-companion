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

## Run

```bash
xmxx-companion serve \
  --view-key xmxx-viewkey.txt \
  --rpc https://node.sethforprivacy.com:18089 \
  [--from 3500000] \
  [--port 8787]
```

- `--view-key` — the `address=...` / `view_key=...` file exported from the app
- `--rpc` — any standard Monero daemon JSON-RPC endpoint (remote or local; no
  node storage needed on the box)
- `--from` — block height to start scanning from (defaults to the chain tip)

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
- [ ] **Not yet exercised against a live daemon** — first deploy must test
      against a real node before real funds
- [ ] wallet2 `unsigned_tx_set` interop (Cake/Feather import) — tracked in
      [xmxx-core](https://github.com/OZARUMOTO/xmxx-core), needs CryptoNight-v0
      + portable_storage parsing

Crypto lives in [OZARUMOTO/xmxx-core](https://github.com/OZARUMOTO/xmxx-core)
(monero-oxide / monero-wallet, audited stack) — vendored here as a path dep.
