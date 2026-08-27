// SPDX-FileCopyrightText: 2026 OZARUMOTO
// SPDX-License-Identifier: GPL-3.0-or-later
//
// XMXX-COMPANION — the box-side relay for the xmxx KeyOS app.
//
// Usage:
//   xmxx-companion serve --view-key xmxx-viewkey.txt --rpc https://node:18089 [--from 3500000] [--port 8787]
//
// The view-key file is what the app exports to the Airlock (address + view_key).
// The device keeps the spend key; the box only ever holds the view key.
//
// Endpoints:
//   /             sync page: owned outputs, balance, xmr-output QR (raw bytes)
//   /send?a=..&p=..   build an unsigned tx -> envelope -> binary QR
//   /broadcast    POST xmr-txsigned hex -> publish via the daemon
//
// The unsigned tx is a monero-wallet SignableTransaction wrapped in the
// xmxx-core view-key-authenticated envelope. The device verifies the
// envelope signature, reviews, signs with its spend key, and the box
// broadcasts the signed tx.
//
// COMPILE-VERIFIED ONLY — the daemon-RPC layer is written against the
// documented Monero daemon RPC but has not been exercised against a live
// node yet. First deploy: test against a real daemon before real funds.

mod rpc;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use monero_wallet::{
    interface::{FeePriority, ProvidesFeeRates as _, ProvidesUnvalidatedScannableBlocks as _, PublishTransaction as _},
    Scanner, ViewPair,
};
use tiny_http::{Method, Response, Server, StatusCode};
use zeroize::Zeroizing;

use rpc::DaemonRpc;

/// The address + view key exported by the app (xmxx-viewkey.txt).
struct WalletConfig {
    address: String,
    view_key: [u8; 32],
}

fn parse_view_key_file(path: &str) -> anyhow::Result<WalletConfig> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("cannot read {path}: {e}"))?;
    let mut address = None;
    let mut view_key = None;
    for line in content.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("address=") {
            address = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("view_key=") {
            view_key = Some(v.to_string());
        }
    }
    let address = address.ok_or_else(|| anyhow!("no address= in {path}"))?;
    let view_key_hex = view_key.ok_or_else(|| anyhow!("no view_key= in {path}"))?;
    let bytes = hex::decode(view_key_hex).map_err(|e| anyhow!("view_key hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("view_key must be 32 bytes"));
    }
    let mut vk = [0u8; 32];
    vk.copy_from_slice(&bytes);
    Ok(WalletConfig { address, view_key: vk })
}

/// Owned outputs found by scanning, kept in memory + persisted.
struct WalletState {
    outputs: Vec<OwnedOutput>,
    scanned_to: usize,
}

/// An owned output with everything the device needs to derive its key image
/// and everything the companion needs to build a spend.
#[derive(Clone)]
struct OwnedOutput {
    /// tx public key R (from the tx extra).
    tx_pub_key: [u8; 32],
    /// index within the transaction.
    index_in_tx: u64,
    /// global ringct output index (for decoy selection).
    index_on_chain: u64,
    /// the one-time output key P.
    key: [u8; 32],
    /// amount in piconeros.
    amount: u64,
    /// the serialized monero-wallet WalletOutput (for OutputWithDecoys::new).
    wallet_output: Vec<u8>,
}

struct Shared {
    rpc: DaemonRpc,
    pair: ViewPair,
    view_key: Zeroizing<monero_oxide::ed25519::Scalar>,
    address: String,
    from: usize,
    state: Mutex<WalletState>,
    state_file: String,
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().ok_or_else(|| anyhow!("usage: xmxx-companion serve --view-key <file> --rpc <url> [--from <h>] [--port <p>]"))?;
    if cmd != "serve" {
        return Err(anyhow!("unknown command {cmd}"));
    }
    let mut view_key_file = None;
    let mut rpc_url = None;
    let mut from = None;
    let mut port = 8787u16;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--view-key" => view_key_file = args.next(),
            "--rpc" => rpc_url = args.next(),
            "--from" => from = args.next().and_then(|s| s.parse().ok()),
            "--port" => port = args.next().and_then(|s| s.parse().ok()).unwrap_or(port),
            other => return Err(anyhow!("unknown flag {other}")),
        }
    }
    let view_key_file = view_key_file.ok_or_else(|| anyhow!("--view-key required"))?;
    let rpc_url = rpc_url.ok_or_else(|| anyhow!("--rpc required"))?;

    let cfg = parse_view_key_file(&view_key_file)?;
    let rpc = DaemonRpc::new(&rpc_url)?;
    let latest = rpc.latest_block_number_().map_err(|e| anyhow!("node: {e}"))?;

    // spend pubkey lives inside the address: base58 decode -> [net(1)] spend(32) view(32) chk(4)
    let addr_raw = xmxx_core::wallet::base58_decode(cfg.address.trim())
        .ok_or_else(|| anyhow!("address did not base58-decode"))?;
    if addr_raw.len() != 69 || addr_raw[0] != 0x12 {
        return Err(anyhow!("address is not a mainnet standard address"));
    }
    let mut spend_pub = [0u8; 32];
    spend_pub.copy_from_slice(&addr_raw[1..33]);

    let view_scalar = Zeroizing::new(monero_oxide::ed25519::Scalar::from(
        curve25519_dalek::Scalar::from_bytes_mod_order(cfg.view_key),
    ));
    let pair = ViewPair::new(
        monero_oxide::ed25519::Point::from(
            curve25519_dalek::edwards::CompressedEdwardsY(spend_pub)
                .decompress()
                .ok_or_else(|| anyhow!("bad spend pubkey in address"))?,
        ),
        Zeroizing::new(*view_scalar),
    )
    .map_err(|e| anyhow!("view pair: {e:?}"))?;

    let from = from.unwrap_or(latest.saturating_sub(5000));
    let state_file = format!("{view_key_file}.state.json");

    let shared = Arc::new(Shared {
        rpc,
        pair,
        view_key: view_scalar,
        address: cfg.address.trim().to_string(),
        from,
        state: Mutex::new(WalletState { outputs: vec![], scanned_to: 0 }),
        state_file,
    });

    // Initial sync on boot so the first page load is fast.
    if let Err(e) = sync_once(&shared) {
        eprintln!("warning: initial sync failed: {e}");
    }

    let server = Server::http(format!("0.0.0.0:{port}")).map_err(|e| anyhow!("bind: {e}"))?;
    println!("xmxx-companion listening on http://0.0.0.0:{port}");
    println!("  wallet: {}", shared.address);
    println!("  rpc:    {}", rpc_url);
    println!("  sync from height {}", shared.from);

    for mut request in server.incoming_requests() {
        let shared = shared.clone();
        std::thread::spawn(move || {
            let url = request.url().to_string();
            let path = url.split('?').next().unwrap_or("/").to_string();
            let result = match (request.method(), path.as_str()) {
                (Method::Get, "/") => handle_sync(&shared),
                (Method::Get, "/send") => {
                    let q: HashMap<String, String> = url
                        .split('?')
                        .nth(1)
                        .unwrap_or("")
                        .split('&')
                        .filter_map(|kv| {
                            let mut it = kv.splitn(2, '=');
                            Some((it.next()?.to_string(), it.next().unwrap_or("").to_string()))
                        })
                        .collect();
                    let a = q.get("a").cloned().unwrap_or_default();
                    let p = q.get("p").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                    handle_send(&shared, &a, p)
                }
                (Method::Post, "/broadcast") => {
                    let mut body = String::new();
                    let _ = request.as_reader().read_to_string(&mut body);
                    handle_broadcast(&shared, body.trim())
                }
                _ => Ok(html_page("xmxx-companion", "<p>404 — try / or /send?a=&lt;addr&gt;&amp;p=&lt;piconero&gt;</p>")),
            };
            match result {
                Ok(page) => {
                    let _ = request.respond(Response::from_string(page).with_header(
                        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap(),
                    ));
                }
                Err(e) => {
                    let page = html_page("xmxx-companion", &format!("<p class='err'>{e}</p>"));
                    let _ = request.respond(Response::from_string(page).with_status_code(StatusCode(500)));
                }
            }
        });
    }
    Ok(())
}

/// Scan new blocks and merge any owned outputs into state.
fn sync_once(shared: &Arc<Shared>) -> anyhow::Result<()> {
    let latest = shared.rpc.latest_block_number_()?;
    let (mut outputs, mut scanned_to) = {
        let s = shared.state.lock().unwrap();
        (s.outputs.clone(), s.scanned_to)
    };
    if scanned_to == 0 {
        scanned_to = shared.from;
    }
    if latest <= scanned_to {
        return Ok(());
    }

    let mut scanner = Scanner::new(shared.pair.clone());
    let mut batch_start = scanned_to;
    while batch_start <= latest {
        let batch_end = (batch_start + 50).min(latest);
        let scannable = futures::executor::block_on(
            shared.rpc.contiguous_scannable_blocks(batch_start..=batch_end),
        )
        .map_err(|e| anyhow!("scan: {e}"))?;
        for usb in scannable {
            // Convert to the checked ScannableBlock and map each tx hash (in
            // the block header, same order as the txs) to its tx public key R.
            // Primary-address outputs use the main tx key; subaddress outputs
            // need per-output additional keys, which v1 does not sync (the app
            // uses its primary address).
            let hashes = usb.block.transactions.clone();
            let txs: Vec<monero_wallet::transaction::Transaction<monero_wallet::transaction::Pruned>> =
                usb.transactions.iter().map(|t| t.as_ref().clone()).collect();
            let mut tx_keys: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
            for (h, tx) in hashes.iter().zip(txs.iter()) {
                tx_keys.insert(*h, rpc::tx_public_key(tx).unwrap_or([0u8; 32]));
            }
            let sb = monero_wallet::interface::ScannableBlock {
                block: usb.block,
                transactions: txs,
                output_index_for_first_ringct_output: usb.output_index_for_first_ringct_output,
            };
            let found = scanner.scan(sb).map_err(|e| anyhow!("scanner: {e:?}"))?;
            for out in found.not_additionally_locked() {
                let amount = out.commitment().amount;
                if amount == 0 {
                    continue; // the unspendable 0-amount change marker (base fee) output
                }
                let tx_pub_key = tx_keys.get(&out.transaction()).copied().unwrap_or([0u8; 32]);
                outputs.push(OwnedOutput {
                    tx_pub_key,
                    index_in_tx: out.index_in_transaction(),
                    index_on_chain: out.index_on_blockchain(),
                    key: out.key().compress().to_bytes(),
                    amount,
                    wallet_output: out.serialize(),
                });
                println!("xmxx: found output {} @ tx index {} amount {}",
                    out.index_on_blockchain(), out.index_in_transaction(), amount);
            }
        }
        batch_start = batch_end + 1;
        scanned_to = batch_end;
    }

    {
        let mut s = shared.state.lock().unwrap();
        s.outputs = outputs;
        s.scanned_to = scanned_to;
    }
    let _ = std::fs::write(&shared.state_file, format!("{scanned_to}\n"));
    Ok(())
}

/// Build the sync page: balance + the xmr-output QR the device scans.
fn handle_sync(shared: &Arc<Shared>) -> anyhow::Result<String> {
    let _ = sync_once(shared)?;
    let (outputs, scanned_to) = {
        let s = shared.state.lock().unwrap();
        (s.outputs.clone(), s.scanned_to)
    };
    let balance: u64 = outputs.iter().map(|o| o.amount).sum();

    // Group by tx_pub_key -> entries for the xmr-output payload.
    let mut grouped: HashMap<[u8; 32], Vec<(u64, [u8; 32])>> = HashMap::new();
    for o in &outputs {
        grouped.entry(o.tx_pub_key).or_default().push((o.index_in_tx, o.key));
    }
    let mut payloads = Vec::new();
    for (r, entries) in grouped {
        let mut s = format!("xmr-output:{}", hex::encode(r));
        for (idx, key) in entries {
            s.push_str(&format!(";{idx}:{}", hex::encode(key)));
        }
        payloads.push(s);
    }

    let mut qr_svgs = String::new();
    for p in &payloads {
        qr_svgs.push_str(&qr_svg(p.as_bytes()));
    }

    let mut rows = String::new();
    for o in &outputs {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>tx {}</td><td>idx {}</td><td>{:.12} XMR</td></tr>",
            hex::encode(&o.tx_pub_key[..4]),
            o.index_on_chain,
            o.index_in_tx,
            o.amount as f64 / 1e12
        ));
    }

    Ok(html_page(
        "xmxx sync",
        &format!(
            "<h2>{}</h2><p class='big'>balance: <b>{:.12} XMR</b> · {} output(s) · synced to block {}</p>
             <p>Hold the Prime over a QR below (one per tx) → scan with the sync tab → the device proves ownership (x·G == P) and derives its key images.</p>
             <div class='qrs'>{}</div>
             <table><tr><th>R (short)</th><th>global idx</th><th>tx idx</th><th>amount</th></tr>{}</table>",
            shared.address, balance as f64 / 1e12, outputs.len(), scanned_to, qr_svgs, rows
        ),
    ))
}

/// Build an unsigned transaction and serve the envelope QR for the device.
fn handle_send(shared: &Arc<Shared>, to_addr: &str, amount: u64) -> anyhow::Result<String> {
    if amount == 0 {
        return Err(anyhow!("amount must be > 0 (piconeros)"));
    }
    let _ = sync_once(shared)?;
    let (outputs, _) = {
        let s = shared.state.lock().unwrap();
        (s.outputs.clone(), s.scanned_to)
    };
    if outputs.is_empty() {
        return Err(anyhow!("no spendable outputs yet — send some XMR to the address first"));
    }

    // Destination address validation + parse.
    if !xmxx_core::wallet::validate_address(to_addr) {
        return Err(anyhow!("bad destination address"));
    }
    let dest: monero_wallet::address::MoneroAddress = monero_wallet::address::Address::from_str(
        monero_wallet::address::Network::Mainnet,
        to_addr,
    )
    .map_err(|e| anyhow!("destination parse: {e}"))?;

    // Fee rate from the node.
    let fee_rate = futures::executor::block_on(shared.rpc.fee_rate(FeePriority::Normal, 10_000))
        .map_err(|e| anyhow!("fee: {e}"))?;

    // Greedy coin selection: largest outputs first, enough to cover amount +
    // fee. monero-wallet re-checks sufficiency and shunts change to fee if
    // the remainder is dust.
    let mut sorted: Vec<OwnedOutput> = outputs;
    sorted.sort_by(|a, b| b.amount.cmp(&a.amount));
    let mut selected = Vec::new();
    let mut total = 0u64;
    for o in &sorted {
        if total >= amount {
            break;
        }
        total += o.amount;
        selected.push(o);
    }
    if total < amount {
        return Err(anyhow!("insufficient funds: {:.12} XMR available", total as f64 / 1e12));
    }

    // Deserialize the wallet outputs and add decoys (ring size 16 = CLSAG+BP+).
    use rand_core::SeedableRng as _;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0u8; 32]); // decoys only; real signing happens on-device
    let latest = shared.rpc.latest_block_number_()?;
    let mut inputs = Vec::with_capacity(selected.len());
    for o in &selected {
        let mut slice: &[u8] = &o.wallet_output;
        let wallet_output = monero_wallet::WalletOutput::read(&mut slice)
            .map_err(|e| anyhow!("wallet output: {e}"))?;
        let input = futures::executor::block_on(monero_wallet::OutputWithDecoys::new(
            &mut rng,
            &shared.rpc,
            16,
            latest,
            wallet_output,
        ))
        .map_err(|e| anyhow!("decoys: {e}"))?;
        inputs.push(input);
    }

    // Change back to the primary address (non-fingerprintable wallet protocol).
    let change = monero_wallet::send::Change::new(shared.pair.clone(), None);

    let tx = monero_wallet::send::SignableTransaction::new(
        monero_wallet::ringct::RctType::ClsagBulletproofPlus,
        Zeroizing::new(<[u8; 32]>::from(*shared.view_key)),
        inputs,
        vec![(dest, amount)],
        change,
        vec![],
        fee_rate,
    )
    .map_err(|e| anyhow!("build tx: {e}"))?;

    let payload = tx.serialize();
    let destinations = vec![(to_addr.to_string(), amount)];
    let envelope = xmxx_core::txset::encode_unsigned_tx_set(
        &destinations,
        &payload,
        &shared.view_key,
    )
    .map_err(|e| anyhow!("envelope: {e}"))?;

    // Binary QR of the raw envelope bytes (device parses raw OR hex form).
    let raw = hex::decode(envelope.strip_prefix("xmr-txunsigned:").unwrap_or(&envelope))
        .unwrap_or_default();
    if raw.len() > 2953 {
        return Err(anyhow!(
            "envelope too big for a single QR ({} bytes > 2953). Use fewer inputs or a larger QR-capable viewer.",
            raw.len()
        ));
    }
    let svg = qr_svg(&raw);
    let hex_form = envelope.clone();

    Ok(html_page(
        "xmxx send — scan with Prime",
        &format!(
            "<h2>Send {:.12} XMR</h2><p>to <code>{}</code></p>
             <p>Fee rate: per-weight (node estimate) · inputs: {} · hold the Prime over the QR → review → sign → then open /broadcast and paste the xmr-txsigned hex.</p>
             <div class='qr'>{}</div>
             <p>hex (fallback): <code style='word-break:break-all'>{}</code></p>",
            amount as f64 / 1e12, to_addr, selected.len(), svg, hex_form
        ),
    ))
}

/// Parse + broadcast a signed tx returned by the device.
fn handle_broadcast(shared: &Arc<Shared>, body: &str) -> anyhow::Result<String> {
    let body = body.trim();
    let bytes = body
        .strip_prefix("xmr-txsigned:")
        .map(|h| hex::decode(h).map_err(|e| anyhow!("hex: {e}")))
        .unwrap_or_else(|| Ok(body.as_bytes().to_vec()))?;
    let mut slice: &[u8] = &bytes;
    let tx = monero_wallet::transaction::Transaction::read(&mut slice)
        .map_err(|e| anyhow!("signed tx parse: {e}"))?;
    futures::executor::block_on(shared.rpc.publish_transaction(&tx))
        .map_err(|e| anyhow!("broadcast failed: {e}"))?;
    let hash = hex::encode(tx.hash());
    Ok(html_page(
        "xmxx broadcast",
        &format!("<h2>✅ broadcast</h2><p>The transaction was accepted by the node.</p><p>tx hash: <code>{hash}</code></p>"),
    ))
}

// ---------------------------------------------------------------------------
// QR + page helpers
// ---------------------------------------------------------------------------

/// Render a binary payload as an SVG QR (byte mode, auto version, EC Q).
fn qr_svg(data: &[u8]) -> String {
    match qrcode::QrCode::with_error_correction_level(data, qrcode::EcLevel::Q) {
        Ok(code) => {
            let size = code.width();
            let cell = 6;
            let mut svg = format!(
                "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {} {}' shape-rendering='crispEdges'>",
                size * cell,
                size * cell
            );
            svg.push_str("<rect width='100%' height='100%' fill='white'/>");
            for y in 0..size {
                for x in 0..size {
                    if code[(x, y)] == qrcode::Color::Dark {
                        svg.push_str(&format!(
                            "<rect x='{}' y='{}' width='{}' height='{}' fill='black'/>",
                            x * cell,
                            y * cell,
                            cell,
                            cell
                        ));
                    }
                }
            }
            svg.push_str("</svg>");
            svg
        }
        Err(_) => "<p>QR encode failed</p>".to_string(),
    }
}

fn html_page(title: &str, body: &str) -> String {
    format!(
        "<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{title}</title>
        <style>
        body {{ background:#000; color:#fff; font-family:ui-monospace,monospace; padding:16px; }}
        .qr {{ background:#fff; padding:12px; display:inline-block; border-radius:8px; }}
        .qrs {{ display:flex; gap:16px; flex-wrap:wrap; }}
        .qrs .qr {{ margin-bottom:8px; }}
        h2 {{ color:#ff6a00; }}
        .big {{ font-size:18px; }}
        .err {{ color:#ff4444; }}
        code {{ background:#222; padding:2px 6px; border-radius:4px; }}
        table {{ border-collapse:collapse; margin-top:16px; }}
        td,th {{ border:1px solid #333; padding:4px 10px; text-align:left; }}
        a {{ color:#ff8c42; }}
        </style></head><body>{body}</body></html>"
    )
}
