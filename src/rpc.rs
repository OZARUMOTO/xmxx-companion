// SPDX-FileCopyrightText: 2026 OZARUMOTO
// SPDX-License-Identifier: GPL-3.0-or-later
//
// XMXX-COMPANION daemon RPC — implements monero-interface's `Provides*`
// traits against a standard Monero daemon JSON-RPC endpoint, so
// monero-wallet's Scanner / OutputWithDecoys / SignableTransaction work
// against any full node (remote or local). No node storage on the box.

use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use serde_json::{json, Value};

use monero_wallet::interface::{
    EvaluateUnlocked, InterfaceError, PrunedTransactionWithPrunableHash,
    RingCtOutputInformation, TransactionsError, UnvalidatedScannableBlock,
};
use monero_oxide::{
    block::Block,
    ed25519::{CompressedPoint, Point},
    io::VarInt,
    transaction::{Pruned, Transaction},
};

/// A Monero daemon JSON-RPC client.
#[derive(Clone)]
pub struct DaemonRpc {
    inner: Arc<Inner>,
}

struct Inner {
    url: String,
    agent: ureq::Agent,
    /// Cached (block_height, cumulative_ringct_output_count) at that height,
    /// so each scan batch doesn't re-fetch the whole output distribution.
    ringct_at: Mutex<Option<(usize, u64)>>,
}

impl DaemonRpc {
    pub fn new(url: &str) -> anyhow::Result<Self> {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(120))
            .build();
        let rpc = DaemonRpc {
            inner: Arc::new(Inner {
                url: url.to_string(),
                agent,
                ringct_at: Mutex::new(None),
            }),
        };
        // Fail fast if the node is unreachable.
        rpc.latest_block_number_().map_err(|e| anyhow!("node unreachable at {url}: {e}"))?;
        Ok(rpc)
    }

    fn post(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 0, "method": method, "params": params });
        let resp = self
            .inner
            .agent
            .post(&format!("{}/json_rpc", self.inner.url))
            .send_json(body)
            .map_err(|e| anyhow!("rpc {method}: {e}"))?;
        let v: Value = resp.into_json().map_err(|e| anyhow!("rpc {method}: bad json: {e}"))?;
        if let Some(err) = v.get("error") {
            return Err(anyhow!("rpc {method} error: {err}"));
        }
        v.get("result").cloned().ok_or_else(|| anyhow!("rpc {method}: no result"))
    }

    /// POST JSON to a daemon URI endpoint (e.g. `/get_transactions`).
    ///
    /// Since 0.18.x, monerod serves the tx-level methods as URI endpoints
    /// (`/get_transactions`, `/get_outs`, `/send_raw_transaction`, ...)
    /// rather than in the `/json_rpc` map — calling them via `/json_rpc`
    /// returns "Method not found".
    fn post_uri(&self, uri: &str, body: Value) -> anyhow::Result<Value> {
        let resp = self
            .inner
            .agent
            .post(&format!("{}{}", self.inner.url, uri))
            .send_json(body)
            .map_err(|e| anyhow!("rpc {uri}: {e}"))?;
        let v: Value = resp.into_json().map_err(|e| anyhow!("rpc {uri}: bad json: {e}"))?;
        if let Some(err) = v.get("error") {
            return Err(anyhow!("rpc {uri} error: {err}"));
        }
        // URI endpoints return the response object directly, with no
        // `result` wrapper (unlike /json_rpc).
        Ok(v)
    }

    /// get_block_count → the number of the latest block (count - 1).
    pub fn latest_block_number_(&self) -> anyhow::Result<usize> {
        let res = self.post("get_block_count", json!({}))?;
        let count = res["count"].as_u64().ok_or_else(|| anyhow!("get_block_count: bad count"))?;
        Ok(count.saturating_sub(1) as usize)
    }

    /// (block, pruned txs) for a range.
    ///
    /// 0.18.x daemons serve `get_blocks_by_height` only as a *binary*
    /// endpoint (`/get_blocks_by_height.bin`), so we assemble each range
    /// from `get_block` (JSON, per height — returns the block blob with tx
    /// hashes) plus `get_transactions` (URI endpoint).
    fn blocks_by_height_(
        &self,
        start: usize,
        end: usize,
    ) -> anyhow::Result<Vec<(Block, Vec<Transaction<Pruned>>)>> {
        let mut out = Vec::with_capacity(end.saturating_sub(start) + 1);
        for height in start..=end {
            let block = self.block_(json!({ "height": height }))?;
            let hashes = block.transactions.clone();
            let raw = self.txs_(&hashes, true)?;
            let mut txs = Vec::with_capacity(raw.len());
            for (bytes, _) in raw {
                let mut slice: &[u8] = &bytes;
                let tx = Transaction::<Pruned>::read(&mut slice)
                    .map_err(|e| anyhow!("tx parse: {e}"))?;
                txs.push(tx);
            }
            out.push((block, txs));
        }
        Ok(out)
    }

    /// get_transactions → (as_hex bytes, prunable_hash) for the requested hashes.
    /// Callers parse with the transaction type matching the `prune` flag.
    fn txs_(
        &self,
        hashes: &[[u8; 32]],
        prune: bool,
    ) -> anyhow::Result<Vec<(Vec<u8>, Option<[u8; 32]>)>> {
        if hashes.is_empty() {
            return Ok(vec![]);
        }
        let hashes_hex: Vec<String> = hashes.iter().map(hex::encode).collect();
        let res = self.post_uri(
            "/get_transactions",
            json!({ "txs_hashes": hashes_hex, "prune": prune, "split": true }),
        )?;
        let txs = res["txs"].as_array().ok_or_else(|| anyhow!("get_transactions: no txs"))?;
        let mut out = Vec::with_capacity(txs.len());
        for t in txs {
            // With prune=true the daemon returns the pruned blob in
            // `pruned_as_hex` and leaves `as_hex` empty; with prune=false
            // the full tx is in `as_hex`.
            let as_hex = t["as_hex"].as_str().unwrap_or("");
            let tx_hex = if as_hex.is_empty() {
                t["pruned_as_hex"].as_str().unwrap_or("")
            } else {
                as_hex
            };
            let bytes = hex::decode(tx_hex).map_err(|e| anyhow!("tx hex: {e}"))?;
            let prunable_hash = match t["prunable_hash"].as_str() {
                Some(h) if !h.is_empty() => {
                    let b = hex::decode(h).map_err(|e| anyhow!("prunable_hash hex: {e}"))?;
                    Some(b.try_into().map_err(|_| anyhow!("prunable_hash len"))?)
                }
                _ => None,
            };
            out.push((bytes, prunable_hash));
        }
        Ok(out)
    }

    /// get_block by height OR hash → one block.
    fn block_(&self, params: Value) -> anyhow::Result<Block> {
        let res = self.post("get_block", params)?;
        let blob_hex = res["blob"].as_str().ok_or_else(|| anyhow!("get_block: no blob"))?;
        let blob = hex::decode(blob_hex).map_err(|e| anyhow!("blob hex: {e}"))?;
        let mut slice: &[u8] = &blob;
        Block::read(&mut slice).map_err(|e| anyhow!("block parse: {e}"))
    }

    /// get_o_indexes → global ringct output indexes of a tx.
    fn o_indexes_(&self, txid: [u8; 32]) -> anyhow::Result<Vec<u64>> {
        let res = self.post("get_o_indexes", json!({ "txid": hex::encode(txid) }))?;
        res["o_indexes"]
            .as_array()
            .ok_or_else(|| anyhow!("get_o_indexes: no o_indexes"))?
            .iter()
            .map(|v| v.as_u64().ok_or_else(|| anyhow!("get_o_indexes: bad index")))
            .collect()
    }

    /// get_outs → key + mask (commitment) + unlock + txid for global indexes.
    fn outs_(&self, indexes: &[u64]) -> anyhow::Result<Vec<OutInfo>> {
        if indexes.is_empty() {
            return Ok(vec![]);
        }
        let outputs: Vec<Value> =
            indexes.iter().map(|i| json!({ "index": i, "txid": true })).collect();
        let res = self.post_uri("/get_outs", json!({ "outputs": outputs }))?;
        let outs = res["outs"].as_array().ok_or_else(|| anyhow!("get_outs: no outs"))?;
        let mut out = Vec::with_capacity(outs.len());
        for o in outs {
            let key_hex = o["key"].as_str().ok_or_else(|| anyhow!("get_outs: no key"))?;
            let mask_hex = o["mask"].as_str().ok_or_else(|| anyhow!("get_outs: no mask"))?;
            let unlocked = o["unlocked"].as_bool().unwrap_or(true);
            let txid_hex = o["txid"].as_str().ok_or_else(|| anyhow!("get_outs: no txid"))?;
            out.push(OutInfo {
                key: hex::decode(key_hex).map_err(|e| anyhow!("key hex: {e}"))?,
                mask: hex::decode(mask_hex).map_err(|e| anyhow!("mask hex: {e}"))?,
                unlocked,
                txid: hex::decode(txid_hex).map_err(|e| anyhow!("txid hex: {e}"))?,
            });
        }
        Ok(out)
    }

    /// get_output_distribution (cumulative) for the ringct pool over a range.
    fn distribution_(&self, from: usize, to: usize) -> anyhow::Result<Vec<u64>> {
        let res = self.post(
            "get_output_distribution",
            json!({
                "amounts": [0],
                "cumulative": true,
                "from_height": from,
                "to_height": to,
            }),
        )?;
        let dist = res["distributions"]
            .as_array()
            .and_then(|d| d.first())
            .and_then(|d| d["distribution"].as_array())
            .ok_or_else(|| anyhow!("get_output_distribution: bad response"))?;
        dist.iter()
            .map(|v| v.as_u64().ok_or_else(|| anyhow!("distribution: bad value")))
            .collect()
    }

    /// The cumulative ringct output count at `height` (inclusive): the count
    /// of ringct outputs in blocks 0..=height. Cached per height so repeated
    /// scan batches don't re-fetch the entire distribution.
    fn ringct_count_at(&self, height: usize) -> anyhow::Result<u64> {
        let mut guard = self.inner.ringct_at.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((h, c)) = *guard {
            if h == height {
                return Ok(c);
            }
        }
        if height == 0 {
            *guard = Some((0, 0));
            return Ok(0);
        }
        let dist = self.distribution_(0, height)?;
        let c = *dist.last().unwrap_or(&0);
        *guard = Some((height, c));
        Ok(c)
    }

    /// Advance the cached ringct count after scanning blocks [start, end]:
    /// the count at `end` = count at `start-1` + ringct outputs in the range.
    fn advance_ringct_count(&self, end: usize, ringct_in_range: u64) {
        if let Ok(mut guard) = self.inner.ringct_at.lock() {
            let pre = guard.map(|(_, c)| c).unwrap_or(0);
            *guard = Some((end, pre + ringct_in_range));
        }
    }
}

/// A raw get_outs entry before type conversion.
struct OutInfo {
    key: Vec<u8>,
    mask: Vec<u8>,
    unlocked: bool,
    txid: Vec<u8>,
}

fn point_from_32(bytes: &[u8]) -> Result<Point, InterfaceError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| InterfaceError::InternalError("bad point length".to_string()))?;
    CompressedPoint::from(arr)
        .decompress()
        .ok_or_else(|| InterfaceError::InvalidInterface("invalid point".to_string()))
}

fn interface_err(e: anyhow::Error) -> InterfaceError {
    InterfaceError::InternalError(e.to_string())
}

// ---------------------------------------------------------------------------
// monero-interface trait impls
// ---------------------------------------------------------------------------

impl monero_wallet::interface::ProvidesBlockchainMeta for DaemonRpc {
    fn latest_block_number(
        &self,
    ) -> impl Send + core::future::Future<Output = Result<usize, InterfaceError>> {
        async move { self.latest_block_number_().map_err(interface_err) }
    }
}

impl monero_wallet::interface::ProvidesUnvalidatedBlockchain for DaemonRpc {
    fn contiguous_blocks(
        &self,
        range: std::ops::RangeInclusive<usize>,
    ) -> impl Send + core::future::Future<Output = Result<Vec<Block>, InterfaceError>> {
        async move {
            let blocks =
                self.blocks_by_height_(*range.start(), *range.end()).map_err(interface_err)?;
            Ok(blocks.into_iter().map(|(b, _)| b).collect())
        }
    }

    fn block(
        &self,
        hash: [u8; 32],
    ) -> impl Send + core::future::Future<Output = Result<Block, InterfaceError>> {
        async move { self.block_(json!({ "hash": hex::encode(hash) })).map_err(interface_err) }
    }

    fn block_by_number(
        &self,
        number: usize,
    ) -> impl Send + core::future::Future<Output = Result<Block, InterfaceError>> {
        async move { self.block_(json!({ "height": number })).map_err(interface_err) }
    }

    fn block_hash(
        &self,
        number: usize,
    ) -> impl Send + core::future::Future<Output = Result<[u8; 32], InterfaceError>> {
        async move {
            let res = self
                .post("get_block_header_by_height", json!({ "height": number }))
                .map_err(interface_err)?;
            let hash_hex = res["block_header"]["hash"]
                .as_str()
                .ok_or_else(|| InterfaceError::InvalidInterface("no hash".to_string()))?;
            hex::decode(hash_hex)
                .map_err(|e| InterfaceError::InvalidInterface(format!("hash hex: {e}")))?
                .try_into()
                .map_err(|_| InterfaceError::InvalidInterface("bad hash len".to_string()))
        }
    }
}

impl monero_wallet::interface::ProvidesUnvalidatedTransactions for DaemonRpc {
    fn transactions(
        &self,
        hashes: &[[u8; 32]],
    ) -> impl Send + core::future::Future<Output = Result<Vec<Transaction>, TransactionsError>> {
        let hashes = hashes.to_vec();
        async move {
            let txs = self
                .txs_(&hashes, false)
                .map_err(|e| TransactionsError::from(InterfaceError::InternalError(e.to_string())))?;
            let mut out = Vec::with_capacity(txs.len());
            for (bytes, _) in txs {
                let mut slice: &[u8] = &bytes;
                let tx = Transaction::read(&mut slice)
                    .map_err(|e| TransactionsError::from(InterfaceError::InternalError(e.to_string())))?;
                out.push(tx);
            }
            Ok(out)
        }
    }

    fn pruned_transactions(
        &self,
        hashes: &[[u8; 32]],
    ) -> impl Send + core::future::Future<
        Output = Result<Vec<PrunedTransactionWithPrunableHash>, TransactionsError>,
    > {
        let hashes = hashes.to_vec();
        async move {
            let txs = self
                .txs_(&hashes, true)
                .map_err(|e| TransactionsError::from(InterfaceError::InternalError(e.to_string())))?;
            let mut out = Vec::with_capacity(txs.len());
            for (bytes, prunable_hash) in txs {
                let mut slice: &[u8] = &bytes;
                let tx = Transaction::<Pruned>::read(&mut slice).map_err(|e| {
                    TransactionsError::from(InterfaceError::InternalError(e.to_string()))
                })?;
                out.push(
                    PrunedTransactionWithPrunableHash::new(tx, prunable_hash)
                        .ok_or(TransactionsError::PrunedTransaction)?,
                );
            }
            Ok(out)
        }
    }
}

impl monero_wallet::interface::ProvidesUnvalidatedOutputs for DaemonRpc {
    fn output_indexes(
        &self,
        hash: [u8; 32],
    ) -> impl Send + core::future::Future<Output = Result<Vec<u64>, InterfaceError>> {
        async move { self.o_indexes_(hash).map_err(interface_err) }
    }

    fn ringct_outputs(
        &self,
        indexes: &[u64],
    ) -> impl Send + core::future::Future<Output = Result<Vec<RingCtOutputInformation>, InterfaceError>> {
        let indexes = indexes.to_vec();
        async move {
            let outs = self.outs_(&indexes).map_err(interface_err)?;
            let mut res = Vec::with_capacity(outs.len());
            for info in &outs {
                let key = point_from_32(&info.key)?;
                let commitment = point_from_32(&info.mask)?;
                let transaction: [u8; 32] = info
                    .txid
                    .as_slice()
                    .try_into()
                    .map_err(|_| InterfaceError::InvalidInterface("bad txid len".to_string()))?;
                res.push(RingCtOutputInformation {
                    block_number: 0, // not provided by get_outs; unused in our flows
                    unlocked: info.unlocked,
                    key: key.compress(),
                    commitment,
                    transaction,
                });
            }
            Ok(res)
        }
    }
}

impl monero_wallet::interface::ProvidesUnvalidatedScannableBlocks for DaemonRpc {
    fn contiguous_scannable_blocks(
        &self,
        range: std::ops::RangeInclusive<usize>,
    ) -> impl Send + core::future::Future<
        Output = Result<Vec<UnvalidatedScannableBlock>, InterfaceError>,
    > {
        let start = *range.start();
        let end = *range.end();
        async move {
            let blocks = self.blocks_by_height_(start, end).map_err(interface_err)?;
            // Cumulative ringct output count BEFORE each block: cached count at
            // `start - 1` plus the running total within the range.
            let pre = self.ringct_count_at(start.saturating_sub(1)).map_err(interface_err)?;
            let mut running = pre;
            let mut out = Vec::with_capacity(blocks.len());
            for (block, txs) in blocks {
                let first = running;
                // RingCT (zero-amount) outputs are the only ones in V2 txs.
                for tx in &txs {
                    if tx.version() == 2 {
                        running += tx.prefix().outputs.len() as u64;
                    }
                }
                let transactions = txs
                    .into_iter()
                    // The daemon's get_blocks_by_height blobs are pruned; the
                    // prunable hash is not conveyed here. We never run the
                    // checked validation path, so a placeholder is fine.
                    .filter_map(|tx| PrunedTransactionWithPrunableHash::new(tx, Some([0u8; 32])))
                    .collect();
                out.push(UnvalidatedScannableBlock {
                    block,
                    transactions,
                    output_index_for_first_ringct_output: Some(first),
                });
            }
            if let Some(last) = out.last() {
                self.advance_ringct_count(last.block.number(), running - pre);
            }
            Ok(out)
        }
    }

    fn scannable_block(
        &self,
        hash: [u8; 32],
    ) -> impl Send + core::future::Future<
        Output = Result<UnvalidatedScannableBlock, InterfaceError>,
    > {
        async move {
            let block = self.block_(json!({ "hash": hex::encode(hash) })).map_err(interface_err)?;
            let number = block.number();
            let (_, txs) = self
                .blocks_by_height_(number, number)
                .map_err(interface_err)?
                .pop()
                .ok_or_else(|| InterfaceError::InvalidInterface("empty block".to_string()))?;
            let pre = self.ringct_count_at(number.saturating_sub(1)).map_err(interface_err)?;
            let ringct: u64 = txs
                .iter()
                .filter(|t| t.version() == 2)
                .map(|t| t.prefix().outputs.len() as u64)
                .sum();
            let transactions = txs
                .into_iter()
                .filter_map(|tx| PrunedTransactionWithPrunableHash::new(tx, Some([0u8; 32])))
                .collect();
            self.advance_ringct_count(number, ringct);
            Ok(UnvalidatedScannableBlock {
                block,
                transactions,
                output_index_for_first_ringct_output: Some(pre),
            })
        }
    }
}

impl monero_wallet::interface::ProvidesUnvalidatedDecoys for DaemonRpc {
    fn ringct_output_distribution(
        &self,
        range: impl Send + core::ops::RangeBounds<usize>,
    ) -> impl Send + core::future::Future<Output = Result<Vec<u64>, InterfaceError>> {
        let (from, to) = range_bounds(range);
        async move { self.distribution_(from, to).map_err(interface_err) }
    }

    fn unlocked_ringct_outputs(
        &self,
        indexes: &[u64],
        _evaluate_unlocked: EvaluateUnlocked,
    ) -> impl Send + core::future::Future<Output = Result<Vec<Option<[Point; 2]>>, TransactionsError>> {
        let indexes = indexes.to_vec();
        async move {
            let outs = self
                .outs_(&indexes)
                .map_err(|e| TransactionsError::from(InterfaceError::InternalError(e.to_string())))?;
            let mut res = Vec::with_capacity(outs.len());
            for info in outs {
                if !info.unlocked {
                    res.push(None);
                    continue;
                }
                let key = point_from_32(&info.key).map_err(TransactionsError::from)?;
                let commitment = point_from_32(&info.mask).map_err(TransactionsError::from)?;
                res.push(Some([key, commitment]));
            }
            Ok(res)
        }
    }
}

impl monero_wallet::interface::ProvidesUnvalidatedFeeRates for DaemonRpc {
    fn fee_rate(
        &self,
        _priority: monero_wallet::interface::FeePriority,
    ) -> impl Send + core::future::Future<Output = Result<monero_wallet::interface::FeeRate, monero_wallet::interface::FeeError>> {
        async move {
            let res = self
                .post("get_fee_estimate", json!({ "grace_blocks": 10 }))
                .map_err(|e| monero_wallet::interface::FeeError::InterfaceError(InterfaceError::InternalError(e.to_string())))?;
            let per_kb = res["fee"]
                .as_u64()
                .ok_or_else(|| monero_wallet::interface::FeeError::InvalidFee)?;
            // Daemon fee is per kB; Monero weight is ~2048 per kB.
            let per_weight = (per_kb / 2048).max(1);
            monero_wallet::interface::FeeRate::new(per_weight, 2048)
                .ok_or(monero_wallet::interface::FeeError::InvalidFee)
        }
    }
}

impl monero_wallet::interface::PublishTransaction for DaemonRpc {
    fn publish_transaction(
        &self,
        transaction: &Transaction,
    ) -> impl Send + core::future::Future<Output = Result<(), monero_wallet::interface::PublishTransactionError>> {
        let blob = transaction.serialize();
        async move {
            let res = self
                .post_uri("/send_raw_transaction", json!({ "tx_as_hex": hex::encode(blob) }))
                .map_err(|e| monero_wallet::interface::PublishTransactionError::InterfaceError(InterfaceError::InternalError(e.to_string())))?;
            match res["status"].as_str() {
                Some("OK") => Ok(()),
                other => Err(monero_wallet::interface::PublishTransactionError::TransactionRejected(
                    format!("daemon refused: {other:?} reason={}", res["reason"]),
                )),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn range_bounds(range: impl core::ops::RangeBounds<usize>) -> (usize, usize) {
    use core::ops::Bound;
    let from = match range.start_bound() {
        Bound::Included(&n) => n,
        Bound::Excluded(&n) => n + 1,
        Bound::Unbounded => 0,
    };
    let to = match range.end_bound() {
        Bound::Included(&n) => n,
        Bound::Excluded(&n) => n.saturating_sub(1),
        Bound::Unbounded => usize::MAX,
    };
    (from, to)
}

/// Parse the tx public key (first extra key) out of a pruned transaction.
pub fn tx_public_key(tx: &Transaction<Pruned>) -> Option<[u8; 32]> {
    let mut buf: &[u8] = &tx.prefix().extra;
    let extra = monero_wallet::extra::Extra::read(&mut buf).ok()?;
    let (keys, _additional) = extra.keys()?;
    let r = keys.first()?;
    Some(r.compress().to_bytes())
}

/// Encode the xmr-output payload for one transaction's owned outputs.
#[allow(dead_code)]
pub fn encode_output_payload(
    tx_pub_key: &[u8; 32],
    outputs: &[(u64, [u8; 32], Option<(u32, u32)>)],
) -> String {
    let mut s = format!("xmr-output:{}", hex::encode(tx_pub_key));
    for (idx, key, sub) in outputs {
        match sub {
            Some((major, minor)) => {
                s.push_str(&format!(";{}:{}:{}:{}", idx, hex::encode(key), major, minor));
            }
            None => {
                s.push_str(&format!(";{}:{}", idx, hex::encode(key)));
            }
        }
    }
    s
}

/// VarInt-encode a u64 (for the one-time-key derivation when the companion
/// needs to reproduce the offset for verification).
#[allow(dead_code)]
pub fn varint(n: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    VarInt::write(&n, &mut out).expect("varint to Vec cannot fail");
    out
}


