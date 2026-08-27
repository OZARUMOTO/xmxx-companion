// SPDX-FileCopyrightText: 2026 OZARUMOTO
// SPDX-License-Identifier: GPL-3.0-or-later
//
// XMXX-CORE transaction set — the xmr-txunsigned / xmr-txsigned wire format.
//
// The wire format is monero-wallet's native `SignableTransaction` serialization
// (a vetted, Cypher-Stack-audited structure: inputs with decoys and
// commitments, payments, fee rate), wrapped in an envelope that is
// **authenticated with the view keypair**:
//
//   magic "xmxx-txunsigned-v1" ‖ version(1) ‖ destinations ‖ payload ‖ sig
//
// where `destinations` is the human-review summary (address + piconeros) the
// companion built, `payload` is the serialized SignableTransaction, and `sig`
// is Monero's Schnorr signature (crypto.cpp generate_signature) over
// `keccak256(destinations ‖ payload)` under the wallet's view key. Verifying
// the signature before touching the payload proves (a) the data is unmodified
// and (b) the sender holds this wallet's view key — the "is this my wallet?"
// test, and the same auth model as wallet2's unsigned_tx_set (minus the
// CryptoNight-v0 key derivation, which wallet2-format interop would require).
//
// Review + signing:
//   * necessary_fee is recomputed on-device from the actual object being
//     signed (fee/change are recalculated from the fee rate, per monero-wallet).
//   * Each input is ownership-verified during signing: monero-wallet's
//     sign() asserts (spend + key_offset)·G == P and refuses otherwise, so a
//     companion cannot make the device sign inputs it does not own.
//   * Signing is deterministic: a ChaCha20Rng seeded from
//     keccak256(payload ‖ view_pub) makes the signature a pure function of
//     the unsigned set and the keys — reproducible and testable.
//
// The destination summary is companion-asserted (the device has no way to
// recompute payment intents from the serialized tx), but it is bound to the
// payload by the envelope signature and shown alongside the payload
// fingerprint, which the user can cross-check against the companion.

use rand_core::SeedableRng as _;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::wallet::validate_address;
use crate::{Point, Scalar};

const MAGIC: &[u8; 18] = b"xmxx-txunsigned-v1";
const VERSION: u8 = 1;

/// An authenticated unsigned transaction set, parsed and ready for review or
/// signing. Everything except `destinations` is device-derived.
pub struct UnsignedTxSet {
    /// keccak256(payload) — the fingerprint of the exact bytes that will be
    /// signed. Shown on the review screen for cross-checking.
    pub fingerprint: [u8; 32],
    /// Destination summary (address, piconeros) supplied by the companion and
    /// authenticated by the envelope signature.
    pub destinations: Vec<(String, u64)>,
    /// The minimum fee this transaction requires, recomputed on-device from
    /// the parsed object (not echoed from the companion).
    pub necessary_fee: u64,
    /// Serialized `SignableTransaction` — the exact bytes that are signed.
    pub payload: Vec<u8>,
    tx: monero_wallet::send::SignableTransaction,
}

/// Review-screen projection of an unsigned transaction.
#[derive(Clone, Debug)]
pub struct TxPreview {
    pub to_addr: String,
    pub amount_xmr: String,
    pub fee_xmr: String,
    pub status: String,
    pub fingerprint_hex: String,
}

#[derive(Debug)]
pub enum TxSetError {
    Decode(String),
    InvalidEnvelope(String),
    AuthenticationFailed,
    Parse(String),
    Sign(String),
}

impl core::fmt::Display for TxSetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TxSetError::Decode(e) => write!(f, "decode error: {e}"),
            TxSetError::InvalidEnvelope(e) => write!(f, "invalid envelope: {e}"),
            TxSetError::AuthenticationFailed => write!(f, "authentication failed: not this wallet's unsigned set"),
            TxSetError::Parse(e) => write!(f, "parse error: {e}"),
            TxSetError::Sign(e) => write!(f, "signing error: {e}"),
        }
    }
}

impl std::error::Error for TxSetError {}

/// Build an `xmr-txunsigned` payload for the companion: serialize the
/// `SignableTransaction`, wrap it with the destination summary, and sign the
/// envelope with the wallet's private view key.
pub fn encode_unsigned_tx_set(
    destinations: &[(String, u64)],
    payload: &[u8],
    view_key: &Scalar,
) -> Result<String, TxSetError> {
    for (addr, _) in destinations {
        if !validate_address(addr) {
            return Err(TxSetError::InvalidEnvelope(format!("bad destination address: {addr}")));
        }
    }

    let mut envelope = Vec::with_capacity(18 + 1 + payload.len() + 64 + 32 * destinations.len());
    envelope.extend_from_slice(MAGIC);
    envelope.push(VERSION);

    let mut dest_region = Vec::with_capacity(4 + 33 * destinations.len());
    dest_region.extend_from_slice(&(destinations.len() as u32).to_le_bytes());
    for (addr, amount) in destinations {
        let addr_bytes = addr.as_bytes();
        if addr_bytes.len() > u8::MAX as usize {
            return Err(TxSetError::InvalidEnvelope("address too long".into()));
        }
        dest_region.push(addr_bytes.len() as u8);
        dest_region.extend_from_slice(addr_bytes);
        dest_region.extend_from_slice(&amount.to_le_bytes());
    }

    envelope.extend_from_slice(&dest_region);

    envelope.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    envelope.extend_from_slice(payload);

    // data_to_sign = keccak256(destinations ‖ payload)
    let data_to_sign = keccak256(&[&dest_region, payload].concat());

    let view_pub = mul_base(view_key);
    let (c, r) = schnorr_sign(&data_to_sign, view_key, &view_pub);
    envelope.extend_from_slice(&c);
    envelope.extend_from_slice(&r);

    Ok(format!("xmr-txunsigned:{}", hex::encode(&envelope)))
}

/// Parse and authenticate an `xmr-txunsigned` payload. Verifies the envelope
/// signature with the wallet's public view key, then parses the
/// `SignableTransaction`. Refuses anything not signed by this wallet's view
/// key or that fails to parse.
pub fn parse_unsigned_tx_set(
    qr_data: &str,
    view_pub: &Point,
) -> Result<UnsignedTxSet, TxSetError> {
    let hex_data = qr_data.trim().strip_prefix("xmr-txunsigned:").unwrap_or(qr_data.trim());
    let raw = hex::decode(hex_data).map_err(|e| TxSetError::Decode(e.to_string()))?;
    parse_envelope(&raw, view_pub)
}

/// Parse + authenticate an `xmr-txunsigned` payload passed as RAW BYTES (the
/// Prime's QR scanner yields binary; binary envelopes are also far more
/// space-efficient than hex for multi-input txs). Accepts an optional
/// `xmr-txunsigned:` text prefix for hex-encoded payloads.
pub fn parse_unsigned_tx_set_bytes(
    qr_data: &[u8],
    view_pub: &Point,
) -> Result<UnsignedTxSet, TxSetError> {
    let data: &[u8] = match qr_data.strip_prefix(b"xmr-txunsigned:") {
        Some(rest) => rest,
        None => qr_data,
    };
    // If the payload is all ASCII hex chars, it's the hex form; decode it.
    // Otherwise treat it as the raw envelope bytes.
    let raw = if !data.is_empty() && data.iter().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(data).map_err(|e| TxSetError::Decode(e.to_string()))?
    } else {
        data.to_vec()
    };
    parse_envelope(&raw, view_pub)
}

/// The shared envelope parse: magic/version/destinations/payload/signature,
/// Schnorr verification with the wallet's public view key, then
/// `SignableTransaction::read`. Refuses anything not signed by this wallet.
fn parse_envelope(raw: &[u8], view_pub: &Point) -> Result<UnsignedTxSet, TxSetError> {
    // Magic + version.
    if raw.len() < 18 + 1 + 4 + 4 + 64 {
        return Err(TxSetError::InvalidEnvelope("payload too short".into()));
    }
    if &raw[..18] != MAGIC {
        return Err(TxSetError::InvalidEnvelope("bad magic".into()));
    }
    if raw[18] != VERSION {
        return Err(TxSetError::InvalidEnvelope(format!("unsupported version {}", raw[18])));
    }

    let mut pos = 19;
    let dest_count = u32::from_le_bytes(raw[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;

    let mut destinations = Vec::with_capacity(dest_count);
    for _ in 0..dest_count {
        let addr_len = *raw.get(pos).ok_or_else(|| TxSetError::InvalidEnvelope("truncated destination".into()))? as usize;
        pos += 1;
        let addr_bytes = raw.get(pos..pos + addr_len).ok_or_else(|| TxSetError::InvalidEnvelope("truncated address".into()))?;
        pos += addr_len;
        let addr = std::str::from_utf8(addr_bytes)
            .map_err(|_| TxSetError::InvalidEnvelope("address not utf-8".into()))?
            .to_string();
        let amount = u64::from_le_bytes(
            raw.get(pos..pos + 8).ok_or_else(|| TxSetError::InvalidEnvelope("truncated amount".into()))?.try_into().unwrap(),
        );
        pos += 8;
        if !validate_address(&addr) {
            return Err(TxSetError::InvalidEnvelope(format!("bad destination address: {addr}")));
        }
        destinations.push((addr, amount));
    }
    let dest_region_end = pos;

    let payload_len = u32::from_le_bytes(raw[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let payload = raw
        .get(pos..pos + payload_len)
        .ok_or_else(|| TxSetError::InvalidEnvelope("truncated payload".into()))?
        .to_vec();
    pos += payload_len;

    let sig = raw.get(pos..pos + 64).ok_or_else(|| TxSetError::InvalidEnvelope("missing signature".into()))?;
    let (c, r) = (&sig[..32], &sig[32..]);

    // data_to_sign = keccak256(destinations ‖ payload)
    let dest_region = &raw[18 + 1..dest_region_end];
    let data_to_sign = keccak256(&[dest_region, &payload].concat());
    if !schnorr_verify(&data_to_sign, view_pub, c, r) {
        return Err(TxSetError::AuthenticationFailed);
    }

    // Parse the actual object we will sign.
    let mut slice: &[u8] = &payload;
    let tx = monero_wallet::send::SignableTransaction::read(&mut slice)
        .map_err(|e| TxSetError::Parse(format!("SignableTransaction::read: {e}")))?;

    let fingerprint = keccak256(&payload);

    Ok(UnsignedTxSet {
        fingerprint,
        destinations,
        necessary_fee: tx.necessary_fee(),
        payload,
        tx,
    })
}

/// Project the review screen. `necessary_fee` and the fingerprint are
/// device-derived; the destination list is companion-asserted (authenticated
/// by the envelope signature).
pub fn preview_tx(set: &UnsignedTxSet) -> TxPreview {
    let (to_addr, amount) = match set.destinations.first() {
        Some((addr, amt)) => (addr.clone(), *amt),
        None => ("(no destination)".to_string(), 0),
    };
    let total = set.destinations.iter().map(|(_, a)| a).sum::<u64>();

    TxPreview {
        to_addr,
        amount_xmr: format_xmr(amount),
        fee_xmr: format_xmr(set.necessary_fee),
        status: format!(
            "{} destination(s) · {} total · authenticated",
            set.destinations.len(),
            format_xmr(total)
        ),
        fingerprint_hex: hex::encode(set.fingerprint),
    }
}

/// Sign the unsigned set with CLSAG + Bulletproof+ (monero-wallet's audited
/// path), deterministically, and return the serialized signed transaction for
/// the companion to broadcast.
///
/// Fails loudly on any input the wallet does not own (monero-wallet asserts
/// (spend + key_offset)·G == P per input), on malformed data, or if signing
/// itself errors — it never returns success without a real signature.
pub fn sign_tx(set: UnsignedTxSet, spend_key: &Scalar, view_pub: &Point) -> Result<Vec<u8>, TxSetError> {
    // Deterministic RNG: keccak256(payload ‖ view_pub) — the signature becomes
    // a pure function of the unsigned set and the keys.
    let mut seed_input = set.payload.clone();
    seed_input.extend_from_slice(&view_pub.compress().to_bytes());
    let seed = keccak256(&seed_input);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);

    let signed = set
        .tx
        .sign(&mut rng, &Zeroizing::new(*spend_key))
        .map_err(|e| TxSetError::Sign(e.to_string()))?;

    let mut out = Vec::with_capacity(1024);
    signed
        .write(&mut out)
        .map_err(|e| TxSetError::Sign(format!("serialize signed tx: {e}")))?;
    Ok(out)
}

/// Format piconeros as an XMR string.
pub fn format_xmr(piconero: u64) -> String {
    let whole = piconero / 1_000_000_000_000;
    let frac = piconero % 1_000_000_000_000;
    if frac == 0 {
        format!("{whole}.000000000000 XMR")
    } else {
        format!("{whole}.{frac:012} XMR")
    }
}

// ---------------------------------------------------------------------------
// Envelope auth: Monero Schnorr signatures (src/crypto/crypto.cpp)
// ---------------------------------------------------------------------------

/// Monero's generate_signature with a deterministic nonce:
///   c = H_s(hash ‖ V ‖ k·G),  r = k − c·sec
/// where k = H_s("xmxx-schnorr-k" ‖ hash ‖ sec). Deterministic so the device
/// needs no RNG (and reproduces the same signature given the same inputs).
pub fn schnorr_sign(hash: &[u8; 32], sec: &Scalar, pub_: &Point) -> ([u8; 32], [u8; 32]) {
    let sec_bytes: [u8; 32] = <[u8; 32]>::from(*sec);
    let pub_bytes = pub_.compress().to_bytes();

    let mut k_material = b"xmxx-schnorr-k".to_vec();
    k_material.extend_from_slice(hash);
    k_material.extend_from_slice(&sec_bytes);
    let k_dalek: curve25519_dalek::Scalar = Scalar::hash(&k_material).into();

    let k_g = curve25519_dalek::EdwardsPoint::mul_base(&k_dalek);

    let mut c_material = hash.to_vec();
    c_material.extend_from_slice(&pub_bytes);
    c_material.extend_from_slice(&k_g.compress().to_bytes());
    let c = Scalar::hash(&c_material);

    // r = k − c·sec
    let c_dalek: curve25519_dalek::Scalar = c.into();
    let sec_dalek: curve25519_dalek::Scalar = (*sec).into();
    let r_dalek = k_dalek - c_dalek * sec_dalek;

    (<[u8; 32]>::from(c), <[u8; 32]>::from(Scalar::from(r_dalek)))
}

/// Monero's check_signature: recompute c over (hash, V, c·V + r·G) and
/// compare constant-time.
pub fn schnorr_verify(
    hash: &[u8; 32],
    pub_: &Point,
    c: &[u8],
    r: &[u8],
) -> bool {
    let c_dalek = curve25519_dalek::Scalar::from_bytes_mod_order(
        <[u8; 32]>::try_from(c).ok().unwrap_or([0u8; 32]),
    );
    let r_dalek = curve25519_dalek::Scalar::from_bytes_mod_order(
        <[u8; 32]>::try_from(r).ok().unwrap_or([0u8; 32]),
    );
    let v_dalek: curve25519_dalek::EdwardsPoint = (*pub_).into();

    // V' = c·V + r·G
    let v_prime = &c_dalek * &v_dalek
        + &r_dalek * &curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

    let pub_bytes = pub_.compress().to_bytes();
    let mut material = hash.to_vec();
    material.extend_from_slice(&pub_bytes);
    material.extend_from_slice(&v_prime.compress().to_bytes());
    let c_prime = Scalar::hash(&material);

    let expected: [u8; 32] = <[u8; 32]>::from(c_prime);
    let given: [u8; 32] = <[u8; 32]>::try_from(c).ok().unwrap_or([0u8; 32]);
    bool::from(expected.ct_eq(&given))
}

fn mul_base(scalar: &Scalar) -> Point {
    let dalek: curve25519_dalek::Scalar = (*scalar).into();
    Point::from(curve25519_dalek::EdwardsPoint::mul_base(&dalek))
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::Hasher;
    let mut keccak = tiny_keccak::Keccak::v256();
    keccak.update(data);
    let mut out = [0u8; 32];
    keccak.finalize(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::MoneroWallet;

    fn wallet() -> MoneroWallet {
        MoneroWallet::derive(&[13u8; 32], 0)
    }

    /// Round-trip: build an envelope (view key), parse + authenticate it
    /// (view pub), and review it.
    #[test]
    fn envelope_round_trip_and_review() {
        let w = wallet();
        let destinations = vec![(w.subaddress(0, 0), 1_200_000_000_000u64)];
        let payload = b"not-a-real-signable-tx-payload".to_vec();

        let encoded = encode_unsigned_tx_set(&destinations, &payload, w.view_key()).unwrap();
        let parsed = parse_unsigned_tx_set(&encoded, &w.view_public_point());
        // The dummy payload is not a valid SignableTransaction — parse must
        // authenticate first (it will fail at parse, not at auth).
        let err = parsed.err().expect("dummy payload must fail to parse");
        assert!(matches!(err, TxSetError::Parse(_)), "expected parse error, got {err:?}");
    }

    /// The raw-bytes entry point parses the same envelope (binary QR path).
    #[test]
    fn bytes_entry_point_parses_envelope() {
        let w = wallet();
        let destinations = vec![(w.subaddress(0, 0), 1_200_000_000_000u64)];
        let payload = vec![0xabu8; 128];

        let encoded = encode_unsigned_tx_set(&destinations, &payload, w.view_key()).unwrap();
        let raw = hex::decode(encoded.strip_prefix("xmr-txunsigned:").unwrap()).unwrap();

        // Raw bytes: must fail at PARSE (auth passed, dummy payload invalid),
        // proving auth + structure are handled identically to the string path.
        println!("DBG1 len={} magic_ok={}", raw.len(), &raw[..18] == b"xmxx-txunsigned-v1");
        println!("DBG1 count={} addr_len={}", u32::from_le_bytes(raw[19..23].try_into().unwrap()), raw[23]);
        println!("DBG1 addr={}", String::from_utf8_lossy(&raw[24..119]));
        println!("DBG1 real={}", destinations[0].0);
        let err = parse_unsigned_tx_set_bytes(&raw, &w.view_public_point())
            .err()
            .expect("dummy payload must fail to parse");
        assert!(matches!(err, TxSetError::Parse(_)), "got {err:?}");

        // Tampered raw bytes must fail authentication. Tamper a PAYLOAD byte
        // (a destination-address byte is rejected by address validation before
        // the signature check, which is a different error path).
        let payload_start = 19 + 4 + (1 + 95 + 8) + 4;
        let mut tampered = raw.clone();
        tampered[payload_start] ^= 0x01;
        let err2 = parse_unsigned_tx_set_bytes(&tampered, &w.view_public_point())
            .err()
            .expect("tampered raw must fail");
        assert!(matches!(err2, TxSetError::AuthenticationFailed), "got {err2:?}");

        // The hex-prefixed form through the bytes entry must also work.
        let err3 = parse_unsigned_tx_set_bytes(encoded.as_bytes(), &w.view_public_point())
            .err()
            .expect("hex form through bytes entry must fail at parse");
        assert!(matches!(err3, TxSetError::Parse(_)), "got {err3:?}");
    }

    /// Tampering with any byte of the envelope must fail authentication.
    #[test]
    fn tampered_envelope_fails_authentication() {
        let w = wallet();
        let destinations = vec![(w.address().to_string(), 1u64)];
        let payload = vec![0xabu8; 128];

        let encoded = encode_unsigned_tx_set(&destinations, &payload, w.view_key()).unwrap();
        let raw = hex::decode(encoded.strip_prefix("xmr-txunsigned:").unwrap()).unwrap();

        // Flip one payload byte.
        let mut tampered = raw.clone();
        let payload_start = 19 + 4 + (1 + w.address().len() + 8) + 4;
        tampered[payload_start] ^= 0x01;
        let err = parse_unsigned_tx_set(
            &format!("xmr-txunsigned:{}", hex::encode(&tampered)),
            &w.view_public_point(),
        )
        .err()
        .expect("tampered envelope must fail");
        assert!(matches!(err, TxSetError::AuthenticationFailed), "got {err:?}");

        // Also flipping a destination amount byte must fail.
        let mut tampered2 = raw;
        tampered2[19 + 4 + 1 + w.address().len()] ^= 0x01; // amount byte
        let err2 = parse_unsigned_tx_set(
            &format!("xmr-txunsigned:{}", hex::encode(&tampered2)),
            &w.view_public_point(),
        )
        .err()
        .expect("tampered amount must fail");
        assert!(matches!(err2, TxSetError::AuthenticationFailed), "got {err2:?}");
    }

    /// An envelope signed by a DIFFERENT wallet's view key must be rejected —
    /// the "is this my wallet?" test.
    #[test]
    fn foreign_wallet_envelope_rejected() {
        let w = wallet();
        let other = MoneroWallet::derive(&[99u8; 32], 0);

        let destinations = vec![(w.address().to_string(), 1u64)];
        let payload = vec![1u8; 64];
        // Sign with the OTHER wallet's view key.
        let encoded = encode_unsigned_tx_set(&destinations, &payload, other.view_key()).unwrap();

        let err = parse_unsigned_tx_set(
            &encoded,
            &w.view_public_point(),
        )
        .err()
        .expect("foreign-wallet envelope must fail");
        assert!(matches!(err, TxSetError::AuthenticationFailed), "got {err:?}");
    }

    /// Invalid addresses are rejected at build time.
    #[test]
    fn bad_destination_address_rejected() {
        let w = wallet();
        let err = encode_unsigned_tx_set(&[("not-an-address".to_string(), 1u64)], b"x", w.view_key())
            .err()
            .expect("bad address must fail");
        assert!(matches!(err, TxSetError::InvalidEnvelope(_)));
    }

    /// Schnorr sign/verify round-trip, plus a wrong-key failure.
    #[test]
    fn schnorr_round_trip() {
        let w = wallet();
        let hash = keccak256(b"test payload");
        let pub_ = w.view_public_point();
        let (c, r) = schnorr_sign(&hash, w.view_key(), &pub_);
        assert!(schnorr_verify(&hash, &pub_, &c, &r));

        // Wrong hash fails.
        let other_hash = keccak256(b"other");
        assert!(!schnorr_verify(&other_hash, &pub_, &c, &r));

        // Wrong public key fails.
        let other_pub = MoneroWallet::derive(&[1u8; 32], 0).view_public_point();
        assert!(!schnorr_verify(&hash, &other_pub, &c, &r));
    }
}
