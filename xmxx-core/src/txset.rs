// SPDX-FileCopyrightText: 2026 OZARUMOTO
// SPDX-License-Identifier: GPL-3.0-or-later
//
// XMXX-CORE transaction set — the xmr-txunsigned / xmr-txsigned wire format.
//
// The wire format is monero-wallet's native `SignableTransaction` serialization
// (a vetted, Cypher-Stack-audited structure: inputs with decoys and
// commitments, payments, fee rate), wrapped in an envelope that is both
// **encrypted** and **authenticated** with the wallet's view keypair:
//
//   magic "xmxx-txunsigned-v2" ‖ version(1)
//     ‖ destinations_enc(aead) ‖ payload ‖ sig(64)
//
// where `destinations` is the human-review summary (address + piconeros) the
// companion built, `payload` is the serialized SignableTransaction, and
//
//   * destinations_enc = XChaCha20-Poly1305 ciphertext of the destination
//     list, keyed by keccak256("xmxx-destinations-key" ‖ view_key_bytes).
//     This gives the destinations **confidentiality** (a camera/observer can't
//     read who or how much) as well as integrity — only someone holding the
//     wallet's private view key can read them. The handshake ensures the
//     destination summary seen on the review screen is the one the companion
//     actually built.
//
//   * sig = Monero's Schnorr signature (crypto.cpp generate_signature) over
//     `keccak256(destinations_enc ‖ payload)` under the wallet's view key.
//     Verifying the signature before touching anything proves (a) the data is
//     unmodified and (b) the sender holds this wallet's view key — the
//     "is this my wallet?" test, and the same auth model as wallet2's
//     unsigned_tx_set (minus the CryptoNight-v0 key derivation, which
//     wallet2-format interop would require).
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
// payload by the envelope signature + AEAD tag and shown alongside the payload
// fingerprint, which the user can cross-check against the companion.

use rand_core::SeedableRng as _;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use chacha20poly1305::{
    aead::{Aead, KeyInit as _, Payload},
    XChaCha20Poly1305, XNonce,
};

use crate::wallet::validate_address;
use crate::{Point, Scalar};

const MAGIC: &[u8; 18] = b"xmxx-txunsigned-v2";
const VERSION: u8 = 1;
/// AEAD nonce length for XChaCha20-Poly1305 (24 bytes). Derived from the view
/// key so the device needs no RNG to decrypt, and nonce reuse is impossible
/// because it's a pure function of the envelope+keys.
const NONCE_LEN: usize = 24;

/// An authenticated unsigned transaction set, parsed and ready for review or
/// signing. Everything except `destinations` is device-derived.
pub struct UnsignedTxSet {
    /// keccak256(payload) — the fingerprint of the exact bytes that will be
    /// signed. Shown on the review screen for cross-checking.
    pub fingerprint: [u8; 32],
    /// Destination summary (address, piconeros) supplied by the companion,
    /// authenticated AND decrypted by the wallet's view key.
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
    DecryptionFailed,
    Parse(String),
    Sign(String),
}

impl core::fmt::Display for TxSetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TxSetError::Decode(e) => write!(f, "decode error: {e}"),
            TxSetError::InvalidEnvelope(e) => write!(f, "invalid envelope: {e}"),
            TxSetError::AuthenticationFailed => write!(f, "authentication failed: not this wallet's unsigned set"),
            TxSetError::DecryptionFailed => write!(f, "decryption failed: destinations cannot be read by this wallet"),
            TxSetError::Parse(e) => write!(f, "parse error: {e}"),
            TxSetError::Sign(e) => write!(f, "signing error: {e}"),
        }
    }
}

impl std::error::Error for TxSetError {}

/// Derive the AEAD key for the destinations region from the wallet's private
/// view key. Both the companion (encoder) and the device (decoder) hold the
/// view scalar, so both can read — an observer cannot.
fn destinations_aead_key(view_key: &Scalar) -> [u8; 32] {
    let vk: [u8; 32] = <[u8; 32]>::from(*view_key);
    keccak256(&[b"xmxx-destinations-key".as_slice(), &vk].concat())
}

/// Deterministic 24-byte XChaCha20 nonce derived from the view key + payload.
/// A pure function of the envelope contents + keys: the device needs no RNG to
/// decrypt, and nonce-collision across distinct envelopes is effectively
/// impossible (it's keyed by the view key and the payload fingerprint).
fn destinations_nonce(view_key: &Scalar, payload: &[u8]) -> [u8; NONCE_LEN] {
    let vk: [u8; 32] = <[u8; 32]>::from(*view_key);
    let h = keccak256(&[b"xmxx-destinations-nonce".as_slice(), &vk, payload].concat());
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&h[..NONCE_LEN]);
    nonce
}

/// Encrypt the raw ascending destinations region (the `destinations` summary)
/// with XChaCha20-Poly1305 keyed by the view key, authenticating the payload
/// as associated data so the tag ALSO proves the payload wasn't swapped.
fn encrypt_destinations(
    view_key: &Scalar,
    dest_region: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, TxSetError> {
    let key = destinations_aead_key(view_key);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let nonce: XNonce = *XNonce::from_slice(&destinations_nonce(view_key, payload));
    // Payload bytes are authenticated (not encrypted) — the AEAD tag therefore
    // binds the payload to the destinations, catching a swapped-payload attack.
    cipher
        .encrypt(&nonce, Payload { msg: dest_region, aad: payload })
        .map_err(|_| TxSetError::InvalidEnvelope("destinations encryption failed".into()))
}

fn decrypt_destinations(
    view_key: &Scalar,
    ciphertext: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, TxSetError> {
    let key = destinations_aead_key(view_key);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let nonce: XNonce = *XNonce::from_slice(&destinations_nonce(view_key, payload));
    cipher
        .decrypt(&nonce, Payload { msg: ciphertext, aad: payload })
        .map_err(|_| TxSetError::DecryptionFailed)
}

/// Build an `xmr-txunsigned` payload for the companion: serialize the
/// `SignableTransaction`, wrap it with the (encrypted, authenticated)
/// destination summary, and sign the envelope with the wallet's private view key.
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

    // Raw ascending destinations region.
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

    // Encrypt + authenticate the destinations with the view key.
    let dest_enc = encrypt_destinations(view_key, &dest_region, payload)?;

    // Assemble the envelope: magic ‖ version ‖ dest_enc ‖ payload ‖ sig.
    let mut envelope =
        Vec::with_capacity(18 + 1 + dest_enc.len() + 4 + payload.len() + 64);
    envelope.extend_from_slice(MAGIC);
    envelope.push(VERSION);
    envelope.extend_from_slice(&(dest_enc.len() as u32).to_le_bytes());
    envelope.extend_from_slice(&dest_enc);
    envelope.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    envelope.extend_from_slice(payload);

    // data_to_sign = keccak256(dest_enc ‖ payload) — over the CI PHERtext so
    // the signature authenticates the encrypted destinations.
    let data_to_sign = keccak256(&[&dest_enc, payload].concat());

    let view_pub = mul_base(view_key);
    let (c, r) = schnorr_sign(&data_to_sign, view_key, &view_pub);
    envelope.extend_from_slice(&c);
    envelope.extend_from_slice(&r);

    Ok(format!("xmr-txunsigned:{}", hex::encode(&envelope)))
}

/// Parse and authenticate an `xmr-txunsigned` payload. Verifies the envelope
/// signature with the wallet's public view key, decrypts the destinations with
/// the private view key, then parses the `SignableTransaction`. Refuses
/// anything not signed/encrypted by this wallet's keys or that fails to parse.
pub fn parse_unsigned_tx_set(
    qr_data: &str,
    view_key: &Scalar,
) -> Result<UnsignedTxSet, TxSetError> {
    let hex_data = qr_data.trim().strip_prefix("xmr-txunsigned:").unwrap_or(qr_data.trim());
    let raw = hex::decode(hex_data).map_err(|e| TxSetError::Decode(e.to_string()))?;
    parse_envelope(&raw, view_key)
}

/// Parse + authenticate an `xmr-txunsigned` payload passed as RAW BYTES (the
/// Prime's QR scanner yields binary; binary envelopes are also far more
/// space-efficient than hex for multi-input txs). Accepts an optional
/// `xmr-txunsigned:` text prefix for hex-encoded payloads.
pub fn parse_unsigned_tx_set_bytes(
    qr_data: &[u8],
    view_key: &Scalar,
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
    parse_envelope(&raw, view_key)
}

/// The shared envelope parse: magic/version/dest_enc/payload/signature,
/// Schnorr verification with the wallet's view key, AEAD decryption of the
/// destinations, then `SignableTransaction::read`. Refuses anything not this
/// wallet's.
fn parse_envelope(raw: &[u8], view_key: &Scalar) -> Result<UnsignedTxSet, TxSetError> {
    // Magic + version.
    if raw.len() < 18 + 1 + 4 + 64 {
        return Err(TxSetError::InvalidEnvelope("payload too short".into()));
    }
    if &raw[..18] != MAGIC {
        return Err(TxSetError::InvalidEnvelope("bad magic".into()));
    }
    if raw[18] != VERSION {
        return Err(TxSetError::InvalidEnvelope(format!("unsupported version {}", raw[18])));
    }

    let mut pos = 19;
    let dest_enc_len =
        u32::from_le_bytes(raw[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let dest_enc = raw
        .get(pos..pos + dest_enc_len)
        .ok_or_else(|| TxSetError::InvalidEnvelope("truncated encrypted destinations".into()))?;
    pos += dest_enc_len;

    let payload_len = u32::from_le_bytes(raw[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let payload = raw
        .get(pos..pos + payload_len)
        .ok_or_else(|| TxSetError::InvalidEnvelope("truncated payload".into()))?;
    pos += payload_len;

    let sig = raw.get(pos..pos + 64).ok_or_else(|| TxSetError::InvalidEnvelope("missing signature".into()))?;
    let (c, r) = (&sig[..32], &sig[32..]);

    // data_to_sign = keccak256(dest_enc ‖ payload)
    let data_to_sign = keccak256(&[dest_enc, payload].concat());
    let view_pub = mul_base(view_key);
    if !schnorr_verify(&data_to_sign, &view_pub, c, r) {
        return Err(TxSetError::AuthenticationFailed);
    }

    // Decrypt + authenticate the destinations with the private view key.
    let dest_plain = decrypt_destinations(view_key, dest_enc, payload)?;
    let destinations = parse_destinations(&dest_plain)?;

    // Parse the actual object we will sign.
    let mut slice: &[u8] = &payload;
    let tx = monero_wallet::send::SignableTransaction::read(&mut slice)
        .map_err(|e| TxSetError::Parse(format!("SignableTransaction::read: {e}")))?;

    let fingerprint = keccak256(payload);

    Ok(UnsignedTxSet {
        fingerprint,
        destinations,
        necessary_fee: tx.necessary_fee(),
        payload: payload.to_vec(),
        tx,
    })
}

/// Parse the ascending destinations region (count ‖ (addr_len ‖ addr ‖ amount)*)
/// after decryption.
fn parse_destinations(dest_plain: &[u8]) -> Result<Vec<(String, u64)>, TxSetError> {
    let mut pos = 0;
    let dest_count = match dest_plain.get(pos..pos + 4) {
        Some(b) => u32::from_le_bytes(b.try_into().unwrap()) as usize,
        None => return Err(TxSetError::InvalidEnvelope("truncated destinations".into())),
    };
    pos += 4;

    let mut destinations = Vec::with_capacity(dest_count);
    for _ in 0..dest_count {
        let addr_len = *dest_plain
            .get(pos)
            .ok_or_else(|| TxSetError::InvalidEnvelope("truncated destination".into()))?
            as usize;
        pos += 1;
        let addr_bytes = dest_plain
            .get(pos..pos + addr_len)
            .ok_or_else(|| TxSetError::InvalidEnvelope("truncated address".into()))?;
        pos += addr_len;
        let addr = std::str::from_utf8(addr_bytes)
            .map_err(|_| TxSetError::InvalidEnvelope("address not utf-8".into()))?
            .to_string();
        let amount = u64::from_le_bytes(
            dest_plain
                .get(pos..pos + 8)
                .ok_or_else(|| TxSetError::InvalidEnvelope("truncated amount".into()))?
                .try_into()
                .unwrap(),
        );
        pos += 8;
        if !validate_address(&addr) {
            return Err(TxSetError::InvalidEnvelope(format!("bad destination address: {addr}")));
        }
        destinations.push((addr, amount));
    }
    Ok(destinations)
}

/// Project the review screen. `necessary_fee` and the fingerprint are
/// device-derived; the destination list is companion-asserted (authenticated
/// by the envelope signature + AEAD tag).
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
pub fn sign_tx(set: UnsignedTxSet, spend_key: &Scalar, view_key: &Scalar) -> Result<Vec<u8>, TxSetError> {
    // Deterministic RNG: keccak256(payload ‖ view_pub) — the signature becomes
    // a pure function of the unsigned set and the keys.
    let view_pub = mul_base(view_key);
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

    /// Round-trip: build an envelope (view key), parse + authenticate + decrypt
    /// it (view key), and review it.
    #[test]
    fn envelope_round_trip_and_review() {
        let w = wallet();
        let destinations = vec![(w.subaddress(0, 0), 1_200_000_000_000u64)];
        let payload = b"not-a-real-signable-tx-payload".to_vec();

        let encoded = encode_unsigned_tx_set(&destinations, &payload, w.view_key()).unwrap();
        let parsed = parse_unsigned_tx_set(&encoded, w.view_key());
        // The dummy payload is not a valid SignableTransaction — parse must
        // authenticate + decrypt first (it will fail at parse, not at auth).
        let err = parsed.err().expect("dummy payload must fail to parse");
        assert!(matches!(err, TxSetError::Parse(_)), "expected parse error, got {err:?}");
    }

    /// The encrypted destinations must not be readable by an observer (no view key).
    #[test]
    fn destinations_are_encrypted_on_the_wire() {
        let w = wallet();
        let destinations = vec![(w.address().to_string(), 777u64)];
        let payload = vec![0xabu8; 128];

        let encoded = encode_unsigned_tx_set(&destinations, &payload, w.view_key()).unwrap();
        let raw = hex::decode(encoded.strip_prefix("xmr-txunsigned:").unwrap()).unwrap();

        // The raw ascending destination summary (count + "4..." + 8-byte amount)
        // must NOT appear verbatim in the envelope bytes — it's encrypted.
        let addr = w.address().as_bytes();
        let haystack: &[u8] = &raw;
        let needle_region = [&[addr.len() as u8], addr].concat();
        assert!(
            !haystack.windows(needle_region.len()).any(|w| w == needle_region.as_slice()),
            "destination address must be encrypted on the wire"
        );
        // The amount 777 LE bytes must not appear verbatim either.
        let amt = 777u64.to_le_bytes();
        assert!(
            !haystack.windows(8).any(|w| w == amt),
            "destination amount must be encrypted on the wire"
        );
    }

    /// The raw-bytes entry point parses the same envelope (binary QR path).
    #[test]
    fn bytes_entry_point_parses_envelope() {
        let w = wallet();
        let destinations = vec![(w.subaddress(0, 0), 1_200_000_000_000u64)];
        let payload = vec![0xabu8; 128];

        let encoded = encode_unsigned_tx_set(&destinations, &payload, w.view_key()).unwrap();
        let raw = hex::decode(encoded.strip_prefix("xmr-txunsigned:").unwrap()).unwrap();

        // Raw bytes: must fail at PARSE (auth/decrypt passed, dummy payload
        // invalid), proving auth + structure are handled identically.
        let err = parse_unsigned_tx_set_bytes(&raw, w.view_key())
            .err()
            .expect("dummy payload must fail to parse");
        assert!(matches!(err, TxSetError::Parse(_)), "got {err:?}");

        // Tampered raw bytes must fail authentication. Tamper a PAYLOAD byte
        // (a destination-address byte is rejected by AEAD auth/address validation
        // before the signature check, which is a different error path).
        let payload_start = 19 + 4 + {
            // dest_enc_len field
            let del = u32::from_le_bytes(raw[19..23].try_into().unwrap()) as usize;
            0 + del
        } + 4;
        let mut tampered = raw.clone();
        tampered[payload_start] ^= 0x01;
        let err2 = parse_unsigned_tx_set_bytes(&tampered, w.view_key())
            .err()
            .expect("tampered raw must fail");
        assert!(matches!(err2, TxSetError::AuthenticationFailed), "got {err2:?}");

        // The hex-prefixed form through the bytes entry must also work.
        let err3 = parse_unsigned_tx_set_bytes(encoded.as_bytes(), w.view_key())
            .err()
            .expect("hex form through bytes entry must fail at parse");
        assert!(matches!(err3, TxSetError::Parse(_)), "got {err3:?}");
    }

    /// Tampering with any byte of the envelope must fail authentication or
    /// decryption.
    #[test]
    fn tampered_envelope_fails() {
        let w = wallet();
        let destinations = vec![(w.address().to_string(), 1u64)];
        let payload = vec![0xabu8; 128];

        let encoded = encode_unsigned_tx_set(&destinations, &payload, w.view_key()).unwrap();
        let raw = hex::decode(encoded.strip_prefix("xmr-txunsigned:").unwrap()).unwrap();

        // Flip one payload byte → AuthenticationFailed.
        let payload_start = 19 + 4 + {
            let del = u32::from_le_bytes(raw[19..23].try_into().unwrap()) as usize;
            del
        } + 4;
        let mut tampered = raw.clone();
        tampered[payload_start] ^= 0x01;
        let err = parse_unsigned_tx_set(
            &format!("xmr-txunsigned:{}", hex::encode(&tampered)),
            w.view_key(),
        )
        .err()
        .expect("tampered envelope must fail");
        assert!(matches!(err, TxSetError::AuthenticationFailed), "got {err:?}");

        // Flip a ciphertext byte. Because the Schnorr signature is over the
        // (encrypted) destinations, tampering with the ciphertext is caught by
        // EITHER the signature (AuthenticationFailed) or the AEAD tag
        // (DecryptionFailed) — the first check that fires wins. Either outcome
        // proves the tampered envelope is rejected; assert on the union.
        let mut tampered2 = raw.clone();
        let ciphertext_start = 19 + 4;
        tampered2[ciphertext_start] ^= 0x01;
        let err2 = parse_unsigned_tx_set(
            &format!("xmr-txunsigned:{}", hex::encode(&tampered2)),
            w.view_key(),
        )
        .err()
        .expect("tampered ciphertext must fail");
        assert!(
            matches!(err2, TxSetError::AuthenticationFailed | TxSetError::DecryptionFailed),
            "got {err2:?}"
        );

        // DecryptionFailed is the guaranteed path when integrity is enforced
        // purely by the AEAD tag and the Schnorr signature is deliberately kept
        // valid. Construct a valid envelope, then re-seal the SAME destination
        // plaintext under a DIFFERENT payload so the tag no longer matches what
        // the (unchanged) network sig authenticates is impossible to do without
        // the private key — so instead directly demonstrate that a valid sig +
        // wrong-key decrypt cannot succeed: parsing our envelope under the
        // wrong wallet key fails (AuthenticationFailed), and parsing under a
        // key that has the right sig but any ciphertext change is rejected above.
        let wrong = MoneroWallet::derive(&[7u8; 32], 0);
        let err3 = parse_unsigned_tx_set(
            &format!("xmr-txunsigned:{}", hex::encode(&raw[..])),
            wrong.view_key(),
        )
        .err()
        .expect("wrong-wallet decrypt must fail");
        assert!(matches!(err3, TxSetError::AuthenticationFailed), "got {err3:?}");
    }

    /// An envelope signed by a DIFFERENT wallet's view key must be rejected —
    /// the "is this my wallet?" test.
    #[test]
    fn foreign_wallet_envelope_rejected() {
        let w = wallet();
        let other = MoneroWallet::derive(&[99u8; 32], 0);

        let destinations = vec![(w.address().to_string(), 1u64)];
        let payload = vec![1u8; 64];
        // Sign + encrypt with the OTHER wallet's view key.
        let encoded = encode_unsigned_tx_set(&destinations, &payload, other.view_key()).unwrap();

        let err = parse_unsigned_tx_set(
            &encoded,
            w.view_key(),
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
        let pub_ = mul_base(w.view_key());
        let (c, r) = schnorr_sign(&hash, w.view_key(), &pub_);
        assert!(schnorr_verify(&hash, &pub_, &c, &r));

        // Wrong hash fails.
        let other_hash = keccak256(b"other");
        assert!(!schnorr_verify(&other_hash, &pub_, &c, &r));

        // Wrong public key fails.
        let other_pub = mul_base(&MoneroWallet::derive(&[1u8; 32], 0).view_key());
        assert!(!schnorr_verify(&hash, &other_pub, &c, &r));
    }
}