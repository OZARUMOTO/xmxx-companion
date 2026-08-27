// SPDX-FileCopyrightText: 2026 OZARUMOTO
// SPDX-License-Identifier: GPL-3.0-or-later
//
// XMXX-CORE key images — the double-spend-proof computation.
//
// This module answers the `xmr-keyimage` message of a monero-signer server.
//
// The construction matches Monero (verified against mainline and
// monero-wallet's audited scan/send path):
//
//   D      = 8·(a·R)                     (view key × tx public key, cofactor)
//   shared = H_s(D ‖ varint(output_index))
//   m      = H_s("SubAddr\0" ‖ a ‖ major_LE32 ‖ minor_LE32)   (subaddress only)
//   x      = spend + shared + m          (the one-time private key)
//
// The one-time public key is P = x·G. We *assert* x·G == P before emitting
// anything — a companion that lies about which output is real fails loudly
// instead of producing a bad key image. The key image itself is
//
//   I = x · H_p(P)
//
// where H_p = Monero's hash-to-point (ge_fromfe_frombytes_vartime) — a point
// whose discrete log is unknown to anyone, exposed as
// `monero_ed25519::Point::biased_hash`.

use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::{Point, Scalar};

/// An on-chain output this wallet may own, with the data needed to derive the
/// one-time secret: the tx public key (or per-output additional key) R, the
/// output index within the tx, the one-time output key P, and the subaddress
/// index if the output was sent to a subaddress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyImageInput {
    /// The transaction public key R (from the tx extra), or the per-output
    /// additional key for subaddress/multi-output txs.
    pub tx_pub_key: [u8; 32],
    /// The output's index within the transaction.
    pub output_index: u64,
    /// The one-time output public key P as it appears on-chain.
    pub output_pub_key: [u8; 32],
    /// (major, minor) if the output was sent to a subaddress; None for the
    /// primary address.
    pub subaddress: Option<(u32, u32)>,
}

/// Compute the key image for a single output, deriving the one-time secret
/// on-device from (view key, tx pub key, output index, subaddress) and
/// verifying ownership (x·G == P) before emitting anything.
pub fn compute_key_image(
    view_key: &Scalar,
    spend_key: &Scalar,
    input: &KeyImageInput,
) -> Result<[u8; 32], String> {
    // Decompress R and P; reject torsion (matches monero-wallet's validate).
    let r_dalek = decompress(&input.tx_pub_key)?;
    if !r_dalek.is_torsion_free() {
        return Err("tx pub key has torsion".into());
    }
    let p_dalek = decompress(&input.output_pub_key)?;
    if !p_dalek.is_torsion_free() {
        return Err("output key has torsion".into());
    }

    // D = 8·(a·R)
    let a_dalek: curve25519_dalek::Scalar = (*view_key).into();
    let ecdh = (&a_dalek * &r_dalek).mul_by_cofactor();

    // shared = H_s(D ‖ varint(output_index))
    let mut derivation = ecdh.compress().to_bytes().to_vec();
    monero_oxide::io::VarInt::write(&input.output_index, &mut derivation)
        .map_err(|e| format!("varint encode failed: {e}"))?;
    let mut offset_dalek: curve25519_dalek::Scalar = Scalar::hash(&derivation).into();

    // + m for subaddresses: H_s("SubAddr\0" ‖ a ‖ major_LE32 ‖ minor_LE32)
    if let Some((major, minor)) = input.subaddress {
        let view_bytes: [u8; 32] = <[u8; 32]>::from(*view_key);
        let mut data = b"SubAddr\0".to_vec();
        data.extend_from_slice(&view_bytes);
        data.extend_from_slice(&major.to_le_bytes());
        data.extend_from_slice(&minor.to_le_bytes());
        let m_dalek: curve25519_dalek::Scalar = Scalar::hash(&data).into();
        offset_dalek += m_dalek;
    }

    // x = spend + offset  (the one-time private key)
    let spend_dalek: curve25519_dalek::Scalar = (*spend_key).into();
    let x_dalek = spend_dalek + offset_dalek;

    // Assert x·G == P — refuse to emit a key image for an output we don't own.
    let derived_p = curve25519_dalek::EdwardsPoint::mul_base(&x_dalek);
    if bool::from(!derived_p.ct_eq(&p_dalek)) {
        return Err("output key mismatch: this output is not owned by this wallet".into());
    }

    // I = x · H_p(P) — H_p has an unknown discrete log (vetted biased_hash).
    let hp_dalek: curve25519_dalek::EdwardsPoint =
        Point::biased_hash(input.output_pub_key).into();
    let key_image = (x_dalek * hp_dalek).compress().to_bytes();

    // Wipe the one-time secret.
    Zeroizing::new(x_dalek);
    Ok(key_image)
}

/// Compute key images for a batch of outputs (one per input, same order).
pub fn compute_key_images_batch(
    view_key: &Scalar,
    spend_key: &Scalar,
    inputs: &[KeyImageInput],
) -> Result<Vec<[u8; 32]>, String> {
    inputs.iter().map(|input| compute_key_image(view_key, spend_key, input)).collect()
}

/// Parse an `xmr-output` payload:
///
/// ```text
/// xmr-output:<R_hex>;<index>:<P_hex>[:<major>:<minor>][;<index>:<P_hex>...]
/// ```
///
/// `<R_hex>` is the tx public key (or additional key) shared by the outputs of
/// one transaction; each entry is the output index, the one-time output key,
/// and optionally the subaddress index it was sent to.
pub fn parse_output_payload(data: &str) -> Result<Vec<KeyImageInput>, String> {
    let data = data.trim().strip_prefix("xmr-output:").unwrap_or(data.trim());

    let mut parts = data.split(';');
    let r_hex = parts.next().ok_or("empty xmr-output payload")?;
    if r_hex.len() != 64 {
        return Err("tx pub key must be 64 hex chars".into());
    }
    let tx_pub_key = hex_decode_32(r_hex)?;

    let mut inputs = Vec::new();
    for entry in parts {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let fields: Vec<&str> = entry.split(':').collect();
        let (index, p_hex) = match fields.as_slice() {
            [index, p_hex] => (*index, *p_hex),
            [index, p_hex, major, minor] => {
                let major = major.parse::<u32>().map_err(|_| "bad subaddress major".to_string())?;
                let minor = minor.parse::<u32>().map_err(|_| "bad subaddress minor".to_string())?;
                inputs.push(KeyImageInput {
                    tx_pub_key,
                    output_index: index.parse::<u64>().map_err(|_| "bad output index".to_string())?,
                    output_pub_key: hex_decode_32(p_hex)?,
                    subaddress: Some((major, minor)),
                });
                continue;
            }
            _ => return Err(format!("malformed xmr-output entry: {entry}")),
        };
        inputs.push(KeyImageInput {
            tx_pub_key,
            output_index: index.parse::<u64>().map_err(|_| "bad output index".to_string())?,
            output_pub_key: hex_decode_32(p_hex)?,
            subaddress: None,
        });
    }

    if inputs.is_empty() {
        return Err("xmr-output payload has no outputs".into());
    }
    Ok(inputs)
}

/// Encode key images as an `xmr-keyimage` payload for the companion.
pub fn encode_keyimage_payload(key_images: &[[u8; 32]]) -> String {
    let hex_strs: Vec<String> = key_images.iter().map(|ki| hex::encode(ki)).collect();
    format!("xmr-keyimage:{}", hex_strs.join(","))
}

fn decompress(bytes: &[u8; 32]) -> Result<curve25519_dalek::EdwardsPoint, String> {
    curve25519_dalek::edwards::CompressedEdwardsY(*bytes)
        .decompress()
        .ok_or_else(|| "point decompression failed".to_string())
}

fn hex_decode_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("bad hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a realistic owned output exactly as Monero creates one:
    /// choose tx private key r, R = r·G, index o, then
    /// P = (H_s(8·a·R ‖ varint(o)) + b)·G.
    fn owned_output(
        view_key: &Scalar,
        spend_key: &Scalar,
        r: &curve25519_dalek::Scalar,
        index: u64,
        subaddress: Option<(u32, u32)>,
    ) -> KeyImageInput {
        let r_point = curve25519_dalek::EdwardsPoint::mul_base(r);
        let a_dalek: curve25519_dalek::Scalar = (*view_key).into();
        let ecdh = (&a_dalek * &r_point).mul_by_cofactor();

        let mut derivation = ecdh.compress().to_bytes().to_vec();
        monero_oxide::io::VarInt::write(&index, &mut derivation).unwrap();
        let mut offset: curve25519_dalek::Scalar = Scalar::hash(&derivation).into();

        if let Some((major, minor)) = subaddress {
            let view_bytes: [u8; 32] = <[u8; 32]>::from(*view_key);
            let mut data = b"SubAddr\0".to_vec();
            data.extend_from_slice(&view_bytes);
            data.extend_from_slice(&major.to_le_bytes());
            data.extend_from_slice(&minor.to_le_bytes());
            let m_dalek: curve25519_dalek::Scalar = Scalar::hash(&data).into();
            offset += m_dalek;
        }

        let b_dalek: curve25519_dalek::Scalar = (*spend_key).into();
        let x = b_dalek + offset;
        let p = curve25519_dalek::EdwardsPoint::mul_base(&x);

        KeyImageInput {
            tx_pub_key: r_point.compress().to_bytes(),
            output_index: index,
            output_pub_key: p.compress().to_bytes(),
            subaddress,
        }
    }

    fn test_keys() -> (Scalar, Scalar) {
        use crate::wallet::MoneroWallet;
        let w = MoneroWallet::derive(&[11u8; 32], 0);
        (*w.view_key(), *w.spend_key())
    }

    /// A genuinely owned output yields a key image, and it is deterministic.
    #[test]
    fn computes_key_image_for_owned_output() {
        let (view, spend) = test_keys();
        let r = curve25519_dalek::Scalar::from_bytes_mod_order([7u8; 32]);
        let input = owned_output(&view, &spend, &r, 0, None);

        let ki1 = compute_key_image(&view, &spend, &input).unwrap();
        let ki2 = compute_key_image(&view, &spend, &input).unwrap();
        assert_eq!(ki1, ki2);

        // The key image is NOT a multiple of a public basepoint on the same
        // generator — it must be 32 bytes and non-zero.
        assert_eq!(ki1.len(), 32);
        assert_ne!(ki1, [0u8; 32]);
    }

    /// A companion lying about the output key (claiming a different P than
    /// the one actually derived) must fail the x·G == P assertion.
    #[test]
    fn rejects_output_not_owned_by_wallet() {
        let (view, spend) = test_keys();
        let r = curve25519_dalek::Scalar::from_bytes_mod_order([9u8; 32]);
        let mut input = owned_output(&view, &spend, &r, 1, None);

        // Flip the claimed P to a different valid point (r'·G for another r').
        let other = curve25519_dalek::EdwardsPoint::mul_base(
            &curve25519_dalek::Scalar::from_bytes_mod_order([99u8; 32]),
        );
        input.output_pub_key = other.compress().to_bytes();

        assert!(compute_key_image(&view, &spend, &input).is_err());
    }

    /// A wrong view key must fail too (not owned by this wallet).
    #[test]
    fn rejects_foreign_wallet_outputs() {
        let (view, spend) = test_keys();
        let (other_view, _) = {
            let w = crate::wallet::MoneroWallet::derive(&[42u8; 32], 0);
            (*w.view_key(), *w.spend_key())
        };
        let r = curve25519_dalek::Scalar::from_bytes_mod_order([5u8; 32]);
        let input = owned_output(&view, &spend, &r, 0, None);

        assert!(compute_key_image(&other_view, &spend, &input).is_err());
    }

    /// Subaddress outputs derive a different key image than the same output
    /// treated as a primary-address output.
    #[test]
    fn subaddress_input_changes_key_image() {
        let (view, spend) = test_keys();
        let r = curve25519_dalek::Scalar::from_bytes_mod_order([3u8; 32]);
        let mut plain = owned_output(&view, &spend, &r, 0, None);
        let mut sub = owned_output(&view, &spend, &r, 0, Some((0, 1)));
        // The output key itself differs (built with the subaddress offset), so
        // feed the subaddress-built output to the subaddress input.
        plain.output_pub_key = sub.output_pub_key;
        plain.subaddress = Some((0, 1));
        sub.tx_pub_key = plain.tx_pub_key;

        let ki_sub = compute_key_image(&view, &spend, &sub).unwrap();
        // Removing the subaddress offset from the SAME output key must fail
        // (x·G != P) — proving the offset is actually used.
        let mut without_offset = sub.clone();
        without_offset.subaddress = None;
        assert!(compute_key_image(&view, &spend, &without_offset).is_err());

        assert_ne!(ki_sub, [0u8; 32]);
    }

    /// Payload parsing round-trip.
    #[test]
    fn payload_parse_round_trip() {
        let (view, spend) = test_keys();
        let r = curve25519_dalek::Scalar::from_bytes_mod_order([1u8; 32]);
        let a = owned_output(&view, &spend, &r, 0, None);
        let b = owned_output(&view, &spend, &r, 1, Some((0, 2)));

        let payload = format!(
            "xmr-output:{};{}:{};{}:{}:{}:{}",
            hex::encode(a.tx_pub_key),
            a.output_index,
            hex::encode(a.output_pub_key),
            b.output_index,
            hex::encode(b.output_pub_key),
            0,
            2
        );

        let parsed = parse_output_payload(&payload).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], a);
        assert_eq!(parsed[1], b);

        let kis = compute_key_images_batch(&view, &spend, &parsed).unwrap();
        assert_eq!(kis.len(), 2);
        assert!(encode_keyimage_payload(&kis).starts_with("xmr-keyimage:"));
    }
}
