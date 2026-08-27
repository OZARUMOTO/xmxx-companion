// SPDX-FileCopyrightText: 2026 OZARUMOTO
// SPDX-License-Identifier: GPL-3.0-or-later
//
// XMXX-CORE wallet — Monero key derivation from a seed.
//
// This module answers the `xmr-address` message of a monero-signer server:
// turn a 32-byte seed into spend/view keys, a mainnet address, subaddresses,
// and a 25-word Monero mnemonic — without ever printing private keys.
//
// Derivation (verified against mainline Monero):
//   * account key = SLIP-0010 m/44'/128'/account' from the seed  (Trezor/Ledger)
//   * spend       = sc_reduce32(account_key)   = Scalar::from_bytes_mod_order
//   * view        = sc_reduce32(keccak256(spend))
//
// A wallet derived this way restores anywhere: the reduced spend scalar
// encodes to Monero's own 25-word mnemonic (electrum-words scheme), which
// monero-wallet-cli, Feather, and Cake all import.
//
// Subaddress construction follows monero/src/device/device_default.cpp exactly:
//   m = H_s("SubAddr\0" ‖ private_view_key ‖ major_LE32 ‖ minor_LE32)
//   D = B + m·G,  C = a·D

use zeroize::{Zeroize, Zeroizing};

use crate::slip10;
use crate::words::ENGLISH_WORDS;
use crate::{Point, Scalar};

/// A Monero wallet: private spend/view scalars plus the public material.
///
/// Private keys are `Zeroizing` (wiped on drop). The `Debug` impl prints no
/// key material — only the address.
pub struct MoneroWallet {
    spend_key: Zeroizing<Scalar>,
    view_key: Zeroizing<Scalar>,
    spend_pub: Point,
    view_pub: Point,
    address: String,
}

impl core::fmt::Debug for MoneroWallet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MoneroWallet").field("address", &self.address).finish()
    }
}

impl Clone for MoneroWallet {
    fn clone(&self) -> Self {
        MoneroWallet {
            spend_key: self.spend_key.clone(),
            view_key: self.view_key.clone(),
            spend_pub: self.spend_pub,
            view_pub: self.view_pub,
            address: self.address.clone(),
        }
    }
}

impl Drop for MoneroWallet {
    fn drop(&mut self) {
        self.spend_key.zeroize();
        self.view_key.zeroize();
    }
}

impl MoneroWallet {
    /// Derive the wallet for `account` (SLIP-0010 m/44'/128'/account') from a
    /// 32-byte seed. `account` is the xmxx "wallet slot".
    pub fn derive(app_seed: &[u8; 32], account: u32) -> MoneroWallet {
        let node = slip10::monero_account(app_seed, account);
        // spend = sc_reduce32(account key)
        let spend = Scalar::from(curve25519_dalek::Scalar::from_bytes_mod_order(node.key));
        Self::from_spend_key(spend)
    }

    /// Restore a wallet from a spend key (e.g. decoded from a 25-word
    /// mnemonic). The spend key is reduced; view = sc_reduce32(keccak256(spend)).
    pub fn from_spend_key(spend: Scalar) -> MoneroWallet {
        let spend = Zeroizing::new(spend);
        // view = sc_reduce32(keccak256(spend))
        let spend_bytes: [u8; 32] = <[u8; 32]>::from(*spend);
        let view = Zeroizing::new(Scalar::hash(&spend_bytes));

        let spend_pub = mul_base(&spend);
        let view_pub = mul_base(&view);

        let address = encode_address(
            &spend_pub.compress().to_bytes(),
            &view_pub.compress().to_bytes(),
        );

        MoneroWallet { spend_key: spend, view_key: view, spend_pub, view_pub, address }
    }

    /// The private spend scalar (used only by `txset::sign_tx` on-device).
    pub fn spend_key(&self) -> &Scalar {
        &self.spend_key
    }

    /// The private view scalar. Only exported for the companion's chain scan
    /// (user-consented, via the app's view-key export) — never on its own.
    pub fn view_key(&self) -> &Scalar {
        &self.view_key
    }

    /// Public spend key (32 bytes).
    pub fn spend_public(&self) -> [u8; 32] {
        self.spend_pub.compress().to_bytes()
    }

    /// Public view key (32 bytes) — safe to hand to a companion.
    pub fn view_public(&self) -> [u8; 32] {
        self.view_pub.compress().to_bytes()
    }

    /// Public view key as a curve point (for envelope signature verification).
    pub fn view_public_point(&self) -> Point {
        self.view_pub
    }

    /// The 95-char mainnet address (starts with `4`).
    pub fn address(&self) -> &str {
        &self.address
    }

    /// A subaddress at (major, minor) = (account, address). Matches
    /// monero/src/device/device_default.cpp get_subaddress_secret_key.
    pub fn subaddress(&self, major: u32, minor: u32) -> String {
        let view_bytes: [u8; 32] = <[u8; 32]>::from(*self.view_key);
        let mut data = b"SubAddr\0".to_vec();
        data.extend_from_slice(&view_bytes);
        data.extend_from_slice(&major.to_le_bytes());
        data.extend_from_slice(&minor.to_le_bytes());
        let m = Scalar::hash(&data);

        // D = B + m·G
        let m_dalek: curve25519_dalek::Scalar = m.into();
        let d_dalek = into_dalek(self.spend_pub)
            + &m_dalek * &curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        // C = a·D
        let a_dalek: curve25519_dalek::Scalar = (*self.view_key).into();
        let c_dalek = &a_dalek * &d_dalek;

        encode_subaddress(
            &d_dalek.compress().to_bytes(),
            &c_dalek.compress().to_bytes(),
        )
    }

    /// The 25-word Monero mnemonic of the spend key — the seed phrase to write
    /// down. Restores in any Monero wallet.
    pub fn spend_mnemonic(&self) -> String {
        let bytes: [u8; 32] = <[u8; 32]>::from(*self.spend_key);
        encode_mnemonic(&bytes)
    }
}

fn mul_base(scalar: &Scalar) -> Point {
    let dalek: curve25519_dalek::Scalar = (*scalar).into();
    Point::from(curve25519_dalek::EdwardsPoint::mul_base(&dalek))
}

fn into_dalek(p: Point) -> curve25519_dalek::EdwardsPoint {
    p.into()
}

/// Encode a Monero mainnet address from spend/view public keys.
///
/// Payload: [network_version(1)=0x12] [spend_pub(32)] [view_pub(32)] =
/// 65 bytes, then a Keccak-256 checksum of those 65 bytes truncated to 4
/// bytes = 69 bytes, base58-encoded to 95 chars starting with `4`.
pub fn encode_address(spend_pub: &[u8; 32], view_pub: &[u8; 32]) -> String {
    encode_with_network_byte(0x12, spend_pub, view_pub)
}

/// Encode a Monero mainnet SUBADDRESS from its spend/view public keys.
///
/// Subaddresses use network byte 0x2A (mainnet), producing the characteristic
/// `8...` prefix — a 0x12 byte would make a wallet parse it as a standard
/// (unspendable) address.
pub fn encode_subaddress(spend_pub: &[u8; 32], view_pub: &[u8; 32]) -> String {
    encode_with_network_byte(0x2A, spend_pub, view_pub)
}

fn encode_with_network_byte(network_byte: u8, spend_pub: &[u8; 32], view_pub: &[u8; 32]) -> String {
    use tiny_keccak::Hasher;

    let mut data = Vec::with_capacity(69);
    data.push(network_byte);
    data.extend_from_slice(spend_pub);
    data.extend_from_slice(view_pub);

    // Keccak-256 (pre-NIST padding) checksum — the first 4 bytes.
    let mut keccak = tiny_keccak::Keccak::v256();
    keccak.update(&data);
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);
    data.extend_from_slice(&hash[..4]);

    base58_encode(&data)
}

/// Validate a Monero mainnet address string (accepts an optional `monero:`
/// prefix). Accepts standard (0x12) and subaddress (0x2A) network bytes;
/// checks length and the embedded Keccak checksum.
pub fn validate_address(addr: &str) -> bool {
    let addr = addr.strip_prefix("monero:").unwrap_or(addr);
    let Some(raw) = base58_decode(addr) else { return false };
    if raw.len() != 69 {
        return false;
    }
    if raw[0] != 0x12 && raw[0] != 0x2A {
        return false;
    }
    use tiny_keccak::Hasher;
    let mut keccak = tiny_keccak::Keccak::v256();
    keccak.update(&raw[..65]);
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);
    raw[65..69] == hash[..4]
}

/// Monero-specific base58 — matches monero/src/common/base58.cpp exactly.
///
/// Blocks are 1–8 bytes. Each block is treated as a BIG-ENDIAN u64 and encoded
/// into `encoded_block_sizes[block_len]` base58 chars. Output within each block
/// is RIGHT-ALIGNED — leading positions stay as `1` (= 0 in base58), which is
/// what produces the characteristic `4...` mainnet prefix.
pub fn base58_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const ENCODED_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];
    const BLOCK_SIZE: usize = 8;

    let mut result = String::new();

    for chunk in data.chunks(BLOCK_SIZE) {
        let block_len = chunk.len();
        let encoded_len = ENCODED_SIZES[block_len];

        let mut num: u64 = 0;
        for &byte in chunk {
            num = num.wrapping_mul(256).wrapping_add(byte as u64);
        }

        let mut buf = vec![ALPHABET[0]; encoded_len];
        let mut i = encoded_len as isize - 1;
        let mut n = num;
        while n > 0 {
            buf[i as usize] = ALPHABET[(n % 58) as usize];
            n /= 58;
            i -= 1;
        }

        result.push_str(&buf.iter().map(|&b| b as char).collect::<String>());
    }

    result
}

/// Decode Monero base58. Deterministic: each char-length maps to exactly one
/// byte-length (2→1, 3→2, 5→3, 6→4, 7→5, 9→6, 10→7, 11→8), so a single linear
/// pass recovers the blocks. Returns None on any invalid char/length.
pub fn base58_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    fn char_len_to_byte_len(cl: usize) -> Option<usize> {
        Some(match cl {
            2 => 1,
            3 => 2,
            5 => 3,
            6 => 4,
            7 => 5,
            9 => 6,
            10 => 7,
            11 => 8,
            _ => return None,
        })
    }
    fn decode_block(chunk: &[u8], alphabet: &[u8]) -> Option<u64> {
        let mut num: u64 = 0;
        for &c in chunk {
            let pos = alphabet.iter().position(|&a| a == c)?;
            num = num.checked_mul(58)?.checked_add(pos as u64)?;
        }
        Some(num)
    }
    fn block_to_bytes(mut num: u64, byte_len: usize) -> Vec<u8> {
        let mut b = vec![0u8; byte_len];
        let mut i = byte_len;
        while i > 0 {
            i -= 1;
            b[i] = (num & 0xff) as u8;
            num >>= 8;
        }
        b
    }

    let s = input.as_bytes();
    let mut out = Vec::with_capacity(69);
    let mut i = 0;
    while i < s.len() {
        let mut took: Option<(usize, usize)> = None;
        for cl in [11usize, 10, 9, 7, 6, 5, 3, 2] {
            if i + cl > s.len() {
                continue;
            }
            if let Some(bl) = char_len_to_byte_len(cl) {
                took = Some((cl, bl));
                break;
            }
        }
        let (cl, bl) = took?;
        out.extend_from_slice(&block_to_bytes(decode_block(&s[i..i + cl], ALPHABET)?, bl));
        i += cl;
    }
    Some(out)
}

/// URI-ready QR content for a Monero address.
pub fn address_qr_content(address: &str) -> String {
    format!("monero:{address}")
}

/// Encode a 32-byte key as hex.
pub fn hex_key(key: &[u8; 32]) -> String {
    hex::encode(key)
}

// ---------------------------------------------------------------------------
// 25-word mnemonic (Monero electrum-words scheme, src/mnemonics/electrum-words.cpp)
// ---------------------------------------------------------------------------

const WORDLIST_LEN: u64 = 1626;
const UNIQUE_PREFIX: usize = 3; // English words are unique by their first 3 chars

/// Encode a 32-byte spend key as 25 Monero words (24 data + 1 checksum word).
/// The checksum word duplicates the word at index CRC32(trimmed words) % 24.
pub fn encode_mnemonic(seed: &[u8; 32]) -> String {
    let mut words: Vec<&str> = Vec::with_capacity(25);

    // 8 groups of 4 bytes → 3 words each (big-endian u32).
    for i in 0..8 {
        let w0 = u32::from_be_bytes([seed[i * 4], seed[i * 4 + 1], seed[i * 4 + 2], seed[i * 4 + 3]]);
        let w1 = (w0 % WORDLIST_LEN as u32) as usize;
        let w2 = ((w0 / WORDLIST_LEN as u32 + w1 as u32) % WORDLIST_LEN as u32) as usize;
        let w3 = (((w0 / WORDLIST_LEN as u32) / WORDLIST_LEN as u32 + w2 as u32) % WORDLIST_LEN as u32) as usize;
        words.push(ENGLISH_WORDS[w1]);
        words.push(ENGLISH_WORDS[w2]);
        words.push(ENGLISH_WORDS[w3]);
    }

    // Checksum word: a duplicate of one of the 24, chosen by CRC-32.
    let idx = checksum_index(&words);
    words.push(words[idx]);
    words.join(" ")
}

/// Decode a 25-word Monero phrase back to the 32-byte spend key. Verifies the
/// checksum word. Mirrors electrum-words.cpp words_to_bytes.
pub fn mnemonic_to_spend(phrase: &str) -> Result<[u8; 32], String> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if words.len() != 25 {
        return Err(format!("expected 25 words, got {}", words.len()));
    }

    // Resolve indices.
    let mut idxs = Vec::with_capacity(25);
    for w in &words {
        let pos = ENGLISH_WORDS.iter().position(|&candidate| candidate == *w);
        match pos {
            Some(p) => idxs.push(p as u64),
            None => return Err(format!("word not in Monero English list: {w}")),
        }
    }

    // Checksum: last word must equal the word at CRC32(trimmed 24) % 24.
    if words[24] != words[checksum_index(&words[..24])] {
        return Err("bad checksum word".into());
    }

    // 8 groups of 3 words → 4 bytes (big-endian).
    let mut seed = [0u8; 32];
    for g in 0..8 {
        let w1 = idxs[g * 3];
        let w2 = idxs[g * 3 + 1];
        let w3 = idxs[g * 3 + 2];
        // w0 = w1 + N*((N−w1+w2) mod N) + N²*((N−w2+w3) mod N), wrapped to u32
        // exactly like the C++ uint32_t arithmetic.
        let w0 = w1
            .wrapping_add(WORDLIST_LEN.wrapping_mul((WORDLIST_LEN.wrapping_sub(w1).wrapping_add(w2)) % WORDLIST_LEN))
            .wrapping_add(
                (WORDLIST_LEN * WORDLIST_LEN)
                    .wrapping_mul((WORDLIST_LEN.wrapping_sub(w2).wrapping_add(w3)) % WORDLIST_LEN),
            );
        if (w0 as u32 as u64) % WORDLIST_LEN != w1 {
            return Err("invalid word group".into());
        }
        let bytes = (w0 as u32).to_be_bytes();
        seed[g * 4..g * 4 + 4].copy_from_slice(&bytes);
    }

    Ok(seed)
}

/// Index of the checksum word: CRC-32 (IEEE) of the concatenated 3-char
/// prefixes of the words, mod the word count (24).
fn checksum_index(words: &[&str]) -> usize {
    let mut trimmed = String::new();
    for w in words {
        trimmed.push_str(&w[..UNIQUE_PREFIX.min(w.len())]);
    }
    (crc32(trimmed.as_bytes()) % words.len() as u32) as usize
}

/// Standard IEEE CRC-32 (matches boost::crc_32_type used by electrum-words.cpp).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed all-zero test seed.
    #[test]
    fn address_is_valid_monero_mainnet_shape() {
        let w = MoneroWallet::derive(&[0u8; 32], 0);

        assert_eq!(w.address.len(), 95, "address must be 95 chars");
        assert!(w.address.starts_with('4'), "mainnet address starts with 4, got {}", w.address);

        let raw = base58_decode(&w.address).unwrap();
        assert_eq!(raw.len(), 69);
        assert_eq!(raw[0], 0x12, "network version byte");
        assert!(validate_address(&w.address), "address must self-validate");
        assert!(validate_address(&format!("monero:{}", w.address)));

        // Public keys must equal mul_base of the private keys.
        let spend_pub = w.spend_public();
        let view_pub = w.view_public();
        assert_eq!(&raw[1..33], &spend_pub, "embedded spend pubkey");
        assert_eq!(&raw[33..65], &view_pub, "embedded view pubkey");
    }

    /// view == sc_reduce32(keccak256(spend)) — the Monero invariant that makes
    /// the wallet restorable from the spend key alone.
    #[test]
    fn view_key_is_keccak_of_spend() {
        let w = MoneroWallet::derive(&[9u8; 32], 0);
        let spend_bytes: [u8; 32] = <[u8; 32]>::from(*w.spend_key);
        let expected: [u8; 32] = <[u8; 32]>::from(Scalar::hash(&spend_bytes));
        let actual: [u8; 32] = <[u8; 32]>::from(*w.view_key);
        assert_eq!(actual, expected, "view key must be sc_reduce32(keccak256(spend))");
    }

    /// Different accounts (slots) derive different wallets.
    #[test]
    fn accounts_derive_distinct_wallets() {
        let seed = [7u8; 32];
        let a0 = MoneroWallet::derive(&seed, 0);
        let a1 = MoneroWallet::derive(&seed, 1);
        assert_ne!(a0.address, a1.address);
        assert_ne!(a0.spend_public(), a1.spend_public());
    }

    /// Subaddress construction: D = B + m·G, C = a·D — recomputed independently.
    #[test]
    fn subaddress_matches_monero_construction() {
        let w = MoneroWallet::derive(&[3u8; 32], 0);
        let sub = w.subaddress(0, 1);
        assert!(validate_address(&sub), "subaddress must validate");
        assert_eq!(sub.len(), 95);

        // m = H_s("SubAddr\0" ‖ view ‖ major_LE ‖ minor_LE)
        let view_bytes: [u8; 32] = <[u8; 32]>::from(*w.view_key);
        let mut data = b"SubAddr\0".to_vec();
        data.extend_from_slice(&view_bytes);
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        let m = Scalar::hash(&data);

        let m_dalek: curve25519_dalek::Scalar = m.into();
        let b_dalek: curve25519_dalek::EdwardsPoint = w.spend_pub.into();
        let d_dalek = b_dalek + &m_dalek * &curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        let a_dalek: curve25519_dalek::Scalar = (*w.view_key).into();
        let c_dalek = &a_dalek * &d_dalek;

        let expected = encode_subaddress(&d_dalek.compress().to_bytes(), &c_dalek.compress().to_bytes());
        assert_eq!(sub, expected);
        // Subaddresses must carry the 0x2A network byte (8-prefix), not 0x12.
        let raw = base58_decode(&sub).unwrap();
        assert_eq!(raw[0], 0x2A, "subaddress network byte");
        assert!(sub.starts_with('8'), "mainnet subaddress starts with 8, got {}", sub);
    }

    /// Distinct subaddresses for different (major, minor).
    #[test]
    fn subaddresses_are_distinct() {
        let w = MoneroWallet::derive(&[3u8; 32], 0);
        let a = w.subaddress(0, 0);
        let b = w.subaddress(0, 1);
        let c = w.subaddress(1, 0);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    /// Single-block base58 vectors, computed independently against Monero's
    /// block encoder:
    ///   - a 1-byte zero block → 2 chars "11"
    ///   - a 2-byte zero block → 3 chars "111"
    ///   - an 8-byte all-0xff block → 11 chars starting with `j` (max u64)
    #[test]
    fn base58_single_block_vectors() {
        assert_eq!(base58_encode(&[0x00]), "11");
        assert_eq!(base58_encode(&[0x00, 0x00]), "111");
        assert_eq!(base58_encode(&[0x00; 8]), "11111111111"); // 8 bytes → 11 chars
        assert_eq!(base58_encode(&[0xff; 8]), "jpXCZedGfVQ"); // u64::MAX, verified vector
    }

    /// CRC-32 known vector: "123456789" → 0xCBF43926.
    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    /// Mnemonic round-trips and the checksum word duplicates one of the first 24.
    #[test]
    fn mnemonic_round_trip() {
        let w = MoneroWallet::derive(&[42u8; 32], 0);
        let phrase = w.spend_mnemonic();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 25);
        // Checksum word must be a duplicate of an earlier word.
        assert!(words[..24].contains(&words[24]), "checksum word must duplicate a data word");

        let decoded = mnemonic_to_spend(&phrase).unwrap();
        let spend_bytes: [u8; 32] = <[u8; 32]>::from(*w.spend_key);
        assert_eq!(decoded, spend_bytes, "mnemonic must decode to the spend key");

        // Restoring from the decoded spend key reproduces the same wallet.
        let restored = MoneroWallet::from_spend_key(Scalar::from(
            curve25519_dalek::Scalar::from_bytes_mod_order(decoded),
        ));
        assert_eq!(restored.address(), w.address());
        assert_eq!(restored.spend_public(), w.spend_public());
    }

    /// A tampered phrase must fail the checksum.
    #[test]
    fn mnemonic_rejects_tampering() {
        let w = MoneroWallet::derive(&[5u8; 32], 0);
        let phrase = w.spend_mnemonic();
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        // Flip a middle word to a different valid word.
        let original = words[10];
        let replacement = ENGLISH_WORDS.iter().find(|w| **w != original).unwrap();
        words[10] = replacement;
        assert!(mnemonic_to_spend(&words.join(" ")).is_err());
    }

    /// The zero-seed wallet is deterministic and stable across calls.
    #[test]
    fn derivation_is_deterministic() {
        let a = MoneroWallet::derive(&[1u8; 32], 0);
        let b = MoneroWallet::derive(&[1u8; 32], 0);
        assert_eq!(a.address(), b.address());
        assert_eq!(a.spend_public(), b.spend_public());
        assert_eq!(a.spend_mnemonic(), b.spend_mnemonic());
    }
}
