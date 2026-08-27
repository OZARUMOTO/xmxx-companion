// SPDX-FileCopyrightText: 2026 OZARUMOTO
// SPDX-License-Identifier: GPL-3.0-or-later
//
// SLIP-0010 hierarchical deterministic key derivation, ed25519 curve.
//
// Only hardened derivation is used (ed25519 does not support non-hardened
// children). This is the Trezor/Ledger standard for Monero accounts:
// m/44'/128'/account'. The derived 32-byte key is NOT yet a Monero scalar —
// callers reduce it with sc_reduce32 (Scalar::from_bytes_mod_order) exactly as
// Trezor/Ledger do, which makes the spend key exportable as a 25-word
// Monero mnemonic.
//
// Spec: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
// Implemented with RustCrypto's hmac + sha2 (vetted, no hand-rolled hashing).

use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// A node in the SLIP-0010 tree: a 32-byte private key and its chain code.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Slip10Node {
    pub key: [u8; 32],
    pub chain_code: [u8; 32],
}

impl core::fmt::Debug for Slip10Node {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print the key material.
        f.debug_struct("Slip10Node").field("chain_code", &hex::encode(self.chain_code)).finish()
    }
}

/// Master node from a seed (SLIP-0010: HMAC-SHA512(key = b"ed25519 seed", data = seed)).
pub fn master(seed: &[u8]) -> Slip10Node {
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed").expect("HMAC accepts any key length");
    mac.update(seed);
    let out = mac.finalize().into_bytes();
    node_from_hmac(out.as_slice())
}

/// Hardened child at `index` (SLIP-0010 ed25519; the hardened bit is set here,
/// callers pass the plain index, e.g. `derive_child(44)` for 44').
pub fn derive_child(parent: &Slip10Node, index: u32) -> Slip10Node {
    // data = 0x00 || ser256(k_par) || ser32(i | 0x80000000)
    let hardened = index | 0x8000_0000;
    let mut data = [0u8; 37];
    data[1..33].copy_from_slice(&parent.key);
    data[33..37].copy_from_slice(&hardened.to_be_bytes());

    let mut mac = HmacSha512::new_from_slice(&parent.chain_code).expect("HMAC accepts any key length");
    mac.update(&data);
    let out = mac.finalize().into_bytes();
    node_from_hmac(out.as_slice())
}

/// The standard Monero account path m/44'/128'/account' for a 32-byte seed.
pub fn monero_account(seed: &[u8; 32], account: u32) -> Slip10Node {
    let m = master(seed);
    let m44 = derive_child(&m, 44);
    let m128 = derive_child(&m44, 128);
    derive_child(&m128, account)
}

fn node_from_hmac(out: &[u8]) -> Slip10Node {
    let mut node = Slip10Node { key: [0u8; 32], chain_code: [0u8; 32] };
    node.key.copy_from_slice(&out[..32]);
    node.chain_code.copy_from_slice(&out[32..64]);
    node
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&hex::decode(s).unwrap());
        out
    }

    /// Official SLIP-0010 test vector 1 (ed25519), seed 000102...0f.
    /// https://github.com/satoshilabs/slips/blob/master/slip-0010.md
    #[test]
    fn official_vector_1_ed25519() {
        let seed = (0u8..16).collect::<Vec<_>>();
        let m = master(&seed);
        assert_eq!(m.key, hex("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"));
        assert_eq!(m.chain_code, hex("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"));

        let m0h = derive_child(&m, 0);
        assert_eq!(m0h.key, hex("68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"));
        assert_eq!(m0h.chain_code, hex("8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"));

        let m0h1 = derive_child(&m0h, 1);
        assert_eq!(m0h1.key, hex("b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"));
        assert_eq!(m0h1.chain_code, hex("a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14"));

        let m0h1_2h = derive_child(&m0h1, 2);
        assert_eq!(m0h1_2h.key, hex("92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9"));
        assert_eq!(m0h1_2h.chain_code, hex("2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c"));

        let m0h1_2h2 = derive_child(&m0h1_2h, 2);
        assert_eq!(m0h1_2h2.key, hex("30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662"));
        assert_eq!(m0h1_2h2.chain_code, hex("8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc"));

        let m0h1_2h2_1b = derive_child(&m0h1_2h2, 1000000000);
        assert_eq!(m0h1_2h2_1b.key, hex("8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"));
        assert_eq!(m0h1_2h2_1b.chain_code, hex("68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230"));
    }

    /// Distinct accounts must produce distinct keys.
    #[test]
    fn accounts_are_distinct() {
        let seed = [7u8; 32];
        let a0 = monero_account(&seed, 0);
        let a1 = monero_account(&seed, 1);
        assert_ne!(a0.key, a1.key);
        assert_ne!(a0.chain_code, a1.chain_code);
    }
}
