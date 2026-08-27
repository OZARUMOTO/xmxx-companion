// SPDX-FileCopyrightText: 2026 OZARUMOTO
// SPDX-License-Identifier: GPL-3.0-or-later
//
// XMXX-CORE — OZARUMOTO's Monero reference crypto.
//
// Extracted from the xmxx KeyOS app so it can back a foundation `monero-signer`
// server. Pure crypto only: key derivation, key images, and the authenticated
// unsigned/signed tx wire formats. No UI, no transport, no device state.
//
// The three modules map 1:1 onto a signer-server message surface:
//   * `wallet`    → xmr-address  (SLIP-0010 seed → spend/view + verified base58)
//   * `keyimage`  → xmr-keyimage (one-time keys + double-spend proofs)
//   * `txset`     → xmr-txunsigned / xmr-txsigned (authenticated wire format)
//
// Everything is host-compilable with `cargo build` / `cargo test`. This crate
// is std-only: the underlying Monero stack (monero-oxide / monero-wallet) is
// no_std-capable, but this crate does not claim no_std until it actually builds
// that way — the `device` entry point lives in the app, which calls
// `wallet::MoneroWallet::derive(&app_seed, account)` with the KeyOS app seed.
pub mod wallet;
pub mod keyimage;
pub mod txset;

mod slip10;
mod words;

// Re-export the exact scalar/point types used across the wire formats so the
// app and companion import one set of types (from monero-oxide's ed25519).
pub use monero_oxide::ed25519::{Point, Scalar, CompressedPoint};
