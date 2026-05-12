//! Encode and decode [Stellar strkeys] as defined by [SEP-23].
//!
//! Strkeys are the human-readable textual representation of identifiers used
//! across the Stellar network — account IDs, signing keys, contract IDs,
//! liquidity pool IDs, and others. Each strkey begins with a single ASCII
//! letter that identifies its kind (`G`, `S`, `M`, `T`, `X`, `P`, `C`, `L`,
//! `B`) and is encoded as base32 without padding. The binary form is a
//! one-byte version, the type's payload, and a two-byte CRC16-XMODEM
//! checksum, ensuring that mistyped strkeys are detected before they are
//! used.
//!
//! This crate provides:
//!
//! - The [`Strkey`] enum, which can hold and round-trip any strkey kind
//!   other than `PrivateKeyEd25519` (`S…`); private-key strkeys are
//!   handled directly via [`ed25519::PrivateKey`], with rendering gated
//!   behind [`Unredacted`].
//! - Per-kind types in this module ([`PreAuthTx`], [`HashX`], [`Contract`],
//!   [`LiquidityPool`], [`ClaimableBalance`]) and in [`ed25519`]
//!   ([`ed25519::PublicKey`], [`ed25519::PrivateKey`],
//!   [`ed25519::MuxedAccount`], [`ed25519::SignedPayload`]) for callers that
//!   know the kind in advance.
//! - [`Display`](core::fmt::Display) and [`FromStr`](core::str::FromStr)
//!   implementations for every kind, plus inherent `to_string` /
//!   `from_string` / `from_slice` methods. [`ed25519::PrivateKey`] is the
//!   exception: it does not implement `Display` or inherent `to_string`
//!   directly — wrap it in [`Unredacted`] (`pk.as_unredacted()`) to render
//!   the encoded strkey form.
//!
//! # Strkey kinds
//!
//! | Prefix | Kind                                                                  | Payload bytes |
//! |--------|-----------------------------------------------------------------------|---------------|
//! | `G`    | [`Strkey::PublicKeyEd25519`] / [`ed25519::PublicKey`]                  |            32 |
//! | `S`    | [`ed25519::PrivateKey`] only (omitted from [`Strkey`])                 |            32 |
//! | `M`    | [`Strkey::MuxedAccountEd25519`] / [`ed25519::MuxedAccount`]            |            40 |
//! | `T`    | [`Strkey::PreAuthTx`] / [`PreAuthTx`]                                  |            32 |
//! | `X`    | [`Strkey::HashX`] / [`HashX`]                                          |            32 |
//! | `P`    | [`Strkey::SignedPayloadEd25519`] / [`ed25519::SignedPayload`]          |        40–100 |
//! | `C`    | [`Strkey::Contract`] / [`Contract`]                                    |            32 |
//! | `L`    | [`Strkey::LiquidityPool`] / [`LiquidityPool`]                          |            32 |
//! | `B`    | [`Strkey::ClaimableBalance`] / [`ClaimableBalance`]                    |            33 |
//!
//! # Examples
//!
//! Parse any strkey when the kind isn't known up front:
//!
//! ```
//! use stellar_strkey::Strkey;
//!
//! let s = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
//! let strkey: Strkey = s.parse().unwrap();
//! assert!(matches!(strkey, Strkey::PublicKeyEd25519(_)));
//! ```
//!
//! Parse a specific kind and reject anything else:
//!
//! ```
//! use stellar_strkey::Contract;
//!
//! let s = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
//! let contract: Contract = s.parse().unwrap();
//! assert_eq!(contract.0, [0u8; 32]);
//! ```
//!
//! Construct a strkey from raw bytes and render it:
//!
//! ```
//! use stellar_strkey::ed25519::PublicKey;
//!
//! let key = PublicKey([0u8; 32]);
//! assert_eq!(
//!     key.to_string().as_str(),
//!     "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
//! );
//! ```
//!
//! # `no_std`
//!
//! With default features the crate is `no_std` and does not depend on
//! `alloc`. Encoding uses fixed-capacity buffers from the `heapless` crate,
//! so each kind's `to_string` returns a `heapless::String` sized to the
//! maximum length for that kind.
//!
//! # Cargo features
//!
//! - `serde` — derives [`Serialize`]/[`Deserialize`] that round-trip strkeys
//!   as their textual form. [`ed25519::PrivateKey`] is `Deserialize` but
//!   not directly `Serialize`; wrap in [`Unredacted`] to serialize.
//! - `serde-decoded` — adds a `Decoded<T>` wrapper that serializes a strkey
//!   as a structured JSON object with hex-encoded byte fields, which is
//!   useful for tooling that wants to inspect the underlying bytes. Requires
//!   `alloc` and implies `serde`.
//! - `cli` — builds the `stellar-strkey` binary for encoding and decoding
//!   strkeys from the command line. Requires `std` (disables `no_std` for
//!   the crate). Not intended for enabling with the library.
//!
//! [Stellar strkeys]: https://developers.stellar.org/docs/learn/glossary#strkey
//! [SEP-23]: https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md
//! [`Serialize`]: https://docs.rs/serde/latest/serde/trait.Serialize.html
//! [`Deserialize`]: https://docs.rs/serde/latest/serde/trait.Deserialize.html

#![cfg_attr(not(feature = "cli"), no_std)]

#[cfg(feature = "serde-decoded")]
extern crate alloc;

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct Version<'a> {
    pub pkg: &'a str,
    pub rev: &'a str,
}
pub const VERSION: Version = Version {
    pkg: env!("CARGO_PKG_VERSION"),
    rev: env!("GIT_REVISION"),
};

#[doc(hidden)]
pub mod convert;
mod crc;
pub mod ed25519;
mod error;
mod strkey;
mod typ;
mod unredacted;
mod version;

pub use error::*;
pub use strkey::*;
pub use unredacted::Unredacted;

#[cfg(feature = "serde-decoded")]
pub mod decoded_json_format;
#[cfg(feature = "serde-decoded")]
pub use decoded_json_format::Decoded;

#[cfg(feature = "cli")]
pub mod cli;
