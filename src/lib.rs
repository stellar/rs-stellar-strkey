#![cfg_attr(not(feature = "cli"), no_std)]
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

mod convert;
mod crc;
pub mod ed25519;
mod error;
mod hex;
mod strkey;
mod typ;
mod version;

pub use error::*;
pub use strkey::*;

#[cfg(feature = "serde-decoded")]
pub mod decoded_json_format;
#[cfg(feature = "serde-decoded")]
pub use decoded_json_format::Decoded;

#[cfg(feature = "cli")]
pub mod cli;
