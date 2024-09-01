#![no_std]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

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
mod strkey;
mod typ;
mod version;

pub use error::*;
pub use strkey::*;
