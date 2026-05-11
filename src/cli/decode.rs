use std::str::FromStr;

use crate::{
    cli::unredacted_private_strkey::UnredactedPrivateStrkey, ed25519, DecodeError, Decoded, Strkey,
    Unredacted,
};
use clap::Args;

#[derive(Debug)]
pub enum Error {
    Decode(String, DecodeError),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::Decode(s, inner) => f.write_fmt(format_args!("decoding {s:?}: {inner}")),
        }
    }
}

impl core::error::Error for Error {}

#[derive(Args, Debug, Clone)]
#[command()]
pub struct Cmd {
    /// Strkey to decode
    #[arg()]
    strkey: String,
}

impl Cmd {
    pub fn run(&self) -> Result<(), Error> {
        let s = &self.strkey;
        // `S…` strkeys are decoded via `ed25519::PrivateKey` directly; the
        // Strkey enum intentionally excludes that variant.
        let json = if let Ok(k) = Strkey::from_str(s) {
            serde_json::to_string_pretty(&Decoded(&k)).unwrap()
        } else {
            let pk = ed25519::PrivateKey::from_str(s).map_err(|e| Error::Decode(s.clone(), e))?;
            let wrapper = UnredactedPrivateStrkey::PrivateKeyEd25519(Unredacted(pk));
            serde_json::to_string_pretty(&Decoded(&wrapper)).unwrap()
        };
        println!("{json}");
        Ok(())
    }
}
