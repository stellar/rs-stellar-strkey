use std::str::FromStr;

use crate::{DecodeError, Strkey};
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
        let strkey =
            Strkey::from_str(&self.strkey).map_err(|e| Error::Decode(self.strkey.clone(), e))?;
        let json = serde_json::to_string_pretty(&strkey).unwrap();
        println!("{json}");
        Ok(())
    }
}
