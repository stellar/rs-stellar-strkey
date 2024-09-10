use std::str::FromStr;

use clap::Args;
use stellar_strkey::DecodeError;

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
        let strkey = stellar_strkey::Strkey::from_str(&self.strkey)
            .map_err(|e| Error::Decode(self.strkey.clone(), e))?;
        println!("{strkey:?}");
        Ok(())
    }
}
