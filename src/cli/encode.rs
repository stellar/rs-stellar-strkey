use clap::Args;

use crate::{Decoded, Strkey};

#[derive(Debug)]
pub enum Error {
    Json(serde_json::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::Json(e) => core::fmt::Display::fmt(e, f),
        }
    }
}

impl core::error::Error for Error {}

#[derive(Args, Debug, Clone)]
#[command()]
pub struct Cmd {
    /// JSON for Strkey to encode
    #[arg()]
    json: String,
}

impl Cmd {
    pub fn run(&self) -> Result<(), Error> {
        let Decoded(strkey): Decoded<Strkey> =
            serde_json::from_str(&self.json).map_err(Error::Json)?;
        println!("{strkey}");
        Ok(())
    }
}
