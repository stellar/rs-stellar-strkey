use std::io::Read;
use std::str::FromStr;

use crate::{DecodeError, Decoded, Strkey};
use clap::Args;

#[derive(Debug)]
pub enum Error {
    Decode(String, DecodeError),
    Io(std::io::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::Decode(s, inner) => f.write_fmt(format_args!("decoding {s:?}: {inner}")),
            Error::Io(e) => f.write_fmt(format_args!("reading stdin: {e}")),
        }
    }
}

impl core::error::Error for Error {}

#[derive(Args, Debug, Clone)]
#[command()]
pub struct Cmd {
    /// Strkey to decode (reads from stdin if not provided)
    #[arg()]
    strkey: Option<String>,
}

impl Cmd {
    pub fn run(&self) -> Result<(), Error> {
        let input = match &self.strkey {
            Some(s) => s.clone(),
            None => {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s).map_err(Error::Io)?;
                s.trim().to_string()
            }
        };
        let strkey = Strkey::from_str(&input).map_err(|e| Error::Decode(input.clone(), e))?;
        let json = serde_json::to_string_pretty(&Decoded(&strkey)).unwrap();
        println!("{json}");
        Ok(())
    }
}
