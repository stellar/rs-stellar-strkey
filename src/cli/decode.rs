use std::io::{IsTerminal, Read};
use std::str::FromStr;

use crate::{DecodeError, Decoded, Strkey};
use clap::Args;

#[derive(Debug)]
pub enum Error {
    Decode(String, DecodeError),
    Io(std::io::Error),
    NoInput,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::Decode(s, inner) => f.write_fmt(format_args!("decoding {s:?}: {inner}")),
            Error::Io(e) => f.write_fmt(format_args!("reading stdin: {e}")),
            Error::NoInput => {
                f.write_str("no input: provide a positional argument or pipe input to stdin")
            }
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
        let buf;
        let input = match &self.strkey {
            Some(s) => s.as_str(),
            None => {
                let stdin = std::io::stdin();
                if stdin.is_terminal() {
                    return Err(Error::NoInput);
                }
                let mut s = String::new();
                stdin
                    .lock()
                    .take(Strkey::MAX_ENCODED_LEN as u64 + 1)
                    .read_to_string(&mut s)
                    .map_err(Error::Io)?;
                buf = s;
                buf.trim()
            }
        };
        let strkey = Strkey::from_str(input).map_err(|e| Error::Decode(input.to_string(), e))?;
        let json = serde_json::to_string_pretty(&Decoded(&strkey)).unwrap();
        println!("{json}");
        Ok(())
    }
}
