use std::io::{IsTerminal, Read};
use std::str::FromStr;

use crate::{DecodeError, Decoded, Strkey};
use clap::Args;

#[derive(Debug)]
pub enum Error {
    Decode(String, DecodeError),
    InputTooLarge { len: usize, max: usize },
    Io(std::io::Error),
    NoInput,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::Decode(s, inner) => f.write_fmt(format_args!("decoding {s:?}: {inner}")),
            Error::InputTooLarge { len, max } => f.write_fmt(format_args!(
                "strkey input too large: {len} bytes (max {max})"
            )),
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
            Some(s) => s.trim(),
            None => {
                let stdin = std::io::stdin();
                if stdin.is_terminal() {
                    return Err(Error::NoInput);
                }
                // Read with a small amount of headroom over the longest valid
                // strkey to accommodate trailing whitespace from pipes.
                let cap = Strkey::MAX_ENCODED_LEN + 16;
                let mut s = String::new();
                stdin
                    .lock()
                    .take(cap as u64 + 1)
                    .read_to_string(&mut s)
                    .map_err(Error::Io)?;
                buf = s;
                let trimmed = buf.trim();
                if trimmed.len() > Strkey::MAX_ENCODED_LEN {
                    return Err(Error::InputTooLarge {
                        len: trimmed.len(),
                        max: Strkey::MAX_ENCODED_LEN,
                    });
                }
                trimmed
            }
        };
        let strkey = Strkey::from_str(input).map_err(|e| Error::Decode(input.to_string(), e))?;
        let json = serde_json::to_string_pretty(&Decoded(&strkey)).unwrap();
        println!("{json}");
        Ok(())
    }
}
