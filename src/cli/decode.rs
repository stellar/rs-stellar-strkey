use std::io::Read;
use std::str::FromStr;

use crate::{DecodeError, Decoded, Strkey};
use clap::Args;

// Bound on the strkey input size. The longest legitimate strkey is a
// signed_payload_ed25519 with a 64-byte payload, encoded to 165 base32
// characters; 256 allows headroom and prevents unbounded reads from stdin.
const MAX_STRKEY_LEN: usize = 256;

#[derive(Debug)]
pub enum Error {
    Decode(String, DecodeError),
    InputTooLarge { len: usize, max: usize },
    Io(std::io::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::Decode(s, inner) => f.write_fmt(format_args!("decoding {s:?}: {inner}")),
            Error::InputTooLarge { len, max } => f.write_fmt(format_args!(
                "strkey input too large: {len} bytes (max {max})"
            )),
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
    pub(super) strkey: Option<String>,
}

impl Cmd {
    pub fn run(&self) -> Result<(), Error> {
        let buf;
        let input = match &self.strkey {
            Some(s) => s.trim(),
            None => {
                let mut s = String::new();
                std::io::stdin()
                    .lock()
                    .take(MAX_STRKEY_LEN as u64 + 1)
                    .read_to_string(&mut s)
                    .map_err(Error::Io)?;
                if s.len() > MAX_STRKEY_LEN {
                    return Err(Error::InputTooLarge {
                        len: s.len(),
                        max: MAX_STRKEY_LEN,
                    });
                }
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
