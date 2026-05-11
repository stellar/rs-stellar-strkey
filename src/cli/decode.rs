use std::io::{IsTerminal, Read};
use std::str::FromStr;

use crate::{ed25519, DecodeError, Decoded, Strkey, Unredacted};
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
            Error::NoInput => f.write_str("no input: pipe input to stdin"),
        }
    }
}

impl core::error::Error for Error {}

#[derive(Args, Debug, Clone)]
#[command()]
pub struct Cmd {}

impl Cmd {
    pub fn run(&self, opts: &super::RunOpts) -> Result<(), Error> {
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            return Err(Error::NoInput);
        }
        // Allow some headroom over the longest valid strkey so that
        // common trailing whitespace (e.g. \n, \r\n) is accepted.
        // Anything beyond that is rejected outright rather than
        // silently truncated.
        let max = Strkey::MAX_ENCODED_LEN + 16;
        let mut buf = String::new();
        stdin
            .lock()
            .take(max as u64 + 1)
            .read_to_string(&mut buf)
            .map_err(Error::Io)?;
        if buf.len() > max {
            return Err(Error::InputTooLarge {
                len: buf.len(),
                max,
            });
        }
        let input = buf.trim();
        // `S…` strkeys are decoded via `ed25519::PrivateKey` directly; the
        // Strkey enum intentionally excludes that variant.
        let json = if let Ok(k) = Strkey::from_str(input) {
            serde_json::to_string_pretty(&Decoded(&k)).unwrap()
        } else {
            let pk = ed25519::PrivateKey::from_str(input)
                .map_err(|e| Error::Decode(input.to_string(), e))?;
            if !opts.quiet {
                super::warn_private_key();
            }
            serde_json::to_string_pretty(&serde_json::json!({
                "private_key_ed25519": Decoded(Unredacted(&pk)),
            }))
            .unwrap()
        };
        println!("{json}");
        Ok(())
    }
}
