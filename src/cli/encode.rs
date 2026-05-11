use std::io::{IsTerminal, Read};

use clap::Args;

use crate::{Decoded, Strkey};

// Bound on the JSON input size. The largest legitimate Decoded<Strkey> JSON
// (a pretty-printed signed_payload_ed25519 with a max 64-byte payload) is
// under 300 bytes; 10 KiB allows generous formatting headroom while
// preventing pathologically large hex fields from forcing intermediate
// allocations during deserialization.
const MAX_JSON_LEN: usize = 10 * 1024;

#[derive(Debug)]
pub enum Error {
    InputTooLarge { len: usize, max: usize },
    Json(serde_json::Error),
    Io(std::io::Error),
    NoInput,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::InputTooLarge { len, max } => f.write_fmt(format_args!(
                "json input too large: {len} bytes (max {max})"
            )),
            Error::Json(e) => f.write_fmt(format_args!("{e}")),
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
    /// JSON for Strkey to encode (reads from stdin if not provided)
    #[arg()]
    json: Option<String>,
}

impl Cmd {
    pub fn run(&self) -> Result<(), Error> {
        let buf;
        let input = match &self.json {
            Some(s) => s.as_str(),
            None => {
                let stdin = std::io::stdin();
                if stdin.is_terminal() {
                    return Err(Error::NoInput);
                }
                let mut s = String::new();
                stdin
                    .lock()
                    .take(MAX_JSON_LEN as u64 + 1)
                    .read_to_string(&mut s)
                    .map_err(Error::Io)?;
                buf = s;
                buf.as_str()
            }
        };
        if input.len() > MAX_JSON_LEN {
            return Err(Error::InputTooLarge {
                len: input.len(),
                max: MAX_JSON_LEN,
            });
        }
        let Decoded(strkey): Decoded<Strkey> = serde_json::from_str(input).map_err(Error::Json)?;
        println!("{strkey}");
        Ok(())
    }
}
