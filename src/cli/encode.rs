use std::io::{IsTerminal, Read};

use clap::Args;

use crate::{ed25519, Decoded, Strkey, Unredacted};

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
        let mut input = String::new();
        stdin
            .lock()
            .take(MAX_JSON_LEN as u64 + 1)
            .read_to_string(&mut input)
            .map_err(Error::Io)?;
        if input.len() > MAX_JSON_LEN {
            return Err(Error::InputTooLarge {
                len: input.len(),
                max: MAX_JSON_LEN,
            });
        }
        // Peek at the variant key: `private_key_ed25519` is handled outside
        // the Strkey enum and routed through `ed25519::PrivateKey`.
        let value: serde_json::Value = serde_json::from_str(&input).map_err(Error::Json)?;
        let pk_value = value
            .as_object()
            .filter(|m| m.len() == 1)
            .and_then(|m| m.get("private_key_ed25519"))
            .cloned();
        if let Some(pk_value) = pk_value {
            let Decoded(Unredacted(pk)): Decoded<Unredacted<ed25519::PrivateKey>> =
                serde_json::from_value(pk_value).map_err(Error::Json)?;
            if !opts.quiet {
                super::warn_private_key();
            }
            println!("{}", Unredacted(&pk));
        } else {
            let Decoded(strkey): Decoded<Strkey> =
                serde_json::from_value(value).map_err(Error::Json)?;
            println!("{strkey}");
        }
        Ok(())
    }
}
