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
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::InputTooLarge { len, max } => f.write_fmt(format_args!(
                "json input too large: {len} bytes (max {max})"
            )),
            Error::Json(e) => f.write_fmt(format_args!("{e}")),
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
        if self.json.len() > MAX_JSON_LEN {
            return Err(Error::InputTooLarge {
                len: self.json.len(),
                max: MAX_JSON_LEN,
            });
        }
        let Decoded(strkey): Decoded<Strkey> =
            serde_json::from_str(&self.json).map_err(Error::Json)?;
        println!("{strkey}");
        Ok(())
    }
}
