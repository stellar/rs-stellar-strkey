use clap::Args;

use crate::{cli::unredacted_private_strkey::UnredactedPrivateStrkey, Decoded, Strkey};

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
        // Peek at the variant key: `private_key_ed25519` is handled outside
        // the Strkey enum and routed through `UnredactedPrivateStrkey`.
        let value: serde_json::Value = serde_json::from_str(&self.json).map_err(Error::Json)?;
        let is_private = value
            .as_object()
            .filter(|m| m.len() == 1)
            .and_then(|m| m.keys().next())
            .map(|k| k == "private_key_ed25519")
            .unwrap_or(false);
        if is_private {
            let Decoded(UnredactedPrivateStrkey::PrivateKeyEd25519(unredacted)): Decoded<
                UnredactedPrivateStrkey,
            > = serde_json::from_value(value).map_err(Error::Json)?;
            println!("{unredacted}");
        } else {
            let Decoded(strkey): Decoded<Strkey> =
                serde_json::from_value(value).map_err(Error::Json)?;
            println!("{strkey}");
        }
        Ok(())
    }
}
