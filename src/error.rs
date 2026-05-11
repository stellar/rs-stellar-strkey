#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum DecodeError {
    // TODO: Add meaningful errors for each problem that can occur.
    Invalid,
    /// The strkey is a private key (`S…`), which is not accepted by
    /// `Strkey::from_string` / `FromStr`. Use
    /// [`ed25519::PrivateKey`](crate::ed25519::PrivateKey) directly to
    /// decode private-key strkeys.
    PrivateKey,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            DecodeError::Invalid {} => f.write_str("the strkey is invalid"),
            DecodeError::PrivateKey {} => {
                f.write_str("the strkey is a private key; use ed25519::PrivateKey to decode it")
            }
        }
    }
}

impl core::error::Error for DecodeError {}
