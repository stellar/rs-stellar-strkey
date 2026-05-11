#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum DecodeError {
    // TODO: Add meaningful errors for each problem that can occur.
    Invalid,
    /// The input is `S`-prefixed and may be a private-key strkey. `Strkey`
    /// does not parse `S…`. Route the input to
    /// [`ed25519::PrivateKey`](crate::ed25519::PrivateKey).
    PrivateKey,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            DecodeError::Invalid {} => f.write_str("the strkey is invalid"),
            DecodeError::PrivateKey {} => {
                f.write_str("the strkey is `S`-prefixed; use ed25519::PrivateKey to decode it")
            }
        }
    }
}

impl core::error::Error for DecodeError {}
