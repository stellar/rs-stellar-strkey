#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum DecodeError {
    // TODO: Add meaningful errors for each problem that can occur.
    Invalid,
    /// The input is `S`-prefixed and may be a private-key strkey. `Strkey`
    /// does not parse `S…` inputs to keep secret bytes out of its
    /// non-zeroizing decode path; the input is rejected on the first byte
    /// without validating length, CRC, or contents. Route the input to
    /// [`ed25519::PrivateKey`](crate::ed25519::PrivateKey) (which zeroizes
    /// its decode buffers) for full validation.
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
