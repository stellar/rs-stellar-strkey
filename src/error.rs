/// An error returned when decoding a strkey.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum DecodeError {
    /// The input is not valid base32 (no padding): an invalid symbol, an
    /// invalid encoded length, or non-zero trailing bits were encountered.
    InvalidBase32,
    /// The decoded data is shorter than the minimum required to contain a
    /// version byte and CRC.
    TooShort,
    /// The decoded data is longer than the maximum the requested strkey kind
    /// can hold.
    TooLong,
    /// The CRC16-XMODEM checksum did not match.
    ChecksumMismatch,
    /// The version byte is not a supported strkey kind for the type being
    /// decoded.
    UnsupportedVersion,
    /// The claimable-balance sub-version byte (the first byte of the payload)
    /// is not a supported claimable-balance version. Only `V0` (`0x00`) is
    /// defined.
    UnsupportedClaimableBalanceVersion,
    /// The decoded payload does not have the expected length for the strkey
    /// kind.
    InvalidPayloadLength,
    /// The payload contains padding bytes that must be zero but are not.
    InvalidPadding,
    /// The input is `S`-prefixed and may be a private-key strkey. `Strkey`
    /// does not parse `S…`. Route the input to
    /// [`ed25519::PrivateKey`](crate::ed25519::PrivateKey).
    PrivateKey,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            DecodeError::InvalidBase32 => f.write_str("the strkey is not valid base32"),
            DecodeError::TooShort => f.write_str("the strkey decodes to fewer bytes than required"),
            DecodeError::TooLong => f.write_str("the strkey decodes to more bytes than allowed"),
            DecodeError::ChecksumMismatch => f.write_str("the strkey checksum does not match"),
            DecodeError::UnsupportedVersion => {
                f.write_str("the strkey version byte is not a supported kind")
            }
            DecodeError::UnsupportedClaimableBalanceVersion => f.write_str(
                "the strkey claimable-balance sub-version byte is not a supported version",
            ),
            DecodeError::InvalidPayloadLength => {
                f.write_str("the strkey payload is not the expected length")
            }
            DecodeError::InvalidPadding => {
                f.write_str("the strkey payload has non-zero padding bytes")
            }
            DecodeError::PrivateKey => {
                f.write_str("the strkey is `S`-prefixed; use ed25519::PrivateKey to decode it")
            }
        }
    }
}

impl core::error::Error for DecodeError {}
