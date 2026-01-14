#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum DecodeError {
    // TODO: Add meaningful errors for each problem that can occur.
    Invalid,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            DecodeError::Invalid {} => f.write_str("the strkey is invalid"),
        }
    }
}

impl core::error::Error for DecodeError {}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum EncodeError {
    /// The output buffer is too small to hold the encoded strkey.
    BufferTooSmall {
        /// The size of the buffer provided.
        buf_len: usize,
        /// The size required to encode the strkey.
        required_len: usize,
    },
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            EncodeError::BufferTooSmall {
                buf_len,
                required_len,
            } => write!(
                f,
                "buffer too small: provided {buf_len} bytes, need {required_len}"
            ),
        }
    }
}

impl core::error::Error for EncodeError {}
