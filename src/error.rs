use core::fmt;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum DecodeError {
    // TODO: Add meaningful errors for each problem that can occur.
    Invalid,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Invalid => write!(f, "the strkey is invalid"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}
