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
