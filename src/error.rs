#[derive(thiserror::Error, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum DecodeError {
    // TODO: Add meaningful errors for each problem that can occur.
    #[error("the strkey is invalid")]
    Invalid,

    #[error("error from seed phrase")]
    SeedPhrase,

    #[error("invalid path index")]
    InvalidPath,
}
