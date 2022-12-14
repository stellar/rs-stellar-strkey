use std::str::FromStr;

use crate::DecodeError;

pub fn from_seed(seed: &[u8]) -> Result<bip39::Mnemonic, DecodeError> {
    bip39::Mnemonic::from_entropy(seed).map_err(|_| DecodeError::SeedPhrase)
}

pub fn random(word_count: usize) -> Result<bip39::Mnemonic, DecodeError> {
    bip39::Mnemonic::generate(word_count).map_err(|_| DecodeError::SeedPhrase)
}

pub fn to_seed(seed_phrase: &str) -> Result<[u8; 64], DecodeError> {
    bip39::Mnemonic::from_str(seed_phrase)
        .map_err(|_| DecodeError::SeedPhrase)
        .map(|nm| nm.to_seed(""))
}
