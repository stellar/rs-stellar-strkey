use std::str::FromStr;

use thiserror::Error;

use crate::crc::checksum;

#[derive(Error, Clone, PartialEq, Eq, Debug)]
pub enum DecodeError {
    // TODO: Add meaningful errors for each problem that can occur.
    #[error("the strkey is invalid")]
    Invalid,
}

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub enum Strkey {
    PublicKeyEd25519(StrkeyPublicKeyEd25519),
    PrivateKeyEd25519(StrkeyPrivateKeyEd25519),
}

impl Strkey {
    pub fn to_string(&self) -> String {
        match self {
            Self::PublicKeyEd25519(x) => x.to_string(),
            Self::PrivateKeyEd25519(x) => x.to_string(),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::PUBLIC_KEY_ED25519 => Ok(Self::PublicKeyEd25519(
                StrkeyPublicKeyEd25519::from_payload(&payload)?,
            )),
            version::PRIVATE_KEY_ED25519 => Ok(Self::PrivateKeyEd25519(
                StrkeyPrivateKeyEd25519::from_payload(&payload)?,
            )),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl FromStr for Strkey {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Strkey::from_string(s)
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub struct StrkeyPublicKeyEd25519(pub [u8; 32]);

impl StrkeyPublicKeyEd25519 {
    pub fn to_string(&self) -> String {
        encode(version::PUBLIC_KEY_ED25519, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(ed25519) => Ok(Self(ed25519)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::PUBLIC_KEY_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl FromStr for StrkeyPublicKeyEd25519 {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        StrkeyPublicKeyEd25519::from_string(s)
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub struct StrkeyPrivateKeyEd25519(pub [u8; 32]);

impl StrkeyPrivateKeyEd25519 {
    pub fn to_string(&self) -> String {
        encode(version::PRIVATE_KEY_ED25519, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(ed25519) => Ok(Self(ed25519)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::PRIVATE_KEY_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl FromStr for StrkeyPrivateKeyEd25519 {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        StrkeyPrivateKeyEd25519::from_string(s)
    }
}

mod version {
    use super::public_key_alg::*;
    use super::typ::*;

    pub const PUBLIC_KEY_ED25519: u8 = PUBLIC_KEY | ED25519;
    pub const PRIVATE_KEY_ED25519: u8 = PRIVATE_KEY | ED25519;
}

mod typ {
    pub const PUBLIC_KEY: u8 = 6 << 3;
    pub const PRIVATE_KEY: u8 = 18 << 3;
}

mod public_key_alg {
    pub const ED25519: u8 = 0;
}

// TODO: Could encode and decode, and the functions upstream that call them, be
// const fn's?

fn encode(ver: u8, payload: &[u8]) -> String {
    let mut d: Vec<u8> = Vec::with_capacity(1 + payload.len() + 2);
    d.push(ver);
    d.extend_from_slice(&payload);
    d.extend_from_slice(&checksum(&d));
    base32::encode(base32::Alphabet::RFC4648 { padding: false }, &d)
}

fn decode(s: &str) -> Result<(u8, Vec<u8>), DecodeError> {
    // TODO: Look at what other base32 implementations are available, because
    // this one allows for decoding of non-canonical base32 strings, and doesn't
    // come with helpful methods for validating the length is canonical.
    let data = base32::decode(base32::Alphabet::RFC4648 { padding: false }, &s);
    if let Some(data) = data {
        let s_canonical_len = (data.len() * 8 + 4) / 5;
        if s.len() != s_canonical_len {
            return Err(DecodeError::Invalid);
        }
        if data.len() < 3 {
            return Err(DecodeError::Invalid);
        }
        let ver = data[0];
        let (data_without_crc, crc_actual) = data.split_at(data.len() - 2);
        let crc_expect = checksum(&data_without_crc);
        if crc_actual != crc_expect {
            return Err(DecodeError::Invalid);
        }
        let payload = &data_without_crc[1..];
        Ok((ver, payload.to_vec()))
    } else {
        Err(DecodeError::Invalid)
    }
}
