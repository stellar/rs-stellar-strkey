use crate::crc::checksum;
use num_enum::TryFromPrimitive;
use std::convert::TryFrom;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DecodeError {
    // TODO: Add meaningful errors for each problem that can occur.
    Invalid,
}

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub enum Strkey {
    PublicKeyEd25519([u8; 32]),
    PrivateKeyEd25519([u8; 32]),
}

impl Strkey {
    pub fn to_string(&self) -> String {
        match self {
            Self::PublicKeyEd25519(bs) => encode(Version::PublicKeyEd25519, bs),
            Self::PrivateKeyEd25519(bs) => encode(Version::PrivateKeyEd25519, bs),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        let payload_slice = match <[u8; 32]>::try_from(payload) {
            Ok(bs) => bs,
            Err(_) => return Err(DecodeError::Invalid),
        };
        match ver {
            Version::PublicKeyEd25519 => Ok(Self::PublicKeyEd25519(payload_slice)),
            Version::PrivateKeyEd25519 => Ok(Self::PrivateKeyEd25519(payload_slice)),
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
pub struct PublicKeyEd25519(pub [u8; 32]);

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, TryFromPrimitive)]
#[repr(u8)]
enum Version {
    PublicKeyEd25519 = typ::PUBLIC_KEY | public_key_alg::ED25519,
    PrivateKeyEd25519 = typ::PRIVATE_KEY | public_key_alg::ED25519,
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

fn encode(v: Version, payload: &[u8]) -> String {
    let mut d: Vec<u8> = Vec::with_capacity(1 + payload.len() + 2);
    d.push(v as u8);
    d.extend_from_slice(&payload);
    d.extend_from_slice(&checksum(&d));
    base32::encode(base32::Alphabet::RFC4648 { padding: false }, &d)
}

fn decode(s: &str) -> Result<(Version, Vec<u8>), DecodeError> {
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
        let ver = match Version::try_from(data[0]) {
            Ok(ver) => ver,
            Err(_) => return Err(DecodeError::Invalid),
        };
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
