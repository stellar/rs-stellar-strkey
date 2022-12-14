use std::str::FromStr;

use crate::{
    convert::{decode, encode},
    error::DecodeError,
    seed_phrase, version,
};

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PrivateKey(pub [u8; 32]);

impl PrivateKey {
    pub fn to_string(&self) -> String {
        encode(version::PRIVATE_KEY_ED25519, &self.0)
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
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

impl PrivateKey {
    pub fn from_seed(seed: &[u8]) -> Result<Self, DecodeError> {
        Self::from_seed_and_path(seed, "")
    }

    pub fn from_seed_and_path(seed: &[u8], path: &str) -> Result<Self, DecodeError> {
        Self::from_payload(&from_seed_and_path(seed, path)?.key)
    }

    pub fn random_with_seed_phrase() -> Result<(String, Self), DecodeError> {
        let nm = seed_phrase::random(12)?;
        Ok((nm.to_string(), Self::from_seed(&nm.to_seed(""))?))
    }

    pub fn seeded_seed_phrase(seed: &[u8]) -> Result<(String, Self), DecodeError> {
        let nm = seed_phrase::from_seed(seed)?;
        Ok((nm.to_string(), Self::from_seed(&nm.to_seed(""))?))
    }

    pub fn from_seed_phrase(seed_phrase: &str) -> Result<Self, DecodeError> {
        Self::from_seed(&seed_phrase::to_seed(seed_phrase)?)
    }
}

impl FromStr for PrivateKey {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PrivateKey::from_string(s)
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    pub fn to_string(&self) -> String {
        encode(version::PUBLIC_KEY_ED25519, &self.0)
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
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

impl PublicKey {
    pub fn from_seed(seed: &[u8]) -> Result<Self, DecodeError> {
        Self::from_seed_and_path(seed, "")
    }

    pub fn from_seed_and_path(seed: &[u8], path: &str) -> Result<Self, DecodeError> {
        let p = from_seed_and_path(seed, path)?;
        Self::from_payload(&p.public_key()[1..])
    }

    pub fn from_seed_phrase(seed_phrase: &str) -> Result<Self, DecodeError> {
        Self::from_seed(&seed_phrase::to_seed(seed_phrase)?)
    }
}

impl FromStr for PublicKey {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PublicKey::from_string(s)
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct MuxedAccount {
    pub ed25519: [u8; 32],
    pub id: u64,
}

impl MuxedAccount {
    pub fn to_string(&self) -> String {
        let mut payload: [u8; 40] = [0; 40];
        let (ed25519, id) = payload.split_at_mut(32);
        ed25519.copy_from_slice(&self.ed25519);
        id.copy_from_slice(&self.id.to_be_bytes());
        encode(version::MUXED_ACCOUNT_ED25519, &payload)
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() < 40 {
            return Err(DecodeError::Invalid);
        }
        let (ed25519, id) = payload.split_at(32);
        Ok(Self {
            ed25519: ed25519.try_into().map_err(|_| DecodeError::Invalid)?,
            id: u64::from_be_bytes(id.try_into().map_err(|_| DecodeError::Invalid)?),
        })
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::MUXED_ACCOUNT_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl FromStr for MuxedAccount {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        MuxedAccount::from_string(s)
    }
}

/// Stores a signed payload ed25519 signer.
///
/// The payload must not have a size larger than u32::MAX.
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct SignedPayload {
    pub ed25519: [u8; 32],
    pub payload: Vec<u8>,
}

impl SignedPayload {
    /// Returns the strkey string for the signed payload signer.
    ///
    /// ### Panics
    ///
    /// When the payload is larger than u32::MAX.
    pub fn to_string(&self) -> String {
        let inner_payload_len = self.payload.len();
        let payload_len = 32 + 4 + inner_payload_len + (4 - inner_payload_len % 4) % 4;

        let inner_payload_len_u32: u32 = inner_payload_len
            .try_into()
            .expect("payload length larger than u32::MAX");

        let mut payload = vec![0; payload_len];
        payload[..32].copy_from_slice(&self.ed25519);
        payload[32..32 + 4].copy_from_slice(&(inner_payload_len_u32).to_be_bytes());
        payload[32 + 4..32 + 4 + inner_payload_len].copy_from_slice(&self.payload);

        encode(version::SIGNED_PAYLOAD_ED25519, &payload)
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        // 32-byte for the signer, 4-byte for the payload size, then either 4-byte for the
        // min or 64-byte for the max payload
        const MIN_LENGTH: usize = 32 + 4 + 4;
        const MAX_LENGTH: usize = 32 + 4 + 64;
        let payload_len = payload.len();
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&payload_len) {
            return Err(DecodeError::Invalid);
        }
        let inner_payload_len = u32::from_be_bytes(
            (&payload[32..32 + 4])
                .try_into()
                .map_err(|_| DecodeError::Invalid)?,
        );
        if (inner_payload_len + (4 - inner_payload_len % 4) % 4) as usize != payload_len - 32 - 4 {
            return Err(DecodeError::Invalid);
        }
        let ed25519 = (&payload[0..32])
            .try_into()
            .map_err(|_| DecodeError::Invalid)?;
        let inner_payload = &payload[32 + 4..32 + 4 + inner_payload_len as usize];

        Ok(Self {
            ed25519,
            payload: inner_payload.to_vec(),
        })
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::SIGNED_PAYLOAD_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl FromStr for SignedPayload {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SignedPayload::from_string(s)
    }
}

pub fn from_seed_and_path(seed: &[u8], path: &str) -> Result<slip10::Key, DecodeError> {
    slip10::derive_key_from_path(
        seed,
        slip10::Curve::Ed25519,
        &slip10::BIP32Path::from_str(path).map_err(|_| DecodeError::InvalidPath)?,
    )
    .map_err(|_| DecodeError::SeedPhrase)
}
