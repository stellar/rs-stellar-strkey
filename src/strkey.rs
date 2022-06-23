use crate::crc::checksum;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum DecodeError {
    // TODO: Add meaningful errors for each problem that can occur.
    Invalid,
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Strkey {
    PublicKeyEd25519(StrkeyPublicKeyEd25519),
    PrivateKeyEd25519(StrkeyPrivateKeyEd25519),
    PreAuthTx(StrkeyPreAuthTx),
    HashX(StrkeyHashX),
    MuxedAccountEd25519(StrkeyMuxedAccountEd25519),
    SignedPayloadEd25519(StrkeySignedPayloadEd25519),
}

impl Strkey {
    pub fn to_string(&self) -> String {
        match self {
            Self::PublicKeyEd25519(x) => x.to_string(),
            Self::PrivateKeyEd25519(x) => x.to_string(),
            Self::PreAuthTx(x) => x.to_string(),
            Self::HashX(x) => x.to_string(),
            Self::MuxedAccountEd25519(x) => x.to_string(),
            Self::SignedPayloadEd25519(x) => x.to_string(),
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
            version::PRE_AUTH_TX => Ok(Self::PreAuthTx(StrkeyPreAuthTx::from_payload(&payload)?)),
            version::HASH_X => Ok(Self::HashX(StrkeyHashX::from_payload(&payload)?)),
            version::MUXED_ACCOUNT_ED25519 => Ok(Self::MuxedAccountEd25519(
                StrkeyMuxedAccountEd25519::from_payload(&payload)?,
            )),
            version::SIGNED_PAYLOAD_ED25519 => Ok(Self::SignedPayloadEd25519(
                StrkeySignedPayloadEd25519::from_payload(&payload)?,
            )),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
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

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
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

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct StrkeyMuxedAccountEd25519 {
    pub ed25519: [u8; 32],
    pub id: u64,
}

impl StrkeyMuxedAccountEd25519 {
    pub fn to_string(&self) -> String {
        let payload = {
            let mut payload: [u8; 40] = [0; 40];
            let (ed25519, id) = payload.split_at_mut(32);
            ed25519.copy_from_slice(&self.ed25519);
            id.copy_from_slice(&self.id.to_be_bytes());
            payload
        };
        encode(version::MUXED_ACCOUNT_ED25519, &payload)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match <[u8; 40]>::try_from(payload) {
            Ok(muxed) => {
                let (ed25519, id) = muxed.split_at(32);
                Ok(Self {
                    ed25519: ed25519.try_into().map_err(|_| DecodeError::Invalid)?,
                    id: u64::from_be_bytes(id.try_into().map_err(|_| DecodeError::Invalid)?),
                })
            }
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::MUXED_ACCOUNT_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct StrkeyPreAuthTx(pub [u8; 32]);

impl StrkeyPreAuthTx {
    pub fn to_string(&self) -> String {
        encode(version::PRE_AUTH_TX, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(pre_auth_tx) => Ok(Self(pre_auth_tx)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::PRE_AUTH_TX => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct StrkeyHashX(pub [u8; 32]);

impl StrkeyHashX {
    pub fn to_string(&self) -> String {
        encode(version::HASH_X, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(hash_x) => Ok(Self(hash_x)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::HASH_X => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct StrkeySignedPayloadEd25519 {
    pub ed25519: [u8; 32],
    pub payload: Vec<u8>,
}

impl StrkeySignedPayloadEd25519 {
    pub fn to_string(&self) -> String {
        let payload = {
            let inner_payload_len = self.payload.len();
            let payload_len = 32 + 4 + inner_payload_len + (4 - inner_payload_len % 4) % 4;
            let mut payload = vec![0; payload_len];
            let (ed25519, payload_len_bytes_inner_payload) = payload.split_at_mut(32);
            let (payload_len_bytes, inner_payload) =
                payload_len_bytes_inner_payload.split_at_mut(4);
            ed25519.copy_from_slice(&self.ed25519);
            payload_len_bytes.copy_from_slice(&(inner_payload_len as u32).to_be_bytes());
            inner_payload[..inner_payload_len].copy_from_slice(&self.payload);
            payload
        };
        encode(version::SIGNED_PAYLOAD_ED25519, &payload)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match Vec::try_from(payload) {
            Ok(signed_payload) => {
                let payload_len = signed_payload.len();
                // 32-byte for the signer, 4-byte for the payload size, then either 4-byte for the
                // min or 64-byte for the max payload
                if payload_len < 32 + 4 + 4 || payload_len > 32 + 4 + 64 {
                    return Err(DecodeError::Invalid);
                }
                let inner_payload_len = u32::from_be_bytes(
                    (&signed_payload[32..32 + 4])
                        .try_into()
                        .map_err(|_| DecodeError::Invalid)?,
                );
                if (inner_payload_len + (4 - inner_payload_len % 4) % 4) as usize
                    != payload_len - 32 - 4
                {
                    return Err(DecodeError::Invalid);
                }

                let ed25519 = (&signed_payload[0..32])
                    .try_into()
                    .map_err(|_| DecodeError::Invalid)?;
                let inner_payload = &signed_payload[32 + 4..32 + 4 + inner_payload_len as usize];

                Ok(Self {
                    ed25519: ed25519,
                    payload: inner_payload.to_vec(),
                })
            }
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::SIGNED_PAYLOAD_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

mod version {
    use super::public_key_alg::*;
    use super::typ;

    pub const PUBLIC_KEY_ED25519: u8 = typ::PUBLIC_KEY | ED25519;
    pub const PRIVATE_KEY_ED25519: u8 = typ::PRIVATE_KEY | ED25519;
    pub const MUXED_ACCOUNT_ED25519: u8 = typ::MUXED_ACCOUNT | ED25519;
    pub const PRE_AUTH_TX: u8 = typ::PRE_AUTH_TX;
    pub const HASH_X: u8 = typ::HASH_X;
    pub const SIGNED_PAYLOAD_ED25519: u8 = typ::SIGNED_PAYLOAD | ED25519;
}

mod typ {
    pub const PUBLIC_KEY: u8 = 6 << 3;
    pub const PRIVATE_KEY: u8 = 18 << 3;
    pub const MUXED_ACCOUNT: u8 = 12 << 3;
    pub const PRE_AUTH_TX: u8 = 19 << 3;
    pub const HASH_X: u8 = 23 << 3;
    pub const SIGNED_PAYLOAD: u8 = 15 << 3;
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
