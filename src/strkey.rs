use core::{
    fmt::Debug,
    str::FromStr,
};

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use core::fmt::Display;

use crate::convert::decode_len;
use crate::{
    convert::{decode, encode},
    ed25519,
    error::DecodeError,
    version,
};

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Strkey {
    PublicKeyEd25519(ed25519::PublicKey),
    PrivateKeyEd25519(ed25519::PrivateKey),
    PreAuthTx(PreAuthTx),
    HashX(HashX),
    MuxedAccountEd25519(ed25519::MuxedAccount),
    SignedPayloadEd25519(ed25519::SignedPayload),
    Contract(Contract),
}

impl Strkey {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        match self {
            Self::PublicKeyEd25519(x) => x.to_string(),
            Self::PrivateKeyEd25519(x) => x.to_string(),
            Self::PreAuthTx(x) => x.to_string(),
            Self::HashX(x) => x.to_string(),
            Self::MuxedAccountEd25519(x) => x.to_string(),
            Self::SignedPayloadEd25519(x) => x.to_string(),
            Self::Contract(x) => x.to_string(),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload = [0u8; 100];
        let len = decode_len(s.len())?;
        let mut payload = &mut payload[..len];
        let ver = decode(s.as_bytes(), &mut payload)?;

        match ver {
            version::PUBLIC_KEY_ED25519 => Ok(Self::PublicKeyEd25519(
                ed25519::PublicKey::from_payload(&payload)?,
            )),
            version::PRIVATE_KEY_ED25519 => Ok(Self::PrivateKeyEd25519(
                ed25519::PrivateKey::from_payload(&payload)?,
            )),
            version::PRE_AUTH_TX => Ok(Self::PreAuthTx(PreAuthTx::from_payload(&payload)?)),
            version::HASH_X => Ok(Self::HashX(HashX::from_payload(&payload)?)),
            version::MUXED_ACCOUNT_ED25519 => Ok(Self::MuxedAccountEd25519(
                ed25519::MuxedAccount::from_payload(&payload)?,
            )),
            version::SIGNED_PAYLOAD_ED25519 => Ok(Self::SignedPayloadEd25519(
                ed25519::SignedPayload::from_payload(&payload)?,
            )),
            version::CONTRACT => Ok(Self::Contract(Contract::from_payload(&payload)?)),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[cfg(feature = "alloc")]
impl Display for Strkey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl FromStr for Strkey {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Strkey::from_string(s)
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct PreAuthTx(pub [u8; 32]);

impl Debug for PreAuthTx {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PreAuthTx(")?;
        for &b in self.0.iter() {
            write!(f, "{:02x}", b)?;
        }

        write!(f, ")")?;
        Ok(())
    }
}

impl PreAuthTx {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        let mut output = [0; 56];
        self.to_encoded(&mut output);
        String::from_utf8(output.to_vec()).unwrap()
    }

    pub fn to_encoded(&self, output: &mut [u8]) {
        encode(version::PRE_AUTH_TX, &self.0, output);
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload = [0u8; 32];
        let ver = decode(s.as_bytes(), &mut payload)?;
        match ver {
            version::PRE_AUTH_TX => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[cfg(feature = "alloc")]
impl Display for PreAuthTx {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl FromStr for PreAuthTx {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PreAuthTx::from_string(s)
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct HashX(pub [u8; 32]);

impl Debug for HashX {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HashX(")?;
        for &b in self.0.iter() {
            write!(f, "{:02x}", b)?;
        }

        write!(f, ")")?;
        Ok(())
    }
}

impl HashX {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        let mut output = [0; 56];
        self.to_encoded(&mut output);
        String::from_utf8(output.to_vec()).unwrap()
    }

    pub fn to_encoded(&self, output: &mut [u8]) {
        encode(version::HASH_X, &self.0, output);
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload = [0u8; 32];
        let ver = decode(s.as_bytes(), &mut payload)?;
        match ver {
            version::HASH_X => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[cfg(feature = "alloc")]
impl Display for HashX {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl FromStr for HashX {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HashX::from_string(s)
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Contract(pub [u8; 32]);

impl Debug for Contract {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Contract(")?;
        for &b in self.0.iter() {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")?;
        Ok(())
    }
}

impl Contract {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        let mut output = [0; 56];
        self.to_encoded(&mut output);
        String::from_utf8(output.to_vec()).unwrap()
    }

    pub fn to_encoded(&self, output: &mut [u8]) {
        encode(version::CONTRACT, &self.0, output);
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload = [0u8; 32];
        let ver = decode(s.as_bytes(), &mut payload)?;
        match ver {
            version::CONTRACT => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[cfg(feature = "alloc")]
impl Display for Contract {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl FromStr for Contract {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Contract::from_string(s)
    }
}
