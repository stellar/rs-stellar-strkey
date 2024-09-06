use core::{fmt::Debug, str::FromStr};

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use core::fmt::Display;

use crate::convert::decode_len;
use crate::{
    convert::{decode, encode},
    ed25519,
    error::DecodeError,
    typ, version,
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

// TODO: add a trait?
// pub trait StrkeyTrait: Sized + Debug {
//     #[cfg(feature = "alloc")]
//     fn to_string(&self) -> String;
//     fn to_encoded(&self, output: &mut [u8]);
//     fn encoded_len(&self) -> usize;
//     fn from_string(s: &str) -> Result<Self, DecodeError>;
// }

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

    pub fn to_encoded(&self, output: &mut [u8]) {
        match self {
            Self::PublicKeyEd25519(x) => x.to_encoded(output),
            Self::PrivateKeyEd25519(x) => x.to_encoded(output),
            Self::PreAuthTx(x) => x.to_encoded(output),
            Self::HashX(x) => x.to_encoded(output),
            Self::MuxedAccountEd25519(x) => x.to_encoded(output),
            Self::SignedPayloadEd25519(x) => x.to_encoded(output),
            Self::Contract(x) => x.to_encoded(output),
        }
    }

    pub fn encoded_len(&self) -> usize {
        match self {
            Strkey::PublicKeyEd25519(x) => x.encoded_len(),
            Strkey::PrivateKeyEd25519(x) => x.encoded_len(),
            Strkey::PreAuthTx(x) => x.encoded_len(),
            Strkey::HashX(x) => x.encoded_len(),
            Strkey::MuxedAccountEd25519(x) => x.encoded_len(),
            Strkey::SignedPayloadEd25519(x) => x.encoded_len(),
            Strkey::Contract(x) => x.encoded_len(),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload = [0u8; typ::MAX_PAYLOAD_LEN];
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
pub struct PreAuthTx(pub [u8; typ::RAW_PRE_AUTH_TX_LEN]);

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
        let mut output = [0; typ::ENCODED_PRE_AUTH_TX_LEN];
        self.to_encoded(&mut output);
        String::from_utf8(output.to_vec()).unwrap()
    }

    /// Returns the length of the encoded [PreAuthTx].
    ///
    /// # Note
    ///
    /// The encoded [PreAuthTx] length is always [`typ::ENCODED_PRE_AUTH_TX_LEN`] bytes.
    pub fn encoded_len(&self) -> usize {
        typ::ENCODED_PRE_AUTH_TX_LEN
    }

    /// Encodes the [PreAuthTx] into the provided buffer.
    ///
    /// # Panics
    ///
    /// If the output buffer's length is not equal to the encoded [PreAuthTx] length.
    pub fn to_encoded(&self, output: &mut [u8]) {
        encode(version::PRE_AUTH_TX, &self.0, output);
    }

    /// Creates a [PreAuthTx] from the raw payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - The raw payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is not a valid [PreAuthTx].
    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    /// Creates a [PreAuthTx] from the strkey encoded [PreAuthTx].
    ///
    /// # Arguments
    ///
    /// * `s` - The strkey encoded [PreAuthTx].
    ///
    /// # Errors
    ///
    /// Returns an error if the strkey is not a valid [PreAuthTx].
    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload = [0u8; typ::RAW_PRE_AUTH_TX_LEN];
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
pub struct HashX(pub [u8; typ::RAW_HASH_X_LEN]);

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
        let mut output = [0; typ::ENCODED_HASH_X_LEN];
        self.to_encoded(&mut output);
        String::from_utf8(output.to_vec()).unwrap()
    }

    /// Returns the length of the encoded [HashX].
    ///
    /// # Note
    ///
    /// The encoded [HashX] length is always [`typ::ENCODED_HASH_X_LEN`] bytes.
    pub fn encoded_len(&self) -> usize {
        typ::ENCODED_HASH_X_LEN
    }

    /// Encodes the [HashX] into the provided buffer.
    ///
    /// # Panics
    ///
    /// If the output buffer's length is not equal to the encoded [HashX] length.
    pub fn to_encoded(&self, output: &mut [u8]) {
        encode(version::HASH_X, &self.0, output);
    }

    /// Creates a [HashX] from the raw payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - The raw payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is not a valid [HashX].
    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    /// Creates a [HashX] from the strkey encoded [HashX].
    ///
    /// # Arguments
    ///
    /// * `s` - The strkey encoded [HashX].
    ///
    /// # Errors
    ///
    /// Returns an error if the strkey is not a valid [HashX].
    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload = [0u8; typ::RAW_HASH_X_LEN];
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
pub struct Contract(pub [u8; typ::RAW_CONTRACT_LEN]);

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
        let mut output = [0; typ::ENCODED_CONTRACT_LEN];
        self.to_encoded(&mut output);
        String::from_utf8(output.to_vec()).unwrap()
    }

    /// Returns the length of the encoded [Contract].
    ///
    /// # Note
    ///
    /// The encoded [Contract] length is always [`typ::ENCODED_CONTRACT_LEN`] bytes.
    pub fn encoded_len(&self) -> usize {
        typ::ENCODED_CONTRACT_LEN
    }

    /// Encodes the [Contract] into the provided buffer.
    ///
    /// # Panics
    ///
    /// If the output buffer's length is not equal to the encoded [Contract] length.
    pub fn to_encoded(&self, output: &mut [u8]) {
        encode(version::CONTRACT, &self.0, output);
    }

    /// Creates a [Contract] from the raw payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - The raw payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is not a valid [Contract].
    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    /// Creates a [Contract] from the strkey encoded [Contract].
    ///
    /// # Arguments
    ///
    /// * `s` - The strkey encoded [Contract].
    ///
    /// # Errors
    ///
    /// Returns an error if the strkey is not a valid [Contract].
    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload = [0u8; typ::RAW_CONTRACT_LEN];
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
