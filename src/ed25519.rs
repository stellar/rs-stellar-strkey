use crate::{
    convert::{decode, encode},
    error::DecodeError,
    version,
};

use alloc::{format, string::String, vec, vec::Vec};
use core::{
    fmt::{Debug, Display},
    str::FromStr,
};

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
pub struct PrivateKey(pub [u8; 32]);

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PrivateKey(")?;
        write!(
            f,
            "{}",
            &self
                .0
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )?;
        write!(f, ")")?;
        Ok(())
    }
}

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

impl Display for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl FromStr for PrivateKey {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PrivateKey::from_string(s)
    }
}

#[cfg(feature = "serde")]
mod private_key_object_format {
    use super::*;
    use crate::object_format::ObjectFormat;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::serde_as;

    #[serde_as]
    #[derive(Serialize)]
    #[serde(transparent)]
    struct Shadow<'a>(#[serde_as(as = "serde_with::hex::Hex")] &'a [u8; 32]);

    #[serde_as]
    #[derive(Deserialize)]
    #[serde(transparent)]
    struct ShadowOwned(#[serde_as(as = "serde_with::hex::Hex")] [u8; 32]);

    impl Serialize for ObjectFormat<&PrivateKey> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            Shadow(&self.0 .0).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for ObjectFormat<PrivateKey> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let shadow = ShadowOwned::deserialize(deserializer)?;
            Ok(ObjectFormat(PrivateKey(shadow.0)))
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
pub struct PublicKey(pub [u8; 32]);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PublicKey(")?;
        write!(
            f,
            "{}",
            &self
                .0
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )?;
        write!(f, ")")?;
        Ok(())
    }
}

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

impl Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl FromStr for PublicKey {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PublicKey::from_string(s)
    }
}

#[cfg(feature = "serde")]
mod public_key_object_format {
    use super::*;
    use crate::object_format::ObjectFormat;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::serde_as;

    #[serde_as]
    #[derive(Serialize)]
    #[serde(transparent)]
    struct Shadow<'a>(#[serde_as(as = "serde_with::hex::Hex")] &'a [u8; 32]);

    #[serde_as]
    #[derive(Deserialize)]
    #[serde(transparent)]
    struct ShadowOwned(#[serde_as(as = "serde_with::hex::Hex")] [u8; 32]);

    impl Serialize for ObjectFormat<&PublicKey> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            Shadow(&self.0 .0).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for ObjectFormat<PublicKey> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let shadow = ShadowOwned::deserialize(deserializer)?;
            Ok(ObjectFormat(PublicKey(shadow.0)))
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
pub struct MuxedAccount {
    pub ed25519: [u8; 32],
    pub id: u64,
}

impl Debug for MuxedAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MuxedAccount(")?;
        write!(
            f,
            "{}",
            &self
                .ed25519
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )?;
        write!(f, ", ")?;
        write!(f, "{}", self.id)?;
        write!(f, ")")?;
        Ok(())
    }
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

impl Display for MuxedAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl FromStr for MuxedAccount {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        MuxedAccount::from_string(s)
    }
}

#[cfg(feature = "serde")]
mod muxed_account_object_format {
    use super::*;
    use crate::object_format::ObjectFormat;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::serde_as;

    #[serde_as]
    #[derive(Serialize)]
    struct Shadow<'a> {
        #[serde_as(as = "serde_with::hex::Hex")]
        ed25519: &'a [u8; 32],
        id: u64,
    }

    #[serde_as]
    #[derive(Deserialize)]
    struct ShadowOwned {
        #[serde_as(as = "serde_with::hex::Hex")]
        ed25519: [u8; 32],
        id: u64,
    }

    impl Serialize for ObjectFormat<&MuxedAccount> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            Shadow {
                ed25519: &self.0.ed25519,
                id: self.0.id,
            }
            .serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for ObjectFormat<MuxedAccount> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let shadow = ShadowOwned::deserialize(deserializer)?;
            Ok(ObjectFormat(MuxedAccount {
                ed25519: shadow.ed25519,
                id: shadow.id,
            }))
        }
    }
}

/// Stores a signed payload ed25519 signer.
///
/// The payload must not have a size larger than u32::MAX.
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
pub struct SignedPayload {
    pub ed25519: [u8; 32],
    pub payload: Vec<u8>,
}

impl Debug for SignedPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SignedPayload(")?;
        write!(
            f,
            "{}",
            &self
                .ed25519
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )?;
        write!(f, ", ")?;
        write!(
            f,
            "{}",
            &self
                .payload
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )?;
        write!(f, ")")?;
        Ok(())
    }
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
        const MAX_INNER_PAYLOAD_LENGTH: u32 = 64;
        const MIN_LENGTH: usize = 32 + 4 + 4;
        const MAX_LENGTH: usize = 32 + 4 + (MAX_INNER_PAYLOAD_LENGTH as usize);
        let payload_len = payload.len();
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&payload_len) {
            return Err(DecodeError::Invalid);
        }

        // Decode ed25519 public key. 32 bytes.
        let mut offset = 0;
        let ed25519: [u8; 32] = payload
            .get(offset..offset + 32)
            .ok_or(DecodeError::Invalid)?
            .try_into()
            .map_err(|_| DecodeError::Invalid)?;
        offset += 32;

        // Decode inner payload length. 4 bytes.
        let inner_payload_len = u32::from_be_bytes(
            payload
                .get(offset..offset + 4)
                .ok_or(DecodeError::Invalid)?
                .try_into()
                .map_err(|_| DecodeError::Invalid)?,
        );
        offset += 4;

        // Check inner payload length is inside accepted range.
        if inner_payload_len > MAX_INNER_PAYLOAD_LENGTH {
            return Err(DecodeError::Invalid);
        }

        // Decode inner payload.
        let inner_payload = payload
            .get(offset..offset + inner_payload_len as usize)
            .ok_or(DecodeError::Invalid)?;
        offset += inner_payload_len as usize;

        // Calculate padding at end of inner payload. 0-3 bytes.
        let padding_len = (4 - inner_payload_len % 4) % 4;

        // Decode padding.
        let padding = payload
            .get(offset..offset + padding_len as usize)
            .ok_or(DecodeError::Invalid)?;
        offset += padding_len as usize;

        // Check padding is all zeros.
        if padding.iter().any(|b| *b != 0) {
            return Err(DecodeError::Invalid);
        }

        // Check that entire payload consumed.
        if offset != payload_len {
            return Err(DecodeError::Invalid);
        }

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

impl Display for SignedPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl FromStr for SignedPayload {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SignedPayload::from_string(s)
    }
}

#[cfg(feature = "serde")]
mod signed_payload_object_format {
    use super::*;
    use crate::object_format::ObjectFormat;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::serde_as;

    #[serde_as]
    #[derive(Serialize)]
    struct Shadow<'a> {
        #[serde_as(as = "serde_with::hex::Hex")]
        ed25519: &'a [u8; 32],
        #[serde_as(as = "serde_with::hex::Hex")]
        payload: &'a [u8],
    }

    #[serde_as]
    #[derive(Deserialize)]
    struct ShadowOwned {
        #[serde_as(as = "serde_with::hex::Hex")]
        ed25519: [u8; 32],
        #[serde_as(as = "serde_with::hex::Hex")]
        payload: Vec<u8>,
    }

    impl Serialize for ObjectFormat<&SignedPayload> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            Shadow {
                ed25519: &self.0.ed25519,
                payload: &self.0.payload,
            }
            .serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for ObjectFormat<SignedPayload> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let shadow = ShadowOwned::deserialize(deserializer)?;
            Ok(ObjectFormat(SignedPayload {
                ed25519: shadow.ed25519,
                payload: shadow.payload,
            }))
        }
    }
}
