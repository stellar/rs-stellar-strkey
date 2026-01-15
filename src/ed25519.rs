use crate::{
    convert::{binary_len, decode, encode, encode_len},
    error::DecodeError,
    version,
};

use core::{
    fmt::{Debug, Display},
    str::FromStr,
};
use heapless::{String, Vec};

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
pub struct PrivateKey(pub [u8; 32]);

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PrivateKey(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl PrivateKey {
    pub(crate) const PAYLOAD_LEN: usize = 32;
    pub(crate) const BINARY_LEN: usize = binary_len(Self::PAYLOAD_LEN);
    pub(crate) const ENCODED_LEN: usize = encode_len(Self::BINARY_LEN);
    const _ASSERTS: () = {
        assert!(Self::BINARY_LEN == 35);
        assert!(Self::ENCODED_LEN == 56);
    };

    pub fn to_string(&self) -> String<{ Self::ENCODED_LEN }> {
        encode::<{ Self::BINARY_LEN }, { Self::ENCODED_LEN }>(version::PRIVATE_KEY_ED25519, &self.0)
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(ed25519) => Ok(Self(ed25519)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode::<{ Self::BINARY_LEN }, { Self::PAYLOAD_LEN }>(s)?;
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

#[cfg(feature = "serde-decoded")]
mod private_key_decoded_serde_impl {
    use super::*;
    use crate::decoded_json_format::Decoded;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::serde_as;

    #[serde_as]
    #[derive(Serialize)]
    #[serde(transparent)]
    struct DecodedBorrowed<'a>(#[serde_as(as = "serde_with::hex::Hex")] &'a [u8; 32]);

    #[serde_as]
    #[derive(Deserialize)]
    #[serde(transparent)]
    struct DecodedOwned(#[serde_as(as = "serde_with::hex::Hex")] [u8; 32]);

    impl Serialize for Decoded<&PrivateKey> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let Self(PrivateKey(bytes)) = self;
            DecodedBorrowed(bytes).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Decoded<PrivateKey> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let DecodedOwned(bytes) = DecodedOwned::deserialize(deserializer)?;
            Ok(Decoded(PrivateKey(bytes)))
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
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl PublicKey {
    pub(crate) const PAYLOAD_LEN: usize = 32;
    pub(crate) const BINARY_LEN: usize = binary_len(Self::PAYLOAD_LEN);
    pub(crate) const ENCODED_LEN: usize = encode_len(Self::BINARY_LEN);
    const _ASSERTS: () = {
        assert!(Self::BINARY_LEN == 35);
        assert!(Self::ENCODED_LEN == 56);
    };

    pub fn to_string(&self) -> String<{ Self::ENCODED_LEN }> {
        encode::<{ Self::BINARY_LEN }, { Self::ENCODED_LEN }>(version::PUBLIC_KEY_ED25519, &self.0)
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(ed25519) => Ok(Self(ed25519)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode::<{ Self::BINARY_LEN }, { Self::PAYLOAD_LEN }>(s)?;
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

#[cfg(feature = "serde-decoded")]
mod public_key_decoded_serde_impl {
    use super::*;
    use crate::decoded_json_format::Decoded;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::serde_as;

    #[serde_as]
    #[derive(Serialize)]
    #[serde(transparent)]
    struct DecodedBorrowed<'a>(#[serde_as(as = "serde_with::hex::Hex")] &'a [u8; 32]);

    #[serde_as]
    #[derive(Deserialize)]
    #[serde(transparent)]
    struct DecodedOwned(#[serde_as(as = "serde_with::hex::Hex")] [u8; 32]);

    impl Serialize for Decoded<&PublicKey> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let Self(PublicKey(bytes)) = self;
            DecodedBorrowed(bytes).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Decoded<PublicKey> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let DecodedOwned(bytes) = DecodedOwned::deserialize(deserializer)?;
            Ok(Decoded(PublicKey(bytes)))
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
        for b in &self.ed25519 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ", {}", self.id)?;
        write!(f, ")")
    }
}

impl MuxedAccount {
    pub(crate) const PAYLOAD_LEN: usize = 32 + 8; // ed25519 + id
    pub(crate) const BINARY_LEN: usize = binary_len(Self::PAYLOAD_LEN);
    pub(crate) const ENCODED_LEN: usize = encode_len(Self::BINARY_LEN);
    const _ASSERTS: () = {
        assert!(Self::BINARY_LEN == 43);
        assert!(Self::ENCODED_LEN == 69);
    };

    pub fn to_string(&self) -> String<{ Self::ENCODED_LEN }> {
        let mut payload: [u8; Self::PAYLOAD_LEN] = [0; Self::PAYLOAD_LEN];
        let (ed25519, id) = payload.split_at_mut(32);
        ed25519.copy_from_slice(&self.ed25519);
        id.copy_from_slice(&self.id.to_be_bytes());
        encode::<{ Self::BINARY_LEN }, { Self::ENCODED_LEN }>(
            version::MUXED_ACCOUNT_ED25519,
            &payload,
        )
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
        let (ver, payload) = decode::<{ Self::BINARY_LEN }, { Self::PAYLOAD_LEN }>(s)?;
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

#[cfg(feature = "serde-decoded")]
mod muxed_account_decoded_serde_impl {
    use super::*;
    use crate::decoded_json_format::Decoded;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::serde_as;

    #[serde_as]
    #[derive(Serialize)]
    struct DecodedBorrowed<'a> {
        #[serde_as(as = "serde_with::hex::Hex")]
        ed25519: &'a [u8; 32],
        id: u64,
    }

    #[serde_as]
    #[derive(Deserialize)]
    struct DecodedOwned {
        #[serde_as(as = "serde_with::hex::Hex")]
        ed25519: [u8; 32],
        id: u64,
    }

    impl Serialize for Decoded<&MuxedAccount> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let Self(MuxedAccount { ed25519, id }) = self;
            DecodedBorrowed { ed25519, id: *id }.serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Decoded<MuxedAccount> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let DecodedOwned { ed25519, id } = DecodedOwned::deserialize(deserializer)?;
            Ok(Decoded(MuxedAccount { ed25519, id }))
        }
    }
}

/// Stores a signed payload ed25519 signer.
///
/// The payload must not have a size larger than 64 bytes.
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
pub struct SignedPayload {
    pub ed25519: [u8; 32],
    pub payload: Vec<u8, 64>,
}

impl Debug for SignedPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SignedPayload(")?;
        for b in &self.ed25519 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ", ")?;
        for b in &self.payload {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl SignedPayload {
    // Max payload: 32 ed25519 + 4 len + 64 inner payload = 100
    pub(crate) const MAX_PAYLOAD_LEN: usize = 32 + 4 + 64;
    pub(crate) const MAX_BINARY_LEN: usize = binary_len(Self::MAX_PAYLOAD_LEN);
    pub(crate) const MAX_ENCODED_LEN: usize = encode_len(Self::MAX_BINARY_LEN);
    const _ASSERTS: () = {
        assert!(Self::MAX_PAYLOAD_LEN == 100);
        assert!(Self::MAX_BINARY_LEN == 103);
        assert!(Self::MAX_ENCODED_LEN == 165);
    };

    /// Returns the strkey string for the signed payload signer.
    pub fn to_string(&self) -> String<{ Self::MAX_ENCODED_LEN }> {
        let inner_payload_len = self.payload.len();
        let payload_len = 32 + 4 + inner_payload_len + (4 - inner_payload_len % 4) % 4;

        let inner_payload_len_u32: u32 = inner_payload_len as u32;

        // Max payload_len is 100 (32 + 4 + 64), use fixed array
        let mut payload = [0u8; Self::MAX_PAYLOAD_LEN];
        payload[..32].copy_from_slice(&self.ed25519);
        payload[32..32 + 4].copy_from_slice(&(inner_payload_len_u32).to_be_bytes());
        payload[32 + 4..32 + 4 + inner_payload_len].copy_from_slice(&self.payload);

        encode::<{ Self::MAX_BINARY_LEN }, { Self::MAX_ENCODED_LEN }>(
            version::SIGNED_PAYLOAD_ED25519,
            &payload[..payload_len],
        )
    }

    /// Decodes a signed payload from raw bytes.
    ///
    /// ### Errors
    ///
    /// If the payload is larger than 64 bytes.
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

        let mut payload = Vec::new();
        payload
            .extend_from_slice(inner_payload)
            .map_err(|_| DecodeError::Invalid)?;
        Ok(Self { ed25519, payload })
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode::<{ Self::MAX_BINARY_LEN }, { Self::MAX_PAYLOAD_LEN }>(s)?;
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

#[cfg(feature = "serde-decoded")]
mod signed_payload_decoded_serde_impl {
    use super::{SignedPayload, Vec};
    use crate::decoded_json_format::Decoded;
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::serde_as;

    #[serde_as]
    #[derive(Serialize)]
    struct DecodedBorrowed<'a> {
        #[serde_as(as = "serde_with::hex::Hex")]
        ed25519: &'a [u8; 32],
        #[serde_as(as = "serde_with::hex::Hex")]
        payload: &'a [u8],
    }

    #[serde_as]
    #[derive(Deserialize)]
    struct DecodedOwned {
        #[serde_as(as = "serde_with::hex::Hex")]
        ed25519: [u8; 32],
        #[serde_as(as = "serde_with::hex::Hex")]
        payload: alloc::vec::Vec<u8>,
    }

    impl Serialize for Decoded<&SignedPayload> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let Self(SignedPayload { ed25519, payload }) = self;
            DecodedBorrowed { ed25519, payload }.serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Decoded<SignedPayload> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let DecodedOwned { ed25519, payload } = DecodedOwned::deserialize(deserializer)?;
            let mut new_payload = Vec::new();
            new_payload
                .extend_from_slice(&payload)
                .map_err(|_| de::Error::custom("payload too large"))?;
            Ok(Decoded(SignedPayload {
                ed25519,
                payload: new_payload,
            }))
        }
    }
}
