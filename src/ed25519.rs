use crate::{
    convert::{decode_to_slice, encode},
    error::DecodeError,
    version,
};

#[cfg(feature = "alloc")]
use alloc::string::String;

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
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// Max encoded length for 32-byte payload strkeys (1 ver + 32 payload + 2 crc = 35 bytes -> 56 base32 chars)
pub const STRKEY_LEN_32: usize = 56;
/// Max encoded length for 36-byte payload strkeys (ClaimableBalance)
pub const STRKEY_LEN_36: usize = 63;
/// Max encoded length for 40-byte payload strkeys (MuxedAccount)
pub const STRKEY_LEN_40: usize = 69;
/// Max encoded length for 104-byte payload strkeys (SignedPayload)
pub const STRKEY_LEN_104: usize = 172;

impl PrivateKey {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        encode(version::PRIVATE_KEY_ED25519, &self.0)
    }

    #[cfg(not(feature = "alloc"))]
    pub fn to_string(&self) -> heapless::String<STRKEY_LEN_32> {
        encode(version::PRIVATE_KEY_ED25519, &self.0)
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(ed25519) => Ok(Self(ed25519)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut buf = [0u8; 128];
        let (ver, len) = decode_to_slice(s, &mut buf)?;
        match ver {
            version::PRIVATE_KEY_ED25519 => Self::from_payload(&buf[..len]),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_string())
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
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        encode(version::PUBLIC_KEY_ED25519, &self.0)
    }

    #[cfg(not(feature = "alloc"))]
    pub fn to_string(&self) -> heapless::String<STRKEY_LEN_32> {
        encode(version::PUBLIC_KEY_ED25519, &self.0)
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(ed25519) => Ok(Self(ed25519)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut buf = [0u8; 128];
        let (ver, len) = decode_to_slice(s, &mut buf)?;
        match ver {
            version::PUBLIC_KEY_ED25519 => Self::from_payload(&buf[..len]),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_string())
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
        write!(f, ", ")?;
        write!(f, "{}", self.id)?;
        write!(f, ")")
    }
}

impl MuxedAccount {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        let mut payload: [u8; 40] = [0; 40];
        let (ed25519, id) = payload.split_at_mut(32);
        ed25519.copy_from_slice(&self.ed25519);
        id.copy_from_slice(&self.id.to_be_bytes());
        encode(version::MUXED_ACCOUNT_ED25519, &payload)
    }

    #[cfg(not(feature = "alloc"))]
    pub fn to_string(&self) -> heapless::String<STRKEY_LEN_40> {
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
        let mut buf = [0u8; 128];
        let (ver, len) = decode_to_slice(s, &mut buf)?;
        match ver {
            version::MUXED_ACCOUNT_ED25519 => Self::from_payload(&buf[..len]),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for MuxedAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_string())
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
    #[cfg(feature = "alloc")]
    pub payload: alloc::vec::Vec<u8>,
    #[cfg(not(feature = "alloc"))]
    pub payload: heapless::Vec<u8, 64>,
}

impl Debug for SignedPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SignedPayload(")?;
        for b in &self.ed25519 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ", ")?;
        for b in self.payload.as_slice() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl SignedPayload {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        let inner_payload_len = self.payload.len();
        let payload_len = 32 + 4 + inner_payload_len + (4 - inner_payload_len % 4) % 4;

        let inner_payload_len_u32: u32 = inner_payload_len
            .try_into()
            .expect("payload length larger than u32::MAX");

        let mut payload = alloc::vec![0; payload_len];
        payload[..32].copy_from_slice(&self.ed25519);
        payload[32..32 + 4].copy_from_slice(&inner_payload_len_u32.to_be_bytes());
        payload[32 + 4..32 + 4 + inner_payload_len].copy_from_slice(self.payload.as_slice());

        encode(version::SIGNED_PAYLOAD_ED25519, &payload)
    }

    #[cfg(not(feature = "alloc"))]
    pub fn to_string(&self) -> heapless::String<STRKEY_LEN_104> {
        let inner_payload_len = self.payload.len();
        let payload_len = 32 + 4 + inner_payload_len + (4 - inner_payload_len % 4) % 4;

        let inner_payload_len_u32: u32 = inner_payload_len
            .try_into()
            .expect("payload length larger than u32::MAX");

        let mut payload = [0u8; 104]; // Max: 32 + 4 + 64 + 4 padding = 104
        payload[..32].copy_from_slice(&self.ed25519);
        payload[32..32 + 4].copy_from_slice(&inner_payload_len_u32.to_be_bytes());
        payload[32 + 4..32 + 4 + inner_payload_len].copy_from_slice(self.payload.as_slice());

        encode(version::SIGNED_PAYLOAD_ED25519, &payload[..payload_len])
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

        #[cfg(feature = "alloc")]
        let payload = inner_payload.to_vec();
        #[cfg(not(feature = "alloc"))]
        let payload = heapless::Vec::from_slice(inner_payload).map_err(|_| DecodeError::Invalid)?;

        Ok(Self { ed25519, payload })
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut buf = [0u8; 128];
        let (ver, len) = decode_to_slice(s, &mut buf)?;
        match ver {
            version::SIGNED_PAYLOAD_ED25519 => Self::from_payload(&buf[..len]),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for SignedPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_string())
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
    use super::*;
    use crate::decoded_json_format::Decoded;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
            DecodedBorrowed {
                ed25519,
                payload: payload.as_slice(),
            }
            .serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Decoded<SignedPayload> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let DecodedOwned { ed25519, payload } = DecodedOwned::deserialize(deserializer)?;
            Ok(Decoded(SignedPayload { ed25519, payload }))
        }
    }
}
