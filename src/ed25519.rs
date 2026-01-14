use crate::{
    convert::{decode, encode, encode_to_fmt},
    error::DecodeError,
    version,
};

use alloc::{string::String, vec, vec::Vec};
use core::{
    fmt::{Debug, Display},
    str::FromStr,
};

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// Write bytes as hex to a formatter efficiently using a stack buffer.
fn write_hex(f: &mut core::fmt::Formatter<'_>, bytes: &[u8]) -> core::fmt::Result {
    // Use a fixed-size stack buffer for the hex string (64 bytes covers 32 input bytes)
    // For longer inputs, fall back to heap allocation
    if bytes.len() <= 32 {
        let mut buf = [0u8; 64];
        for (i, &b) in bytes.iter().enumerate() {
            buf[i * 2] = HEX_CHARS[(b >> 4) as usize];
            buf[i * 2 + 1] = HEX_CHARS[(b & 0xf) as usize];
        }
        // SAFETY: HEX_CHARS only contains ASCII characters
        let s = unsafe { core::str::from_utf8_unchecked(&buf[..bytes.len() * 2]) };
        f.write_str(s)
    } else {
        // Fallback for larger inputs (e.g., SignedPayload)
        let mut buf = alloc::vec![0u8; bytes.len() * 2];
        for (i, &b) in bytes.iter().enumerate() {
            buf[i * 2] = HEX_CHARS[(b >> 4) as usize];
            buf[i * 2 + 1] = HEX_CHARS[(b & 0xf) as usize];
        }
        // SAFETY: HEX_CHARS only contains ASCII characters
        let s = unsafe { core::str::from_utf8_unchecked(&buf) };
        f.write_str(s)
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
pub struct PrivateKey(pub [u8; 32]);

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PrivateKey(")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
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
        encode_to_fmt(version::PRIVATE_KEY_ED25519, &self.0, f)
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
        f.write_str("PublicKey(")?;
        write_hex(f, &self.0)?;
        f.write_str(")")
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
        encode_to_fmt(version::PUBLIC_KEY_ED25519, &self.0, f)
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
        f.write_str("MuxedAccount(")?;
        write_hex(f, &self.ed25519)?;
        write!(f, ", {})", self.id)
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
        let mut payload: [u8; 40] = [0; 40];
        let (ed25519, id) = payload.split_at_mut(32);
        ed25519.copy_from_slice(&self.ed25519);
        id.copy_from_slice(&self.id.to_be_bytes());
        encode_to_fmt(version::MUXED_ACCOUNT_ED25519, &payload, f)
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
    pub payload: Vec<u8>,
}

impl Debug for SignedPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SignedPayload(")?;
        write_hex(f, &self.ed25519)?;
        f.write_str(", ")?;
        write_hex(f, &self.payload)?;
        f.write_str(")")
    }
}

impl SignedPayload {
    /// Returns the strkey string for the signed payload signer.
    ///
    /// ### Panics
    ///
    /// When the payload is larger than 64 bytes.
    pub fn to_string(&self) -> String {
        let inner_payload_len = self.payload.len();
        assert!(inner_payload_len <= 64, "payload length larger than 64");
        let payload_len = 32 + 4 + inner_payload_len + (4 - inner_payload_len % 4) % 4;

        let inner_payload_len_u32: u32 = inner_payload_len as u32;

        let mut payload = vec![0; payload_len];
        payload[..32].copy_from_slice(&self.ed25519);
        payload[32..32 + 4].copy_from_slice(&(inner_payload_len_u32).to_be_bytes());
        payload[32 + 4..32 + 4 + inner_payload_len].copy_from_slice(&self.payload);

        encode(version::SIGNED_PAYLOAD_ED25519, &payload)
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
        if padding.iter().any(|&b| b != 0) {
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
        let inner_payload_len = self.payload.len();
        let payload_len = 32 + 4 + inner_payload_len + (4 - inner_payload_len % 4) % 4;

        let inner_payload_len_u32: u32 = inner_payload_len
            .try_into()
            .expect("payload length larger than u32::MAX");

        let mut payload = vec![0; payload_len];
        payload[..32].copy_from_slice(&self.ed25519);
        payload[32..32 + 4].copy_from_slice(&(inner_payload_len_u32).to_be_bytes());
        payload[32 + 4..32 + 4 + inner_payload_len].copy_from_slice(&self.payload);

        encode_to_fmt(version::SIGNED_PAYLOAD_ED25519, &payload, f)
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
        payload: Vec<u8>,
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
            Ok(Decoded(SignedPayload { ed25519, payload }))
        }
    }
}
