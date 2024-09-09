use crate::{
    convert::{decode, encode},
    error::DecodeError,
    version,
};

use crate::convert::encode_len;
use core::{fmt::Debug, str::FromStr};

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use core::fmt::Display;

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrivateKey(pub [u8; 32]);

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PrivateKey(")?;
        for &b in self.0.iter() {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")?;
        Ok(())
    }
}

impl PrivateKey {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        let mut output = [0; 56];
        self.to_encoded(&mut output);
        String::from_utf8(output.to_vec()).unwrap()
    }

    pub fn encoded_len(&self) -> usize {
        56
    }

    /// Encodes the private key into the provided buffer.
    ///
    /// ### Panics
    ///
    /// If the buffer's length is not equal to the encoded private key length,
    /// which is 56 bytes.
    pub fn to_encoded(&self, output: &mut [u8]) {
        encode(version::PRIVATE_KEY_ED25519, &self.0, output);
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(ed25519) => Ok(Self(ed25519)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload = [0u8; 32];
        let ver = decode(s.as_bytes(), &mut payload)?;
        match ver {
            version::PRIVATE_KEY_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[cfg(feature = "alloc")]
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

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublicKey(pub [u8; 32]);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PublicKey(")?;
        for &b in self.0.iter() {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")?;
        Ok(())
    }
}

impl PublicKey {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        let mut output = [0; 56];
        self.to_encoded(&mut output);
        String::from_utf8(output.to_vec()).unwrap()
    }

    pub fn encoded_len(&self) -> usize {
        56
    }

    /// Encodes the public key into the provided buffer.
    ///
    /// ### Panics
    ///
    /// If the buffer's length is not equal to the encoded public key length,
    /// which is 56 bytes.
    pub fn to_encoded(&self, output: &mut [u8]) {
        encode(version::PUBLIC_KEY_ED25519, &self.0, output);
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(ed25519) => Ok(Self(ed25519)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload = [0u8; 32];

        let ver = decode(s.as_bytes(), &mut payload)?;
        match ver {
            version::PUBLIC_KEY_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[cfg(feature = "alloc")]
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

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MuxedAccount {
    pub ed25519: [u8; 32],
    pub id: u64,
}

impl Debug for MuxedAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MuxedAccount(")?;
        let mut first = true;
        for &b in self.ed25519.iter() {
            if !first {
                write!(f, "{:02x}", b)?;
            } else {
                write!(f, "{:02x}", b)?;
                first = false;
            }
        }
        write!(f, ", ")?;
        write!(f, "{}", self.id)?;
        write!(f, ")")?;
        Ok(())
    }
}

impl MuxedAccount {
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        let mut output = [0; 69];
        self.to_encoded(&mut output);
        String::from_utf8(output.to_vec()).unwrap()
    }

    pub fn encoded_len(&self) -> usize {
        69
    }

    /// Encodes the muxed account into the provided buffer.
    ///
    /// ### Panics
    ///
    /// If the buffer's length is not equal to the encoded muxed account length,
    /// which is 69 bytes.
    pub fn to_encoded(&self, output: &mut [u8]) {
        let mut payload: [u8; 40] = [0; 40];
        let (ed25519, id) = payload.split_at_mut(32);
        ed25519.copy_from_slice(&self.ed25519);
        id.copy_from_slice(&self.id.to_be_bytes());
        encode(version::MUXED_ACCOUNT_ED25519, &payload, output);
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
        let mut payload = [0u8; 40];
        let ver = decode(s.as_bytes(), &mut payload)?;
        match ver {
            version::MUXED_ACCOUNT_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[cfg(feature = "alloc")]
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

/// Stores a signed payload ed25519 signer.
///
/// The payload must not have a size larger than u32::MAX.
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct SignedPayload {
    pub ed25519: [u8; 32],
    pub payload: [u8; 64],
    pub payload_len: usize,
}

impl Debug for SignedPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MuxedAccount(")?;
        for &b in self.ed25519.iter() {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ", ")?;

        for i in 0..self.payload_len {
            write!(f, "{:02x}", self.payload[i])?;
        }

        write!(f, ")")?;
        Ok(())
    }
}

impl SignedPayload {
    /// Returns the strkey string for the signed payload signer.
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        let mut output = [0; 165];
        let encoded_len = self.encoded_len();
        self.to_encoded(&mut output[..encoded_len]);
        String::from_utf8(output[..encoded_len].to_vec()).unwrap()
    }

    pub fn encoded_len(&self) -> usize {
        let inner_payload_len = self.payload_len + (4 - self.payload_len % 4) % 4;
        encode_len(32 + 4 + inner_payload_len)
    }

    /// Encodes the signed payload into the provided buffer.
    ///
    /// ### Panics
    /// TODO
    pub fn to_encoded(&self, output: &mut [u8]) {
        let mut payload = [0u8; 32 + 4 + 64];
        let inner_payload_len = self.payload_len + (4 - self.payload_len % 4) % 4;
        payload[..32].copy_from_slice(&self.ed25519);
        payload[32..32 + 4].copy_from_slice(&(self.payload_len as u32).to_be_bytes());
        payload[32 + 4..].copy_from_slice(&self.payload);
        encode(
            version::SIGNED_PAYLOAD_ED25519,
            &payload[..32 + 4 + inner_payload_len],
            output,
        );
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

        let inner_payload_with_padding_len = inner_payload_len + (4 - inner_payload_len % 4) % 4;
        if payload_len != 32 + 4 + inner_payload_with_padding_len as usize {
            return Err(DecodeError::Invalid);
        }

        // Decode inner payload.
        let mut inner_payload = [0u8; 64];
        inner_payload[..inner_payload_len as usize]
            .copy_from_slice(&payload[offset..offset + inner_payload_len as usize]);
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
            payload: inner_payload,
            payload_len: inner_payload_len as usize,
        })
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload = [0u8; 100];
        let ver = decode(s.as_bytes(), &mut payload)?;
        match ver {
            version::SIGNED_PAYLOAD_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

#[cfg(feature = "alloc")]
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
