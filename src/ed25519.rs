use crate::{
    convert::{decode, encode},
    error::DecodeError,
    typ, version,
};

use crate::convert::encode_len;
use core::{fmt::Debug, str::FromStr};

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use core::fmt::Display;

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrivateKey(pub [u8; typ::RAW_PRIVATE_KEY_LEN]);

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
    /// Returns the [String] representation of the [PrivateKey].
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        let mut output = [0; typ::ENCODED_PRIVATE_KEY_LEN];
        self.to_encoded(&mut output);
        String::from_utf8(output.to_vec()).unwrap()
    }

    /// Returns the length of the encoded [PrivateKey].
    ///
    /// # Note
    ///
    /// The encoded [PrivateKey] length is always [`typ::ENCODED_PRIVATE_KEY_LEN`] bytes.
    pub fn encoded_len(&self) -> usize {
        typ::ENCODED_PRIVATE_KEY_LEN
    }

    /// Encodes the [PrivateKey] into the provided buffer.
    ///
    /// # Panics
    ///
    /// If the output buffer's length is not equal to the encoded [PrivateKey] length.
    pub fn to_encoded(&self, output: &mut [u8]) {
        encode(version::PRIVATE_KEY_ED25519, &self.0, output);
    }

    /// Creates a [PrivateKey] from the raw payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - The raw payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is not a valid [PrivateKey].
    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(ed25519) => Ok(Self(ed25519)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    /// Creates a [PrivateKey] from the strkey encoded [PrivateKey].
    ///
    /// # Arguments
    ///
    /// * `s` - The strkey encoded [PrivateKey].
    ///
    /// # Errors
    ///
    /// Returns an error if the strkey is not a valid [PrivateKey].
    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload = [0u8; typ::RAW_PRIVATE_KEY_LEN];
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
pub struct PublicKey(pub [u8; typ::RAW_PUBLIC_KEY_LEN]);

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
    /// Returns the [String] representation of the [PublicKey].
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        let mut output = [0; typ::ENCODED_PUBLIC_KEY_LEN];
        self.to_encoded(&mut output);
        String::from_utf8(output.to_vec()).unwrap()
    }

    /// Returns the length of the encoded [PublicKey].
    ///
    /// # Note
    ///
    /// The encoded [PublicKey] length is always [`typ::PUBLIC_KEY_ED25519`] bytes.
    pub fn encoded_len(&self) -> usize {
        typ::ENCODED_PUBLIC_KEY_LEN
    }

    /// Encodes the [PublicKey] into the provided buffer.
    ///
    /// # Panics
    ///
    /// If the output buffer's length is not equal to the encoded [PublicKey] length.
    pub fn to_encoded(&self, output: &mut [u8]) {
        encode(version::PUBLIC_KEY_ED25519, &self.0, output);
    }

    /// Creates a [PublicKey] from the raw payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - The raw payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is not a valid [PublicKey].
    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(ed25519) => Ok(Self(ed25519)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    /// Creates a [PublicKey] from the strkey encoded [PublicKey].
    ///
    /// # Arguments
    ///
    /// * `s` - The strkey encoded [PublicKey].
    ///
    /// # Errors
    ///
    /// Returns an error if the strkey is not a valid [PublicKey].
    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload = [0u8; typ::RAW_PUBLIC_KEY_LEN];

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
    pub ed25519: [u8; typ::RAW_PUBLIC_KEY_LEN],
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
    /// Returns the [String] representation of the [MuxedAccount].
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        let mut output = [0; typ::ENCODED_MUXED_ACCOUNT_LEN];
        self.to_encoded(&mut output);
        String::from_utf8(output.to_vec()).unwrap()
    }

    /// Returns the length of the encoded [MuxedAccount].
    ///
    /// # Note
    ///
    /// The encoded [MuxedAccount] length is always [`typ::ENCODED_MUXED_ACCOUNT_LEN`] bytes.
    pub fn encoded_len(&self) -> usize {
        typ::ENCODED_MUXED_ACCOUNT_LEN
    }

    /// Encodes the [MuxedAccount] into the provided buffer.
    ///
    /// # Panics
    ///
    /// If the output buffer's length is not equal to the encoded [MuxedAccount] length.
    pub fn to_encoded(&self, output: &mut [u8]) {
        let mut payload = [0u8; typ::RAW_MUXED_ACCOUNT_LEN];
        let (ed25519, id) = payload.split_at_mut(32);
        ed25519.copy_from_slice(&self.ed25519);
        id.copy_from_slice(&self.id.to_be_bytes());
        encode(version::MUXED_ACCOUNT_ED25519, &payload, output);
    }

    /// Creates a [MuxedAccount] from the raw payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - The raw payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is not a valid [MuxedAccount].
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

    /// Creates a [MuxedAccount] from the strkey encoded [MuxedAccount].
    ///
    /// # Arguments
    ///
    /// * `s` - The strkey encoded [MuxedAccount].
    ///
    /// # Errors
    ///
    /// Returns an error if the strkey is not a valid [MuxedAccount].
    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut payload = [0u8; typ::RAW_MUXED_ACCOUNT_LEN];
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
    pub ed25519: [u8; typ::RAW_PUBLIC_KEY_LEN],
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
    /// Returns the [String] representation of the [SignedPayload].
    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> String {
        let mut output = [0; typ::ENCODED_SIGNED_PAYLOAD_MAX_LEN];
        let encoded_len = self.encoded_len();
        self.to_encoded(&mut output[..encoded_len]);
        String::from_utf8(output[..encoded_len].to_vec()).unwrap()
    }

    /// Returns the length of the encoded [SignedPayload].
    ///
    /// # Note
    ///
    /// The encoded [SignedPayload] length is between [`typ::ENCODED_SIGNED_PAYLOAD_MIN_LEN`]
    /// and [`typ::ENCODED_SIGNED_PAYLOAD_MAX_LEN`] bytes.
    pub fn encoded_len(&self) -> usize {
        let inner_payload_len = self.payload_len + (4 - self.payload_len % 4) % 4;
        encode_len(32 + 4 + inner_payload_len)
    }

    /// Encodes the [SignedPayload] into the provided buffer.
    ///
    /// # Panics
    ///
    /// If the output buffer's length is not equal to the encoded [SignedPayload] length.
    pub fn to_encoded(&self, output: &mut [u8]) {
        let mut payload = [0u8; typ::RAW_SIGNED_PAYLOAD_MAX_LEN];
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

    /// Creates a [SignedPayload] from the raw payload.
    ///
    /// # Arguments
    ///
    /// * `payload` - The raw payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is not a valid [SignedPayload].
    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        // 32-byte for the signer, 4-byte for the payload size, then either 4-byte for the
        // min or 64-byte for the max payload, including padding.
        const MAX_INNER_PAYLOAD_LENGTH: u32 = 64;
        const MIN_INNER_PAYLOAD_LENGTH: u32 = 1;
        const MIN_LENGTH: usize = typ::RAW_SIGNED_PAYLOAD_MIN_LEN;
        const MAX_LENGTH: usize = typ::RAW_SIGNED_PAYLOAD_MAX_LEN;
        const PAYLOAD_SIZE_LEN: usize = 4;
        let payload_len = payload.len();
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&payload_len) {
            return Err(DecodeError::Invalid);
        }

        // Decode ed25519 public key. 32 bytes.
        let mut offset = 0;
        let ed25519: [u8; typ::RAW_PUBLIC_KEY_LEN] = payload
            .get(offset..offset + typ::RAW_PUBLIC_KEY_LEN)
            .ok_or(DecodeError::Invalid)?
            .try_into()
            .map_err(|_| DecodeError::Invalid)?;
        offset += typ::RAW_PUBLIC_KEY_LEN;

        // Decode inner payload length. 4 bytes.
        let inner_payload_len = u32::from_be_bytes(
            payload
                .get(offset..offset + PAYLOAD_SIZE_LEN)
                .ok_or(DecodeError::Invalid)?
                .try_into()
                .map_err(|_| DecodeError::Invalid)?,
        );
        offset += 4;

        // Check inner payload length is inside accepted range.
        if inner_payload_len > MAX_INNER_PAYLOAD_LENGTH
            || inner_payload_len < MIN_INNER_PAYLOAD_LENGTH
        {
            return Err(DecodeError::Invalid);
        }

        // Calculate padding at end of inner payload. 0-3 bytes.
        let padding_len = (4 - inner_payload_len % 4) % 4;
        let inner_payload_with_padding_len = inner_payload_len + padding_len;
        if payload_len
            != typ::RAW_PUBLIC_KEY_LEN + PAYLOAD_SIZE_LEN + inner_payload_with_padding_len as usize
        {
            return Err(DecodeError::Invalid);
        }

        // Decode inner payload.
        let mut inner_payload = [0u8; MAX_INNER_PAYLOAD_LENGTH as usize];
        inner_payload[..inner_payload_len as usize]
            .copy_from_slice(&payload[offset..offset + inner_payload_len as usize]);
        offset += inner_payload_len as usize;

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

    /// Creates a [SignedPayload] from the strkey encoded [SignedPayload].
    ///
    /// # Arguments
    ///
    /// * `s` - The strkey encoded [SignedPayload].
    ///
    /// # Errors
    ///
    /// Returns an error if the strkey is not a valid [SignedPayload].
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
