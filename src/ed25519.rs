use crate::{
    convert::{binary_len, decode, decode_zeroizing, encode, encode_len, encode_zeroizing},
    error::DecodeError,
    unredacted::Unredacted,
    version,
};

use core::{
    fmt::{Debug, Display},
    str::FromStr,
};
use heapless::{String, Vec};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// An Ed25519 private key (raw 32-byte seed).
///
/// # Zeroize
///
/// `PrivateKey` derives [`Zeroize`] and [`ZeroizeOnDrop`]: the 32 seed bytes
/// are overwritten with zeroes when a value is dropped.
/// [`from_string`](Self::from_string) and [`from_slice`](Self::from_slice)
/// zero their intermediate scratch buffers when they return.
/// [`Unredacted::write_string`] is the encoding path that wraps its scratch
/// buffers in [`Zeroizing`] and writes directly into a caller-provided
/// buffer, avoiding any return-value move.
///
/// [`Debug`] emits `PrivateKey([REDACTED])`. To render the encoded strkey
/// form, serialize via `serde`, or emit the raw seed bytes in any form,
/// wrap the value in [`Unredacted`] — see [`Unredacted`]'s doc for the full
/// list of paths that opt-in unlocks.
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde_with::DeserializeFromStr))]
pub struct PrivateKey(pub [u8; 32]);

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PrivateKey([REDACTED])")
    }
}

impl PrivateKey {
    pub(crate) const PAYLOAD_LEN: usize = 32;
    pub(crate) const BINARY_LEN: usize = binary_len(Self::PAYLOAD_LEN);
    pub const ENCODED_LEN: usize = encode_len(Self::BINARY_LEN);
    const _ASSERTS: () = {
        assert!(Self::BINARY_LEN == 35);
        assert!(Self::ENCODED_LEN == 56);
    };
}

impl Unredacted<&PrivateKey> {
    /// Encodes this private key to its strkey string form.
    ///
    /// # Zeroize
    ///
    /// The intermediate scratch buffers used during encoding are zeroed on
    /// drop, but the returned `String` itself is plain — its bytes are not
    /// zeroed when the value is dropped. Use
    /// [`write_string`](Self::write_string) for zeroizing.
    pub fn to_string(&self) -> String<{ PrivateKey::ENCODED_LEN }> {
        let mut zeroizing: Zeroizing<String<{ PrivateKey::ENCODED_LEN }>> =
            Zeroizing::new(String::new());
        self.write_string(&mut zeroizing);
        let mut out: String<{ PrivateKey::ENCODED_LEN }> = String::new();
        out.push_str(&zeroizing).unwrap();
        out
    }

    /// Encodes this private key to its strkey string form, writing the
    /// result into the caller-provided buffer.
    ///
    /// # Zeroize
    ///
    /// The intermediate scratch buffers used during encoding are wrapped in
    /// [`Zeroizing`] and zeroed on drop, and the encoded bytes are written
    /// directly into `out` rather than returned by value, so no copy is left
    /// on this method's stack frame.
    pub fn write_string(&self, out: &mut Zeroizing<String<{ PrivateKey::ENCODED_LEN }>>) {
        encode_zeroizing::<
            { PrivateKey::PAYLOAD_LEN },
            { PrivateKey::BINARY_LEN },
            { PrivateKey::ENCODED_LEN },
        >(version::PRIVATE_KEY_ED25519, &self.0 .0, out);
    }
}

impl PrivateKey {
    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(ed25519) => Ok(Self(ed25519)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        Self::from_slice(s.as_bytes())
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, DecodeError> {
        let mut payload: Zeroizing<Vec<u8, { Self::PAYLOAD_LEN }>> = Zeroizing::new(Vec::new());
        let ver = decode_zeroizing::<{ Self::PAYLOAD_LEN }, { Self::BINARY_LEN }>(s, &mut payload)?;
        match ver {
            version::PRIVATE_KEY_ED25519 => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }

    /// Borrows this private key as an [`Unredacted`] wrapper so it can be
    /// rendered via [`Display`] or [`to_string`](Unredacted::to_string), or
    /// serialized in its strkey string form.
    pub fn as_unredacted(&self) -> Unredacted<&Self> {
        Unredacted(self)
    }
}

impl Display for Unredacted<&PrivateKey> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf: Zeroizing<String<{ PrivateKey::ENCODED_LEN }>> = Zeroizing::new(String::new());
        self.write_string(&mut buf);
        f.write_str(&buf)
    }
}

impl Debug for Unredacted<&PrivateKey> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PrivateKey(")?;
        for b in &self.0 .0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl Display for Unredacted<PrivateKey> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&Unredacted(&self.0), f)
    }
}

impl Debug for Unredacted<PrivateKey> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&Unredacted(&self.0), f)
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
    use crate::{decoded_json_format::Decoded, unredacted::Unredacted};
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

    impl Serialize for Decoded<Unredacted<&PrivateKey>> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let Self(Unredacted(PrivateKey(bytes))) = self;
            DecodedBorrowed(bytes).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Decoded<Unredacted<PrivateKey>> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let DecodedOwned(bytes) = DecodedOwned::deserialize(deserializer)?;
            Ok(Decoded(Unredacted(PrivateKey(bytes))))
        }
    }
}

/// An ed25519 public key (`G...`).
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
    pub const ENCODED_LEN: usize = encode_len(Self::BINARY_LEN);
    const _ASSERTS: () = {
        assert!(Self::BINARY_LEN == 35);
        assert!(Self::ENCODED_LEN == 56);
    };

    pub fn to_string(&self) -> String<{ Self::ENCODED_LEN }> {
        encode::<{ Self::PAYLOAD_LEN }, { Self::BINARY_LEN }, { Self::ENCODED_LEN }>(
            version::PUBLIC_KEY_ED25519,
            &self.0,
        )
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload.try_into() {
            Ok(ed25519) => Ok(Self(ed25519)),
            Err(_) => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        Self::from_slice(s.as_bytes())
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, DecodeError> {
        let (ver, payload) = decode::<{ Self::PAYLOAD_LEN }, { Self::BINARY_LEN }>(s)?;
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

/// A muxed ed25519 account (`M...`).
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
    pub const ENCODED_LEN: usize = encode_len(Self::BINARY_LEN);
    const _ASSERTS: () = {
        assert!(Self::BINARY_LEN == 43);
        assert!(Self::ENCODED_LEN == 69);
    };

    pub fn to_string(&self) -> String<{ Self::ENCODED_LEN }> {
        let mut payload: [u8; Self::PAYLOAD_LEN] = [0; Self::PAYLOAD_LEN];
        let (ed25519, id) = payload.split_at_mut(32);
        ed25519.copy_from_slice(&self.ed25519);
        id.copy_from_slice(&self.id.to_be_bytes());
        encode::<{ Self::PAYLOAD_LEN }, { Self::BINARY_LEN }, { Self::ENCODED_LEN }>(
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
        Self::from_slice(s.as_bytes())
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, DecodeError> {
        let (ver, payload) = decode::<{ Self::PAYLOAD_LEN }, { Self::BINARY_LEN }>(s)?;
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
/// The inner payload must be 1..=64 bytes. Empty payloads are not valid per
/// stellar-core (SetOptionsOpFrame rejects them with SET_OPTIONS_BAD_SIGNER).
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
pub struct SignedPayload {
    ed25519: [u8; 32],
    payload: Vec<u8, 64>,
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
    pub const MAX_ENCODED_LEN: usize = encode_len(Self::MAX_BINARY_LEN);
    const MIN_INNER_PAYLOAD_LEN: usize = 1;
    const MAX_INNER_PAYLOAD_LEN: usize = 64;
    const MAX_INNER_PAYLOAD_LEN_U32: u32 = 64;
    const _ASSERTS: () = {
        assert!(Self::MAX_PAYLOAD_LEN == 100);
        assert!(Self::MAX_BINARY_LEN == 103);
        assert!(Self::MAX_ENCODED_LEN == 165);
        assert!(Self::MAX_INNER_PAYLOAD_LEN as u32 == Self::MAX_INNER_PAYLOAD_LEN_U32);
        assert!(Self::MAX_INNER_PAYLOAD_LEN_U32 as usize == Self::MAX_INNER_PAYLOAD_LEN);
    };

    /// Constructs a SignedPayload from an ed25519 public key and inner payload.
    ///
    /// ### Errors
    ///
    /// If the inner payload is empty or larger than 64 bytes.
    pub fn new(ed25519: [u8; 32], payload: &[u8]) -> Result<Self, DecodeError> {
        if !(Self::MIN_INNER_PAYLOAD_LEN..=Self::MAX_INNER_PAYLOAD_LEN).contains(&payload.len()) {
            return Err(DecodeError::Invalid);
        }
        let mut p = Vec::new();
        p.extend_from_slice(payload)
            .map_err(|_| DecodeError::Invalid)?;
        Ok(Self {
            ed25519,
            payload: p,
        })
    }

    /// Returns the ed25519 public key.
    pub fn ed25519(&self) -> &[u8; 32] {
        &self.ed25519
    }

    /// Returns the inner payload.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

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

        encode::<{ Self::MAX_PAYLOAD_LEN }, { Self::MAX_BINARY_LEN }, { Self::MAX_ENCODED_LEN }>(
            version::SIGNED_PAYLOAD_ED25519,
            &payload[..payload_len],
        )
    }

    /// Decodes a signed payload from raw bytes.
    ///
    /// ### Errors
    ///
    /// If the inner payload is empty or larger than 64 bytes, if the overall
    /// layout is malformed (wrong total length, truncated fields), or if the
    /// trailing padding bytes are not all zero.
    pub fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        // Min: 32-byte ed25519 key + 4-byte length prefix + 4 bytes (1-byte inner
        // payload padded to 4 per XDR). Empty inner payloads are not valid per
        // stellar-core (SetOptionsOpFrame rejects them with SET_OPTIONS_BAD_SIGNER).
        // Max: 32-byte ed25519 key + 4-byte length prefix + 64-byte inner payload.
        const MIN_LENGTH: usize = 32 + 4 + 4;
        const MAX_LENGTH: usize = 32 + 4 + SignedPayload::MAX_INNER_PAYLOAD_LEN;
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
        if inner_payload_len > Self::MAX_INNER_PAYLOAD_LEN_U32 {
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

        Self::new(ed25519, inner_payload)
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        Self::from_slice(s.as_bytes())
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, DecodeError> {
        let (ver, payload) = decode::<{ Self::MAX_PAYLOAD_LEN }, { Self::MAX_BINARY_LEN }>(s)?;
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
    use super::SignedPayload;
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
            let Self(sp) = self;
            DecodedBorrowed {
                ed25519: sp.ed25519(),
                payload: sp.payload(),
            }
            .serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Decoded<SignedPayload> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let DecodedOwned { ed25519, payload } = DecodedOwned::deserialize(deserializer)?;
            let sp = SignedPayload::new(ed25519, &payload)
                .map_err(|e| de::Error::custom(format_args!("invalid signed payload: {e}")))?;
            Ok(Decoded(sp))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PrivateKey;
    use heapless::String;
    use zeroize::Zeroizing;

    /// `write_string` must produce the same strkey bytes as `to_string`.
    /// Only the buffer-zeroization story differs.
    #[test]
    fn test_private_key_write_string_matches_to_string() {
        let key = PrivateKey([
            0x69, 0xa8, 0xc4, 0xcb, 0xb9, 0xf6, 0x4e, 0x8a, 0x07, 0x98, 0xf6, 0xe1, 0xac, 0x65,
            0xd0, 0x6c, 0x31, 0x62, 0x92, 0x90, 0x56, 0xbc, 0xf4, 0xcd, 0xb7, 0xd3, 0x73, 0x8d,
            0x18, 0x55, 0xf3, 0x63,
        ]);
        let mut buf: Zeroizing<String<{ PrivateKey::ENCODED_LEN }>> = Zeroizing::new(String::new());
        key.as_unredacted().write_string(&mut buf);
        assert_eq!(
            buf.as_str(),
            "SBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWHOKR"
        );
        assert_eq!(buf.as_str(), key.as_unredacted().to_string().as_str());
    }
}
