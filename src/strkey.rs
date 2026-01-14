use crate::{
    convert::decode_to_slice,
    ed25519,
    error::{DecodeError, EncodeError},
    version,
};

#[cfg(feature = "alloc")]
use crate::convert::encode;

use core::{
    fmt::{Debug, Display},
    str::FromStr,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
pub enum Strkey {
    PublicKeyEd25519(ed25519::PublicKey),
    PrivateKeyEd25519(ed25519::PrivateKey),
    PreAuthTx(PreAuthTx),
    HashX(HashX),
    MuxedAccountEd25519(ed25519::MuxedAccount),
    SignedPayloadEd25519(ed25519::SignedPayload),
    Contract(Contract),
    LiquidityPool(LiquidityPool),
    ClaimableBalance(ClaimableBalance),
}

impl Strkey {
    /// Encodes the strkey to a string in the provided buffer.
    /// Returns the encoded string slice.
    pub fn to_str<'a>(&self, buf: &'a mut [u8]) -> Result<&'a str, EncodeError> {
        match self {
            Self::PublicKeyEd25519(x) => x.to_str(buf),
            Self::PrivateKeyEd25519(x) => x.to_str(buf),
            Self::PreAuthTx(x) => x.to_str(buf),
            Self::HashX(x) => x.to_str(buf),
            Self::MuxedAccountEd25519(x) => x.to_str(buf),
            Self::SignedPayloadEd25519(x) => x.to_str(buf),
            Self::Contract(x) => x.to_str(buf),
            Self::LiquidityPool(x) => x.to_str(buf),
            Self::ClaimableBalance(x) => x.to_str(buf),
        }
    }

    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> alloc::string::String {
        match self {
            Self::PublicKeyEd25519(x) => x.to_string(),
            Self::PrivateKeyEd25519(x) => x.to_string(),
            Self::PreAuthTx(x) => x.to_string(),
            Self::HashX(x) => x.to_string(),
            Self::MuxedAccountEd25519(x) => x.to_string(),
            Self::SignedPayloadEd25519(x) => x.to_string(),
            Self::Contract(x) => x.to_string(),
            Self::LiquidityPool(x) => x.to_string(),
            Self::ClaimableBalance(x) => x.to_string(),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut buf = [0u8; 128];
        let (ver, len) = decode_to_slice(s, &mut buf)?;
        let payload = &buf[..len];
        match ver {
            version::PUBLIC_KEY_ED25519 => Ok(Self::PublicKeyEd25519(
                ed25519::PublicKey::from_payload(payload)?,
            )),
            version::PRIVATE_KEY_ED25519 => Ok(Self::PrivateKeyEd25519(
                ed25519::PrivateKey::from_payload(payload)?,
            )),
            version::PRE_AUTH_TX => Ok(Self::PreAuthTx(PreAuthTx::from_payload(payload)?)),
            version::HASH_X => Ok(Self::HashX(HashX::from_payload(payload)?)),
            version::MUXED_ACCOUNT_ED25519 => Ok(Self::MuxedAccountEd25519(
                ed25519::MuxedAccount::from_payload(payload)?,
            )),
            version::SIGNED_PAYLOAD_ED25519 => Ok(Self::SignedPayloadEd25519(
                ed25519::SignedPayload::from_payload(payload)?,
            )),
            version::CONTRACT => Ok(Self::Contract(Contract::from_payload(payload)?)),
            version::LIQUIDITY_POOL => {
                Ok(Self::LiquidityPool(LiquidityPool::from_payload(payload)?))
            }
            version::CLAIMABLE_BALANCE => Ok(Self::ClaimableBalance(
                ClaimableBalance::from_payload(payload)?,
            )),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for Strkey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = [0u8; 176]; // base32 of 107 bytes = 172 chars (for SignedPayload max)
        let s = self.to_str(&mut buf).map_err(|_| core::fmt::Error)?;
        f.write_str(s)
    }
}

impl FromStr for Strkey {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Strkey::from_string(s)
    }
}

#[cfg(feature = "serde-decoded")]
mod strkey_decoded_serde_impl {
    use super::*;
    use crate::decoded_json_format::Decoded;
    use serde::{
        de::{self, MapAccess, Visitor},
        ser::SerializeMap,
        Deserialize, Deserializer, Serialize, Serializer,
    };

    impl Serialize for Decoded<&Strkey> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut map = serializer.serialize_map(Some(1))?;
            match self.0 {
                Strkey::PublicKeyEd25519(key) => {
                    map.serialize_entry("public_key_ed25519", &Decoded(key))?;
                }
                Strkey::PrivateKeyEd25519(key) => {
                    map.serialize_entry("private_key_ed25519", &Decoded(key))?;
                }
                Strkey::PreAuthTx(key) => {
                    map.serialize_entry("pre_auth_tx", &Decoded(key))?;
                }
                Strkey::HashX(key) => {
                    map.serialize_entry("hash_x", &Decoded(key))?;
                }
                Strkey::MuxedAccountEd25519(key) => {
                    map.serialize_entry("muxed_account_ed25519", &Decoded(key))?;
                }
                Strkey::SignedPayloadEd25519(key) => {
                    map.serialize_entry("signed_payload_ed25519", &Decoded(key))?;
                }
                Strkey::Contract(key) => {
                    map.serialize_entry("contract", &Decoded(key))?;
                }
                Strkey::LiquidityPool(key) => {
                    map.serialize_entry("liquidity_pool", &Decoded(key))?;
                }
                Strkey::ClaimableBalance(key) => {
                    map.serialize_entry("claimable_balance", &Decoded(key))?;
                }
            }
            map.end()
        }
    }

    impl<'de> Deserialize<'de> for Decoded<Strkey> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct StrkeyVisitor;

            impl<'de> Visitor<'de> for StrkeyVisitor {
                type Value = Decoded<Strkey>;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("a strkey object")
                }

                fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                    let key: &str = map
                        .next_key()?
                        .ok_or_else(|| de::Error::custom("expected a variant key"))?;

                    let strkey = match key {
                        "public_key_ed25519" => {
                            let Decoded(inner) = map.next_value()?;
                            Strkey::PublicKeyEd25519(inner)
                        }
                        "private_key_ed25519" => {
                            let Decoded(inner) = map.next_value()?;
                            Strkey::PrivateKeyEd25519(inner)
                        }
                        "pre_auth_tx" => {
                            let Decoded(inner) = map.next_value()?;
                            Strkey::PreAuthTx(inner)
                        }
                        "hash_x" => {
                            let Decoded(inner) = map.next_value()?;
                            Strkey::HashX(inner)
                        }
                        "muxed_account_ed25519" => {
                            let Decoded(inner) = map.next_value()?;
                            Strkey::MuxedAccountEd25519(inner)
                        }
                        "signed_payload_ed25519" => {
                            let Decoded(inner) = map.next_value()?;
                            Strkey::SignedPayloadEd25519(inner)
                        }
                        "contract" => {
                            let Decoded(inner) = map.next_value()?;
                            Strkey::Contract(inner)
                        }
                        "liquidity_pool" => {
                            let Decoded(inner) = map.next_value()?;
                            Strkey::LiquidityPool(inner)
                        }
                        "claimable_balance" => {
                            let Decoded(inner) = map.next_value()?;
                            Strkey::ClaimableBalance(inner)
                        }
                        _ => {
                            return Err(de::Error::unknown_variant(
                                key,
                                &[
                                    "public_key_ed25519",
                                    "private_key_ed25519",
                                    "pre_auth_tx",
                                    "hash_x",
                                    "muxed_account_ed25519",
                                    "signed_payload_ed25519",
                                    "contract",
                                    "liquidity_pool",
                                    "claimable_balance",
                                ],
                            ))
                        }
                    };

                    Ok(Decoded(strkey))
                }
            }

            deserializer.deserialize_map(StrkeyVisitor)
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
pub struct PreAuthTx(pub [u8; 32]);

impl Debug for PreAuthTx {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PreAuthTx(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl PreAuthTx {
    /// Encodes the pre-auth transaction to a strkey string in the provided buffer.
    /// Returns the encoded string slice.
    pub fn to_str<'a>(&self, buf: &'a mut [u8]) -> Result<&'a str, EncodeError> {
        let len = crate::convert::encode_to_slice(version::PRE_AUTH_TX, &self.0, buf)?;
        Ok(core::str::from_utf8(&buf[..len]).expect("base32 is valid utf8"))
    }

    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> alloc::string::String {
        encode(version::PRE_AUTH_TX, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut buf = [0u8; 128];
        let (ver, len) = decode_to_slice(s, &mut buf)?;
        match ver {
            version::PRE_AUTH_TX => Self::from_payload(&buf[..len]),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for PreAuthTx {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = [0u8; 64];
        let s = self.to_str(&mut buf).map_err(|_| core::fmt::Error)?;
        f.write_str(s)
    }
}

impl FromStr for PreAuthTx {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PreAuthTx::from_string(s)
    }
}

#[cfg(feature = "serde-decoded")]
mod pre_auth_tx_decoded_serde_impl {
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

    impl Serialize for Decoded<&PreAuthTx> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let Self(PreAuthTx(bytes)) = self;
            DecodedBorrowed(bytes).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Decoded<PreAuthTx> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let DecodedOwned(bytes) = DecodedOwned::deserialize(deserializer)?;
            Ok(Decoded(PreAuthTx(bytes)))
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
pub struct HashX(pub [u8; 32]);

impl Debug for HashX {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HashX(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl HashX {
    /// Encodes the hash-x to a strkey string in the provided buffer.
    /// Returns the encoded string slice.
    pub fn to_str<'a>(&self, buf: &'a mut [u8]) -> Result<&'a str, EncodeError> {
        let len = crate::convert::encode_to_slice(version::HASH_X, &self.0, buf)?;
        Ok(core::str::from_utf8(&buf[..len]).expect("base32 is valid utf8"))
    }

    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> alloc::string::String {
        encode(version::HASH_X, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut buf = [0u8; 128];
        let (ver, len) = decode_to_slice(s, &mut buf)?;
        match ver {
            version::HASH_X => Self::from_payload(&buf[..len]),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for HashX {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = [0u8; 64];
        let s = self.to_str(&mut buf).map_err(|_| core::fmt::Error)?;
        f.write_str(s)
    }
}

impl FromStr for HashX {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HashX::from_string(s)
    }
}

#[cfg(feature = "serde-decoded")]
mod hash_x_decoded_serde_impl {
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

    impl Serialize for Decoded<&HashX> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let Self(HashX(bytes)) = self;
            DecodedBorrowed(bytes).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Decoded<HashX> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let DecodedOwned(bytes) = DecodedOwned::deserialize(deserializer)?;
            Ok(Decoded(HashX(bytes)))
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
pub struct Contract(pub [u8; 32]);

impl Debug for Contract {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Contract(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl Contract {
    /// Encodes the contract to a strkey string in the provided buffer.
    /// Returns the encoded string slice.
    pub fn to_str<'a>(&self, buf: &'a mut [u8]) -> Result<&'a str, EncodeError> {
        let len = crate::convert::encode_to_slice(version::CONTRACT, &self.0, buf)?;
        Ok(core::str::from_utf8(&buf[..len]).expect("base32 is valid utf8"))
    }

    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> alloc::string::String {
        encode(version::CONTRACT, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut buf = [0u8; 128];
        let (ver, len) = decode_to_slice(s, &mut buf)?;
        match ver {
            version::CONTRACT => Self::from_payload(&buf[..len]),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for Contract {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = [0u8; 64];
        let s = self.to_str(&mut buf).map_err(|_| core::fmt::Error)?;
        f.write_str(s)
    }
}

impl FromStr for Contract {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Contract::from_string(s)
    }
}

#[cfg(feature = "serde-decoded")]
mod contract_decoded_serde_impl {
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

    impl Serialize for Decoded<&Contract> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let Self(Contract(bytes)) = self;
            DecodedBorrowed(bytes).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Decoded<Contract> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let DecodedOwned(bytes) = DecodedOwned::deserialize(deserializer)?;
            Ok(Decoded(Contract(bytes)))
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
pub struct LiquidityPool(pub [u8; 32]);

impl Debug for LiquidityPool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "LiquidityPool(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl LiquidityPool {
    /// Encodes the liquidity pool to a strkey string in the provided buffer.
    /// Returns the encoded string slice.
    pub fn to_str<'a>(&self, buf: &'a mut [u8]) -> Result<&'a str, EncodeError> {
        let len = crate::convert::encode_to_slice(version::LIQUIDITY_POOL, &self.0, buf)?;
        Ok(core::str::from_utf8(&buf[..len]).expect("base32 is valid utf8"))
    }

    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> alloc::string::String {
        encode(version::LIQUIDITY_POOL, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut buf = [0u8; 128];
        let (ver, len) = decode_to_slice(s, &mut buf)?;
        match ver {
            version::LIQUIDITY_POOL => Self::from_payload(&buf[..len]),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for LiquidityPool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = [0u8; 64];
        let s = self.to_str(&mut buf).map_err(|_| core::fmt::Error)?;
        f.write_str(s)
    }
}

impl FromStr for LiquidityPool {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        LiquidityPool::from_string(s)
    }
}

#[cfg(feature = "serde-decoded")]
mod liquidity_pool_decoded_serde_impl {
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

    impl Serialize for Decoded<&LiquidityPool> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let Self(LiquidityPool(bytes)) = self;
            DecodedBorrowed(bytes).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Decoded<LiquidityPool> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let DecodedOwned(bytes) = DecodedOwned::deserialize(deserializer)?;
            Ok(Decoded(LiquidityPool(bytes)))
        }
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde_with::SerializeDisplay, serde_with::DeserializeFromStr)
)]
pub enum ClaimableBalance {
    V0([u8; 32]),
}

impl Debug for ClaimableBalance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ClaimableBalance(")?;
        match self {
            Self::V0(v0) => {
                write!(f, "V0(")?;
                for b in v0 {
                    write!(f, "{b:02x}")?;
                }
                write!(f, ")")?;
            }
        }
        write!(f, ")")
    }
}

impl ClaimableBalance {
    /// Encodes the claimable balance to a strkey string in the provided buffer.
    /// Returns the encoded string slice.
    pub fn to_str<'a>(&self, buf: &'a mut [u8]) -> Result<&'a str, EncodeError> {
        match self {
            Self::V0(v0) => {
                // First byte is zero for v0
                let mut payload = [0; 33];
                payload[1..].copy_from_slice(v0);
                let len =
                    crate::convert::encode_to_slice(version::CLAIMABLE_BALANCE, &payload, buf)?;
                Ok(core::str::from_utf8(&buf[..len]).expect("base32 is valid utf8"))
            }
        }
    }

    #[cfg(feature = "alloc")]
    pub fn to_string(&self) -> alloc::string::String {
        match self {
            Self::V0(v0) => {
                // First byte is zero for v0
                let mut payload = [0; 33];
                payload[1..].copy_from_slice(v0);
                encode(version::CLAIMABLE_BALANCE, &payload)
            }
        }
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        match payload {
            // First byte is zero for v0
            [0, rest @ ..] => Ok(Self::V0(rest.try_into().map_err(|_| DecodeError::Invalid)?)),
            _ => Err(DecodeError::Invalid),
        }
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let mut buf = [0u8; 128];
        let (ver, len) = decode_to_slice(s, &mut buf)?;
        match ver {
            version::CLAIMABLE_BALANCE => Self::from_payload(&buf[..len]),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for ClaimableBalance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = [0u8; 64];
        let s = self.to_str(&mut buf).map_err(|_| core::fmt::Error)?;
        f.write_str(s)
    }
}

impl FromStr for ClaimableBalance {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ClaimableBalance::from_string(s)
    }
}

#[cfg(feature = "serde-decoded")]
mod claimable_balance_decoded_serde_impl {
    use super::*;
    use crate::decoded_json_format::Decoded;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::serde_as;

    #[serde_as]
    #[derive(Serialize)]
    #[serde(rename_all = "snake_case")]
    enum DecodedBorrowed<'a> {
        V0(#[serde_as(as = "serde_with::hex::Hex")] &'a [u8; 32]),
    }

    #[serde_as]
    #[derive(Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum DecodedOwned {
        V0(#[serde_as(as = "serde_with::hex::Hex")] [u8; 32]),
    }

    impl Serialize for Decoded<&ClaimableBalance> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            match self.0 {
                ClaimableBalance::V0(bytes) => DecodedBorrowed::V0(bytes).serialize(serializer),
            }
        }
    }

    impl<'de> Deserialize<'de> for Decoded<ClaimableBalance> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let decoded = DecodedOwned::deserialize(deserializer)?;
            Ok(Decoded(match decoded {
                DecodedOwned::V0(bytes) => ClaimableBalance::V0(bytes),
            }))
        }
    }
}
