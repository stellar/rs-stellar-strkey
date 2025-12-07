use alloc::{format, string::String};
use core::{
    fmt::{Debug, Display},
    str::FromStr,
};

use crate::{
    convert::{decode, encode},
    ed25519,
    error::DecodeError,
    version,
};

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
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
    pub fn to_string(&self) -> String {
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
        let (ver, payload) = decode(s)?;
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
            version::LIQUIDITY_POOL => {
                Ok(Self::LiquidityPool(LiquidityPool::from_payload(&payload)?))
            }
            version::CLAIMABLE_BALANCE => Ok(Self::ClaimableBalance(
                ClaimableBalance::from_payload(&payload)?,
            )),
            _ => Err(DecodeError::Invalid),
        }
    }
}

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

#[cfg(feature = "serde")]
mod strkey_object_format {
    use super::*;
    use crate::object_format::ObjectFormat;
    use serde::{
        de::{self, MapAccess, Visitor},
        ser::SerializeMap,
        Deserialize, Deserializer, Serialize, Serializer,
    };

    impl Serialize for ObjectFormat<&Strkey> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut map = serializer.serialize_map(Some(1))?;
            match self.0 {
                Strkey::PublicKeyEd25519(key) => {
                    map.serialize_entry("public_key_ed25519", &ObjectFormat(key))?;
                }
                Strkey::PrivateKeyEd25519(key) => {
                    map.serialize_entry("private_key_ed25519", &ObjectFormat(key))?;
                }
                Strkey::PreAuthTx(key) => {
                    map.serialize_entry("pre_auth_tx", &ObjectFormat(key))?;
                }
                Strkey::HashX(key) => {
                    map.serialize_entry("hash_x", &ObjectFormat(key))?;
                }
                Strkey::MuxedAccountEd25519(key) => {
                    map.serialize_entry("muxed_account_ed25519", &ObjectFormat(key))?;
                }
                Strkey::SignedPayloadEd25519(key) => {
                    map.serialize_entry("signed_payload_ed25519", &ObjectFormat(key))?;
                }
                Strkey::Contract(key) => {
                    map.serialize_entry("contract", &ObjectFormat(key))?;
                }
                Strkey::LiquidityPool(key) => {
                    map.serialize_entry("liquidity_pool", &ObjectFormat(key))?;
                }
                Strkey::ClaimableBalance(key) => {
                    map.serialize_entry("claimable_balance", &ObjectFormat(key))?;
                }
            }
            map.end()
        }
    }

    impl<'de> Deserialize<'de> for ObjectFormat<Strkey> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct StrkeyVisitor;

            impl<'de> Visitor<'de> for StrkeyVisitor {
                type Value = ObjectFormat<Strkey>;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("a strkey object")
                }

                fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                    let key: &str = map
                        .next_key()?
                        .ok_or_else(|| de::Error::custom("expected a variant key"))?;

                    let strkey = match key {
                        "public_key_ed25519" => {
                            let ObjectFormat(inner) = map.next_value()?;
                            Strkey::PublicKeyEd25519(inner)
                        }
                        "private_key_ed25519" => {
                            let ObjectFormat(inner) = map.next_value()?;
                            Strkey::PrivateKeyEd25519(inner)
                        }
                        "pre_auth_tx" => {
                            let ObjectFormat(inner) = map.next_value()?;
                            Strkey::PreAuthTx(inner)
                        }
                        "hash_x" => {
                            let ObjectFormat(inner) = map.next_value()?;
                            Strkey::HashX(inner)
                        }
                        "muxed_account_ed25519" => {
                            let ObjectFormat(account) =
                                ObjectFormat::<ed25519::MuxedAccount>::deserialize(
                                    de::value::MapAccessDeserializer::new(map),
                                )?;
                            return Ok(ObjectFormat(Strkey::MuxedAccountEd25519(account)));
                        }
                        "signed_payload_ed25519" => {
                            let ObjectFormat(payload) =
                                ObjectFormat::<ed25519::SignedPayload>::deserialize(
                                    de::value::MapAccessDeserializer::new(map),
                                )?;
                            return Ok(ObjectFormat(Strkey::SignedPayloadEd25519(payload)));
                        }
                        "contract" => {
                            let ObjectFormat(inner) = map.next_value()?;
                            Strkey::Contract(inner)
                        }
                        "liquidity_pool" => {
                            let ObjectFormat(inner) = map.next_value()?;
                            Strkey::LiquidityPool(inner)
                        }
                        "claimable_balance" => {
                            let ObjectFormat(balance) =
                                ObjectFormat::<ClaimableBalance>::deserialize(
                                    de::value::MapAccessDeserializer::new(map),
                                )?;
                            return Ok(ObjectFormat(Strkey::ClaimableBalance(balance)));
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

                    Ok(ObjectFormat(strkey))
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

impl PreAuthTx {
    pub fn to_string(&self) -> String {
        encode(version::PRE_AUTH_TX, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::PRE_AUTH_TX => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

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

#[cfg(feature = "serde")]
mod pre_auth_tx_object_format {
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

    impl Serialize for ObjectFormat<&PreAuthTx> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let Self(PreAuthTx(bytes)) = self;
            Shadow(bytes).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for ObjectFormat<PreAuthTx> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let ShadowOwned(bytes) = ShadowOwned::deserialize(deserializer)?;
            Ok(ObjectFormat(PreAuthTx(bytes)))
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

impl HashX {
    pub fn to_string(&self) -> String {
        encode(version::HASH_X, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::HASH_X => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

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

#[cfg(feature = "serde")]
mod hash_x_object_format {
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

    impl Serialize for ObjectFormat<&HashX> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let Self(HashX(bytes)) = self;
            Shadow(bytes).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for ObjectFormat<HashX> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let ShadowOwned(bytes) = ShadowOwned::deserialize(deserializer)?;
            Ok(ObjectFormat(HashX(bytes)))
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

impl Contract {
    pub fn to_string(&self) -> String {
        encode(version::CONTRACT, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::CONTRACT => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

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

#[cfg(feature = "serde")]
mod contract_object_format {
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

    impl Serialize for ObjectFormat<&Contract> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let Self(Contract(bytes)) = self;
            Shadow(bytes).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for ObjectFormat<Contract> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let ShadowOwned(bytes) = ShadowOwned::deserialize(deserializer)?;
            Ok(ObjectFormat(Contract(bytes)))
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

impl LiquidityPool {
    pub fn to_string(&self) -> String {
        encode(version::LIQUIDITY_POOL, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode(s)?;
        match ver {
            version::LIQUIDITY_POOL => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for LiquidityPool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl FromStr for LiquidityPool {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        LiquidityPool::from_string(s)
    }
}

#[cfg(feature = "serde")]
mod liquidity_pool_object_format {
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

    impl Serialize for ObjectFormat<&LiquidityPool> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let Self(LiquidityPool(bytes)) = self;
            Shadow(bytes).serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for ObjectFormat<LiquidityPool> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let ShadowOwned(bytes) = ShadowOwned::deserialize(deserializer)?;
            Ok(ObjectFormat(LiquidityPool(bytes)))
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
                write!(
                    f,
                    "V0({})",
                    &v0.iter().map(|b| format!("{b:02x}")).collect::<String>()
                )?;
            }
        }
        write!(f, ")")?;
        Ok(())
    }
}

impl ClaimableBalance {
    pub fn to_string(&self) -> String {
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
        let (ver, payload) = decode(s)?;
        match ver {
            version::CLAIMABLE_BALANCE => Self::from_payload(&payload),
            _ => Err(DecodeError::Invalid),
        }
    }
}

impl Display for ClaimableBalance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl FromStr for ClaimableBalance {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ClaimableBalance::from_string(s)
    }
}

#[cfg(feature = "serde")]
mod claimable_balance_object_format {
    use super::*;
    use crate::object_format::ObjectFormat;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::serde_as;

    #[serde_as]
    #[derive(Serialize)]
    #[serde(rename_all = "snake_case")]
    enum Shadow<'a> {
        V0(#[serde_as(as = "serde_with::hex::Hex")] &'a [u8; 32]),
    }

    #[serde_as]
    #[derive(Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum ShadowOwned {
        V0(#[serde_as(as = "serde_with::hex::Hex")] [u8; 32]),
    }

    impl Serialize for ObjectFormat<&ClaimableBalance> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            match self.0 {
                ClaimableBalance::V0(bytes) => Shadow::V0(bytes).serialize(serializer),
            }
        }
    }

    impl<'de> Deserialize<'de> for ObjectFormat<ClaimableBalance> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let shadow = ShadowOwned::deserialize(deserializer)?;
            Ok(ObjectFormat(match shadow {
                ShadowOwned::V0(bytes) => ClaimableBalance::V0(bytes),
            }))
        }
    }
}
