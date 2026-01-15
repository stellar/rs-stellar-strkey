use core::{
    fmt::{Debug, Display},
    str::FromStr,
};

use heapless::String as HeaplessString;

use crate::{
    convert::{binary_len, decode, encode, encode_len},
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
    // SignedPayload is the longest strkey type.
    const MAX_PAYLOAD_LEN: usize = ed25519::SignedPayload::MAX_PAYLOAD_LEN;
    const MAX_BINARY_LEN: usize = binary_len(Self::MAX_PAYLOAD_LEN);
    const MAX_ENCODED_LEN: usize = encode_len(Self::MAX_BINARY_LEN);
    const _ASSERTS: () = {
        assert!(Self::MAX_PAYLOAD_LEN == 100);
        assert!(Self::MAX_BINARY_LEN == 103);
        assert!(Self::MAX_ENCODED_LEN == 165);
        // Verify MAX_PAYLOAD_LEN >= all type payload lengths.
        assert!(Self::MAX_PAYLOAD_LEN >= ed25519::PrivateKey::PAYLOAD_LEN);
        assert!(Self::MAX_PAYLOAD_LEN >= ed25519::PublicKey::PAYLOAD_LEN);
        assert!(Self::MAX_PAYLOAD_LEN >= ed25519::MuxedAccount::PAYLOAD_LEN);
        assert!(Self::MAX_PAYLOAD_LEN >= ed25519::SignedPayload::MAX_PAYLOAD_LEN);
        assert!(Self::MAX_PAYLOAD_LEN >= PreAuthTx::PAYLOAD_LEN);
        assert!(Self::MAX_PAYLOAD_LEN >= HashX::PAYLOAD_LEN);
        assert!(Self::MAX_PAYLOAD_LEN >= Contract::PAYLOAD_LEN);
        assert!(Self::MAX_PAYLOAD_LEN >= LiquidityPool::PAYLOAD_LEN);
        assert!(Self::MAX_PAYLOAD_LEN >= ClaimableBalance::PAYLOAD_LEN);
        // Verify MAX_BINARY_LEN >= all type binary lengths.
        assert!(Self::MAX_BINARY_LEN >= ed25519::PrivateKey::BINARY_LEN);
        assert!(Self::MAX_BINARY_LEN >= ed25519::PublicKey::BINARY_LEN);
        assert!(Self::MAX_BINARY_LEN >= ed25519::MuxedAccount::BINARY_LEN);
        assert!(Self::MAX_BINARY_LEN >= ed25519::SignedPayload::MAX_BINARY_LEN);
        assert!(Self::MAX_BINARY_LEN >= PreAuthTx::BINARY_LEN);
        assert!(Self::MAX_BINARY_LEN >= HashX::BINARY_LEN);
        assert!(Self::MAX_BINARY_LEN >= Contract::BINARY_LEN);
        assert!(Self::MAX_BINARY_LEN >= LiquidityPool::BINARY_LEN);
        assert!(Self::MAX_BINARY_LEN >= ClaimableBalance::BINARY_LEN);
        // Verify MAX_ENCODED_LEN >= all type encoded lengths.
        assert!(Self::MAX_ENCODED_LEN >= ed25519::PrivateKey::ENCODED_LEN);
        assert!(Self::MAX_ENCODED_LEN >= ed25519::PublicKey::ENCODED_LEN);
        assert!(Self::MAX_ENCODED_LEN >= ed25519::MuxedAccount::ENCODED_LEN);
        assert!(Self::MAX_ENCODED_LEN >= ed25519::SignedPayload::MAX_ENCODED_LEN);
        assert!(Self::MAX_ENCODED_LEN >= PreAuthTx::ENCODED_LEN);
        assert!(Self::MAX_ENCODED_LEN >= HashX::ENCODED_LEN);
        assert!(Self::MAX_ENCODED_LEN >= Contract::ENCODED_LEN);
        assert!(Self::MAX_ENCODED_LEN >= LiquidityPool::ENCODED_LEN);
        assert!(Self::MAX_ENCODED_LEN >= ClaimableBalance::ENCODED_LEN);
    };

    pub fn to_string(&self) -> HeaplessString<{ Self::MAX_ENCODED_LEN }> {
        let mut s: HeaplessString<{ Self::MAX_ENCODED_LEN }> = HeaplessString::new();
        match self {
            Self::PublicKeyEd25519(x) => s.push_str(x.to_string().as_str()).unwrap(),
            Self::PrivateKeyEd25519(x) => s.push_str(x.to_string().as_str()).unwrap(),
            Self::PreAuthTx(x) => s.push_str(x.to_string().as_str()).unwrap(),
            Self::HashX(x) => s.push_str(x.to_string().as_str()).unwrap(),
            Self::MuxedAccountEd25519(x) => s.push_str(x.to_string().as_str()).unwrap(),
            Self::SignedPayloadEd25519(x) => s.push_str(x.to_string().as_str()).unwrap(),
            Self::Contract(x) => s.push_str(x.to_string().as_str()).unwrap(),
            Self::LiquidityPool(x) => s.push_str(x.to_string().as_str()).unwrap(),
            Self::ClaimableBalance(x) => s.push_str(x.to_string().as_str()).unwrap(),
        }
        s
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode::<{ Self::MAX_BINARY_LEN }, { Self::MAX_PAYLOAD_LEN }>(s)?;
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
    pub(crate) const PAYLOAD_LEN: usize = 32;
    pub(crate) const BINARY_LEN: usize = binary_len(Self::PAYLOAD_LEN);
    pub(crate) const ENCODED_LEN: usize = encode_len(Self::BINARY_LEN);
    const _ASSERTS: () = {
        assert!(Self::BINARY_LEN == 35);
        assert!(Self::ENCODED_LEN == 56);
    };

    pub fn to_string(&self) -> HeaplessString<{ Self::ENCODED_LEN }> {
        encode::<{ Self::BINARY_LEN }, { Self::ENCODED_LEN }>(version::PRE_AUTH_TX, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode::<{ Self::BINARY_LEN }, { Self::PAYLOAD_LEN }>(s)?;
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
    pub(crate) const PAYLOAD_LEN: usize = 32;
    pub(crate) const BINARY_LEN: usize = binary_len(Self::PAYLOAD_LEN);
    pub(crate) const ENCODED_LEN: usize = encode_len(Self::BINARY_LEN);
    const _ASSERTS: () = {
        assert!(Self::BINARY_LEN == 35);
        assert!(Self::ENCODED_LEN == 56);
    };

    pub fn to_string(&self) -> HeaplessString<{ Self::ENCODED_LEN }> {
        encode::<{ Self::BINARY_LEN }, { Self::ENCODED_LEN }>(version::HASH_X, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode::<{ Self::BINARY_LEN }, { Self::PAYLOAD_LEN }>(s)?;
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
    pub(crate) const PAYLOAD_LEN: usize = 32;
    pub(crate) const BINARY_LEN: usize = binary_len(Self::PAYLOAD_LEN);
    pub(crate) const ENCODED_LEN: usize = encode_len(Self::BINARY_LEN);
    const _ASSERTS: () = {
        assert!(Self::BINARY_LEN == 35);
        assert!(Self::ENCODED_LEN == 56);
    };

    pub fn to_string(&self) -> HeaplessString<{ Self::ENCODED_LEN }> {
        encode::<{ Self::BINARY_LEN }, { Self::ENCODED_LEN }>(version::CONTRACT, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode::<{ Self::BINARY_LEN }, { Self::PAYLOAD_LEN }>(s)?;
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
    pub(crate) const PAYLOAD_LEN: usize = 32;
    pub(crate) const BINARY_LEN: usize = binary_len(Self::PAYLOAD_LEN);
    pub(crate) const ENCODED_LEN: usize = encode_len(Self::BINARY_LEN);
    const _ASSERTS: () = {
        assert!(Self::BINARY_LEN == 35);
        assert!(Self::ENCODED_LEN == 56);
    };

    pub fn to_string(&self) -> HeaplessString<{ Self::ENCODED_LEN }> {
        encode::<{ Self::BINARY_LEN }, { Self::ENCODED_LEN }>(version::LIQUIDITY_POOL, &self.0)
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        let (ver, payload) = decode::<{ Self::BINARY_LEN }, { Self::PAYLOAD_LEN }>(s)?;
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
    // Payload: 1 version byte + 32 hash bytes = 33
    pub(crate) const PAYLOAD_LEN: usize = 1 + 32;
    pub(crate) const BINARY_LEN: usize = binary_len(Self::PAYLOAD_LEN);
    pub(crate) const ENCODED_LEN: usize = encode_len(Self::BINARY_LEN);
    const _ASSERTS: () = {
        assert!(Self::PAYLOAD_LEN == 33);
        assert!(Self::BINARY_LEN == 36);
        assert!(Self::ENCODED_LEN == 58);
    };

    pub fn to_string(&self) -> HeaplessString<{ Self::ENCODED_LEN }> {
        match self {
            Self::V0(v0) => {
                // First byte is zero for v0
                let mut payload = [0; Self::PAYLOAD_LEN];
                payload[1..].copy_from_slice(v0);
                encode::<{ Self::BINARY_LEN }, { Self::ENCODED_LEN }>(
                    version::CLAIMABLE_BALANCE,
                    &payload,
                )
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
        let (ver, payload) = decode::<{ Self::BINARY_LEN }, { Self::PAYLOAD_LEN }>(s)?;
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
