use core::{
    fmt::{Debug, Display},
    str::FromStr,
};

use heapless::String as HeaplessString;

use crate::{
    convert::{binary_len, decode, encode, encode_len},
    error::DecodeError,
    version,
};

/// Define an enum that wraps multiple strkey kinds and dispatches
/// [`Display`](core::fmt::Display), [`FromStr`](core::str::FromStr), and
/// `Decoded` serde impls across the variants.
///
/// Internal macro: invocations must live inside the `stellar-strkey` crate
/// because the generated `Decoded<&Self>` Serialize impl would otherwise
/// violate Rust's orphan rule.
///
/// Each variant takes a wrapped type. The variant identifier is converted
/// to snake_case to form the JSON key used by the `Decoded` representation
/// (e.g. `PublicKeyEd25519` → `"public_key_ed25519"`).
macro_rules! strkey_enum {
    (
        $(#[$attr:meta])*
        $vis:vis enum $name:ident {
            $($variant:ident($ty:ty)),* $(,)?
        }
    ) => {
        $(#[$attr])*
        #[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
        $vis enum $name {
            $($variant($ty),)*
        }

        impl $name {
            pub fn from_string(s: &str) -> ::core::result::Result<Self, $crate::DecodeError> {
                Self::from_slice(s.as_bytes())
            }

            pub fn from_slice(s: &[u8]) -> ::core::result::Result<Self, $crate::DecodeError> {
                $(
                    if let ::core::result::Result::Ok(k) = <$ty>::from_slice(s) {
                        return ::core::result::Result::Ok(Self::$variant(k));
                    }
                )*
                ::core::result::Result::Err($crate::DecodeError::Invalid)
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match self {
                    $(Self::$variant(k) => ::core::fmt::Display::fmt(k, f),)*
                }
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = $crate::DecodeError;
            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                Self::from_string(s)
            }
        }

        #[cfg(feature = "serde")]
        impl ::serde::Serialize for $name {
            fn serialize<__S: ::serde::Serializer>(
                &self,
                serializer: __S,
            ) -> ::core::result::Result<__S::Ok, __S::Error> {
                serializer.collect_str(self)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<__D: ::serde::Deserializer<'de>>(
                deserializer: __D,
            ) -> ::core::result::Result<Self, __D::Error> {
                struct __V;
                impl<'de> ::serde::de::Visitor<'de> for __V {
                    type Value = $name;
                    fn expecting(
                        &self,
                        f: &mut ::core::fmt::Formatter<'_>,
                    ) -> ::core::fmt::Result {
                        f.write_str("a strkey string")
                    }
                    fn visit_str<__E: ::serde::de::Error>(
                        self,
                        s: &str,
                    ) -> ::core::result::Result<Self::Value, __E> {
                        <Self::Value as ::core::str::FromStr>::from_str(s)
                            .map_err(__E::custom)
                    }
                }
                deserializer.deserialize_str(__V)
            }
        }

        #[cfg(feature = "serde-decoded")]
        $crate::paste::paste! {
            impl ::serde::Serialize for $crate::Decoded<&$name> {
                fn serialize<__S: ::serde::Serializer>(
                    &self,
                    serializer: __S,
                ) -> ::core::result::Result<__S::Ok, __S::Error> {
                    use ::serde::ser::SerializeMap;
                    let mut map = serializer.serialize_map(::core::option::Option::Some(1))?;
                    match self.0 {
                        $(
                            $name::$variant(k) => {
                                map.serialize_entry(
                                    ::core::stringify!([< $variant:snake >]),
                                    &$crate::Decoded(k),
                                )?;
                            }
                        )*
                    }
                    map.end()
                }
            }

            impl<'de> ::serde::Deserialize<'de> for $crate::Decoded<$name> {
                fn deserialize<__D: ::serde::Deserializer<'de>>(
                    deserializer: __D,
                ) -> ::core::result::Result<Self, __D::Error> {
                    struct __V;
                    impl<'de> ::serde::de::Visitor<'de> for __V {
                        type Value = $crate::Decoded<$name>;
                        fn expecting(
                            &self,
                            f: &mut ::core::fmt::Formatter<'_>,
                        ) -> ::core::fmt::Result {
                            f.write_str("a strkey object")
                        }
                        fn visit_map<__M: ::serde::de::MapAccess<'de>>(
                            self,
                            mut map: __M,
                        ) -> ::core::result::Result<Self::Value, __M::Error> {
                            let key: ::std::string::String = map.next_key()?.ok_or_else(|| {
                                <__M::Error as ::serde::de::Error>::custom(
                                    "expected a variant key",
                                )
                            })?;
                            let value = match key.as_str() {
                                $(
                                    ::core::stringify!([< $variant:snake >]) => {
                                        let $crate::Decoded(inner) =
                                            map.next_value::<$crate::Decoded<$ty>>()?;
                                        $name::$variant(inner)
                                    },
                                )*
                                _ => {
                                    return ::core::result::Result::Err(
                                        <__M::Error as ::serde::de::Error>::unknown_variant(
                                            &key,
                                            &[
                                                $(::core::stringify!([< $variant:snake >]),)*
                                            ],
                                        ),
                                    );
                                }
                            };
                            if map.next_key::<::serde::de::IgnoredAny>()?.is_some() {
                                return ::core::result::Result::Err(
                                    <__M::Error as ::serde::de::Error>::custom(
                                        "expected exactly one variant key",
                                    ),
                                );
                            }
                            ::core::result::Result::Ok($crate::Decoded(value))
                        }
                    }
                    deserializer.deserialize_map(__V)
                }
            }
        }
    };
}

pub(crate) use strkey_enum;

strkey_enum! {
    /// A decoded Stellar strkey of any supported non-secret kind.
    ///
    /// This enum intentionally does not include the `PrivateKeyEd25519`
    /// (`S…`) variant — that kind carries secret key material and is
    /// handled separately via [`ed25519::PrivateKey`](crate::ed25519::PrivateKey).
    pub enum Strkey {
        PublicKeyEd25519(crate::ed25519::PublicKey),
        PreAuthTx(crate::PreAuthTx),
        HashX(crate::HashX),
        MuxedAccountEd25519(crate::ed25519::MuxedAccount),
        SignedPayloadEd25519(crate::ed25519::SignedPayload),
        Contract(crate::Contract),
        LiquidityPool(crate::LiquidityPool),
        ClaimableBalance(crate::ClaimableBalance),
    }
}

/// A pre-authorized transaction signer (`T...`).
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
        encode::<{ Self::PAYLOAD_LEN }, { Self::BINARY_LEN }, { Self::ENCODED_LEN }>(
            version::PRE_AUTH_TX,
            &self.0,
        )
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        Self::from_slice(s.as_bytes())
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, DecodeError> {
        let (ver, payload) = decode::<{ Self::PAYLOAD_LEN }, { Self::BINARY_LEN }>(s)?;
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

/// A hash-x signer (`X...`).
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
        encode::<{ Self::PAYLOAD_LEN }, { Self::BINARY_LEN }, { Self::ENCODED_LEN }>(
            version::HASH_X,
            &self.0,
        )
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        Self::from_slice(s.as_bytes())
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, DecodeError> {
        let (ver, payload) = decode::<{ Self::PAYLOAD_LEN }, { Self::BINARY_LEN }>(s)?;
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

/// A contract identifier (`C...`).
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
        encode::<{ Self::PAYLOAD_LEN }, { Self::BINARY_LEN }, { Self::ENCODED_LEN }>(
            version::CONTRACT,
            &self.0,
        )
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        Self::from_slice(s.as_bytes())
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, DecodeError> {
        let (ver, payload) = decode::<{ Self::PAYLOAD_LEN }, { Self::BINARY_LEN }>(s)?;
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

/// A liquidity pool identifier (`L...`).
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
        encode::<{ Self::PAYLOAD_LEN }, { Self::BINARY_LEN }, { Self::ENCODED_LEN }>(
            version::LIQUIDITY_POOL,
            &self.0,
        )
    }

    fn from_payload(payload: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(payload.try_into().map_err(|_| DecodeError::Invalid)?))
    }

    pub fn from_string(s: &str) -> Result<Self, DecodeError> {
        Self::from_slice(s.as_bytes())
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, DecodeError> {
        let (ver, payload) = decode::<{ Self::PAYLOAD_LEN }, { Self::BINARY_LEN }>(s)?;
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

/// A claimable balance identifier (`B...`).
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
                encode::<{ Self::PAYLOAD_LEN }, { Self::BINARY_LEN }, { Self::ENCODED_LEN }>(
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
        Self::from_slice(s.as_bytes())
    }

    pub fn from_slice(s: &[u8]) -> Result<Self, DecodeError> {
        let (ver, payload) = decode::<{ Self::PAYLOAD_LEN }, { Self::BINARY_LEN }>(s)?;
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
