//! CLI-internal type that unifies [`Strkey`] and [`ed25519::PrivateKey`].
//!
//! The library's [`Strkey`] enum intentionally omits the `PrivateKeyEd25519`
//! variant. The CLI still supports `S…` strkeys (decode, encode, JSON
//! round-trip), so this module reintroduces the union for CLI use only,
//! preserving the historical JSON shape with `"private_key_ed25519"` as a
//! valid variant key.

use core::fmt::{self, Display, Formatter};
use std::str::FromStr;

use serde::{
    de::{self, MapAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{ed25519, DecodeError, Decoded, Strkey, Unredacted};

#[derive(Clone, Debug)]
pub enum AnyStrkey {
    Strkey(Strkey),
    PrivateKey(ed25519::PrivateKey),
}

impl FromStr for AnyStrkey {
    type Err = DecodeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Strkey::from_string(s) {
            Ok(k) => Ok(AnyStrkey::Strkey(k)),
            Err(strkey_err) => match ed25519::PrivateKey::from_string(s) {
                Ok(k) => Ok(AnyStrkey::PrivateKey(k)),
                Err(_) => Err(strkey_err),
            },
        }
    }
}

impl Display for AnyStrkey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AnyStrkey::Strkey(k) => Display::fmt(k, f),
            AnyStrkey::PrivateKey(k) => Display::fmt(&Unredacted(k), f),
        }
    }
}

impl Serialize for Decoded<&AnyStrkey> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            AnyStrkey::Strkey(k) => Decoded(k).serialize(serializer),
            AnyStrkey::PrivateKey(k) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("private_key_ed25519", &Decoded(Unredacted(k)))?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Decoded<AnyStrkey> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = Decoded<AnyStrkey>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a strkey object")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let key: &str = map
                    .next_key()?
                    .ok_or_else(|| de::Error::custom("expected a variant key"))?;

                let strkey = if key == "private_key_ed25519" {
                    let Decoded(Unredacted(inner)) =
                        map.next_value::<Decoded<Unredacted<ed25519::PrivateKey>>>()?;
                    AnyStrkey::PrivateKey(inner)
                } else {
                    // Delegate the remaining variants to the library's Strkey
                    // deserializer by replaying the key + value into a fresh
                    // single-entry map.
                    let value: serde_json::Value = map.next_value()?;
                    let mut wrapper = serde_json::Map::with_capacity(1);
                    wrapper.insert(key.to_owned(), value);
                    let Decoded(inner) = serde_json::from_value::<Decoded<Strkey>>(
                        serde_json::Value::Object(wrapper),
                    )
                    .map_err(de::Error::custom)?;
                    AnyStrkey::Strkey(inner)
                };

                if map.next_key::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("expected exactly one variant key"));
                }

                Ok(Decoded(strkey))
            }
        }

        deserializer.deserialize_map(V)
    }
}
