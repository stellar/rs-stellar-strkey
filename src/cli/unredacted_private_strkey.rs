//! CLI-only union of private-key strkey kinds.
//!
//! The library's [`Strkey`](crate::Strkey) enum intentionally excludes the
//! `PrivateKeyEd25519` variant. This type reintroduces it for CLI JSON I/O
//! while keeping the bytes gated behind [`Unredacted`].

use core::fmt;

use serde::{
    de::{self, MapAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{ed25519, Decoded, Unredacted};

pub enum UnredactedPrivateStrkey {
    PrivateKeyEd25519(Unredacted<ed25519::PrivateKey>),
}

impl Serialize for Decoded<&UnredactedPrivateStrkey> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            UnredactedPrivateStrkey::PrivateKeyEd25519(unredacted) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("private_key_ed25519", &Decoded(Unredacted(&unredacted.0)))?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Decoded<UnredactedPrivateStrkey> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Decoded<UnredactedPrivateStrkey>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(r#"a {"private_key_ed25519": "<hex>"} object"#)
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let key: String = map
                    .next_key()?
                    .ok_or_else(|| de::Error::custom("expected a variant key"))?;
                if key != "private_key_ed25519" {
                    return Err(de::Error::unknown_variant(&key, &["private_key_ed25519"]));
                }
                let Decoded(unredacted) =
                    map.next_value::<Decoded<Unredacted<ed25519::PrivateKey>>>()?;
                if map.next_key::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("expected exactly one variant key"));
                }
                Ok(Decoded(UnredactedPrivateStrkey::PrivateKeyEd25519(
                    unredacted,
                )))
            }
        }
        deserializer.deserialize_map(V)
    }
}
