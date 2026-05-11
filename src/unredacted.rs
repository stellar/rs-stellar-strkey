//! Unredacted wrapper used to gate `Display` and `Serialize` on private-key
//! material.
//!
//! [`PrivateKey`](crate::ed25519::PrivateKey) does not implement
//! [`Display`](core::fmt::Display) or `Serialize` directly. Callers wrap the
//! value in [`Unredacted`] to render the encoded strkey form or serialize
//! via `serde`.

/// Wrapper that opts a value in to formatting or serialization that would
/// otherwise expose private-key bytes.
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Unredacted<T>(pub T);

#[cfg(feature = "serde")]
mod serde_impl {
    use super::Unredacted;
    use core::fmt::{self, Display};
    use core::marker::PhantomData;
    use core::str::FromStr;
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

    impl<T> Serialize for Unredacted<T>
    where
        Self: Display,
    {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.collect_str(self)
        }
    }

    impl<'de, T> Deserialize<'de> for Unredacted<T>
    where
        T: FromStr,
        T::Err: Display,
    {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct V<T>(PhantomData<T>);
            impl<'de, T> de::Visitor<'de> for V<T>
            where
                T: FromStr,
                T::Err: Display,
            {
                type Value = Unredacted<T>;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("a strkey string")
                }
                fn visit_str<E: de::Error>(self, s: &str) -> Result<Unredacted<T>, E> {
                    T::from_str(s).map(Unredacted).map_err(E::custom)
                }
            }
            deserializer.deserialize_str(V(PhantomData))
        }
    }
}
