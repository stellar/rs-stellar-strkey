//! Unredacted wrapper for [`PrivateKey`].
//!
//! `PrivateKey` does not implement [`Display`] or `Serialize` directly. To
//! render the encoded strkey form or serialize via `serde`, callers wrap
//! the value in [`Unredacted`].
//!
//! `Debug` on the bare type emits the redacted form, and `Deserialize` is
//! implemented (input only — parsing a strkey string does not leak), so
//! neither requires a wrapper.

use core::fmt::{self, Debug, Display, Formatter};
use core::str::FromStr;

use heapless::String as HeaplessString;
use zeroize::Zeroizing;

use crate::{convert::encode_zeroizing, ed25519::PrivateKey, error::DecodeError, version};

/// Wraps a [`PrivateKey`] so it can be rendered or serialized in its full
/// strkey string form.
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Unredacted<T>(pub T);

impl Unredacted<&PrivateKey> {
    /// Encodes this private key to its strkey string form.
    ///
    /// # Zeroize
    ///
    /// The intermediate scratch buffers used during encoding are zeroed on
    /// drop, but the returned `String` itself is plain — its bytes are not
    /// zeroed when the value is dropped. Use
    /// [`write_string`](Self::write_string) for zeroizing.
    pub fn to_string(&self) -> HeaplessString<{ PrivateKey::ENCODED_LEN }> {
        let mut zeroizing: Zeroizing<HeaplessString<{ PrivateKey::ENCODED_LEN }>> =
            Zeroizing::new(HeaplessString::new());
        self.write_string(&mut zeroizing);
        let mut out: HeaplessString<{ PrivateKey::ENCODED_LEN }> = HeaplessString::new();
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
    pub fn write_string(&self, out: &mut Zeroizing<HeaplessString<{ PrivateKey::ENCODED_LEN }>>) {
        encode_zeroizing::<
            { PrivateKey::PAYLOAD_LEN },
            { PrivateKey::BINARY_LEN },
            { PrivateKey::ENCODED_LEN },
        >(version::PRIVATE_KEY_ED25519, &self.0 .0, out);
    }
}

impl Display for Unredacted<&PrivateKey> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut buf: Zeroizing<HeaplessString<{ PrivateKey::ENCODED_LEN }>> =
            Zeroizing::new(HeaplessString::new());
        self.write_string(&mut buf);
        f.write_str(&buf)
    }
}

impl Debug for Unredacted<&PrivateKey> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(")?;
        for b in &self.0 .0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

// --- Owned Display/Debug (delegate to borrowed form) ---

impl Display for Unredacted<PrivateKey> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&Unredacted(&self.0), f)
    }
}

impl Debug for Unredacted<PrivateKey> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(&Unredacted(&self.0), f)
    }
}

// --- FromStr ---

impl FromStr for Unredacted<PrivateKey> {
    type Err = DecodeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PrivateKey::from_string(s).map(Unredacted)
    }
}

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
