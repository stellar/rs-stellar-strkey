//! Redacted and Unredacted wrappers for [`PrivateKey`] and [`Strkey`].
//!
//! `PrivateKey` and `Strkey` do not implement [`Display`] or `Serialize`
//! directly. To render the encoded strkey form or serialize via `serde`,
//! callers wrap a value in [`Unredacted`] (full strkey form) or
//! [`Redacted`] (redacts the private-key bytes — `Display` only; no
//! `Serialize`, since the redacted form cannot round-trip).
//!
//! `Debug` is implemented on the bare types (and emits the redacted form),
//! and `Deserialize` is implemented (input only — parsing a strkey string
//! does not leak), so neither requires a wrapper.
//!
//! For `PrivateKey`, [`Redacted`] writes only `S[REDACTED]`. For `Strkey`,
//! [`Redacted`] writes `S[REDACTED]` for the
//! [`PrivateKeyEd25519`](Strkey::PrivateKeyEd25519) variant and renders
//! every other variant in its full strkey form (none of those variants
//! contain secret material).

use core::fmt::{self, Debug, Display, Formatter, Write};
use core::str::FromStr;

use heapless::String as HeaplessString;
use zeroize::Zeroizing;

use crate::{convert::encode_zeroizing, ed25519::PrivateKey, error::DecodeError, version, Strkey};

/// Wraps a [`PrivateKey`] or [`Strkey`] so it can be rendered or serialized
/// in its full strkey form.
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Unredacted<T>(pub T);

/// Wraps a [`PrivateKey`] or [`Strkey`] so it can be rendered without
/// exposing private-key bytes. Render-only — no `Serialize` (the redacted
/// form cannot round-trip through `Deserialize`); use `Display` if you need
/// the redacted text in a serialized output.
///
/// `Redacted<&PrivateKey>` writes `S[REDACTED]`. `Redacted<&Strkey>` writes
/// `S[REDACTED]` for the
/// [`PrivateKeyEd25519`](Strkey::PrivateKeyEd25519) variant; all other
/// variants render their full strkey form (none of those variants contain
/// secret material — reach for [`Unredacted`] if a uniform shape across
/// variants matters to you).
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Redacted<T>(pub T);

// --- PrivateKey ---

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

impl Display for Redacted<&PrivateKey> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("S[REDACTED]")
    }
}

impl Debug for Redacted<&PrivateKey> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey([REDACTED])")
    }
}

// --- Strkey ---

impl Unredacted<&Strkey> {
    /// Encodes this strkey to its full strkey string form.
    ///
    /// # Zeroize
    ///
    /// For the `PrivateKeyEd25519` variant, the intermediate scratch
    /// buffers used during encoding are zeroed on drop, but the returned
    /// `HeaplessString` itself is plain — its bytes are not zeroed when
    /// the value is dropped. Use [`write_string`](Self::write_string) for
    /// zeroizing.
    pub fn to_string(&self) -> HeaplessString<{ Strkey::MAX_ENCODED_LEN }> {
        let mut zeroizing: Zeroizing<HeaplessString<{ Strkey::MAX_ENCODED_LEN }>> =
            Zeroizing::new(HeaplessString::new());
        self.write_string(&mut zeroizing);
        let mut out: HeaplessString<{ Strkey::MAX_ENCODED_LEN }> = HeaplessString::new();
        out.push_str(&zeroizing).unwrap();
        out
    }

    /// Encodes this strkey to its full strkey string form, writing the
    /// result into the caller-provided buffer.
    ///
    /// # Zeroize
    ///
    /// For the `PrivateKeyEd25519` variant, the inner encoding path's
    /// scratch buffers are wrapped in [`Zeroizing`] and zeroed on drop,
    /// and the encoded bytes are written directly into `out` rather than
    /// returned by value, so no copy is left on this method's stack frame.
    pub fn write_string(&self, out: &mut Zeroizing<HeaplessString<{ Strkey::MAX_ENCODED_LEN }>>) {
        // The buffer is sized to the longest variant, so a heapless
        // capacity error is unreachable.
        write!(**out, "{}", self).expect("MAX_ENCODED_LEN bound covers every variant");
    }
}

impl Display for Unredacted<&Strkey> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            Strkey::PublicKeyEd25519(k) => Display::fmt(k, f),
            Strkey::PrivateKeyEd25519(k) => Display::fmt(&Unredacted(k), f),
            Strkey::PreAuthTx(k) => Display::fmt(k, f),
            Strkey::HashX(k) => Display::fmt(k, f),
            Strkey::MuxedAccountEd25519(k) => Display::fmt(k, f),
            Strkey::SignedPayloadEd25519(k) => Display::fmt(k, f),
            Strkey::Contract(k) => Display::fmt(k, f),
            Strkey::LiquidityPool(k) => Display::fmt(k, f),
            Strkey::ClaimableBalance(k) => Display::fmt(k, f),
        }
    }
}

impl Debug for Unredacted<&Strkey> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            Strkey::PublicKeyEd25519(k) => write!(f, "PublicKeyEd25519({:?})", k),
            Strkey::PrivateKeyEd25519(k) => write!(f, "PrivateKeyEd25519({:?})", Unredacted(k)),
            Strkey::PreAuthTx(k) => write!(f, "PreAuthTx({:?})", k),
            Strkey::HashX(k) => write!(f, "HashX({:?})", k),
            Strkey::MuxedAccountEd25519(k) => write!(f, "MuxedAccountEd25519({:?})", k),
            Strkey::SignedPayloadEd25519(k) => write!(f, "SignedPayloadEd25519({:?})", k),
            Strkey::Contract(k) => write!(f, "Contract({:?})", k),
            Strkey::LiquidityPool(k) => write!(f, "LiquidityPool({:?})", k),
            Strkey::ClaimableBalance(k) => write!(f, "ClaimableBalance({:?})", k),
        }
    }
}

impl Display for Redacted<&Strkey> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            Strkey::PublicKeyEd25519(k) => Display::fmt(k, f),
            Strkey::PrivateKeyEd25519(k) => Display::fmt(&Redacted(k), f),
            Strkey::PreAuthTx(k) => Display::fmt(k, f),
            Strkey::HashX(k) => Display::fmt(k, f),
            Strkey::MuxedAccountEd25519(k) => Display::fmt(k, f),
            Strkey::SignedPayloadEd25519(k) => Display::fmt(k, f),
            Strkey::Contract(k) => Display::fmt(k, f),
            Strkey::LiquidityPool(k) => Display::fmt(k, f),
            Strkey::ClaimableBalance(k) => Display::fmt(k, f),
        }
    }
}

impl Debug for Redacted<&Strkey> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            Strkey::PublicKeyEd25519(k) => write!(f, "PublicKeyEd25519({:?})", k),
            Strkey::PrivateKeyEd25519(k) => write!(f, "PrivateKeyEd25519({:?})", Redacted(k)),
            Strkey::PreAuthTx(k) => write!(f, "PreAuthTx({:?})", k),
            Strkey::HashX(k) => write!(f, "HashX({:?})", k),
            Strkey::MuxedAccountEd25519(k) => write!(f, "MuxedAccountEd25519({:?})", k),
            Strkey::SignedPayloadEd25519(k) => write!(f, "SignedPayloadEd25519({:?})", k),
            Strkey::Contract(k) => write!(f, "Contract({:?})", k),
            Strkey::LiquidityPool(k) => write!(f, "LiquidityPool({:?})", k),
            Strkey::ClaimableBalance(k) => write!(f, "ClaimableBalance({:?})", k),
        }
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

impl Display for Redacted<PrivateKey> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&Redacted(&self.0), f)
    }
}

impl Debug for Redacted<PrivateKey> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(&Redacted(&self.0), f)
    }
}

impl Display for Unredacted<Strkey> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&Unredacted(&self.0), f)
    }
}

impl Debug for Unredacted<Strkey> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(&Unredacted(&self.0), f)
    }
}

impl Display for Redacted<Strkey> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&Redacted(&self.0), f)
    }
}

impl Debug for Redacted<Strkey> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(&Redacted(&self.0), f)
    }
}

// --- FromStr (Unredacted only; Redacted has no round-trip) ---

impl FromStr for Unredacted<PrivateKey> {
    type Err = DecodeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PrivateKey::from_string(s).map(Unredacted)
    }
}

impl FromStr for Unredacted<Strkey> {
    type Err = DecodeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Strkey::from_string(s).map(Unredacted)
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

    // No `Serialize` for `Redacted<T>`: `S[REDACTED]` cannot round-trip
    // through `Deserialize`, and for `Redacted<Strkey>` the serialized shape
    // would be variant-dependent (full strkey for non-private variants,
    // `S[REDACTED]` for the private one). Callers who need the redacted
    // string in serialized output can render via `Display` and serialize
    // that themselves.

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
