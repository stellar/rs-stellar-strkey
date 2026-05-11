/// Wrapper that opts a value in to formatting or serialization that would
/// otherwise expose private-key bytes.
///
/// Wrap an [`ed25519::PrivateKey`](crate::ed25519::PrivateKey) in `Unredacted`
/// for any of:
///
/// - [`Display`](core::fmt::Display) / `to_string` / `write_string` — renders
///   the encoded strkey string (`S…`).
/// - [`Debug`](core::fmt::Debug) — prints the raw 32-byte seed as hex
///   (`PrivateKey(<hex>)`). Bare `PrivateKey`'s `Debug` redacts.
/// - `serde::Serialize` (under the `serde` feature) — serializes as the
///   strkey string form.
/// - [`Decoded`](crate::Decoded)`<Unredacted<&PrivateKey>>` (under the
///   `serde-decoded` feature) — serializes the raw seed as hex inside a
///   JSON object.
///
/// # Zeroize
///
/// `Display`, `to_string`, and `serde::Serialize` materialize the encoded
/// bytes into a non-zeroizing intermediate (the returned `String`, the
/// formatter, or the serializer's internal buffer). For the strongest
/// guarantees, use [`Unredacted::write_string`] to write directly into a
/// caller-provided [`Zeroizing`](zeroize::Zeroizing) buffer.
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Unredacted<T>(pub T);

#[cfg(feature = "serde")]
impl<T> serde::Serialize for Unredacted<T>
where
    Self: core::fmt::Display,
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
