/// Wrapper that opts a value in to formatting or serialization that would
/// otherwise expose private-key bytes. Wrap an
/// [`ed25519::PrivateKey`](crate::ed25519::PrivateKey) in `Unredacted` to
/// render its encoded strkey form via [`Display`](core::fmt::Display) or
/// to serialize it through `serde`.
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
