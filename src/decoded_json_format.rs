/// Wrapper type that serializes the inner type as a JSON object with hex-encoded bytes.
///
/// By default, strkey types serialize as their string representation (e.g.,
/// `"GA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQHES5"`).
/// Use `Decoded` when you need JSON object output with hex-encoded byte arrays:
///
/// ```ignore
/// use stellar_strkey::{Strkey, Decoded, ed25519};
///
/// let key = Strkey::PublicKeyEd25519(ed25519::PublicKey([0; 32]));
///
/// // Default: string format
/// let s = serde_json::to_string(&key).unwrap();
/// // "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
///
/// // Decoded format
/// let j = serde_json::to_string(&Decoded(&key)).unwrap();
/// // {"public_key_ed25519":"0000000000000000000000000000000000000000000000000000000000000000"}
/// ```
///
/// # Allocation
///
/// The `serde::Deserialize` implementation for this type allocates. Hex
/// decoding of the byte fields is performed via `serde_with::hex::Hex`, which
/// allocates an intermediate `String` (or equivalent) for every hex-encoded
/// field regardless of the input format. There is no zero-allocation
/// deserialization path; deserializing `Decoded<T>` always requires a heap
/// allocator.
///
/// If the input is untrusted, or this type is used in an
/// allocation-sensitive application, callers should validate the input
/// length prior to deserializing to avoid unexpected or unbounded allocations.
pub struct Decoded<T>(pub T);
