use alloc::{format, string::String, vec::Vec};

/// Wrapper type that serializes the inner type as a JSON object with hex-encoded bytes.
///
/// By default, strkey types serialize as their string representation (e.g.,
/// `"GA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQHES5"`).
/// Use `ObjectFormat` when you need JSON object output with hex-encoded byte arrays:
///
/// ```ignore
/// use stellar_strkey::{Strkey, ObjectFormat, ed25519};
///
/// let key = Strkey::PublicKeyEd25519(ed25519::PublicKey([0; 32]));
///
/// // Default: string format
/// let s = serde_json::to_string(&key).unwrap();
/// // "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
///
/// // Object format
/// let j = serde_json::to_string(&ObjectFormat(&key)).unwrap();
/// // {"public_key_ed25519":"0000000000000000000000000000000000000000000000000000000000000000"}
/// ```
pub struct ObjectFormat<T>(pub T);

/// Encode bytes as hex string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode hex string to bytes.
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, &'static str> {
    if hex.len() % 2 != 0 {
        return Err("invalid hex length");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| "invalid hex character"))
        .collect()
}

/// Decode hex string to fixed-size array.
pub fn hex_to_array<const N: usize>(hex: &str) -> Result<[u8; N], &'static str> {
    let bytes = hex_to_bytes(hex)?;
    bytes.try_into().map_err(|_| "invalid hex length")
}
