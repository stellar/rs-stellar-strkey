// TODO: Could encode and decode, and the functions upstream that call them, be
// const fn's?

use heapless::{String, Vec};

use crate::{crc::checksum, error::DecodeError};

/// Calculates the binary length for a given payload length.
///
/// The formula is `1 (version) + payload_len + 2 (checksum)`.
pub const fn binary_len(payload_len: usize) -> usize {
    1 + payload_len + 2
}

/// Calculates the base32 (no padding) encoded length for a given binary length.
///
/// The formula is `ceil(binary_len * 8 / 5)`.
pub const fn encode_len(binary_len: usize) -> usize {
    (binary_len * 8 + 4) / 5
}

// Buffer sizes expected per strkey version:
// +------------------------+-------------+------------+------------+
// | Version                | Payload Len | Binary Len | Base32 Len |
// +------------------------+-------------+------------+------------+
// | PublicKeyEd25519       |          32 |         35 |         56 |
// | PrivateKeyEd25519      |          32 |         35 |         56 |
// | PreAuthTx              |          32 |         35 |         56 |
// | HashX                  |          32 |         35 |         56 |
// | Contract               |          32 |         35 |         56 |
// | LiquidityPool          |          32 |         35 |         56 |
// | ClaimableBalance       |          33 |         36 |         58 |
// | MuxedAccountEd25519    |          40 |         43 |         69 |
// | SignedPayloadEd25519   |     40..100 |    43..103 |    69..165 |
// +------------------------+-------------+------------+------------+

/// Encodes a version byte and payload into a base32 strkey string.
///
/// The binary format is: `version (1 byte) || payload || checksum (2 bytes)`.
/// The checksum is computed over the version and payload bytes.
///
/// # Generic Parameters
///
/// - `P` - Payload buffer capacity
/// - `B` - Binary buffer capacity (must be exactly binary_len(P))
/// - `E` - Encoded output capacity (must be exactly encode_len(B))
///
/// # Panics
///
/// Panics if the binary data exceeds `B` bytes or encoded output exceeds `E`
/// bytes.
pub fn encode<const P: usize, const B: usize, const E: usize>(
    ver: u8,
    payload: &[u8],
) -> String<E> {
    const {
        assert!(B == binary_len(P), "B must be exactly binary_len(P)");
        assert!(E == encode_len(B), "E must be exactly encode_len(B)");
    }

    // Build binary.
    let mut d: Vec<u8, B> = Vec::new();
    d.push(ver).unwrap();
    d.extend_from_slice(payload).unwrap();
    d.extend_from_slice(&checksum(&d)).unwrap();

    // Encode as base32.
    let mut encoded: Vec<u8, E> = Vec::new();
    let encoded_len = data_encoding::BASE32_NOPAD.encode_len(d.len());
    encoded.resize_default(encoded_len).unwrap();
    data_encoding::BASE32_NOPAD.encode_mut(&d, &mut encoded);

    // SAFETY: base32 encoding produces valid ASCII which is valid UTF-8
    unsafe { String::from_utf8_unchecked(encoded) }
}

/// Decodes a base32 strkey string into a version byte and payload.
///
/// The binary format is: `version (1 byte) || payload || checksum (2 bytes)`.
///
/// # Generic Parameters
///
/// - `P` - Payload buffer capacity
/// - `B` - Binary buffer capacity (must be exactly binary_len(P))
///
/// # Errors
///
/// Returns [`DecodeError::Invalid`] if:
/// - The input is not valid base32
/// - The decoded data is less than 3 bytes, meaning there is no payload
/// - The checksum does not match
///
/// # Panics
///
/// Panics if the binary data exceeds `B` bytes.
pub fn decode<const P: usize, const B: usize>(s: &[u8]) -> Result<(u8, Vec<u8, P>), DecodeError> {
    const {
        assert!(B == binary_len(P), "B must be exactly binary_len(P)");
    }

    // Prepare buffer for decoding base32.
    let mut data: Vec<u8, B> = Vec::new();
    let data_len = data_encoding::BASE32_NOPAD
        .decode_len(s.len())
        .map_err(|_| DecodeError::Invalid)?;
    if data_len < 3 {
        return Err(DecodeError::Invalid);
    }
    data.resize_default(data_len)
        .map_err(|_| DecodeError::Invalid)?;

    // Decode base32.
    data_encoding::BASE32_NOPAD
        .decode_mut(s, &mut data)
        .map_err(|_| DecodeError::Invalid)?;

    // Unpack version.
    let ver = data[0];

    // Unpack and check checksum.
    let data_len = data.len();
    let (data_without_crc, crc_actual) = data.split_at(data_len - 2);
    let crc_expect = checksum(data_without_crc);
    if crc_actual != crc_expect {
        return Err(DecodeError::Invalid);
    }

    // Unpack payload.
    // Safety: unwrap cannot fail because const assertion `P >= B - 3` ensures
    // P can hold any valid payload (payload_data.len() <= B - 3 <= P).
    let payload_data = &data_without_crc[1..];
    let payload: Vec<u8, P> = Vec::from_slice(payload_data).unwrap();
    Ok((ver, payload))
}

#[cfg(test)]
mod tests {
    use super::{binary_len, decode, encode, encode_len, DecodeError};

    /// Verifies that `binary_len` matches the expected formula
    /// for all valid strkey payload lengths (0..=100).
    #[test]
    fn test_binary_len() {
        for payload_len in 0..=100 {
            // version (1 byte) + payload len + crc (2 bytes)
            let expected = 1 + payload_len + 2;
            let actual = binary_len(payload_len);
            assert_eq!(actual, expected);
        }
    }

    /// Verifies that `encode_len` matches `data_encoding::BASE32_NOPAD.encode_len`
    /// for all valid strkey payload lengths (3..=100).
    #[test]
    fn test_encode_len() {
        for payload_len in 0..=100 {
            let bin_len = binary_len(payload_len);
            let expected = data_encoding::BASE32_NOPAD.encode_len(bin_len);
            let actual = encode_len(bin_len);
            assert_eq!(actual, expected);

            // Verify actual encoded output matches predicted length
            let payload = [0u8; 100];
            let encoded = encode::<100, 103, 165>(0x00, &payload[..payload_len]);
            assert_eq!(encoded.len(), expected);
        }
    }

    /// Tests that decode accepts minimum valid input (3 binary bytes: version + empty payload + checksum).
    /// This catches the mutation `data_len < 3` -> `data_len <= 3`.
    #[test]
    fn test_decode_minimum_length() {
        // Empty input should fail
        assert_eq!(decode::<0, 3>(b""), Err(DecodeError::Invalid));
        // Too short base32 (decodes to < 3 bytes) should fail
        assert_eq!(decode::<0, 3>(b"AA"), Err(DecodeError::Invalid)); // 1 byte
        assert_eq!(decode::<0, 3>(b"AAAA"), Err(DecodeError::Invalid)); // 2 bytes

        // Valid 3-byte input (version + empty payload + checksum) should succeed
        // "AAAAA" is encode::<0, 3, 5>(0x00, &[]) - version 0x00, empty payload, checksum 0x0000
        let result = decode::<0, 3>(b"AAAAA");
        assert!(
            result.is_ok(),
            "decode should accept 3 binary bytes (empty payload)"
        );
        let (ver, payload) = result.unwrap();
        assert_eq!(ver, 0x00);
        assert!(payload.is_empty());
    }
}
