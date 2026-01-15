// TODO: Could encode and decode, and the functions upstream that call them, be
// const fn's?

use base32ct::{Base32UpperUnpadded, Encoding};
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

/// Calculates the binary length from a base32 (no padding) encoded length.
///
/// The formula is `floor(encoded_len * 5 / 8)`.
pub const fn decode_len(encoded_len: usize) -> usize {
    (encoded_len * 5) / 8
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
/// - `B` - Binary buffer capacity (must be ≥ 1 + payload.len() + 2)
/// - `E` - Encoded output capacity (must be ≥ ceil(B * 8 / 5))
///
/// # Panics
///
/// Panics if the binary data exceeds `B` bytes or encoded output exceeds `E`
/// bytes.
pub fn encode<const B: usize, const E: usize>(ver: u8, payload: &[u8]) -> String<E> {
    const {
        assert!(
            B >= 3,
            "B must be at least 3 (1 version + 0 payload + 2 checksum)"
        );
        // E >= ceil(B * 8 / 5) is equivalent to E * 5 >= B * 8
        assert!(
            E * 5 >= B * 8,
            "E must be at least ceil(B * 8 / 5) for base32 encoding"
        );
    }

    // Build binary.
    let mut d: Vec<u8, B> = Vec::new();
    d.push(ver).unwrap();
    d.extend_from_slice(payload).unwrap();
    d.extend_from_slice(&checksum(&d)).unwrap();

    // Encode as base32.
    let mut encoded: Vec<u8, E> = Vec::new();
    encoded.resize_default(E).unwrap();
    let encoded_str = Base32UpperUnpadded::encode(&d, &mut encoded).unwrap();
    let encoded_len = encoded_str.len();
    encoded.truncate(encoded_len);

    // SAFETY: base32 encoding produces valid ASCII which is valid UTF-8
    unsafe { String::from_utf8_unchecked(encoded) }
}

/// Decodes a base32 strkey string into a version byte and payload.
///
/// The binary format is: `version (1 byte) || payload || checksum (2 bytes)`.
///
/// # Generic Parameters
///
/// - `B` - Binary buffer capacity (must be ≥ decoded binary length)
/// - `P` - Payload buffer capacity (must be ≥ B - 3)
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
/// Panics if the binary data exceeds `B` bytes or decoded payload exceeds `P` bytes.
pub fn decode<const B: usize, const P: usize>(s: &[u8]) -> Result<(u8, Vec<u8, P>), DecodeError> {
    const {
        assert!(
            B >= 3,
            "B must be at least 3 (1 version + 0 payload + 2 checksum)"
        );
        assert!(P >= B - 3, "P must be at least B - 3 to hold the payload");
    }

    // Reject invalid base32 lengths. In unpadded base32, valid lengths produce
    // whole bytes when decoded. Invalid lengths are congruent to 1, 3, or 6
    // mod 8 (these would require partial bytes).
    let len_mod8 = s.len() % 8;
    if len_mod8 == 1 || len_mod8 == 3 || len_mod8 == 6 {
        return Err(DecodeError::Invalid);
    }

    // Calculate decoded length.
    let data_len = decode_len(s.len());
    if data_len < 3 {
        return Err(DecodeError::Invalid);
    }
    if data_len > B {
        return Err(DecodeError::Invalid);
    }

    // Prepare buffer for decoding base32.
    let mut data: Vec<u8, B> = Vec::new();
    data.resize_default(B).unwrap();

    // Decode base32.
    let decoded = Base32UpperUnpadded::decode(s, &mut data).map_err(|_| DecodeError::Invalid)?;
    let decoded_len = decoded.len();
    data.truncate(decoded_len);

    // Validate that unused trailing bits are zero.
    // In base32, each character encodes 5 bits, but the last character may
    // have unused bits. For example, if we decode 7 characters (35 bits) into
    // 4 bytes (32 bits), there are 3 unused bits in the last character.
    // These unused bits must be zero for the encoding to be canonical.
    let total_bits = s.len() * 5;
    let used_bits = decoded_len * 8;
    let unused_bits = total_bits - used_bits;
    if unused_bits > 0 && !s.is_empty() {
        // Get the last character and check its unused bits
        let last_char = s[s.len() - 1];
        // Decode the last character to get its 5-bit value
        let last_value = match last_char {
            b'A'..=b'Z' => last_char - b'A',
            b'2'..=b'7' => last_char - b'2' + 26,
            _ => return Err(DecodeError::Invalid),
        };
        // The unused bits are the low bits of last_value
        let mask = (1u8 << unused_bits) - 1;
        if (last_value & mask) != 0 {
            return Err(DecodeError::Invalid);
        }
    }

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
    let payload_data = &data_without_crc[1..];
    let mut payload: Vec<u8, P> = Vec::new();
    payload.extend_from_slice(payload_data).unwrap();
    Ok((ver, payload))
}
