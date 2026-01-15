// TODO: Could encode and decode, and the functions upstream that call them, be
// const fn's?

use alloc::string::String;
use alloc::vec::Vec;

use crate::{crc::checksum, error::DecodeError};

// Buffer sizes per strkey type:
// +------------------------+-------------+------------+------------+
// | Type                   | Payload Len | Binary Len | Base32 Len |
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
// Binary Len = 1 (version) + Payload Len + 2 (checksum)
// Base32 Len = ceil(Binary Len * 8 / 5)

const MAX_BINARY_LEN: usize = 103;
const MAX_ENCODED_LEN: usize = 165;

/// Encodes a version byte and payload into a base32 strkey string.
///
/// The binary format is: `version (1 byte) || payload || checksum (2 bytes)`.
/// The checksum is computed over the version and payload bytes.
///
/// # Panics
///
/// Panics if the payload length exceeds 100 bytes (the maximum length of any
/// Strkey's payload).
pub fn encode(ver: u8, payload: &[u8]) -> String {
    // Build binary.
    let mut d: heapless::Vec<u8, MAX_BINARY_LEN> = heapless::Vec::new();
    d.push(ver).unwrap();
    d.extend_from_slice(payload).unwrap();
    d.extend_from_slice(&checksum(&d)).unwrap();

    // Encode as base32.
    let mut encoded = heapless::Vec::<u8, MAX_ENCODED_LEN>::new();
    let encoded_len = data_encoding::BASE32_NOPAD.encode_len(d.len());
    encoded.resize_default(encoded_len).unwrap();
    data_encoding::BASE32_NOPAD.encode_mut(&d, &mut encoded);

    // SAFETY: base32 encoding produces valid ASCII which is valid UTF-8
    let s = unsafe { core::str::from_utf8_unchecked(&encoded) };
    String::from(s)
}

/// Decodes a base32 strkey string into a version byte and payload.
///
/// The binary format is: `version (1 byte) || payload || checksum (2 bytes)`.
///
/// # Errors
///
/// Returns [`DecodeError::Invalid`] if:
/// - The input is not valid base32
/// - The decoded data is less than 3 bytes
/// - The decoded data exceeds the maximum size (103 bytes)
/// - The checksum does not match
pub fn decode(s: &str) -> Result<(u8, Vec<u8>), DecodeError> {
    // Prepare buffer for decoding base32.
    let mut data: heapless::Vec<u8, MAX_BINARY_LEN> = heapless::Vec::new();
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
        .decode_mut(s.as_bytes(), &mut data)
        .map_err(|_| DecodeError::Invalid)?;

    // Unpack version.
    let ver = data[0];

    // Unpack and check checksum.
    let (data_without_crc, crc_actual) = data.split_at(data.len() - 2);
    let crc_expect = checksum(data_without_crc);
    if crc_actual != crc_expect {
        return Err(DecodeError::Invalid);
    }
    let payload = &data_without_crc[1..];
    Ok((ver, payload.to_vec()))
}
