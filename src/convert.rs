// TODO: Could encode and decode, and the functions upstream that call them, be
// const fn's?

use alloc::string::String;
use alloc::vec::Vec;

use crate::{crc::checksum, error::DecodeError};

pub fn encode(ver: u8, payload: &[u8]) -> String {
    let mut d: Vec<u8> = Vec::with_capacity(1 + payload.len() + 2);
    d.push(ver);
    d.extend_from_slice(payload);
    d.extend_from_slice(&checksum(&d));
    data_encoding::BASE32_NOPAD.encode(&d)
}

pub fn decode(s: &str) -> Result<(u8, Vec<u8>), DecodeError> {
    let data = data_encoding::BASE32_NOPAD.decode(s.as_bytes()).ok();
    if let Some(data) = data {
        if data.len() < 3 {
            return Err(DecodeError::Invalid);
        }
        let ver = data[0];
        let (data_without_crc, crc_actual) = data.split_at(data.len() - 2);
        let crc_expect = checksum(data_without_crc);
        if crc_actual != crc_expect {
            return Err(DecodeError::Invalid);
        }
        let payload = &data_without_crc[1..];
        Ok((ver, payload.to_vec()))
    } else {
        Err(DecodeError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, DecodeError};

    /// Verifies that `encode_len` matches `data_encoding::BASE32_NOPAD.encode_len`
    /// for all valid strkey payload lengths (3..=100).
    #[test]
    fn test_encode_len() {
        for payload_len in 0..=100 {
            let bin_len = payload_len + 3;
            let expected = data_encoding::BASE32_NOPAD.encode_len(bin_len);

            // Verify actual encoded output matches predicted length
            let payload = [0u8; 100];
            let encoded = encode(0x00, &payload[..payload_len]);
            assert_eq!(encoded.len(), expected);
        }
    }

    /// Tests that decode accepts minimum valid input (3 binary bytes: version + empty payload + checksum).
    /// This catches the mutation `data_len < 3` -> `data_len <= 3`.
    #[test]
    fn test_decode_minimum_length() {
        // Empty input should fail
        assert_eq!(decode(""), Err(DecodeError::Invalid));
        // Too short base32 (decodes to < 3 bytes) should fail
        assert_eq!(decode("AA"), Err(DecodeError::Invalid)); // 1 byte
        assert_eq!(decode("AAAA"), Err(DecodeError::Invalid)); // 2 bytes
        // Valid 3-byte input (version + empty payload + checksum) should succeed
        // "AAAAA" is encode::<3, 5>(0x00, &[]) - version 0x00, empty payload, checksum 0x0000
        let result = decode("AAAAA");
        assert!(result.is_ok(), "decode should accept 3 binary bytes (empty payload)");
        let (ver, payload) = result.unwrap();
        assert_eq!(ver, 0x00);
        assert!(payload.is_empty());
    }
}
