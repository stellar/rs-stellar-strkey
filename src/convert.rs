// TODO: Could encode and decode, and the functions upstream that call them, be
// const fn's?

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::{crc::checksum, error::DecodeError};

pub fn encode(ver: u8, payload: &[u8]) -> String {
    // Max payload: SignedPayload = 32 + 4 + 64 = 100 bytes, + 1 ver + 2 CRC = 103 bytes
    // Base32 of 103 bytes = ceil(103 * 8 / 5) = 166 chars
    // Use stack buffers for typical cases (covers all current strkey types)
    const MAX_DATA_LEN: usize = 103;
    const MAX_ENCODED_LEN: usize = 168; // ceil(103 * 8 / 5) rounded up

    let data_len = 1 + payload.len() + 2;

    if data_len <= MAX_DATA_LEN {
        let mut d = [0u8; MAX_DATA_LEN];
        d[0] = ver;
        d[1..1 + payload.len()].copy_from_slice(payload);
        let crc = checksum(&d[..1 + payload.len()]);
        d[1 + payload.len()..data_len].copy_from_slice(&crc);

        let encoded_len = data_encoding::BASE32_NOPAD.encode_len(data_len);
        let mut buf = [0u8; MAX_ENCODED_LEN];
        data_encoding::BASE32_NOPAD.encode_mut(&d[..data_len], &mut buf[..encoded_len]);
        // SAFETY: BASE32_NOPAD always produces valid ASCII which is valid UTF-8
        unsafe { core::str::from_utf8_unchecked(&buf[..encoded_len]) }.into()
    } else {
        // Fallback for unexpectedly large payloads
        let mut d: Vec<u8> = Vec::with_capacity(data_len);
        d.push(ver);
        d.extend_from_slice(payload);
        d.extend_from_slice(&checksum(&d));
        data_encoding::BASE32_NOPAD.encode(&d)
    }
}

/// Encode directly to a formatter, avoiding intermediate String allocation.
pub fn encode_to_fmt(ver: u8, payload: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    // Max payload: SignedPayload = 32 + 4 + 64 = 100 bytes, + 1 ver + 2 CRC = 103 bytes
    // Base32 of 103 bytes = ceil(103 * 8 / 5) = 166 chars
    // Use stack buffers for typical cases (covers all current strkey types)
    const MAX_DATA_LEN: usize = 103;
    const MAX_ENCODED_LEN: usize = 168; // ceil(103 * 8 / 5) rounded up

    let data_len = 1 + payload.len() + 2;

    if data_len <= MAX_DATA_LEN {
        let mut d = [0u8; MAX_DATA_LEN];
        d[0] = ver;
        d[1..1 + payload.len()].copy_from_slice(payload);
        let crc = checksum(&d[..1 + payload.len()]);
        d[1 + payload.len()..data_len].copy_from_slice(&crc);

        let encoded_len = data_encoding::BASE32_NOPAD.encode_len(data_len);
        let mut buf = [0u8; MAX_ENCODED_LEN];
        data_encoding::BASE32_NOPAD.encode_mut(&d[..data_len], &mut buf[..encoded_len]);
        // SAFETY: BASE32_NOPAD always produces valid ASCII which is valid UTF-8
        let s = unsafe { core::str::from_utf8_unchecked(&buf[..encoded_len]) };
        f.write_str(s)
    } else {
        // Fallback for unexpectedly large payloads
        let mut d: Vec<u8> = Vec::with_capacity(data_len);
        d.push(ver);
        d.extend_from_slice(payload);
        d.extend_from_slice(&checksum(&d));
        let encoded_len = data_encoding::BASE32_NOPAD.encode_len(d.len());
        let mut buf = alloc::vec![0u8; encoded_len];
        data_encoding::BASE32_NOPAD.encode_mut(&d, &mut buf);
        // SAFETY: BASE32_NOPAD always produces valid ASCII which is valid UTF-8
        let s = unsafe { core::str::from_utf8_unchecked(&buf) };
        f.write_str(s)
    }
}

pub fn decode(s: &str) -> Result<(u8, Vec<u8>), DecodeError> {
    let mut data = data_encoding::BASE32_NOPAD
        .decode(s.as_bytes())
        .map_err(|_| DecodeError::Invalid)?;
    if data.len() < 3 {
        return Err(DecodeError::Invalid);
    }
    let ver = data[0];
    let (data_without_crc, crc_actual) = data.split_at(data.len() - 2);
    let crc_expect = checksum(data_without_crc);
    if crc_actual != crc_expect {
        return Err(DecodeError::Invalid);
    }
    // Reuse the existing Vec by removing the version byte and CRC bytes
    let payload_len = data.len() - 3;
    data.copy_within(1..1 + payload_len, 0);
    data.truncate(payload_len);
    Ok((ver, data))
}
