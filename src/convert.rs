// TODO: Could encode and decode, and the functions upstream that call them, be
// const fn's?

use core::fmt;

use crate::{crc::checksum, error::DecodeError};

// Max payload: SignedPayload = 32 + 4 + 64 = 100 bytes, + 1 ver + 2 CRC = 103 bytes
// Base32 of 103 bytes = ceil(103 * 8 / 5) = 166 chars
pub const MAX_DATA_LEN: usize = 103;
pub const MAX_ENCODED_LEN: usize = 168; // ceil(103 * 8 / 5) rounded up

pub type StringBuf = heapless::String<MAX_ENCODED_LEN>;
pub type DataBuf = heapless::Vec<u8, MAX_DATA_LEN>;

pub fn encode(ver: u8, payload: &[u8]) -> StringBuf {
    let data_len = 1 + payload.len() + 2;

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
    // SAFETY: encoded_len <= MAX_ENCODED_LEN by construction
    StringBuf::try_from(s).unwrap()
}

/// Encode directly to a formatter, avoiding intermediate String allocation.
pub fn encode_to_fmt(ver: u8, payload: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let data_len = 1 + payload.len() + 2;

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
}

pub fn decode(s: &str) -> Result<(u8, DataBuf), DecodeError> {
    let len = data_encoding::BASE32_NOPAD
        .decode_len(s.len())
        .map_err(|_| DecodeError::Invalid)?;
    if len < 3 {
        return Err(DecodeError::Invalid);
    }
    let mut data = DataBuf::new();
    data.resize_default(len).map_err(|_| DecodeError::Invalid)?;
    data_encoding::BASE32_NOPAD
        .decode_mut(s.as_bytes(), &mut data)
        .map_err(|_| DecodeError::Invalid)?;
    let ver = data[0];
    let (data_without_crc, crc_actual) = data.split_at(data.len() - 2);
    let crc_expect = checksum(data_without_crc);
    if crc_actual != crc_expect {
        return Err(DecodeError::Invalid);
    }
    let payload_len = data.len() - 3;
    data.copy_within(1..1 + payload_len, 0);
    data.truncate(payload_len);
    Ok((ver, data))
}
