// TODO: Could encode and decode, and the functions upstream that call them, be
// const fn's?

use crate::alloc::string::ToString;
use crate::{crc::checksum, error::DecodeError};
use alloc::string::String;
use alloc::vec::Vec;
use core::str;

// PublicKeyEd25519      32-bytes
// PrivateKeyEd25519     32-bytes
// PreAuthTx             32-bytes
// HashX                 32-bytes
// MuxedAccountEd25519   40-bytes
// SignedPayloadEd25519  32 + 4 + 4 = 40-bytes min, 32 + 4 + 64 = 100-bytes max
// Contract              32-bytes
const MAX_PAYLOAD_SIZE: usize = 32 + 4 + 64;
const MAX_ENCODED_LEN: usize = ((1 + MAX_PAYLOAD_SIZE + 2) * 8 + 4) / 5;

pub fn encode(ver: u8, payload: &[u8]) -> String {
    let mut d = [0u8; 1 + MAX_PAYLOAD_SIZE + 2];
    d[0] = ver;
    d[1..=payload.len()].copy_from_slice(payload);
    let crc = checksum(&d[..=payload.len()]);
    d[1 + payload.len()..1 + payload.len() + 2].copy_from_slice(&crc);
    let len = data_encoding::BASE32_NOPAD.encode_len(1 + payload.len() + 2);
    let mut encoded = [0u8; MAX_ENCODED_LEN];
    data_encoding::BASE32_NOPAD.encode_mut(&d[..payload.len() + 3], &mut encoded[..len]);
    str::from_utf8(&encoded[..len]).unwrap().to_string()
}

pub fn decode(s: &str) -> Result<(u8, Vec<u8>), DecodeError> {
    let len = data_encoding::BASE32_NOPAD
        .decode_len(s.as_bytes().len())
        .map_err(|_| DecodeError::Invalid)?;

    if len < 3 || len > MAX_ENCODED_LEN {
        return Err(DecodeError::Invalid);
    }

    let mut decoded = [0u8; MAX_ENCODED_LEN];
    let _ = data_encoding::BASE32_NOPAD
        .decode_mut(s.as_bytes(), &mut decoded[..len])
        .map_err(|_| DecodeError::Invalid)?;

    let data = &decoded[..len];
    let ver = data[0];
    let (data_without_crc, crc_actual) = data.split_at(data.len() - 2);
    let crc_expect = checksum(data_without_crc);
    if crc_actual != crc_expect {
        return Err(DecodeError::Invalid);
    }

    let payload = &data_without_crc[1..];
    Ok((ver, payload.to_vec()))
}
