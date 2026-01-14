// TODO: Could encode and decode, and the functions upstream that call them, be
// const fn's?

use crate::{
    crc::checksum,
    error::{DecodeError, EncodeError},
};

// Max payload sizes by strkey type:
//   PublicKeyEd25519:      32 bytes (ed25519 key)
//   PrivateKeyEd25519:     32 bytes (ed25519 key)
//   PreAuthTx:             32 bytes (hash)
//   HashX:                 32 bytes (hash)
//   Contract:              32 bytes (hash)
//   LiquidityPool:         32 bytes (hash)
//   MuxedAccountEd25519:   40 bytes (32 ed25519 key + 8 id)
//   ClaimableBalance:      36 bytes (4 type + 32 hash)
//   SignedPayloadEd25519: 104 bytes (32 ed25519 key + 4 len + 64 payload + 4 padding)
//
// Max binary size: 1 (version) + 104 (max payload) + 2 (crc) = 107 bytes
const MAX_BINARY_SIZE: usize = 107;

/// Encodes a version byte and payload into a strkey, writing to the provided buffer.
/// Returns the number of bytes written, or an error if the buffer is too small.
pub fn encode_to_slice(ver: u8, payload: &[u8], out: &mut [u8]) -> Result<usize, EncodeError> {
    let data_len = 1 + payload.len() + 2;

    let mut data = [0u8; MAX_BINARY_SIZE];

    data[0] = ver;
    data[1..1 + payload.len()].copy_from_slice(payload);

    let crc = checksum(&data[..1 + payload.len()]);
    data[1 + payload.len()..data_len].copy_from_slice(&crc);

    // Calculate the encoded length
    let encoded_len = data_encoding::BASE32_NOPAD.encode_len(data_len);
    if out.len() < encoded_len {
        return Err(EncodeError::BufferTooSmall {
            buf_len: out.len(),
            required_len: encoded_len,
        });
    }

    data_encoding::BASE32_NOPAD.encode_mut(&data[..data_len], &mut out[..encoded_len]);
    Ok(encoded_len)
}

/// Decodes a strkey string into a version byte and payload, writing to the provided buffer.
/// Returns the version byte and number of payload bytes written.
pub fn decode_to_slice(s: &str, out: &mut [u8]) -> Result<(u8, usize), DecodeError> {
    let decoded_len = data_encoding::BASE32_NOPAD
        .decode_len(s.len())
        .map_err(|_| DecodeError::Invalid)?;

    if decoded_len < 3 {
        return Err(DecodeError::Invalid);
    }

    let mut data = [0u8; MAX_BINARY_SIZE];
    if decoded_len > data.len() {
        return Err(DecodeError::Invalid);
    }

    data_encoding::BASE32_NOPAD
        .decode_mut(s.as_bytes(), &mut data[..decoded_len])
        .map_err(|_| DecodeError::Invalid)?;

    let ver = data[0];
    let (data_without_crc, crc_actual) = data[..decoded_len].split_at(decoded_len - 2);
    let crc_expect = checksum(data_without_crc);
    if crc_actual != crc_expect {
        return Err(DecodeError::Invalid);
    }

    let payload = &data_without_crc[1..];
    let payload_len = payload.len();

    if out.len() < payload_len {
        return Err(DecodeError::Invalid);
    }

    out[..payload_len].copy_from_slice(payload);
    Ok((ver, payload_len))
}

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "alloc")]
pub fn encode(ver: u8, payload: &[u8]) -> String {
    let mut d = Vec::with_capacity(1 + payload.len() + 2);
    d.push(ver);
    d.extend_from_slice(payload);
    d.extend_from_slice(&checksum(&d));
    data_encoding::BASE32_NOPAD.encode(&d)
}
