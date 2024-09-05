// TODO: Could encode and decode, and the functions upstream that call them, be
// const fn's?

use crate::{crc::checksum, error::DecodeError, typ};

// PublicKeyEd25519      32-bytes
// PrivateKeyEd25519     32-bytes
// PreAuthTx             32-bytes
// HashX                 32-bytes
// MuxedAccountEd25519   40-bytes
// SignedPayloadEd25519  32 + 4 + 4 = 40-bytes min, 32 + 4 + 64 = 100-bytes max
// Contract              32-bytes
const MAX_PAYLOAD_LEN: usize = 32 + 4 + 64;

pub fn encode_len(input_len: usize) -> usize {
    let len = 1 + input_len + 2;
    data_encoding::BASE32_NOPAD.encode_len(len)
}

pub fn encode(ver: u8, input: &[u8], output: &mut [u8]) {
    let mut d = [0u8; 1 + MAX_PAYLOAD_LEN + 2];
    d[0] = ver;
    d[1..=input.len()].copy_from_slice(input);
    let crc = checksum(&d[..=input.len()]);
    d[1 + input.len()..1 + input.len() + 2].copy_from_slice(&crc);
    // TODO
    assert_eq!(encode_len(input.len()), output.len());
    data_encoding::BASE32_NOPAD.encode_mut(&d[..input.len() + 3], output);
}

pub fn decode_len(input_len: usize) -> Result<usize, DecodeError> {
    let len = data_encoding::BASE32_NOPAD
        .decode_len(input_len)
        .map_err(|_| DecodeError::Invalid)?;
    if len < 3 || len > 1 + MAX_PAYLOAD_LEN + 2 {
        return Err(DecodeError::Invalid);
    }
    Ok(len - 3)
}

pub fn decode(input: &[u8], output: &mut [u8]) -> Result<u8, DecodeError> {
    let len = decode_len(input.len())? + 3;

    let mut decoded = [0u8; 1 + MAX_PAYLOAD_LEN + 2];
    let _ = data_encoding::BASE32_NOPAD
        .decode_mut(input, &mut decoded[..len])
        .map_err(|_| DecodeError::Invalid)?;

    let data = &decoded[..len];
    let ver = data[0];

    match ver {
        typ::PUBLIC_KEY | typ::PRIVATE_KEY | typ::PRE_AUTH_TX | typ::HASH_X | typ::CONTRACT => {
            if len != 32 + 3 {
                return Err(DecodeError::Invalid);
            }
        }
        typ::MUXED_ACCOUNT => {
            if len != 40 + 3 {
                return Err(DecodeError::Invalid);
            }
        }
        typ::SIGNED_PAYLOAD => {
            if len < 40 + 3 || len > 100 + 3 {
                return Err(DecodeError::Invalid);
            }
        }
        _ => {
            return Err(DecodeError::Invalid);
        }
    }

    let (data_without_crc, crc_actual) = data.split_at(data.len() - 2);
    let crc_expect = checksum(data_without_crc);
    if crc_actual != crc_expect {
        return Err(DecodeError::Invalid);
    }

    let payload = &data_without_crc[1..];

    output[..payload.len()].copy_from_slice(payload);
    Ok(ver)
}
