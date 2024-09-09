// TODO: Could encode and decode, and the functions upstream that call them, be
// const fn's?

use crate::{crc::checksum, error::DecodeError};

// PublicKeyEd25519      32-bytes
// PrivateKeyEd25519     32-bytes
// PreAuthTx             32-bytes
// HashX                 32-bytes
// MuxedAccountEd25519   40-bytes
// SignedPayloadEd25519  32 + 4 + 4 = 40-bytes min, 32 + 4 + 64 = 100-bytes max
// Contract              32-bytes
const MAX_PAYLOAD_LEN: usize = 32 + 4 + 64;


/// Get the length of the strkey encoded data.
///
/// # Arguments
///
/// * `input_len` - The length of the raw data.
pub fn encode_len(input_len: usize) -> usize {
    let len = 1 + input_len + 2;
    data_encoding::BASE32_NOPAD.encode_len(len)
}


/// Encode the raw data to a strkey.
///
/// # Arguments
///
/// * `ver` - The version byte.
/// * `input` - The raw data.
/// * `output` - The encoded strkey. We assume it is the correct size, and you can get the correct size by calling [encode_len].
///
/// # Panics
///
/// This function will panic if the output buffer is not the correct size.
///
/// # Examples
///
/// ```rust
/// let mut output = [0u8; 100];
/// let input = [0u8; 32];
/// // let output_len = encode_len(input.len());
/// // encode(0, &input, &mut output[..output_len]);
/// ```
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


/// Get the length of the raw data from a strkey.
///
/// # Arguments
///
/// * `input_len` - The length of the strkey encoded data.
///
/// # Errors
///
/// This function will return an error if the strkey is invalid.
pub fn decode_len(input_len: usize) -> Result<usize, DecodeError> {
    let len = data_encoding::BASE32_NOPAD
        .decode_len(input_len)
        .map_err(|_| DecodeError::Invalid)?;
    if len < 3 || len > 1 + MAX_PAYLOAD_LEN + 2 {
        return Err(DecodeError::Invalid);
    }
    Ok(len - 3) // remove version byte and crc length
}

pub fn decode(input: &[u8], output: &mut [u8]) -> Result<u8, DecodeError> {
    let len = decode_len(input.len())? + 3;
    assert_eq!(output.len(), len - 3);
    let mut decoded = [0u8; 1 + MAX_PAYLOAD_LEN + 2];
    let _ = data_encoding::BASE32_NOPAD
        .decode_mut(input, &mut decoded[..len])
        .map_err(|_| DecodeError::Invalid)?;

    let data = &decoded[..len];
    let ver = data[0];

    let (data_without_crc, crc_actual) = data.split_at(data.len() - 2);
    let crc_expect = checksum(data_without_crc);
    if crc_actual != crc_expect {
        return Err(DecodeError::Invalid);
    }

    let payload = &data_without_crc[1..];

    output[..payload.len()].copy_from_slice(payload);
    Ok(ver)
}
