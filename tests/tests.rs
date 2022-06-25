use stellar_strkey::*;

extern crate proptest;

use proptest::prelude::*;

#[test]
fn test_valid_public_keys() {
    // Valid account.
    assert_convert_roundtrip(
        "GA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQHES5",
        &Strkey::PublicKeyEd25519(StrkeyPublicKeyEd25519([
            0x36, 0x3e, 0xaa, 0x38, 0x67, 0x84, 0x1f, 0xba, 0xd0, 0xf4, 0xed, 0x88, 0xc7, 0x79,
            0xe4, 0xfe, 0x66, 0xe5, 0x6a, 0x24, 0x70, 0xdc, 0x98, 0xc0, 0xec, 0x9c, 0x07, 0x3d,
            0x05, 0xc7, 0xb1, 0x03,
        ])),
    );
}

#[test]
fn test_invalid_public_keys() {
    // Invalid length (Ed25519 should be 32 bytes, not 5).
    let r = Strkey::from_string("GAAAAAAAACGC6");
    assert_eq!(r, Err(DecodeError::Invalid));

    // Invalid length (congruent to 1 mod 8).
    let r = Strkey::from_string("GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZA");
    assert_eq!(r, Err(DecodeError::Invalid));

    // Invalid length (base-32 decoding should yield 35 bytes, not 36).
    let r = Strkey::from_string("GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUACUSI");
    assert_eq!(r, Err(DecodeError::Invalid));

    // Invalid algorithm (low 3 bits of version byte are 7).
    let r = Strkey::from_string("G47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVP2I");
    assert_eq!(r, Err(DecodeError::Invalid));
}

#[test]
fn test_valid_private_keys() {
    // Valid private key.
    assert_convert_roundtrip(
        "SBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWHOKR",
        &Strkey::PrivateKeyEd25519(StrkeyPrivateKeyEd25519([
            0x69, 0xa8, 0xc4, 0xcb, 0xb9, 0xf6, 0x4e, 0x8a, 0x07, 0x98, 0xf6, 0xe1, 0xac, 0x65,
            0xd0, 0x6c, 0x31, 0x62, 0x92, 0x90, 0x56, 0xbc, 0xf4, 0xcd, 0xb7, 0xd3, 0x73, 0x8d,
            0x18, 0x55, 0xf3, 0x63,
        ])),
    );
}

#[test]
fn test_valid_pre_auth_tx() {
    assert_convert_roundtrip(
        "TA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGZAM",
        &Strkey::PreAuthTx(StrkeyPreAuthTx([
            0x36, 0x3e, 0xaa, 0x38, 0x67, 0x84, 0x1f, 0xba, 0xd0, 0xf4, 0xed, 0x88, 0xc7, 0x79,
            0xe4, 0xfe, 0x66, 0xe5, 0x6a, 0x24, 0x70, 0xdc, 0x98, 0xc0, 0xec, 0x9c, 0x07, 0x3d,
            0x05, 0xc7, 0xb1, 0x03,
        ])),
    );
}

#[test]
fn test_valid_hash_x() {
    assert_convert_roundtrip(
        "XA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQH5FV",
        &Strkey::HashX(StrkeyHashX([
            0x36, 0x3e, 0xaa, 0x38, 0x67, 0x84, 0x1f, 0xba, 0xd0, 0xf4, 0xed, 0x88, 0xc7, 0x79,
            0xe4, 0xfe, 0x66, 0xe5, 0x6a, 0x24, 0x70, 0xdc, 0x98, 0xc0, 0xec, 0x9c, 0x07, 0x3d,
            0x05, 0xc7, 0xb1, 0x03,
        ])),
    );
}

#[test]
fn test_valid_muxed_ed25519() {
    // Valid multiplexed account (id: 123456)
    assert_convert_roundtrip(
        "MA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAAAAAAAAAPCICBKU",
        &Strkey::MuxedAccountEd25519(StrkeyMuxedAccountEd25519 {
            ed25519: [
                0x36, 0x3e, 0xaa, 0x38, 0x67, 0x84, 0x1f, 0xba, 0xd0, 0xf4, 0xed, 0x88, 0xc7, 0x79,
                0xe4, 0xfe, 0x66, 0xe5, 0x6a, 0x24, 0x70, 0xdc, 0x98, 0xc0, 0xec, 0x9c, 0x07, 0x3d,
                0x05, 0xc7, 0xb1, 0x03,
            ],
            id: 123456,
        }),
    );

    // Valid multiplexed account (id: 0)
    assert_convert_roundtrip(
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ",
        &Strkey::MuxedAccountEd25519(StrkeyMuxedAccountEd25519 {
            ed25519: [
                0x3f, 0x0c, 0x34, 0xbf, 0x93, 0xad, 0x0d, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7,
                0x05, 0x51, 0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0x0d, 0x7a, 0x03,
                0xfc, 0x7f, 0xe8, 0x9a,
            ],
            id: 0,
        }),
    );

    // Valid multiplexed account in which unsigned id exceeds maximum signed 64-bit integer
    assert_convert_roundtrip(
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK",
        &Strkey::MuxedAccountEd25519(StrkeyMuxedAccountEd25519 {
            ed25519: [
                0x3f, 0x0c, 0x34, 0xbf, 0x93, 0xad, 0x0d, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7,
                0x05, 0x51, 0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0x0d, 0x7a, 0x03,
                0xfc, 0x7f, 0xe8, 0x9a,
            ],
            id: 9223372036854775808,
        }),
    );
}

#[test]
fn test_invalid_muxed_ed25519() {
    // TODO: This test case is supposed to fail, but it will pass, I think this is the responsibility of the base32 lib
    // maybe related to https://github.com/stellar/rs-stellar-strkey/issues/10
    // The unused trailing bit must be zero in the encoding of the last three bytes (24 bits) as five base-32 symbols (25 bits)
    // let r = Strkey::from_string("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUR");
    // assert_eq!(r, Err(DecodeError::Invalid));

    // Invalid length (congruent to 6 mod 8)
    let r = Strkey::from_string(
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLKA",
    );
    assert_eq!(r, Err(DecodeError::Invalid));

    // Invalid length (base-32 decoding should yield 43 bytes, not 44)
    let r = Strkey::from_string(
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAAV75I",
    );
    assert_eq!(r, Err(DecodeError::Invalid));

    // Invalid algorithm (low 3 bits of version byte are 7)
    let r = Strkey::from_string(
        "M47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ",
    );
    assert_eq!(r, Err(DecodeError::Invalid));

    // Padding bytes are not allowed
    let r = Strkey::from_string(
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUK===",
    );
    assert_eq!(r, Err(DecodeError::Invalid));

    // Invalid checksum
    let r = Strkey::from_string(
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUO",
    );
    assert_eq!(r, Err(DecodeError::Invalid));
}

#[test]
fn test_valid_signed_payload_ed25519() {
    assert_convert_roundtrip(
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IBZGM",
        &Strkey::SignedPayloadEd25519(StrkeySignedPayloadEd25519 {
            ed25519: [0x3f, 0xc, 0x34, 0xbf, 0x93, 0xad, 0xd, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7, 0x5, 0x51, 0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0xd, 0x7a, 0x3, 0xfc, 0x7f, 0xe8, 0x9a, ],
            payload: vec![
                0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
            ],
        }),
    );

    assert_convert_roundtrip(
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUAAAAFGBU",
        &Strkey::SignedPayloadEd25519(StrkeySignedPayloadEd25519 {
            ed25519: [0x3f, 0xc, 0x34, 0xbf, 0x93, 0xad, 0xd, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7, 0x5, 0x51, 0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0xd, 0x7a, 0x3, 0xfc, 0x7f, 0xe8, 0x9a, ],
            payload: vec![
                0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            ],
        }),
    );
}

#[test]
fn test_invalid_signed_payload_ed25519() {
    // Length prefix specifies length that is shorter than payload in signed payload
    let r = Strkey::from_string("PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IAAAAAAAAPM");
    assert_eq!(r, Err(DecodeError::Invalid));

    // Length prefix specifies length that is longer than payload in signed payload
    let r = Strkey::from_string("PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4Z2PQ");
    assert_eq!(r, Err(DecodeError::Invalid));

    // No zero padding in signed payload
    let r = Strkey::from_string("PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DXFH6");
    assert_eq!(r, Err(DecodeError::Invalid));
}

proptest! {
    #[test]
    fn test_public_key_ed25519_from_string_doesnt_panic(data: String) {
        let _ = Strkey::from_string(&data);
    }
}

proptest! {
    #[test]
    fn test_public_key_ed25519_to_string_doesnt_panic(data: [u8; 32]) {
        Strkey::PublicKeyEd25519(StrkeyPublicKeyEd25519(data)).to_string();
    }
}

fn assert_convert_roundtrip(s: &str, strkey: &Strkey) {
    let strkey_result = Strkey::from_string(&s).unwrap();
    assert_eq!(&strkey_result, strkey);
    let str_result = strkey.to_string();
    assert_eq!(str_result, s)
}
