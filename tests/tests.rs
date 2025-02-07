extern crate proptest;
use proptest::proptest;
use stellar_strkey::*;

#[test]
fn test_valid_public_keys() {
    // Valid account.
    assert_convert_roundtrip(
        "GA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQHES5",
        &Strkey::PublicKeyEd25519(ed25519::PublicKey([
            0x36, 0x3e, 0xaa, 0x38, 0x67, 0x84, 0x1f, 0xba, 0xd0, 0xf4, 0xed, 0x88, 0xc7, 0x79,
            0xe4, 0xfe, 0x66, 0xe5, 0x6a, 0x24, 0x70, 0xdc, 0x98, 0xc0, 0xec, 0x9c, 0x07, 0x3d,
            0x05, 0xc7, 0xb1, 0x03,
        ])),
    );

    // Valid account.
    assert_convert_roundtrip(
        "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ",
        &Strkey::PublicKeyEd25519(ed25519::PublicKey([
            0x3f, 0x0c, 0x34, 0xbf, 0x93, 0xad, 0x0d, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7,
            0x05, 0x51, 0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0x0d, 0x7a, 0x03,
            0xfc, 0x7f, 0xe8, 0x9a,
        ])),
    );
}

#[test]
fn test_invalid_public_keys() {
    // Invalid length (Ed25519 should be 32 bytes, not 5).
    let mut r: Result<Strkey, _> = "GAAAAAAAACGC6".parse();
    assert_eq!(r, Err(DecodeError::Invalid));

    // Invalid length (congruent to 1 mod 8).
    r = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZA".parse();
    assert_eq!(r, Err(DecodeError::Invalid));

    // Invalid length (base-32 decoding should yield 35 bytes, not 36).
    r = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUACUSI".parse();
    assert_eq!(r, Err(DecodeError::Invalid));

    // Invalid algorithm (low 3 bits of version byte are 7).
    r = "G47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVP2I".parse();
    assert_eq!(r, Err(DecodeError::Invalid));

    // Invalid length due to in stream padding bytes
    r = "G=3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQHES5".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
}

#[test]
fn test_valid_private_keys() {
    // Valid private key.
    assert_convert_roundtrip(
        "SBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWHOKR",
        &Strkey::PrivateKeyEd25519(ed25519::PrivateKey([
            0x69, 0xa8, 0xc4, 0xcb, 0xb9, 0xf6, 0x4e, 0x8a, 0x07, 0x98, 0xf6, 0xe1, 0xac, 0x65,
            0xd0, 0x6c, 0x31, 0x62, 0x92, 0x90, 0x56, 0xbc, 0xf4, 0xcd, 0xb7, 0xd3, 0x73, 0x8d,
            0x18, 0x55, 0xf3, 0x63,
        ])),
    );
}

#[test]
fn test_valid_pre_auth_tx() {
    assert_convert_roundtrip(
        "TBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWHXL7",
        &Strkey::PreAuthTx(PreAuthTx([
            0x69, 0xa8, 0xc4, 0xcb, 0xb9, 0xf6, 0x4e, 0x8a, 0x07, 0x98, 0xf6, 0xe1, 0xac, 0x65,
            0xd0, 0x6c, 0x31, 0x62, 0x92, 0x90, 0x56, 0xbc, 0xf4, 0xcd, 0xb7, 0xd3, 0x73, 0x8d,
            0x18, 0x55, 0xf3, 0x63,
        ])),
    );
}

#[test]
fn test_valid_hash_x() {
    assert_convert_roundtrip(
        "XBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWGTOG",
        &Strkey::HashX(HashX([
            0x69, 0xa8, 0xc4, 0xcb, 0xb9, 0xf6, 0x4e, 0x8a, 0x07, 0x98, 0xf6, 0xe1, 0xac, 0x65,
            0xd0, 0x6c, 0x31, 0x62, 0x92, 0x90, 0x56, 0xbc, 0xf4, 0xcd, 0xb7, 0xd3, 0x73, 0x8d,
            0x18, 0x55, 0xf3, 0x63,
        ])),
    );
}

#[test]
fn test_valid_muxed_ed25519() {
    // Valid multiplexed account (id: 123456)
    assert_convert_roundtrip(
        "MA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAAAAAAAAAPCICBKU",
        &Strkey::MuxedAccountEd25519(ed25519::MuxedAccount {
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
        &Strkey::MuxedAccountEd25519(ed25519::MuxedAccount {
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
        &Strkey::MuxedAccountEd25519(ed25519::MuxedAccount {
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
    let mut r: Result<Strkey, _>;

    // The unused trailing bit must be zero in the encoding of the last three
    // bytes (24 bits) as five base-32 symbols (25 bits)
    // 1000_ Q << The last character should be Q, because the last bit is unused, and in
    // 10001 R << the base32 alphabet 10000 maps to Q. 10001 maps to R.
    r = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUR".parse();
    assert_eq!(r, Err(DecodeError::Invalid));

    // Invalid length (congruent to 6 mod 8)
    r = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLKA".parse();
    assert_eq!(r, Err(DecodeError::Invalid));

    // Invalid length (base-32 decoding should yield 43 bytes, not 44)
    r = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAAV75I".parse();
    assert_eq!(r, Err(DecodeError::Invalid));

    // Invalid algorithm (low 3 bits of version byte are 7)
    r = "M47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ".parse();
    assert_eq!(r, Err(DecodeError::Invalid));

    // Padding bytes are not allowed
    r = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUK===".parse();
    assert_eq!(r, Err(DecodeError::Invalid));

    // Invalid checksum
    r = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUO".parse();
    assert_eq!(r, Err(DecodeError::Invalid));

    // Too short
    r = "MA7QYNF7SOWQ3GLR2DMLK".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
}

#[test]
fn test_valid_signed_payload_ed25519() {
    assert_convert_roundtrip(
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IBZGM",
        &Strkey::SignedPayloadEd25519(ed25519::SignedPayload {
            ed25519: [0x3f, 0xc, 0x34, 0xbf, 0x93, 0xad, 0xd, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7, 0x5, 0x51, 0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0xd, 0x7a, 0x3, 0xfc, 0x7f, 0xe8, 0x9a, ],
            payload: vec![
                0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
            ],
        }),
    );

    assert_convert_roundtrip(
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUAAAAFGBU",
        &Strkey::SignedPayloadEd25519(ed25519::SignedPayload {
            ed25519: [0x3f, 0xc, 0x34, 0xbf, 0x93, 0xad, 0xd, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7, 0x5, 0x51, 0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0xd, 0x7a, 0x3, 0xfc, 0x7f, 0xe8, 0x9a, ],
            payload: vec![
                0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            ],
        }),
    );

    // Unused trailing bits are zero
    // A signed payload with a 1 byte version, 32 byte key, and 4 byte length,
    // has the number of total bytes, total bits, and tail bits depending on its payload length:
    //
    // |Version|Key|Length|Payload|CRC|Total|Bits|Unused|
    // |------:|--:|-----:|------:|--:|----:|---:|-----:|
    // |      1| 32|     4|     16|  2|   55| 440|     0|
    // |      1| 32|     4|      4|  2|   43| 344|     1|
    // |      1| 32|     4|     12|  2|   51| 408|     2|
    // |      1| 32|     4|     20|  2|   59| 472|     3|
    // |      1| 32|     4|      8|  2|   47| 376|     4|
    //
    // Where:
    // - Unused bits are calculated as (5 - Bits % 5) % 5
    //
    // Examples using key:
    let ed25519 = [
        0x3f, 0xc, 0x34, 0xbf, 0x93, 0xad, 0xd, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7, 0x5,
        0x51, 0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0xd, 0x7a, 0x3, 0xfc, 0x7f,
        0xe8, 0x9a,
    ];
    // - 0 unused bits:
    assert_convert_roundtrip(
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAKB5",
        &Strkey::SignedPayloadEd25519(ed25519::SignedPayload {
            ed25519,
            payload: [0; 16].into(),
        }),
    );
    // - 1 unused bits:
    assert_convert_roundtrip(
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAACAAAAAABNWS",
        &Strkey::SignedPayloadEd25519(ed25519::SignedPayload {
            ed25519,
            payload: [0; 4].into(),
        }),
    );
    // - 2 unused bits:
    assert_convert_roundtrip(
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAGAAAAAAAAAAAAAAAAAAACTPY",
        &Strkey::SignedPayloadEd25519(ed25519::SignedPayload {
            ed25519,
            payload: [0; 12].into(),
        }),
    );
    // - 3 unused bits:
    assert_convert_roundtrip(
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALGXI",
        &Strkey::SignedPayloadEd25519(ed25519::SignedPayload {
            ed25519,
            payload: [0; 20].into(),
        }),
    );
    // - 4 unused bits:
    assert_convert_roundtrip(
        "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAEAAAAAAAAAAAAARKYQ",
        &Strkey::SignedPayloadEd25519(ed25519::SignedPayload {
            ed25519,
            payload: [0; 8].into(),
        }),
    );
}

#[test]
fn test_invalid_signed_payload_ed25519() {
    // Length prefix specifies length that is shorter than payload in signed payload
    let mut r: Result<Strkey, DecodeError>;
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IAAAAAAAAPM".parse();
    assert_eq!(r, Err(DecodeError::Invalid));

    // Length prefix specifies length that is longer than payload in signed payload
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4Z2PQ".parse();
    assert_eq!(r, Err(DecodeError::Invalid));

    // No zero padding in signed payload
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DXFH6".parse();
    assert_eq!(r, Err(DecodeError::Invalid));

    // Non-zero padding in signed payload
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAA4KVWLTJJFCJJFC7MPA7QYNF7SOWQ3GLR2GXUA7JUAAAAAEAAAAU".parse();
    assert_eq!(r, Err(DecodeError::Invalid));

    // Unused trailing bits must be zero (see valid test case for comparisons)
    // - 1 unused bits:
    //   1001_ S << The last character should be S, because the last bit is unused, and in
    //   10011 T << the base32 alphabet 10010 maps to S. 10011 maps to T.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAACAAAAAABNWT".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    // - 2 unused bits:
    //   110__ Y << The last character should be Y, because the last two bits are unused, and in
    //   11001 Z << the base32 alphabet 11000 maps to Y. 11001 maps to Z.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAGAAAAAAAAAAAAAAAAAAACTPZ"
        .parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   11010 2 << 11010 maps to 2.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAGAAAAAAAAAAAAAAAAAAACTP2"
        .parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   11011 3 << 11011 maps to 3.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAGAAAAAAAAAAAAAAAAAAACTP3"
        .parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    // - 3 unused bits:
    //   01___ I << The last character should be I, because the last three bits are unused, and in
    //   01001 J << the base32 alphabet 01000 maps to I. 01001 maps to J.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALGXJ".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   01010 J << 01010 maps to K.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALGXK".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   01011 L << 01011 maps to L.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALGXL".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   01100 M << 01100 maps to M.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALGXM".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   01101 N << 01101 maps to N.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALGXN".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   01110 O << 01110 maps to O.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALGXO".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   01111 P << 01111 maps to P.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALGXP".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    // - 4 unused bits:
    //   1____ Q << The last character should be Q, because the last four bits are unused, and in
    //   10001 R << the base32 alphabet 10000 maps to Q. 10001 maps to R.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAEAAAAAAAAAAAAARKYR".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   10010 S << 10010 maps to S.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAEAAAAAAAAAAAAARKYS".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   10011 T << 10011 maps to T.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAEAAAAAAAAAAAAARKYT".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   10100 U << 10100 maps to U.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAEAAAAAAAAAAAAARKYU".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   10101 V << 10101 maps to V.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAEAAAAAAAAAAAAARKYV".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   10110 W << 10110 maps to W.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAEAAAAAAAAAAAAARKYW".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   10111 X << 10111 maps to X.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAEAAAAAAAAAAAAARKYX".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   11000 Y << 11000 maps to Y.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAEAAAAAAAAAAAAARKYY".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   11001 Z << 11001 maps to Z.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAEAAAAAAAAAAAAARKYZ".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   11010 2 << 11010 maps to 2.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAEAAAAAAAAAAAAARKY2".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   11011 3 << 11011 maps to 3.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAEAAAAAAAAAAAAARKY3".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   11100 4 << 11100 maps to 4.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAEAAAAAAAAAAAAARKY4".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   11101 5 << 11101 maps to 5.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAEAAAAAAAAAAAAARKY5".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   11110 6 << 11110 maps to 6.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAEAAAAAAAAAAAAARKY6".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
    //   11111 7 << 11111 maps to 7.
    r = "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAEAAAAAAAAAAAAARKY7".parse();
    assert_eq!(r, Err(DecodeError::Invalid));
}

#[test]
fn test_signed_payload_ed25519_payload_sizes() {
    for payload_size in 1..=64 {
        let mut payload = vec![0; payload_size];
        (0..payload_size).for_each(|i| {
            payload[i] = i as u8;
        });

        let signed_payload = Strkey::SignedPayloadEd25519(ed25519::SignedPayload {
            ed25519: [
                0x3f, 0xc, 0x34, 0xbf, 0x93, 0xad, 0xd, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7,
                0x5, 0x51, 0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0xd, 0x7a, 0x3,
                0xfc, 0x7f, 0xe8, 0x9a,
            ],
            payload,
        });

        let encoded = signed_payload.to_string();
        let decoded = Strkey::from_string(&encoded).unwrap();
        assert_eq!(signed_payload, decoded);
    }
}

#[test]
#[should_panic(expected = "payload length larger than u32::MAX")]
fn test_signed_payload_ed25519_payload_length_larger_than_u32_max_panic() {
    let payload = vec![0; u32::MAX as usize + 1];
    let signed_payload = Strkey::SignedPayloadEd25519(ed25519::SignedPayload {
        ed25519: [
            0x3f, 0xc, 0x34, 0xbf, 0x93, 0xad, 0xd, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7, 0x5,
            0x51, 0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0xd, 0x7a, 0x3, 0xfc, 0x7f,
            0xe8, 0x9a,
        ],
        payload,
    });
    signed_payload.to_string();
}

#[test]
fn test_valid_contract() {
    assert_convert_roundtrip(
        "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE",
        &Strkey::Contract(Contract([
            0x36, 0x3e, 0xaa, 0x38, 0x67, 0x84, 0x1f, 0xba, 0xd0, 0xf4, 0xed, 0x88, 0xc7, 0x79,
            0xe4, 0xfe, 0x66, 0xe5, 0x6a, 0x24, 0x70, 0xdc, 0x98, 0xc0, 0xec, 0x9c, 0x07, 0x3d,
            0x05, 0xc7, 0xb1, 0x03,
        ])),
    );

    assert_convert_roundtrip(
        "CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA",
        &Strkey::Contract(Contract([
            0x3f, 0x0c, 0x34, 0xbf, 0x93, 0xad, 0x0d, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7,
            0x05, 0x51, 0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0x0d, 0x7a, 0x03,
            0xfc, 0x7f, 0xe8, 0x9a,
        ])),
    );
}

#[test]
fn test_signed_payload_from_string_doesnt_panic_with_unbounded_size() {
    let payload: Vec<u8> = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let r = stellar_strkey::ed25519::SignedPayload::from_payload(&payload);
    assert_eq!(r, Err(DecodeError::Invalid));
}

#[test]
fn test_valid_liquidity_pool() {
    assert_convert_roundtrip(
        "LA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGZ5J",
        &Strkey::LiquidityPool(LiquidityPool([
            0x36, 0x3e, 0xaa, 0x38, 0x67, 0x84, 0x1f, 0xba, 0xd0, 0xf4, 0xed, 0x88, 0xc7, 0x79,
            0xe4, 0xfe, 0x66, 0xe5, 0x6a, 0x24, 0x70, 0xdc, 0x98, 0xc0, 0xec, 0x9c, 0x07, 0x3d,
            0x05, 0xc7, 0xb1, 0x03,
        ])),
    );

    assert_convert_roundtrip(
        "LA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUPJN",
        &Strkey::LiquidityPool(LiquidityPool([
            0x3f, 0x0c, 0x34, 0xbf, 0x93, 0xad, 0x0d, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7,
            0x05, 0x51, 0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0x0d, 0x7a, 0x03,
            0xfc, 0x7f, 0xe8, 0x9a,
        ])),
    );
}

#[test]
fn test_invalid_liquidity_pool() {
    // TODO: Add invalid liquidity pool tests
}

#[test]
fn test_valid_claimable_balance() {
    assert_convert_roundtrip(
        "BAADMPVKHBTYIH522D2O3CGHPHSP4ZXFNISHBXEYYDWJYBZ5AXD3CA3GDE",
        &Strkey::ClaimableBalance(ClaimableBalance::V0([
            0x36, 0x3e, 0xaa, 0x38, 0x67, 0x84, 0x1f, 0xba, 0xd0, 0xf4, 0xed, 0x88, 0xc7, 0x79,
            0xe4, 0xfe, 0x66, 0xe5, 0x6a, 0x24, 0x70, 0xdc, 0x98, 0xc0, 0xec, 0x9c, 0x07, 0x3d,
            0x05, 0xc7, 0xb1, 0x03,
        ])),
    );
    assert_convert_roundtrip(
        "BAAD6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGR4TU",
        &Strkey::ClaimableBalance(ClaimableBalance::V0([
            0x3f, 0x0c, 0x34, 0xbf, 0x93, 0xad, 0x0d, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7,
            0x05, 0x51, 0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0x0d, 0x7a, 0x03,
            0xfc, 0x7f, 0xe8, 0x9a,
        ])),
    );
}

#[test]
fn test_invalid_claimable_balances() {
    // TODO: Add invalid claimable balance tests
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
        Strkey::PublicKeyEd25519(ed25519::PublicKey(data)).to_string();
    }
}

fn assert_convert_roundtrip(s: &str, strkey: &Strkey) {
    let strkey_result = Strkey::from_string(s).unwrap();
    assert_eq!(&strkey_result, strkey);
    let str_result = format!("{strkey}");
    assert_eq!(s, str_result)
}
