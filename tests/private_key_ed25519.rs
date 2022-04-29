use stellar_strkey::*;

extern crate proptest;

use proptest::prelude::*;

#[test]
fn test_private_key_ed25519_from_string() {
    // Valid private key
    let r = Strkey::from_string("SBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWHOKR");
    assert_eq!(
        r,
        Ok(Strkey::PrivateKeyEd25519([
            0x69, 0xa8, 0xc4, 0xcb, 0xb9, 0xf6, 0x4e, 0x8a, 0x07, 0x98, 0xf6, 0xe1, 0xac, 0x65,
            0xd0, 0x6c, 0x31, 0x62, 0x92, 0x90, 0x56, 0xbc, 0xf4, 0xcd, 0xb7, 0xd3, 0x73, 0x8d,
            0x18, 0x55, 0xf3, 0x63,
        ]))
    );

    //Invalid private key
    let r = Strkey::from_string("SAA6NXOBOXP3RXGAXBW6PGFI5BPK4ODVAWITS4VDOMN5C2M4B66ZML");
    assert_eq!(r, Err(DecodeError::Invalid));
}

proptest! {
    #[test]
    fn test_private_key_ed25519_from_string_doesnt_panic(data: String) {
        let _ = Strkey::from_string(&data);
    }
}

#[test]
fn test_private_key_ed25519_to_string() {
    // Valid private key
    let r = Strkey::PrivateKeyEd25519([
        0x69, 0xa8, 0xc4, 0xcb, 0xb9, 0xf6, 0x4e, 0x8a, 0x07, 0x98, 0xf6, 0xe1, 0xac, 0x65, 0xd0,
        0x6c, 0x31, 0x62, 0x92, 0x90, 0x56, 0xbc, 0xf4, 0xcd, 0xb7, 0xd3, 0x73, 0x8d, 0x18, 0x55,
        0xf3, 0x63,
    ])
    .to_string();
    assert_eq!(
        r,
        "SBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWHOKR",
    );
}

proptest! {
    #[test]
    fn test_private_key_ed25519_to_string_doesnt_panic(data: [u8; 32]) {
        Strkey::PrivateKeyEd25519(data).to_string();
    }
}
