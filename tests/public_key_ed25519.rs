use stellar_strkey::*;
extern crate proptest;
use proptest::prelude::*;

#[test]
fn test_public_key_ed25519_from_string() {
    // Valid account.
    let r = Strkey::from_string("GA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQHES5");
    assert_eq!(
        r,
        Ok(Strkey::PublicKey(PublicKey::Ed25519(PublicKeyEd25519([
            0x36, 0x3e, 0xaa, 0x38, 0x67, 0x84, 0x1f, 0xba, 0xd0, 0xf4, 0xed, 0x88, 0xc7, 0x79,
            0xe4, 0xfe, 0x66, 0xe5, 0x6a, 0x24, 0x70, 0xdc, 0x98, 0xc0, 0xec, 0x9c, 0x07, 0x3d,
            0x05, 0xc7, 0xb1, 0x03,
        ]))))
    );

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

proptest! {
    #[test]
    fn test_public_key_ed25519_from_string_doesnt_panic(data: String) {
        let _ = Strkey::from_string(&data);
    }
}

#[test]
fn test_public_key_ed25519_to_string() {
    // Valid account.
    let r = Strkey::PublicKey(PublicKey::Ed25519(PublicKeyEd25519([
        0x36, 0x3e, 0xaa, 0x38, 0x67, 0x84, 0x1f, 0xba, 0xd0, 0xf4, 0xed, 0x88, 0xc7, 0x79, 0xe4,
        0xfe, 0x66, 0xe5, 0x6a, 0x24, 0x70, 0xdc, 0x98, 0xc0, 0xec, 0x9c, 0x07, 0x3d, 0x05, 0xc7,
        0xb1, 0x03,
    ])))
    .to_string();
    assert_eq!(
        r,
        "GA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQHES5",
    );
}

proptest! {
    #[test]
    fn test_public_key_ed25519_to_string_doesnt_panic(data: [u8; 32]) {
        Strkey::PublicKey(PublicKey::Ed25519(PublicKeyEd25519(data))).to_string();
    }
}
