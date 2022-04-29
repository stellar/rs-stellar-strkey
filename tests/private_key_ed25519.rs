use stellar_strkey::*;
extern crate proptest;
use proptest::prelude::*;

#[test]
fn test_public_key_ed25519_from_string() {
}

proptest! {
    #[test]
    fn test_public_key_ed25519_from_string_doesnt_panic(data: String) {
        let _ = Strkey::from_string(&data);
    }
}

#[test]
fn test_public_key_ed25519_to_string() {
}

proptest! {
    #[test]
    fn test_public_key_ed25519_to_string_doesnt_panic(data: [u8; 32]) {
        Strkey::PrivateKeyEd25519(data).to_string();
    }
}
