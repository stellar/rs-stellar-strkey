#![cfg(feature = "cli")]

use stellar_strkey::*;

#[test]
fn test_ed25519_public_key() {
    assert_eq!(
        serde_json::to_string_pretty(&Strkey::PublicKeyEd25519(ed25519::PublicKey([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ])))
        .unwrap(),
        r#"{
  "public_key_ed25519": "0000000000000000000000000000000000000000000000000000000000000000"
}"#,
    );
}

#[test]
fn test_ed25519_private_key() {
    assert_eq!(
        serde_json::to_string_pretty(&Strkey::PrivateKeyEd25519(ed25519::PrivateKey([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ])))
        .unwrap(),
        r#"{
  "private_key_ed25519": "0000000000000000000000000000000000000000000000000000000000000000"
}"#,
    );
}

#[test]
fn test_contract() {
    assert_eq!(
        serde_json::to_string_pretty(&Strkey::Contract(Contract([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ])))
        .unwrap(),
        r#"{
  "contract": "0000000000000000000000000000000000000000000000000000000000000000"
}"#,
    );
}

#[test]
fn test_hash_x() {
    assert_eq!(
        serde_json::to_string_pretty(&Strkey::HashX(HashX([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ])))
        .unwrap(),
        r#"{
  "hash_x": "0000000000000000000000000000000000000000000000000000000000000000"
}"#,
    );
}

#[test]
fn test_pre_auth_tx() {
    assert_eq!(
        serde_json::to_string_pretty(&Strkey::PreAuthTx(PreAuthTx([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ])))
        .unwrap(),
        r#"{
  "pre_auth_tx": "0000000000000000000000000000000000000000000000000000000000000000"
}"#,
    );
}

#[test]
fn test_ed25519_muxed_account() {
    assert_eq!(
        serde_json::to_string_pretty(&Strkey::MuxedAccountEd25519(ed25519::MuxedAccount {
            ed25519: [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            id: 0,
        }))
        .unwrap(),
        r#"{
  "muxed_account_ed25519": {
    "ed25519": "0000000000000000000000000000000000000000000000000000000000000000",
    "id": 0
  }
}"#,
    );
}

#[test]
fn test_ed25519_signed_payload() {
    assert_eq!(
        serde_json::to_string_pretty(&Strkey::SignedPayloadEd25519(ed25519::SignedPayload {
            ed25519: [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            payload: [1, 2, 3, 4].into(),
        }))
        .unwrap(),
        r#"{
  "signed_payload_ed25519": {
    "ed25519": "0000000000000000000000000000000000000000000000000000000000000000",
    "payload": "01020304"
  }
}"#,
    );
}
