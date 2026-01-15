#![cfg(feature = "cli")]

use stellar_strkey::{ed25519, *};

#[test]
fn test_ed25519_public_key() {
    assert_eq!(
        serde_json::to_string_pretty(&Decoded(&Strkey::PublicKeyEd25519(ed25519::PublicKey([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]))))
        .unwrap(),
        r#"{
  "public_key_ed25519": "0000000000000000000000000000000000000000000000000000000000000000"
}"#,
    );
}

#[test]
fn test_ed25519_private_key() {
    assert_eq!(
        serde_json::to_string_pretty(&Decoded(&Strkey::PrivateKeyEd25519(ed25519::PrivateKey([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]))))
        .unwrap(),
        r#"{
  "private_key_ed25519": "0000000000000000000000000000000000000000000000000000000000000000"
}"#,
    );
}

#[test]
fn test_contract() {
    assert_eq!(
        serde_json::to_string_pretty(&Decoded(&Strkey::Contract(Contract([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]))))
        .unwrap(),
        r#"{
  "contract": "0000000000000000000000000000000000000000000000000000000000000000"
}"#,
    );
}

#[test]
fn test_hash_x() {
    assert_eq!(
        serde_json::to_string_pretty(&Decoded(&Strkey::HashX(HashX([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]))))
        .unwrap(),
        r#"{
  "hash_x": "0000000000000000000000000000000000000000000000000000000000000000"
}"#,
    );
}

#[test]
fn test_pre_auth_tx() {
    assert_eq!(
        serde_json::to_string_pretty(&Decoded(&Strkey::PreAuthTx(PreAuthTx([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]))))
        .unwrap(),
        r#"{
  "pre_auth_tx": "0000000000000000000000000000000000000000000000000000000000000000"
}"#,
    );
}

#[test]
fn test_ed25519_muxed_account() {
    assert_eq!(
        serde_json::to_string_pretty(&Decoded(&Strkey::MuxedAccountEd25519(
            ed25519::MuxedAccount {
                ed25519: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                id: 0,
            }
        )))
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
        serde_json::to_string_pretty(&Decoded(&Strkey::SignedPayloadEd25519(
            ed25519::SignedPayload {
                ed25519: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                payload: heapless::Vec::from_slice(&[1, 2, 3, 4]).unwrap(),
            }
        )))
        .unwrap(),
        r#"{
  "signed_payload_ed25519": {
    "ed25519": "0000000000000000000000000000000000000000000000000000000000000000",
    "payload": "01020304"
  }
}"#,
    );
}

#[test]
fn test_roundtrip_muxed_account() {
    let original = Strkey::MuxedAccountEd25519(ed25519::MuxedAccount {
        ed25519: [0x00; 32],
        id: 42,
    });
    let json = serde_json::to_string(&Decoded(&original)).unwrap();
    let Decoded(deserialized): Decoded<Strkey> = serde_json::from_str(&json).unwrap();
    assert_eq!(original, deserialized);
}

#[test]
fn test_roundtrip_signed_payload() {
    let original = Strkey::SignedPayloadEd25519(ed25519::SignedPayload {
        ed25519: [0x00; 32],
        payload: heapless::Vec::from_slice(&[1, 2, 3, 4]).unwrap(),
    });
    let json = serde_json::to_string(&Decoded(&original)).unwrap();
    let Decoded(deserialized): Decoded<Strkey> = serde_json::from_str(&json).unwrap();
    assert_eq!(original, deserialized);
}

#[test]
fn test_roundtrip_claimable_balance() {
    let original = Strkey::ClaimableBalance(ClaimableBalance::V0([0x00; 32]));
    let json = serde_json::to_string(&Decoded(&original)).unwrap();
    let Decoded(deserialized): Decoded<Strkey> = serde_json::from_str(&json).unwrap();
    assert_eq!(original, deserialized);
}
