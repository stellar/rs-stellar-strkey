use stellar_strkey::{
    ed25519::{MuxedAccount, PrivateKey, PublicKey, SignedPayload},
    ClaimableBalance, Contract, DecodeError, HashX, LiquidityPool, MuxedContract, PreAuthTx,
};

// ============================================================================
// Standard Valid Strkey Samples Across All 10 Supported Types
// ============================================================================

const VALID_PUBLIC_KEY_1: &str = "GA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQHES5";
const VALID_PUBLIC_KEY_2: &str = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";

const VALID_PRIVATE_KEY: &str = "SBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWHOKR";

const VALID_PRE_AUTH_TX: &str = "TBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWHXL7";

const VALID_HASH_X: &str = "XBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWGTOG";

const VALID_MUXED_ACCOUNT_1: &str =
    "MA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAAAAAAAAAPCICBKU";
const VALID_MUXED_ACCOUNT_2: &str =
    "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ";
const VALID_MUXED_ACCOUNT_3: &str =
    "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK";

const VALID_SIGNED_PAYLOAD_1: &str =
    "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IBZGM";
const VALID_SIGNED_PAYLOAD_2: &str =
    "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUAAAAFGBU";

const VALID_CONTRACT_1: &str = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";
const VALID_CONTRACT_2: &str = "CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA";

const VALID_LIQUIDITY_POOL_1: &str = "LA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGZ5J";
const VALID_LIQUIDITY_POOL_2: &str = "LA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUPJN";

const VALID_CLAIMABLE_BALANCE_1: &str =
    "BAADMPVKHBTYIH522D2O3CGHPHSP4ZXFNISHBXEYYDWJYBZ5AXD3CA3GDE";
const VALID_CLAIMABLE_BALANCE_2: &str =
    "BAAD6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGR4TU";

const VALID_MUXED_CONTRACT_1: &str =
    "WA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAAAAAAAAAPCIA6IG";
const VALID_MUXED_CONTRACT_2: &str =
    "WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWC";
const VALID_MUXED_CONTRACT_3: &str =
    "WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAACWJY";

// Sample byte payloads
const SAMPLE_PAYLOAD_1: [u8; 32] = [
    0x36, 0x3e, 0xaa, 0x38, 0x67, 0x84, 0x1f, 0xba, 0xd0, 0xf4, 0xed, 0x88, 0xc7, 0x79, 0xe4, 0xfe,
    0x66, 0xe5, 0x6a, 0x24, 0x70, 0xdc, 0x98, 0xc0, 0xec, 0x9c, 0x07, 0x3d, 0x05, 0xc7, 0xb1, 0x03,
];

const SAMPLE_PAYLOAD_2: [u8; 32] = [
    0x3f, 0x0c, 0x34, 0xbf, 0x93, 0xad, 0x0d, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7, 0x05, 0x51,
    0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0x0d, 0x7a, 0x03, 0xfc, 0x7f, 0xe8, 0x9a,
];

const SAMPLE_PAYLOAD_3: [u8; 32] = [
    0x69, 0xa8, 0xc4, 0xcb, 0xb9, 0xf6, 0x4e, 0x8a, 0x07, 0x98, 0xf6, 0xe1, 0xac, 0x65, 0xd0, 0x6c,
    0x31, 0x62, 0x92, 0x90, 0x56, 0xbc, 0xf4, 0xcd, 0xb7, 0xd3, 0x73, 0x8d, 0x18, 0x55, 0xf3, 0x63,
];

// One representative valid strkey sample for each of the 10 types
const ALL_10_TYPE_REPRESENTATIVES: &[&str] = &[
    VALID_PUBLIC_KEY_1,
    VALID_PRIVATE_KEY,
    VALID_PRE_AUTH_TX,
    VALID_HASH_X,
    VALID_MUXED_ACCOUNT_1,
    VALID_SIGNED_PAYLOAD_1,
    VALID_CONTRACT_1,
    VALID_LIQUIDITY_POOL_1,
    VALID_CLAIMABLE_BALANCE_1,
    VALID_MUXED_CONTRACT_1,
];

// ============================================================================
// 1. ed25519::PublicKey::from_string
// ============================================================================

#[test]
fn test_public_key_from_string_valid() {
    let key1 = PublicKey::from_string(VALID_PUBLIC_KEY_1).unwrap();
    assert_eq!(key1.0, SAMPLE_PAYLOAD_1);
    assert_eq!(key1.to_string().as_str(), VALID_PUBLIC_KEY_1);

    let key2 = PublicKey::from_string(VALID_PUBLIC_KEY_2).unwrap();
    assert_eq!(key2.0, SAMPLE_PAYLOAD_2);
    assert_eq!(key2.to_string().as_str(), VALID_PUBLIC_KEY_2);
}

#[test]
fn test_public_key_from_string_invalid() {
    // Too long strkey input
    assert_eq!(
        PublicKey::from_string("GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJV75ERQ"),
        Err(DecodeError::TooLong)
    );
    // Invalid length (payload smaller than 32 bytes)
    assert_eq!(
        PublicKey::from_string("GAAAAAAAACGC6"),
        Err(DecodeError::InvalidPayloadLength)
    );
    // Invalid base32 character
    assert_eq!(
        PublicKey::from_string("GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZA"),
        Err(DecodeError::InvalidBase32)
    );
    // Unsupported version byte
    assert_eq!(
        PublicKey::from_string("G47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVP2I"),
        Err(DecodeError::UnsupportedVersion)
    );
    // In-stream padding bytes
    assert_eq!(
        PublicKey::from_string("G=3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQHES5"),
        Err(DecodeError::InvalidBase32)
    );
    // Empty and too short
    assert_eq!(PublicKey::from_string(""), Err(DecodeError::TooShort));
    assert_eq!(PublicKey::from_string("AAAA"), Err(DecodeError::TooShort));
}

#[test]
fn test_public_key_from_string_rejects_other_strkey_types() {
    for &sample in ALL_10_TYPE_REPRESENTATIVES {
        let res = PublicKey::from_string(sample);
        if sample == VALID_PUBLIC_KEY_1 {
            assert!(res.is_ok());
        } else {
            assert!(
                res.is_err(),
                "PublicKey::from_string unexpectedly accepted {sample}"
            );
        }
    }
}

// ============================================================================
// 2. ed25519::PrivateKey::from_string
// ============================================================================

#[test]
fn test_private_key_from_string_valid() {
    let key = PrivateKey::from_string(VALID_PRIVATE_KEY).unwrap();
    assert_eq!(key.0, SAMPLE_PAYLOAD_3);
    assert_eq!(
        format!("{}", key.as_unredacted()).as_str(),
        VALID_PRIVATE_KEY
    );
}

#[test]
fn test_private_key_from_string_invalid() {
    // Too short (31 bytes payload instead of 32)
    assert_eq!(
        PrivateKey::from_string("SA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UALAI"),
        Err(DecodeError::InvalidPayloadLength)
    );
    // Too long (33 bytes payload instead of 32)
    assert_eq!(
        PrivateKey::from_string("SBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWHS74FQ"),
        Err(DecodeError::TooLong)
    );
    // Invalid base32
    assert_eq!(
        PrivateKey::from_string("SBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWHOKRA"),
        Err(DecodeError::InvalidBase32)
    );
    // Empty and too short
    assert_eq!(PrivateKey::from_string(""), Err(DecodeError::TooShort));
    assert_eq!(PrivateKey::from_string("AAAA"), Err(DecodeError::TooShort));
}

#[test]
fn test_private_key_from_string_rejects_other_strkey_types() {
    for &sample in ALL_10_TYPE_REPRESENTATIVES {
        let res = PrivateKey::from_string(sample);
        if sample == VALID_PRIVATE_KEY {
            assert!(res.is_ok());
        } else {
            assert!(
                res.is_err(),
                "PrivateKey::from_string unexpectedly accepted {sample}"
            );
        }
    }
}

// ============================================================================
// 3. PreAuthTx::from_string
// ============================================================================

#[test]
fn test_pre_auth_tx_from_string_valid() {
    let tx = PreAuthTx::from_string(VALID_PRE_AUTH_TX).unwrap();
    assert_eq!(tx.0, SAMPLE_PAYLOAD_3);
    assert_eq!(tx.to_string().as_str(), VALID_PRE_AUTH_TX);
}

#[test]
fn test_pre_auth_tx_from_string_invalid() {
    // Too long
    assert_eq!(
        PreAuthTx::from_string("TA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJV73QGA"),
        Err(DecodeError::TooLong)
    );
    // Empty and too short
    assert_eq!(PreAuthTx::from_string(""), Err(DecodeError::TooShort));
    assert_eq!(PreAuthTx::from_string("AAAA"), Err(DecodeError::TooShort));
}

#[test]
fn test_pre_auth_tx_from_string_rejects_other_strkey_types() {
    for &sample in ALL_10_TYPE_REPRESENTATIVES {
        let res = PreAuthTx::from_string(sample);
        if sample == VALID_PRE_AUTH_TX {
            assert!(res.is_ok());
        } else {
            assert!(
                res.is_err(),
                "PreAuthTx::from_string unexpectedly accepted {sample}"
            );
        }
    }
}

// ============================================================================
// 4. HashX::from_string
// ============================================================================

#[test]
fn test_hash_x_from_string_valid() {
    let hash = HashX::from_string(VALID_HASH_X).unwrap();
    assert_eq!(hash.0, SAMPLE_PAYLOAD_3);
    assert_eq!(hash.to_string().as_str(), VALID_HASH_X);
}

#[test]
fn test_hash_x_from_string_invalid() {
    // Too long
    assert_eq!(
        HashX::from_string("XA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJV2S4BA"),
        Err(DecodeError::TooLong)
    );
    // Empty and too short
    assert_eq!(HashX::from_string(""), Err(DecodeError::TooShort));
    assert_eq!(HashX::from_string("AAAA"), Err(DecodeError::TooShort));
}

#[test]
fn test_hash_x_from_string_rejects_other_strkey_types() {
    for &sample in ALL_10_TYPE_REPRESENTATIVES {
        let res = HashX::from_string(sample);
        if sample == VALID_HASH_X {
            assert!(res.is_ok());
        } else {
            assert!(
                res.is_err(),
                "HashX::from_string unexpectedly accepted {sample}"
            );
        }
    }
}

// ============================================================================
// 5. Contract::from_string
// ============================================================================

#[test]
fn test_contract_from_string_valid() {
    let c1 = Contract::from_string(VALID_CONTRACT_1).unwrap();
    assert_eq!(c1.0, SAMPLE_PAYLOAD_1);
    assert_eq!(c1.to_string().as_str(), VALID_CONTRACT_1);

    let c2 = Contract::from_string(VALID_CONTRACT_2).unwrap();
    assert_eq!(c2.0, SAMPLE_PAYLOAD_2);
    assert_eq!(c2.to_string().as_str(), VALID_CONTRACT_2);
}

#[test]
fn test_contract_from_string_invalid() {
    // Too long strkey input
    assert_eq!(
        Contract::from_string("CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJV72WFI"),
        Err(DecodeError::TooLong)
    );
    // Empty and too short
    assert_eq!(Contract::from_string(""), Err(DecodeError::TooShort));
    assert_eq!(Contract::from_string("AAAA"), Err(DecodeError::TooShort));
}

#[test]
fn test_contract_from_string_rejects_other_strkey_types() {
    for &sample in ALL_10_TYPE_REPRESENTATIVES {
        let res = Contract::from_string(sample);
        if sample == VALID_CONTRACT_1 {
            assert!(res.is_ok());
        } else {
            assert!(
                res.is_err(),
                "Contract::from_string unexpectedly accepted {sample}"
            );
        }
    }
}

// ============================================================================
// 6. LiquidityPool::from_string
// ============================================================================

#[test]
fn test_liquidity_pool_from_string_valid() {
    let lp1 = LiquidityPool::from_string(VALID_LIQUIDITY_POOL_1).unwrap();
    assert_eq!(lp1.0, SAMPLE_PAYLOAD_1);
    assert_eq!(lp1.to_string().as_str(), VALID_LIQUIDITY_POOL_1);

    let lp2 = LiquidityPool::from_string(VALID_LIQUIDITY_POOL_2).unwrap();
    assert_eq!(lp2.0, SAMPLE_PAYLOAD_2);
    assert_eq!(lp2.to_string().as_str(), VALID_LIQUIDITY_POOL_2);
}

#[test]
fn test_liquidity_pool_from_string_invalid() {
    // Too long strkey input
    assert_eq!(
        LiquidityPool::from_string("LA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJV7Z72Y"),
        Err(DecodeError::TooLong)
    );
    // Invalid length (5 bytes payload instead of 32)
    assert_eq!(
        LiquidityPool::from_string("LAAAAAAAADLH2"),
        Err(DecodeError::InvalidPayloadLength)
    );
    // Invalid base32
    assert_eq!(
        LiquidityPool::from_string("LA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUPJNA"),
        Err(DecodeError::InvalidBase32)
    );
    // Unsupported version
    assert_eq!(
        LiquidityPool::from_string("L47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUSV4"),
        Err(DecodeError::UnsupportedVersion)
    );
    // Empty and too short
    assert_eq!(LiquidityPool::from_string(""), Err(DecodeError::TooShort));
    assert_eq!(
        LiquidityPool::from_string("AAAA"),
        Err(DecodeError::TooShort)
    );
}

#[test]
fn test_liquidity_pool_from_string_rejects_other_strkey_types() {
    for &sample in ALL_10_TYPE_REPRESENTATIVES {
        let res = LiquidityPool::from_string(sample);
        if sample == VALID_LIQUIDITY_POOL_1 {
            assert!(res.is_ok());
        } else {
            assert!(
                res.is_err(),
                "LiquidityPool::from_string unexpectedly accepted {sample}"
            );
        }
    }
}

// ============================================================================
// 7. ClaimableBalance::from_string
// ============================================================================

#[test]
fn test_claimable_balance_from_string_valid() {
    let cb1 = ClaimableBalance::from_string(VALID_CLAIMABLE_BALANCE_1).unwrap();
    match cb1 {
        ClaimableBalance::V0(hash) => assert_eq!(hash, SAMPLE_PAYLOAD_1),
    }
    assert_eq!(cb1.to_string().as_str(), VALID_CLAIMABLE_BALANCE_1);

    let cb2 = ClaimableBalance::from_string(VALID_CLAIMABLE_BALANCE_2).unwrap();
    match cb2 {
        ClaimableBalance::V0(hash) => assert_eq!(hash, SAMPLE_PAYLOAD_2),
    }
    assert_eq!(cb2.to_string().as_str(), VALID_CLAIMABLE_BALANCE_2);
}

#[test]
fn test_claimable_balance_from_string_invalid() {
    // Too long payload
    assert_eq!(
        ClaimableBalance::from_string(
            "BAAD6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGX74RYA"
        ),
        Err(DecodeError::TooLong)
    );
    // Invalid length (6 bytes payload instead of 33)
    assert_eq!(
        ClaimableBalance::from_string("BAAAAAAAAAAK3EY"),
        Err(DecodeError::InvalidPayloadLength)
    );
    // Empty and too short
    assert_eq!(
        ClaimableBalance::from_string(""),
        Err(DecodeError::TooShort)
    );
    assert_eq!(
        ClaimableBalance::from_string("AAAA"),
        Err(DecodeError::TooShort)
    );
}

#[test]
fn test_claimable_balance_from_string_rejects_other_strkey_types() {
    for &sample in ALL_10_TYPE_REPRESENTATIVES {
        let res = ClaimableBalance::from_string(sample);
        if sample == VALID_CLAIMABLE_BALANCE_1 {
            assert!(res.is_ok());
        } else {
            assert!(
                res.is_err(),
                "ClaimableBalance::from_string unexpectedly accepted {sample}"
            );
        }
    }
}

// ============================================================================
// 8. ed25519::MuxedAccount::from_string
// ============================================================================

#[test]
fn test_muxed_account_from_string_valid() {
    let muxed1 = MuxedAccount::from_string(VALID_MUXED_ACCOUNT_1).unwrap();
    assert_eq!(muxed1.ed25519, SAMPLE_PAYLOAD_1);
    assert_eq!(muxed1.id, 123456);
    assert_eq!(muxed1.to_string().as_str(), VALID_MUXED_ACCOUNT_1);

    let muxed2 = MuxedAccount::from_string(VALID_MUXED_ACCOUNT_2).unwrap();
    assert_eq!(muxed2.ed25519, SAMPLE_PAYLOAD_2);
    assert_eq!(muxed2.id, 0);
    assert_eq!(muxed2.to_string().as_str(), VALID_MUXED_ACCOUNT_2);

    let muxed3 = MuxedAccount::from_string(VALID_MUXED_ACCOUNT_3).unwrap();
    assert_eq!(muxed3.ed25519, SAMPLE_PAYLOAD_2);
    assert_eq!(muxed3.id, 9223372036854775808);
    assert_eq!(muxed3.to_string().as_str(), VALID_MUXED_ACCOUNT_3);
}

#[test]
fn test_muxed_account_from_string_invalid() {
    // Too long input (more than 43 bytes decoded)
    assert_eq!(
        MuxedAccount::from_string(
            "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUERUKZ4JVTO6777RIDA"
        ),
        Err(DecodeError::TooLong)
    );
    // Invalid base32 unused trailing bit
    assert_eq!(
        MuxedAccount::from_string(
            "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUR"
        ),
        Err(DecodeError::InvalidBase32)
    );
    // Invalid length (congruent to 6 mod 8)
    assert_eq!(
        MuxedAccount::from_string(
            "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLKA"
        ),
        Err(DecodeError::InvalidBase32)
    );
    // Invalid algorithm with recomputed checksum
    assert_eq!(
        MuxedAccount::from_string(
            "M47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAABIFE"
        ),
        Err(DecodeError::UnsupportedVersion)
    );
    // Invalid checksum
    assert_eq!(
        MuxedAccount::from_string(
            "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUO"
        ),
        Err(DecodeError::ChecksumMismatch)
    );
    // Too short payload
    assert_eq!(
        MuxedAccount::from_string("MA7QYNF7SOWQ3GLR2DMLK"),
        Err(DecodeError::InvalidPayloadLength)
    );
    // Empty and too short
    assert_eq!(MuxedAccount::from_string(""), Err(DecodeError::TooShort));
    assert_eq!(
        MuxedAccount::from_string("AAAA"),
        Err(DecodeError::TooShort)
    );
}

#[test]
fn test_muxed_account_from_string_rejects_other_strkey_types() {
    for &sample in ALL_10_TYPE_REPRESENTATIVES {
        let res = MuxedAccount::from_string(sample);
        if sample == VALID_MUXED_ACCOUNT_1 {
            assert!(res.is_ok());
        } else {
            assert!(
                res.is_err(),
                "MuxedAccount::from_string unexpectedly accepted {sample}"
            );
        }
    }
}

// ============================================================================
// 9. ed25519::SignedPayload::from_string
// ============================================================================

#[test]
fn test_signed_payload_from_string_valid() {
    let sp1 = SignedPayload::from_string(VALID_SIGNED_PAYLOAD_1).unwrap();
    assert_eq!(
        sp1.ed25519(),
        &[
            0x3f, 0xc, 0x34, 0xbf, 0x93, 0xad, 0xd, 0x99, 0x71, 0xd0, 0x4c, 0xcc, 0x90, 0xf7, 0x5,
            0x51, 0x1c, 0x83, 0x8a, 0xad, 0x97, 0x34, 0xa4, 0xa2, 0xfb, 0xd, 0x7a, 0x3, 0xfc, 0x7f,
            0xe8, 0x9a,
        ]
    );
    assert_eq!(
        sp1.payload(),
        &[
            0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
            0x20,
        ]
    );
    assert_eq!(sp1.to_string().as_str(), VALID_SIGNED_PAYLOAD_1);

    let sp2 = SignedPayload::from_string(VALID_SIGNED_PAYLOAD_2).unwrap();
    assert_eq!(sp2.payload().len(), 29);
    assert_eq!(sp2.to_string().as_str(), VALID_SIGNED_PAYLOAD_2);
}

#[test]
fn test_signed_payload_from_string_invalid() {
    // Too long strkey input
    assert_eq!(
        SignedPayload::from_string("PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAABAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD7ZIHA"),
        Err(DecodeError::TooLong)
    );
    // Non-zero padding
    assert_eq!(
        SignedPayload::from_string(
            "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAA4KVWLTJJFCJJFC7MPA7QYNF7SOWQ3GLR2GXUA7JUAAAAAEAAAAU"
        ),
        Err(DecodeError::InvalidPadding)
    );
    // Invalid base32 unused trailing bits
    assert_eq!(
        SignedPayload::from_string(
            "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAACAAAAAABNWT"
        ),
        Err(DecodeError::InvalidBase32)
    );
    // Empty and too short
    assert_eq!(SignedPayload::from_string(""), Err(DecodeError::TooShort));
    assert_eq!(
        SignedPayload::from_string("AAAA"),
        Err(DecodeError::TooShort)
    );
}

#[test]
fn test_signed_payload_from_string_rejects_other_strkey_types() {
    for &sample in ALL_10_TYPE_REPRESENTATIVES {
        let res = SignedPayload::from_string(sample);
        if sample == VALID_SIGNED_PAYLOAD_1 {
            assert!(res.is_ok());
        } else {
            assert!(
                res.is_err(),
                "SignedPayload::from_string unexpectedly accepted {sample}"
            );
        }
    }
}

// ============================================================================
// 10. MuxedContract::from_string
// ============================================================================

#[test]
fn test_muxed_contract_from_string_valid() {
    let mc1 = MuxedContract::from_string(VALID_MUXED_CONTRACT_1).unwrap();
    assert_eq!(mc1.contract_id, SAMPLE_PAYLOAD_1);
    assert_eq!(mc1.id, 123456);
    assert_eq!(mc1.to_string().as_str(), VALID_MUXED_CONTRACT_1);

    let mc2 = MuxedContract::from_string(VALID_MUXED_CONTRACT_2).unwrap();
    assert_eq!(mc2.contract_id, SAMPLE_PAYLOAD_2);
    assert_eq!(mc2.id, 0);
    assert_eq!(mc2.to_string().as_str(), VALID_MUXED_CONTRACT_2);

    let mc3 = MuxedContract::from_string(VALID_MUXED_CONTRACT_3).unwrap();
    assert_eq!(mc3.contract_id, SAMPLE_PAYLOAD_2);
    assert_eq!(mc3.id, 9223372036854775808);
    assert_eq!(mc3.to_string().as_str(), VALID_MUXED_CONTRACT_3);
}

#[test]
fn test_muxed_contract_from_string_invalid() {
    // Too long input
    assert_eq!(
        MuxedContract::from_string(
            "WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAAIOUI"
        ),
        Err(DecodeError::TooLong)
    );
    // Too short payload (39 bytes instead of 40)
    assert_eq!(
        MuxedContract::from_string(
            "WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAUCCQ"
        ),
        Err(DecodeError::InvalidPayloadLength)
    );
    // Unused trailing bit must be zero
    assert_eq!(
        MuxedContract::from_string(
            "WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWD"
        ),
        Err(DecodeError::InvalidBase32)
    );
    // Invalid algorithm with valid CRC
    assert_eq!(
        MuxedContract::from_string(
            "W47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAADXHW"
        ),
        Err(DecodeError::UnsupportedVersion)
    );
    // Invalid checksum
    assert_eq!(
        MuxedContract::from_string(
            "WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWA"
        ),
        Err(DecodeError::ChecksumMismatch)
    );
    // Empty and too short
    assert_eq!(MuxedContract::from_string(""), Err(DecodeError::TooShort));
    assert_eq!(
        MuxedContract::from_string("AAAA"),
        Err(DecodeError::TooShort)
    );
}

#[test]
fn test_muxed_contract_from_string_rejects_other_strkey_types() {
    for &sample in ALL_10_TYPE_REPRESENTATIVES {
        let res = MuxedContract::from_string(sample);
        if sample == VALID_MUXED_CONTRACT_1 {
            assert!(res.is_ok());
        } else {
            assert!(
                res.is_err(),
                "MuxedContract::from_string unexpectedly accepted {sample}"
            );
        }
    }
}

// ============================================================================
// Comprehensive Cross-Type Matrix & Parity Tests
// ============================================================================

#[test]
fn test_exhaustive_cross_type_matrix() {
    // 10x10 cross-type matrix verifying that each type's from_string only accepts its own
    // corresponding strkey and rejects all 9 other strkey kinds.
    for (type_idx, &sample) in ALL_10_TYPE_REPRESENTATIVES.iter().enumerate() {
        assert_eq!(PublicKey::from_string(sample).is_ok(), type_idx == 0);
        assert_eq!(PrivateKey::from_string(sample).is_ok(), type_idx == 1);
        assert_eq!(PreAuthTx::from_string(sample).is_ok(), type_idx == 2);
        assert_eq!(HashX::from_string(sample).is_ok(), type_idx == 3);
        assert_eq!(MuxedAccount::from_string(sample).is_ok(), type_idx == 4);
        assert_eq!(SignedPayload::from_string(sample).is_ok(), type_idx == 5);
        assert_eq!(Contract::from_string(sample).is_ok(), type_idx == 6);
        assert_eq!(LiquidityPool::from_string(sample).is_ok(), type_idx == 7);
        assert_eq!(ClaimableBalance::from_string(sample).is_ok(), type_idx == 8);
        assert_eq!(MuxedContract::from_string(sample).is_ok(), type_idx == 9);
    }
}

#[test]
fn test_from_str_parity_with_from_string() {
    use core::str::FromStr;

    // Verify FromStr implementation delegates precisely to from_string for all types
    assert_eq!(
        PublicKey::from_str(VALID_PUBLIC_KEY_1),
        PublicKey::from_string(VALID_PUBLIC_KEY_1)
    );
    assert_eq!(
        PrivateKey::from_str(VALID_PRIVATE_KEY),
        PrivateKey::from_string(VALID_PRIVATE_KEY)
    );
    assert_eq!(
        PreAuthTx::from_str(VALID_PRE_AUTH_TX),
        PreAuthTx::from_string(VALID_PRE_AUTH_TX)
    );
    assert_eq!(
        HashX::from_str(VALID_HASH_X),
        HashX::from_string(VALID_HASH_X)
    );
    assert_eq!(
        MuxedAccount::from_str(VALID_MUXED_ACCOUNT_1),
        MuxedAccount::from_string(VALID_MUXED_ACCOUNT_1)
    );
    assert_eq!(
        SignedPayload::from_str(VALID_SIGNED_PAYLOAD_1),
        SignedPayload::from_string(VALID_SIGNED_PAYLOAD_1)
    );
    assert_eq!(
        Contract::from_str(VALID_CONTRACT_1),
        Contract::from_string(VALID_CONTRACT_1)
    );
    assert_eq!(
        LiquidityPool::from_str(VALID_LIQUIDITY_POOL_1),
        LiquidityPool::from_string(VALID_LIQUIDITY_POOL_1)
    );
    assert_eq!(
        ClaimableBalance::from_str(VALID_CLAIMABLE_BALANCE_1),
        ClaimableBalance::from_string(VALID_CLAIMABLE_BALANCE_1)
    );
    assert_eq!(
        MuxedContract::from_str(VALID_MUXED_CONTRACT_1),
        MuxedContract::from_string(VALID_MUXED_CONTRACT_1)
    );
}

#[test]
fn test_from_slice_parity_with_from_string() {
    // Verify from_slice and from_string produce identical results across all representative samples
    assert_eq!(
        PublicKey::from_slice(VALID_PUBLIC_KEY_1.as_bytes()),
        PublicKey::from_string(VALID_PUBLIC_KEY_1)
    );
    assert_eq!(
        PrivateKey::from_slice(VALID_PRIVATE_KEY.as_bytes()),
        PrivateKey::from_string(VALID_PRIVATE_KEY)
    );
    assert_eq!(
        PreAuthTx::from_slice(VALID_PRE_AUTH_TX.as_bytes()),
        PreAuthTx::from_string(VALID_PRE_AUTH_TX)
    );
    assert_eq!(
        HashX::from_slice(VALID_HASH_X.as_bytes()),
        HashX::from_string(VALID_HASH_X)
    );
    assert_eq!(
        MuxedAccount::from_slice(VALID_MUXED_ACCOUNT_1.as_bytes()),
        MuxedAccount::from_string(VALID_MUXED_ACCOUNT_1)
    );
    assert_eq!(
        SignedPayload::from_slice(VALID_SIGNED_PAYLOAD_1.as_bytes()),
        SignedPayload::from_string(VALID_SIGNED_PAYLOAD_1)
    );
    assert_eq!(
        Contract::from_slice(VALID_CONTRACT_1.as_bytes()),
        Contract::from_string(VALID_CONTRACT_1)
    );
    assert_eq!(
        LiquidityPool::from_slice(VALID_LIQUIDITY_POOL_1.as_bytes()),
        LiquidityPool::from_string(VALID_LIQUIDITY_POOL_1)
    );
    assert_eq!(
        ClaimableBalance::from_slice(VALID_CLAIMABLE_BALANCE_1.as_bytes()),
        ClaimableBalance::from_string(VALID_CLAIMABLE_BALANCE_1)
    );
    assert_eq!(
        MuxedContract::from_slice(VALID_MUXED_CONTRACT_1.as_bytes()),
        MuxedContract::from_string(VALID_MUXED_CONTRACT_1)
    );
}
