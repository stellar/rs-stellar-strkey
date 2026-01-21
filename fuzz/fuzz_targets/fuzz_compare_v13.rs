#![no_main]

use libfuzzer_sys::{fuzz_target, Corpus};

use stellar_strkey::Strkey as StrkeyNew;
use stellar_strkey_v13::Strkey as StrkeyOld;

// Compare parsing and encoding between the current library and v0.13.
fuzz_target!(|s: &str| -> Corpus {
    // Try parsing with both versions.
    let old_result: Result<StrkeyOld, _> = s.parse();
    let new_result: Result<StrkeyNew, _> = s.parse();

    // Both should succeed or fail together.
    match (&new_result, &old_result) {
        (Ok(new), Ok(old)) => {
            // Both parsed successfully - compare the string representations.
            let new_str = new.to_string();
            let old_str = old.to_string();
            assert_eq!(
                new_str.as_str(),
                old_str.as_str(),
                "String representation mismatch for input: {s}"
            );

            // Verify both round-trip to the same string as input.
            assert_eq!(new_str.as_str(), s, "New version roundtrip failed");
            assert_eq!(old_str.as_str(), s, "Old version roundtrip failed");

            // Compare the decoded data based on variant.
            compare_internals(&new, &old);

            Corpus::Keep
        }
        (Err(_), Err(_)) => {
            // Both failed - that's fine, they agree.
            Corpus::Keep
        }
        (Ok(new), Err(old_err)) => {
            // New succeeded but old failed - this could be a new feature or a bug.
            panic!(
                "New version parsed but old version failed\nInput: {s}\nNew result: {new:?}\nOld error: {old_err:?}"
            );
        }
        (Err(new_err), Ok(old)) => {
            // Old succeeded but new failed - this is a regression.
            panic!(
                "Old version parsed but new version failed\nInput: {s}\nOld result: {old:?}\nNew error: {new_err:?}"
            );
        }
    }
});

/// Compare the inner data of two Strkey values from different library versions.
fn compare_internals(new: &StrkeyNew, old: &StrkeyOld) {
    match (new, old) {
        (StrkeyNew::PublicKeyEd25519(n), StrkeyOld::PublicKeyEd25519(o)) => {
            assert_eq!(n.0, o.0, "PublicKeyEd25519 data mismatch");
        }
        (StrkeyNew::PrivateKeyEd25519(n), StrkeyOld::PrivateKeyEd25519(o)) => {
            assert_eq!(n.0, o.0, "PrivateKeyEd25519 data mismatch");
        }
        (StrkeyNew::PreAuthTx(n), StrkeyOld::PreAuthTx(o)) => {
            assert_eq!(n.0, o.0, "PreAuthTx data mismatch");
        }
        (StrkeyNew::HashX(n), StrkeyOld::HashX(o)) => {
            assert_eq!(n.0, o.0, "HashX data mismatch");
        }
        (StrkeyNew::MuxedAccountEd25519(n), StrkeyOld::MuxedAccountEd25519(o)) => {
            assert_eq!(n.ed25519, o.ed25519, "MuxedAccount ed25519 mismatch");
            assert_eq!(n.id, o.id, "MuxedAccount id mismatch");
        }
        (StrkeyNew::SignedPayloadEd25519(n), StrkeyOld::SignedPayloadEd25519(o)) => {
            assert_eq!(
                n.ed25519, o.ed25519,
                "SignedPayloadEd25519 ed25519 mismatch"
            );
            assert_eq!(
                n.payload.as_slice(),
                o.payload.as_slice(),
                "SignedPayloadEd25519 payload mismatch"
            );
        }
        (StrkeyNew::Contract(n), StrkeyOld::Contract(o)) => {
            assert_eq!(n.0, o.0, "Contract data mismatch");
        }
        (StrkeyNew::LiquidityPool(n), StrkeyOld::LiquidityPool(o)) => {
            assert_eq!(n.0, o.0, "LiquidityPool data mismatch");
        }
        (StrkeyNew::ClaimableBalance(n), StrkeyOld::ClaimableBalance(o)) => match (n, o) {
            (
                stellar_strkey::ClaimableBalance::V0(n_bytes),
                stellar_strkey_v13::ClaimableBalance::V0(o_bytes),
            ) => {
                assert_eq!(n_bytes, o_bytes, "ClaimableBalance V0 data mismatch");
            }
        },
        _ => {
            panic!("Strkey variant mismatch\nNew: {new:?}\nOld: {old:?}");
        }
    }
}
