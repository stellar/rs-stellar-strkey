#![no_main]

use libfuzzer_sys::{arbitrary::Result, fuzz_target, Corpus};

const BASE32_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=";

// Take inputs and attempt to parse them as a strkey.
fuzz_target!(|s: &str| -> Corpus {
    if !s.chars().all(|c| BASE32_ALPHABET.contains(c)) {
        return Corpus::Reject;
    }

    // Parse the input as a strkey. Ignore invalid strkeys.
    let Ok(r): Result<stellar_strkey::Strkey, _> = s.parse() else {
        return Corpus::Keep;
    };

    // Check that the strkey roundtrips back to the identical string.
    let roundtrip_s = r.to_string();
    assert_eq!(roundtrip_s, s);

    Corpus::Keep
});
