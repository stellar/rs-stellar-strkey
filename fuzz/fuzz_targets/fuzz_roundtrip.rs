#![no_main]

use libfuzzer_sys::{arbitrary::Result, fuzz_target, Corpus};

use stellar_strkey::Strkey;

const BASE32_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=";

// Take inputs and attempt to parse them as a strkey.
fuzz_target!(|s: &str| -> Corpus {
    if !s.chars().all(|c| BASE32_ALPHABET.contains(c)) {
        return Corpus::Reject;
    }

    // Parse the input as a strkey. Ignore invalid strkeys.
    let Ok(r): Result<Strkey, _> = s.parse() else {
        return Corpus::Keep;
    };

    // Check that the strkey roundtrips back to the identical string.
    let roundtrip_s = r.to_string();
    assert_eq!(roundtrip_s, s);

    // Check that the first character matches the expected prefix for the type.
    let first_char = s.chars().next().unwrap();
    assert_eq!(
        first_char,
        match r {
            Strkey::PublicKeyEd25519(_) => 'G',
            Strkey::PrivateKeyEd25519(_) => 'S',
            Strkey::MuxedAccountEd25519(_) => 'M',
            Strkey::PreAuthTx(_) => 'T',
            Strkey::HashX(_) => 'X',
            Strkey::SignedPayloadEd25519(_) => 'P',
            Strkey::Contract(_) => 'C',
            Strkey::LiquidityPool(_) => 'L',
            Strkey::ClaimableBalance(_) => 'B',
        }
    );

    // Check that the length of the strkey is what would be expected.
    let len = s.len();
    match &r {
        Strkey::PublicKeyEd25519(_) => assert_eq!(len, 56),
        Strkey::PrivateKeyEd25519(_) => assert_eq!(len, 56),
        Strkey::PreAuthTx(_) => assert_eq!(len, 56),
        Strkey::HashX(_) => assert_eq!(len, 56),
        Strkey::MuxedAccountEd25519(_) => assert_eq!(len, 69),
        Strkey::Contract(_) => assert_eq!(len, 56),
        Strkey::LiquidityPool(_) => assert_eq!(len, 56),
        Strkey::ClaimableBalance(_) => assert_eq!(len, 58),
        Strkey::SignedPayloadEd25519(sp) => {
            let payload_len = sp.payload.len();
            let binary_len = 1              // version
                + 32                        // ed25519
                + 4                         // payload length
                + payload_len               // payload
                + (4 - payload_len % 4) % 4 // payload padding
                + 2; // crc
            let str_len = (binary_len * 8 + 4) / 5; // base32: 5 bits per char, ceil(bits / 5)
            assert_eq!(len, str_len);
        }
    }

    Corpus::Keep
});
