#![no_main]

use heapless::{String, Vec};
use libfuzzer_sys::{fuzz_target, Corpus};
use zeroize::Zeroizing;

use stellar_strkey::convert::{decode, decode_zeroizing, encode, encode_zeroizing};

// Compare the plain and zeroizing variants of encode and decode in the
// `convert` module. Both variants must produce identical output for the same
// input; only their buffer-zeroization story differs.
//
// PrivateKey-style sizes are used (P = 32, B = 35, E = 56) since that is the
// security-relevant case `encode_zeroizing` / `decode_zeroizing` exist for.
fuzz_target!(|data: &[u8]| -> Corpus {
    // Need at least 1 version byte + 32-byte payload to exercise encode.
    if data.len() < 1 + 32 {
        return Corpus::Reject;
    }
    let ver = data[0];
    let payload: [u8; 32] = data[1..1 + 32].try_into().unwrap();
    let decode_input = &data[1 + 32..];

    // -- encode vs encode_zeroizing --
    let plain: String<56> = encode::<32, 35, 56>(ver, &payload);
    let mut zeroizing: Zeroizing<String<56>> = Zeroizing::new(String::new());
    encode_zeroizing::<32, 35, 56>(ver, &payload, &mut zeroizing);
    assert_eq!(
        plain.as_str(),
        zeroizing.as_str(),
        "encode/encode_zeroizing produced different output\nver: {ver:#04x}\npayload: {payload:02x?}"
    );

    // -- decode vs decode_zeroizing on the just-encoded string (must roundtrip) --
    let plain_round = decode::<32, 35>(plain.as_bytes());
    let mut zeroizing_round_payload: Zeroizing<Vec<u8, 32>> = Zeroizing::new(Vec::new());
    let zeroizing_round =
        decode_zeroizing::<32, 35>(plain.as_bytes(), &mut zeroizing_round_payload);
    let (round_ver, round_payload) = plain_round.expect("encoded string must decode");
    let round_ver_z = zeroizing_round.expect("encoded string must decode (zeroizing)");
    assert_eq!(round_ver, ver, "roundtrip version mismatch");
    assert_eq!(
        round_payload.as_slice(),
        &payload,
        "roundtrip payload mismatch"
    );
    assert_eq!(
        round_ver, round_ver_z,
        "decode/decode_zeroizing version mismatch"
    );
    assert_eq!(
        round_payload.as_slice(),
        zeroizing_round_payload.as_slice(),
        "decode/decode_zeroizing payload mismatch"
    );

    // -- decode vs decode_zeroizing on arbitrary input (must agree, including
    //    on errors) --
    let plain_arb = decode::<32, 35>(decode_input);
    let mut zeroizing_arb_payload: Zeroizing<Vec<u8, 32>> = Zeroizing::new(Vec::new());
    let zeroizing_arb = decode_zeroizing::<32, 35>(decode_input, &mut zeroizing_arb_payload);
    match (&plain_arb, &zeroizing_arb) {
        (Ok((vp, pp)), Ok(vz)) => {
            assert_eq!(vp, vz, "decode/decode_zeroizing version mismatch on arbitrary input");
            assert_eq!(
                pp.as_slice(),
                zeroizing_arb_payload.as_slice(),
                "decode/decode_zeroizing payload mismatch on arbitrary input"
            );
        }
        (Err(ep), Err(ez)) => {
            assert_eq!(ep, ez, "decode/decode_zeroizing error mismatch on arbitrary input");
        }
        _ => panic!(
            "decode/decode_zeroizing disagreed on arbitrary input: plain={plain_arb:?} zeroizing={zeroizing_arb:?}"
        ),
    }

    Corpus::Keep
});
