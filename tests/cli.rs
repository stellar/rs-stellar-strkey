#![cfg(feature = "cli")]

use std::io::Write;
use std::process::{Command, ExitStatus, Stdio};

const BIN_PATH: &str = env!("CARGO_BIN_EXE_stellar-strkey");

// Sample strkeys for each of the 10 supported types
const SAMPLE_PUBLIC_KEY: &str = "GA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQHES5";
const SAMPLE_PRIVATE_KEY: &str = "SBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWHOKR";
const SAMPLE_PRE_AUTH_TX: &str = "TBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWHXL7";
const SAMPLE_HASH_X: &str = "XBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWGTOG";
const SAMPLE_MUXED_ACCOUNT: &str =
    "MA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAAAAAAAAAPCICBKU";
const SAMPLE_SIGNED_PAYLOAD: &str =
    "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IBZGM";
const SAMPLE_CONTRACT: &str = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";
const SAMPLE_LIQUIDITY_POOL: &str = "LA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGZ5J";
const SAMPLE_CLAIMABLE_BALANCE: &str = "BAADMPVKHBTYIH522D2O3CGHPHSP4ZXFNISHBXEYYDWJYBZ5AXD3CA3GDE";
const SAMPLE_MUXED_CONTRACT: &str =
    "WA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAAAAAAAAAPCIA6IG";

const ALL_10_SAMPLES: &[&str] = &[
    SAMPLE_PUBLIC_KEY,
    SAMPLE_PRIVATE_KEY,
    SAMPLE_PRE_AUTH_TX,
    SAMPLE_HASH_X,
    SAMPLE_MUXED_ACCOUNT,
    SAMPLE_SIGNED_PAYLOAD,
    SAMPLE_CONTRACT,
    SAMPLE_LIQUIDITY_POOL,
    SAMPLE_CLAIMABLE_BALANCE,
    SAMPLE_MUXED_CONTRACT,
];

/// Helper to execute the stellar-strkey binary with arguments and optional stdin.
fn run_strkey_cli(args: &[&str], stdin_data: Option<&[u8]>) -> (ExitStatus, String, String) {
    let mut child = Command::new(BIN_PATH)
        .args(args)
        .stdin(if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn stellar-strkey CLI process");

    if let Some(data) = stdin_data {
        let mut stdin = child.stdin.take().expect("failed to open stdin");
        stdin.write_all(data).expect("failed to write to stdin");
    }

    let output = child
        .wait_with_output()
        .expect("failed to wait for CLI process to exit");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output.status, stdout, stderr)
}

// ============================================================================
// 1. Version Subcommand
// ============================================================================

#[test]
fn test_cli_version_subcommand() {
    let (status, stdout, stderr) = run_strkey_cli(&["version"], None);
    assert!(status.success());
    assert!(stderr.is_empty());
    assert!(stdout.starts_with("stellar-strkey 1.0.0"));
}

// ============================================================================
// 2. Zero Subcommand
// ============================================================================

#[test]
fn test_cli_zero_default_strkey_output() {
    let types = [
        (
            "public_key_ed25519",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        ),
        (
            "pre_auth_tx",
            "TAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABLVU",
        ),
        (
            "hash_x",
            "XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPQN",
        ),
        (
            "muxed_account_ed25519",
            "MAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB5IG",
        ),
        (
            "signed_payload_ed25519",
            "PAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAADSYC",
        ),
        (
            "contract",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        ),
        (
            "liquidity_pool",
            "LAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABLIR",
        ),
        (
            "claimable_balance_v0",
            "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFMUE",
        ),
        (
            "muxed_contract",
            "WAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADCKU",
        ),
    ];

    for (strkey_type, expected_strkey) in types {
        let (status, stdout, stderr) = run_strkey_cli(&["zero", strkey_type], None);
        assert!(status.success(), "zero {strkey_type} failed");
        assert!(stderr.is_empty());
        assert_eq!(stdout.trim(), expected_strkey);
    }
}

#[test]
fn test_cli_zero_json_output() {
    let (status, stdout, stderr) = run_strkey_cli(&["zero", "contract", "--output", "json"], None);
    assert!(status.success());
    assert!(stderr.is_empty());

    let val: serde_json::Value = serde_json::from_str(&stdout).expect("output must be valid JSON");
    let contract_hex = val
        .get("contract")
        .and_then(|v| v.as_str())
        .expect("must contain contract field");
    assert_eq!(contract_hex, "0".repeat(64));
}

#[test]
fn test_cli_zero_invalid_type_errors() {
    let (status, _, stderr) = run_strkey_cli(&["zero", "non_existent_type"], None);
    assert!(!status.success());
    assert!(
        stderr.contains("error:") && (stderr.contains("isn't valid") || stderr.contains("invalid"))
    );
}

// ============================================================================
// 3. Decode Subcommand
// ============================================================================

#[test]
fn test_cli_decode_public_key() {
    let input = format!("{SAMPLE_PUBLIC_KEY}\n");
    let (status, stdout, stderr) = run_strkey_cli(&["decode"], Some(input.as_bytes()));
    assert!(status.success());
    assert!(stderr.is_empty());

    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(json.get("public_key_ed25519").is_some());
}

#[test]
fn test_cli_decode_private_key_prints_warning_to_stderr() {
    let input = format!("{SAMPLE_PRIVATE_KEY}\n");
    let (status, stdout, stderr) = run_strkey_cli(&["decode"], Some(input.as_bytes()));
    assert!(status.success());
    assert!(stderr.contains("Warning: output contains a private key"));

    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(json.get("private_key_ed25519").is_some());
}

#[test]
fn test_cli_decode_private_key_quiet_flag_suppresses_warning() {
    let input = format!("{SAMPLE_PRIVATE_KEY}\n");
    let (status, stdout, stderr) = run_strkey_cli(&["-q", "decode"], Some(input.as_bytes()));
    assert!(status.success());
    assert!(stderr.is_empty(), "quiet flag must suppress warning");

    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(json.get("private_key_ed25519").is_some());
}

#[test]
fn test_cli_decode_empty_input_errors() {
    let (status, _, stderr) = run_strkey_cli(&["decode"], Some(b""));
    assert!(!status.success());
    assert!(stderr.contains("decoding strkey:"));
}

#[test]
fn test_cli_decode_invalid_strkey_errors() {
    let (status, _, stderr) = run_strkey_cli(&["decode"], Some(b"INVALID_STRKEY\n"));
    assert!(!status.success());
    assert!(stderr.contains("decoding strkey:"));
}

#[test]
fn test_cli_decode_input_too_large_errors() {
    // MAX_ENCODED_LEN is 165, max accepted is 165 + 16 = 181
    let oversized = "G".repeat(190);
    let (status, _, stderr) = run_strkey_cli(&["decode"], Some(oversized.as_bytes()));
    assert!(!status.success());
    assert!(stderr.contains("strkey input too large"));
}

// ============================================================================
// 4. Encode Subcommand
// ============================================================================

#[test]
fn test_cli_encode_from_json() {
    let json_input =
        r#"{"contract": "363eaa3867841fbad0f4ed88c779e4fe66e56a2470dc98c0ec9c073d05c7b103"}"#;
    let (status, stdout, stderr) = run_strkey_cli(&["encode"], Some(json_input.as_bytes()));
    assert!(status.success());
    assert!(stderr.is_empty());
    assert_eq!(stdout.trim(), SAMPLE_CONTRACT);
}

#[test]
fn test_cli_encode_private_key_prints_warning() {
    let json_input = r#"{"private_key_ed25519": "69a8c4cbb9f64e8a0798f6e1ac65d06c3162929056bcf4cdb7d3738d1855f363"}"#;
    let (status, stdout, stderr) = run_strkey_cli(&["encode"], Some(json_input.as_bytes()));
    assert!(status.success());
    assert!(stderr.contains("Warning: output contains a private key"));
    assert_eq!(stdout.trim(), SAMPLE_PRIVATE_KEY);
}

#[test]
fn test_cli_encode_private_key_quiet_flag_suppresses_warning() {
    let json_input = r#"{"private_key_ed25519": "69a8c4cbb9f64e8a0798f6e1ac65d06c3162929056bcf4cdb7d3738d1855f363"}"#;
    let (status, stdout, stderr) =
        run_strkey_cli(&["--quiet", "encode"], Some(json_input.as_bytes()));
    assert!(status.success());
    assert!(stderr.is_empty());
    assert_eq!(stdout.trim(), SAMPLE_PRIVATE_KEY);
}

#[test]
fn test_cli_encode_empty_input_errors() {
    let (status, _, stderr) = run_strkey_cli(&["encode"], Some(b""));
    assert!(!status.success());
    assert!(stderr.contains("EOF while parsing a value"));
}

#[test]
fn test_cli_encode_invalid_json_errors() {
    let (status, _, stderr) = run_strkey_cli(&["encode"], Some(b"not a valid json"));
    assert!(!status.success());
    assert!(stderr.contains("expected value") || stderr.contains("error"));
}

#[test]
fn test_cli_encode_input_too_large_errors() {
    // MAX_JSON_LEN is 10 KiB
    let huge_input = " ".repeat(10 * 1024 + 1);
    let (status, _, stderr) = run_strkey_cli(&["encode"], Some(huge_input.as_bytes()));
    assert!(!status.success());
    assert!(stderr.contains("json input too large"));
}

// ============================================================================
// 5. Decode -> Encode Round-trip Tests (Issue #127 / #125 follow-up)
// ============================================================================

#[test]
fn test_cli_decode_encode_roundtrip_all_types() {
    // Pipe strkey -> decode -> json -> encode -> strkey
    // Verifies the end-to-end path through both subcommands without deserialization failures.
    for &sample in ALL_10_SAMPLES {
        let is_private_key = sample.starts_with('S');
        let decode_args: &[&str] = if is_private_key {
            &["-q", "decode"]
        } else {
            &["decode"]
        };

        // 1. Decode strkey to JSON
        let (decode_status, json_output, _) = run_strkey_cli(decode_args, Some(sample.as_bytes()));
        assert!(
            decode_status.success(),
            "CLI decode failed for sample {sample}"
        );
        assert!(!json_output.trim().is_empty());

        // 2. Encode JSON back to strkey
        let encode_args: &[&str] = if is_private_key {
            &["-q", "encode"]
        } else {
            &["encode"]
        };
        let (encode_status, re_encoded_strkey, _) =
            run_strkey_cli(encode_args, Some(json_output.as_bytes()));
        assert!(
            encode_status.success(),
            "CLI encode failed on decode output of {sample}"
        );

        // 3. Verify exact roundtrip equality
        assert_eq!(
            re_encoded_strkey.trim(),
            sample,
            "Round-trip failed for sample {sample}"
        );
    }
}

#[test]
fn test_cli_zero_decode_encode_pipeline() {
    // Pipe zero <type> -> decode -> encode -> assert equality
    let types = [
        "public_key_ed25519",
        "pre_auth_tx",
        "hash_x",
        "muxed_account_ed25519",
        "signed_payload_ed25519",
        "contract",
        "liquidity_pool",
        "claimable_balance_v0",
        "muxed_contract",
    ];

    for strkey_type in types {
        // Step 1: zero command
        let (zero_status, zero_strkey, _) = run_strkey_cli(&["zero", strkey_type], None);
        assert!(zero_status.success());
        let zero_strkey = zero_strkey.trim();

        // Step 2: decode command
        let (decode_status, json_output, _) =
            run_strkey_cli(&["decode"], Some(zero_strkey.as_bytes()));
        assert!(decode_status.success());

        // Step 3: encode command
        let (encode_status, re_encoded, _) =
            run_strkey_cli(&["encode"], Some(json_output.as_bytes()));
        assert!(encode_status.success());

        assert_eq!(
            re_encoded.trim(),
            zero_strkey,
            "zero pipeline roundtrip failed for {strkey_type}"
        );
    }
}

// ============================================================================
// 6. Help and Unknown Flag Tests
// ============================================================================

#[test]
fn test_cli_help_flag() {
    let (status, stdout, _) = run_strkey_cli(&["--help"], None);
    assert!(status.success());
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("decode"));
    assert!(stdout.contains("encode"));
    assert!(stdout.contains("zero"));
    assert!(stdout.contains("version"));
}

#[test]
fn test_cli_unknown_subcommand_errors() {
    let (status, _, stderr) = run_strkey_cli(&["unknown_cmd"], None);
    assert!(!status.success());
    assert!(stderr.contains("unrecognized subcommand"));
}
