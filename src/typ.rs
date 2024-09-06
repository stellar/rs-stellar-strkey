pub const PUBLIC_KEY: u8 = 6 << 3;
pub const PRIVATE_KEY: u8 = 18 << 3;
pub const MUXED_ACCOUNT: u8 = 12 << 3;
pub const PRE_AUTH_TX: u8 = 19 << 3;
pub const HASH_X: u8 = 23 << 3;
pub const SIGNED_PAYLOAD: u8 = 15 << 3;
pub const CONTRACT: u8 = 2 << 3;

pub mod public_key_alg {
    pub const ED25519: u8 = 0;
}

pub const ENCODED_PUBLIC_KEY_LEN: usize = 56;
pub const ENCODED_PRIVATE_KEY_LEN: usize = 56;
pub const ENCODED_MUXED_ACCOUNT_LEN: usize = 69;
pub const ENCODED_PRE_AUTH_TX_LEN: usize = 56;
pub const ENCODED_HASH_X_LEN: usize = 56;
#[allow(dead_code)]
pub const ENCODED_SIGNED_PAYLOAD_MIN_LEN: usize = 69;
#[allow(dead_code)]
pub const ENCODED_SIGNED_PAYLOAD_MAX_LEN: usize = 165;
pub const ENCODED_CONTRACT_LEN: usize = 56;

pub const RAW_PUBLIC_KEY_LEN: usize = 32;
pub const RAW_PRIVATE_KEY_LEN: usize = 32;
pub const RAW_MUXED_ACCOUNT_LEN: usize = 40; // MuxedAccountEd25519
pub const RAW_PRE_AUTH_TX_LEN: usize = 32;
pub const RAW_HASH_X_LEN: usize = 32;
#[allow(dead_code)]
pub const RAW_SIGNED_PAYLOAD_MIN_LEN: usize = 40; // 32 + 4 + 4 = 40-bytes
pub const RAW_SIGNED_PAYLOAD_MAX_LEN: usize = 100; // 32 + 4 + 64 = 100-bytes
pub const RAW_CONTRACT_LEN: usize = 32;

// TODO: is OK to put this here?
pub(crate) const MAX_PAYLOAD_LEN: usize = RAW_SIGNED_PAYLOAD_MAX_LEN;
