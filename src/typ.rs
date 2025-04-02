pub const PUBLIC_KEY: u8 = 6 << 3; // 'G' prefix
pub const PRIVATE_KEY: u8 = 18 << 3; // 'S' prefix
pub const MUXED_ACCOUNT: u8 = 12 << 3; // 'M' prefix
pub const PRE_AUTH_TX: u8 = 19 << 3; // 'T' prefix
pub const HASH_X: u8 = 23 << 3; // 'H' prefix
pub const SIGNED_PAYLOAD: u8 = 15 << 3; // 'P' prefix
pub const CONTRACT: u8 = 2 << 3; // 'C' prefix
pub const LIQUIDITY_POOL: u8 = 11 << 3; // 'L' prefix
pub const CLAIMABLE_BALANCE: u8 = 1 << 3; // 'B' prefix

pub mod public_key_alg {
    pub const ED25519: u8 = 0;
}
