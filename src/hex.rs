const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// Write bytes as hex to a formatter efficiently using a stack buffer.
/// Max input is 64 bytes (SignedPayload inner payload), so 128 bytes for hex output.
pub fn write_hex(f: &mut core::fmt::Formatter<'_>, bytes: &[u8]) -> core::fmt::Result {
    let mut buf = [0u8; 128];
    for (i, &b) in bytes.iter().enumerate() {
        buf[i * 2] = HEX_CHARS[(b >> 4) as usize];
        buf[i * 2 + 1] = HEX_CHARS[(b & 0xf) as usize];
    }
    // SAFETY: HEX_CHARS only contains ASCII characters
    let s = unsafe { core::str::from_utf8_unchecked(&buf[..bytes.len() * 2]) };
    f.write_str(s)
}
