const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// Write bytes as hex to a formatter efficiently using a stack buffer.
pub fn write_hex(f: &mut core::fmt::Formatter<'_>, bytes: &[u8]) -> core::fmt::Result {
    // Use a fixed-size stack buffer for the hex string (64 bytes covers 32 input bytes)
    // For longer inputs, fall back to heap allocation
    if bytes.len() <= 32 {
        let mut buf = [0u8; 64];
        for (i, &b) in bytes.iter().enumerate() {
            buf[i * 2] = HEX_CHARS[(b >> 4) as usize];
            buf[i * 2 + 1] = HEX_CHARS[(b & 0xf) as usize];
        }
        // SAFETY: HEX_CHARS only contains ASCII characters
        let s = unsafe { core::str::from_utf8_unchecked(&buf[..bytes.len() * 2]) };
        f.write_str(s)
    } else {
        // Fallback for larger inputs
        let mut buf = alloc::vec![0u8; bytes.len() * 2];
        for (i, &b) in bytes.iter().enumerate() {
            buf[i * 2] = HEX_CHARS[(b >> 4) as usize];
            buf[i * 2 + 1] = HEX_CHARS[(b & 0xf) as usize];
        }
        // SAFETY: HEX_CHARS only contains ASCII characters
        let s = unsafe { core::str::from_utf8_unchecked(&buf) };
        f.write_str(s)
    }
}
