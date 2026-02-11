//! Shared utility functions: hex encoding/decoding, UUID generation.
//!
//! These are pure, allocation-light helpers used across multiple SDK
//! modules (`frost_bridge`, `ssp`, `operations`). Consolidating them
//! here avoids three identical copies of `hex_nibble`.

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

/// Decode an arbitrary hex string to bytes.
///
/// Returns `None` if the string has an odd length or contains non-hex chars.
pub(crate) fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks_exact(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

/// Decode a hex-encoded 33-byte compressed public key (66 hex chars).
///
/// Returns `None` if the length is not 66 or any char is invalid hex.
pub(crate) fn hex_decode_pubkey(hex: &str) -> Option<[u8; 33]> {
    if hex.len() != 66 {
        return None;
    }
    let mut out = [0u8; 33];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Encode bytes as lowercase hexadecimal.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize]);
        s.push(HEX_CHARS[(b & 0x0F) as usize]);
    }
    s
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// UUID
// ---------------------------------------------------------------------------

/// Generate a UUIDv4 string from random bytes (no external crate needed).
pub(crate) fn generate_uuid_v4<R: rand_core::RngCore>(rng: &mut R) -> String {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    // Set version (4) and variant (RFC 4122).
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        u64::from_be_bytes([
            0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        ]),
    )
}
