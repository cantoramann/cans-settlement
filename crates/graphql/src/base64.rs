//! Base64 encoding/decoding helpers (no external dependency).

/// Standard base64 encode (RFC 4648) with padding.
pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decode a base64url string (without padding) into bytes.
pub(crate) fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let pad = match input.len() % 4 {
        0 => 0u8,
        2 => 2,
        3 => 1,
        _ => return None,
    };

    let mut buf = Vec::with_capacity(input.len() + pad as usize);
    for &b in input.as_bytes() {
        buf.push(match b {
            b'-' => b'+',
            b'_' => b'/',
            other => other,
        });
    }
    buf.resize(buf.len() + pad as usize, b'=');

    decode_standard_bytes(&buf)
}

/// Standard base64 decode (RFC 4648) from raw bytes.
fn decode_standard_bytes(input: &[u8]) -> Option<Vec<u8>> {
    const TABLE: [u8; 128] = {
        let mut t = [0xFFu8; 128];
        let mut i = 0u8;
        while i < 26 {
            t[(b'A' + i) as usize] = i;
            t[(b'a' + i) as usize] = i + 26;
            i += 1;
        }
        let mut d = 0u8;
        while d < 10 {
            t[(b'0' + d) as usize] = d + 52;
            d += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };

    if input.len() % 4 != 0 {
        return None;
    }

    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for chunk in input.chunks_exact(4) {
        let mut vals = [0u8; 4];
        let mut pad_count = 0u8;
        for (i, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                pad_count += 1;
                vals[i] = 0;
            } else if b >= 128 || TABLE[b as usize] == 0xFF {
                return None;
            } else {
                vals[i] = TABLE[b as usize];
            }
        }
        let n = ((vals[0] as u32) << 18)
            | ((vals[1] as u32) << 12)
            | ((vals[2] as u32) << 6)
            | (vals[3] as u32);

        out.push((n >> 16) as u8);
        if pad_count < 2 {
            out.push((n >> 8) as u8);
        }
        if pad_count < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_round_trip() {
        assert_eq!(base64_encode(b"hello world"), "aGVsbG8gd29ybGQ=");
    }

    #[test]
    fn base64url_decode_works() {
        assert_eq!(base64url_decode("AQID"), Some(vec![1, 2, 3]));
        assert!(base64url_decode("AP__").is_some());
    }

    #[test]
    fn real_challenge() {
        let pc = "CAFSTwgBUNyBtMwGogEg0tppfumnJfyoYQXyTew-XPayF9c6wGnG0A_z8x_LUAPyASECaYsnrDCLJ1Zxs8olQ2NGRp0EpbuleK45_rodZYl6aryiASDZS7gAD-fZo64FiHXc2WOIel5WEg2rd9QIfMNk1yGUKw";
        let decoded = base64url_decode(pc);
        assert!(decoded.is_some());
        assert_eq!(decoded.unwrap().len(), 118);
    }
}
