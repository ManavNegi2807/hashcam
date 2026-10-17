//! Minimal standard base64, decode and encode.
//!
//! Hand written so the core has no extra dependency. Base64 never appears in
//! anything hashed or signed: it carries canonical bytes over a wire or in a
//! vector file (`PROTOCOL.md` 11.1, the `*_b64` fields), and the bytes are
//! decoded before any digest is taken.

/// Why a base64 string could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum B64Error {
    /// A character outside the standard alphabet.
    BadCharacter,
    /// Length not a multiple of four, or padding in the wrong place.
    BadLength,
}

impl std::fmt::Display for B64Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadCharacter => f.write_str("BAD_BASE64_CHARACTER"),
            Self::BadLength => f.write_str("BAD_BASE64_LENGTH"),
        }
    }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn value_of(byte: u8) -> Result<u8, B64Error> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(B64Error::BadCharacter),
    }
}

/// Decode standard base64 with padding.
pub fn decode(text: &str) -> Result<Vec<u8>, B64Error> {
    let bytes: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !bytes.len().is_multiple_of(4) {
        return Err(B64Error::BadLength);
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let last_chunk = bytes.len() / 4;
    for (chunk_index, chunk) in bytes.chunks(4).enumerate() {
        let pad = chunk.iter().filter(|b| **b == b'=').count();
        // Padding is legal only as the tail of the final quad.
        if pad > 2 || (pad > 0 && chunk_index + 1 != last_chunk) {
            return Err(B64Error::BadLength);
        }
        if pad > 0 && chunk[4 - pad..].iter().any(|b| *b != b'=') {
            return Err(B64Error::BadLength);
        }
        let mut quad = [0u8; 4];
        for (i, byte) in chunk.iter().enumerate() {
            quad[i] = if *byte == b'=' { 0 } else { value_of(*byte)? };
        }
        let triple = (u32::from(quad[0]) << 18)
            | (u32::from(quad[1]) << 12)
            | (u32::from(quad[2]) << 6)
            | u32::from(quad[3]);
        out.push((triple >> 16) as u8);
        if pad < 2 {
            out.push((triple >> 8) as u8);
        }
        if pad < 1 {
            out.push(triple as u8);
        }
    }
    Ok(out)
}

/// Encode standard base64 with padding.
#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).map_or(0, |b| u32::from(*b));
        let b2 = chunk.get(2).map_or(0, |b| u32::from(*b));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        let idx = |shift: u32| ALPHABET[((triple >> shift) & 0x3F) as usize] as char;
        out.push(idx(18));
        out.push(idx(12));
        out.push(if chunk.len() > 1 { idx(6) } else { '=' });
        out.push(if chunk.len() > 2 { idx(0) } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_length_up_to_a_few_blocks() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let text = encode(&data);
            assert_eq!(decode(&text).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn matches_known_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(decode("Zm9vYmFy").unwrap(), b"foobar");
    }

    #[test]
    fn rejects_bad_input_instead_of_panicking() {
        assert_eq!(decode("Zg=").unwrap_err(), B64Error::BadLength);
        assert_eq!(decode("Zm9v!g==").unwrap_err(), B64Error::BadCharacter);
        assert_eq!(decode("Z===").unwrap_err(), B64Error::BadLength);
    }
}
