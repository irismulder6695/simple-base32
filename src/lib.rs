//! A small, dependency-free RFC 4648 base32 codec.
//!
//! The implementation deliberately supports the two RFC 4648 alphabets that
//! are actually useful in practice: the standard alphabet (`A-Z2-7`) and the
//! "base32hex" alphabet (`0-9A-V`).  Padding is optional on decode and can be
//! requested on encode.
//!
//! # Trade-off
//!
//! There is no streaming encoder or decoder.  The whole input is kept in
//! memory and the output is returned as a `Vec<u8>`.  That keeps the API tiny
//! and makes the padding rules easy to reason about.  For the message sizes
//! this crate is meant for (keys, hashes, small payloads) that is the right
//! trade-off.

/// The RFC 4648 standard alphabet.
const STANDARD_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// The RFC 4648 `base32hex` alphabet.
const HEX_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// Which RFC 4648 alphabet to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alphabet {
    /// The standard alphabet: `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`.
    Standard,
    /// The extended-hex alphabet: `0123456789ABCDEFGHIJKLMNOPQRSTUV`.
    Hex,
}

impl Alphabet {
    fn table(self) -> &'static [u8; 32] {
        match self {
            Alphabet::Standard => STANDARD_ALPHABET,
            Alphabet::Hex => HEX_ALPHABET,
        }
    }
}

/// Errors returned while decoding.
///
/// The variants are intentionally coarse: callers almost always want to know
/// *that* the input was malformed, not which byte was at fault.  Keeping the
/// error small avoids pulling in formatting machinery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The input contained a byte that is not in the selected alphabet.
    InvalidCharacter,
    /// The input contained a padding character in an illegal position.
    InvalidPadding,
    /// The number of significant characters is impossible for a base32
    /// encoding (for example a single leftover character).
    InvalidLength,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::InvalidCharacter => f.write_str("invalid base32 character"),
            DecodeError::InvalidPadding => f.write_str("invalid base32 padding"),
            DecodeError::InvalidLength => f.write_str("invalid base32 length"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encode `input` using the standard alphabet and no padding.
pub fn encode(input: &[u8]) -> Vec<u8> {
    encode_with(input, Alphabet::Standard, false)
}

/// Encode `input` using the standard alphabet, appending `=` padding so the
/// output length is a multiple of eight.
pub fn encode_padded(input: &[u8]) -> Vec<u8> {
    encode_with(input, Alphabet::Standard, true)
}

/// Decode `input` using the standard alphabet.  Padding is optional and, when
/// present, must be well formed.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, DecodeError> {
    decode_with(input, Alphabet::Standard)
}

/// Encode `input` with an explicit alphabet and padding choice.
pub fn encode_with(input: &[u8], alphabet: Alphabet, pad: bool) -> Vec<u8> {
    let table = alphabet.table();
    let mut out = Vec::with_capacity((input.len() * 8 + 4) / 5);

    for chunk in input.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);

        // Pack the five bytes into a 40-bit big-endian integer.  Using u64
        // keeps the shifts simple and avoids any overflow questions.
        let mut acc: u64 = 0;
        for &b in &buf {
            acc = (acc << 8) | u64::from(b);
        }

        // Emit the eight 5-bit groups that make up a full block.
        let chars_in_block = match chunk.len() {
            5 => 8,
            4 => 7,
            3 => 5,
            2 => 4,
            1 => 2,
            _ => unreachable!("chunks(5) yields 1..=5"),
        };

        for i in 0..chars_in_block {
            let shift = 35 - 5 * i as u32;
            let idx = ((acc >> shift) & 0x1F) as usize;
            out.push(table[idx]);
        }

        if pad {
            for _ in chars_in_block..8 {
                out.push(b'=');
            }
        }
    }

    out
}

/// Decode `input` with an explicit alphabet.  Padding is optional and, when
/// present, must be well formed.
pub fn decode_with(input: &[u8], alphabet: Alphabet) -> Result<Vec<u8>, DecodeError> {
    let table = alphabet.table();

    // Build the reverse lookup table.  This is a fixed-size array on the
    // stack, so it costs nothing to create per call and keeps the function
    // self-contained.
    let mut rev = [0xFFu8; 256];
    for (i, &c) in table.iter().enumerate() {
        rev[c as usize] = i as u8;
    }

    // Strip trailing padding, but only if it is well formed: at most six
    // '=' characters, and only at the very end.
    let mut end = input.len();
    let mut pad_count = 0usize;
    while end > 0 && input[end - 1] == b'=' {
        pad_count += 1;
        end -= 1;
    }
    if pad_count > 6 {
        return Err(DecodeError::InvalidPadding);
    }
    if input[..end].contains(&b'=') {
        return Err(DecodeError::InvalidPadding);
    }

    let significant = &input[..end];

    // The number of significant characters determines how many bytes come
    // out.  Any other count is impossible in base32.
    let out_len = match significant.len() % 8 {
        0 => significant.len() / 8 * 5,
        2 => significant.len() / 8 * 5 + 1,
        4 => significant.len() / 8 * 5 + 2,
        5 => significant.len() / 8 * 5 + 3,
        7 => significant.len() / 8 * 5 + 4,
        _ => return Err(DecodeError::InvalidLength),
    };

    // If padding was present, it must agree with the number of significant
    // characters.  This catches inputs such as "AA======" that would otherwise
    // decode to the same bytes as "AA".
    if pad_count != 0 {
        let expected = match significant.len() % 8 {
            0 => 0,
            2 => 6,
            4 => 4,
            5 => 3,
            7 => 1,
            _ => return Err(DecodeError::InvalidLength),
        };
        if pad_count != expected {
            return Err(DecodeError::InvalidPadding);
        }
    }

    let mut out = Vec::with_capacity(out_len);
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;

    for &c in significant {
        let v = rev[c as usize];
        if v == 0xFF {
            return Err(DecodeError::InvalidCharacter);
        }
        acc = (acc << 5) | u64::from(v);
        bits += 5;

        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }

    // Any leftover bits must be zero; otherwise the input had non-canonical
    // trailing bits.  RFC 4648 does not require rejecting those, but rejecting
    // them catches typos and is the safer default for a codec used on keys.
    if bits > 0 && (acc & ((1u64 << bits) - 1)) != 0 {
        return Err(DecodeError::InvalidLength);
    }

    if out.len() != out_len {
        return Err(DecodeError::InvalidLength);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_standard_vectors() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"", b""),
            (b"f", b"MY======"),
            (b"fo", b"MZXQ===="),
            (b"foo", b"MZXW6==="),
            (b"foob", b"MZXW6YQ="),
            (b"fooba", b"MZXW6YTB"),
            (b"foobar", b"MZXW6YTBOI======"),
        ];

        for (plain, encoded) in cases {
            assert_eq!(encode_padded(plain), *encoded, "encode {plain:?}");
            assert_eq!(decode(encoded).unwrap(), *plain, "decode {encoded:?}");
            // The unpadded form must also decode to the same bytes.
            let unpadded: Vec<u8> = encoded.iter().copied().filter(|&b| b != b'=').collect();
            assert_eq!(decode(&unpadded).unwrap(), *plain, "decode unpadded {unpadded:?}");
        }
    }

    #[test]
    fn hex_alphabet_round_trip() {
        let input = b"the quick brown fox";
        let encoded = encode_with(input, Alphabet::Hex, true);
        assert_eq!(decode_with(&encoded, Alphabet::Hex).unwrap(), input);

        // Spot-check the alphabet itself: 'f' maps to 'CO' in base32hex.
        assert_eq!(encode_with(b"f", Alphabet::Hex, false), b"CO");
    }

    #[test]
    fn empty_input_round_trips() {
        assert_eq!(encode(b""), b"");
        assert_eq!(encode_padded(b""), b"");
        assert_eq!(decode(b"").unwrap(), b"");
    }

    #[test]
    fn lowercase_is_rejected() {
        // RFC 4648 does not define lowercase; accepting it would create two
        // encodings for the same bytes, so we reject it.
        assert_eq!(decode(b"my======"), Err(DecodeError::InvalidCharacter));
    }

    #[test]
    fn invalid_character_is_rejected() {
        assert_eq!(decode(b"MZ!W6==="), Err(DecodeError::InvalidCharacter));
    }

    #[test]
    fn invalid_length_is_rejected() {
        assert_eq!(decode(b"A"), Err(DecodeError::InvalidLength));
        assert_eq!(decode(b"AAA"), Err(DecodeError::InvalidLength));
        assert_eq!(decode(b"AAAAAA"), Err(DecodeError::InvalidLength));
    }

    #[test]
    fn padding_must_be_well_formed() {
        // Interior padding is never allowed.
        assert_eq!(decode(b"M=Y"), Err(DecodeError::InvalidPadding));
        // Padding count must match the significant character count.
        assert_eq!(decode(b"MY====="), Err(DecodeError::InvalidPadding));
        assert_eq!(decode(b"MY======="), Err(DecodeError::InvalidPadding));
    }

    #[test]
    fn non_canonical_trailing_bits_are_rejected() {
        // "MB" decodes to the single byte 0x60, but the low bits of the
        // second character are non-zero.  A strict decoder rejects it.
        assert_eq!(decode(b"MB"), Err(DecodeError::InvalidLength));
    }

    #[test]
    fn padding_is_optional_on_decode() {
        assert_eq!(decode(b"MY").unwrap(), b"f");
        assert_eq!(decode(b"MZXW6YTB").unwrap(), b"fooba");
    }

    #[test]
    fn encode_without_padding_has_expected_length() {
        for n in 0..=10 {
            let input = vec![0xAB; n];
            let unpadded = encode(&input);
            let padded = encode_padded(&input);
            assert_eq!(padded.len() % 8, 0, "padded length for {n} bytes");
            assert!(padded.len() >= unpadded.len());
            assert_eq!(decode(&unpadded).unwrap(), input);
        }
    }
}
