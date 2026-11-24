# simple-base32

A dependency-free RFC 4648 base32 codec for byte slices, with optional padding and a choice of the standard or `base32hex` alphabet.

```rust
use simple_base32::{decode, encode, encode_padded};

let bytes = b"foobar";
let encoded = encode_padded(bytes);
assert_eq!(encoded, b"MZXW6YTBOI======");
assert_eq!(decode(&encoded).unwrap(), bytes);

// Padding is optional on the way in and omitted on the way out.
assert_eq!(encode(bytes), b"MZXW6YTBOI");
assert_eq!(decode(b"MZXW6YTBOI").unwrap(), bytes);
```

## Why this exists

Most base32 crates pull in a trait-heavy streaming API or a pile of dependencies for what is a small, fixed transformation. This one keeps the whole surface to four functions and one enum, and returns concrete `Vec<u8>` values so callers do not have to name a codec type. The trade-off is that everything is in memory: there is no `Read`/`Write` streaming path. For the keys, hashes, and small payloads base32 is normally used for, that is the right trade-off.

## The edge you will hit

The decoder is strict. It rejects lowercase input, non-canonical trailing bits, and padding that does not match the number of significant characters. That last rule means `decode(b"MY=====")` fails even though many lenient decoders would accept it. If you need to interoperate with a producer that emits sloppy padding, normalize the input before calling `decode`.

## API

- `encode(&[u8]) -> Vec<u8>` — standard alphabet, no padding.
- `encode_padded(&[u8]) -> Vec<u8>` — standard alphabet, padded to a multiple of eight characters.
- `decode(&[u8]) -> Result<Vec<u8>, DecodeError>` — standard alphabet; padding is optional but must be well formed when present.
- `encode_with(&[u8], Alphabet, bool) -> Vec<u8>` — explicit alphabet and padding choice.
- `decode_with(&[u8], Alphabet) -> Result<Vec<u8>, DecodeError>` — explicit alphabet.
- `Alphabet` — `Standard` or `Hex`.
- `DecodeError` — `InvalidCharacter`, `InvalidPadding`, or `InvalidLength`.
