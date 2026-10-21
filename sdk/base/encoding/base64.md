## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Base64

## 1. Role

### Introduction

`base64` implements RFC 4648 Base64 and Base64URL encoding and decoding.

The same API is used for ordinary Base64 (`+` and `/`) and Base64URL (`-` and `_` without padding), selected through `encoding_t`.

## 2. Data Model

### Main operations

```text
binary / string
      │
      ├── base64_encode(..., encoding_base64)
      │                     └── standard Base64
      │
      └── base64_encode(..., encoding_base64url)
                            └── Base64URL
```

The corresponding decode functions accept both forms according to the selected encoding.

The public implementation uses the low-level Base64 implementation and `encoder_stream_traits` to support output containers such as `std::string`, `binary_t`, and `basic_stream`.

### Streaming

`encoder_stream` and `decoder_stream` maintain incomplete 3-byte/4-character units between `write()` calls.

Consequently, an encoded value does not have to arrive as one complete buffer:

```text
input chunks
   │
   ├── write(chunk 1)
   ├── write(chunk 2)
   ├── write(chunk 3)
   └── flush()
          │
          ▼
       complete output
```

The tests deliberately vary the chunk size to verify that the result is independent of the input boundaries.

## 3. Behavior Model

### Multiline Base64

`base64_encode_multiline()` and `base64_decode_multiline()` provide line-oriented processing for data represented across multiple lines.

The encoder accepts a requested column width. A zero width disables wrapping.

This is useful for formats where Base64 is presented as text rather than as a single uninterrupted string.

### Relation to Radix-64

Radix-64 support is implemented separately in `radix64.*`, but its encoding layer is Base64. Radix-64 adds CRC-24 and armor processing around the Base64 representation.

See [radix64.md](radix64.md).

### Tests

`test/testcase/encode/testcase_base64.cpp`

The testcase covers:

- ordinary Base64 encode/decode
- Base64URL
- encoder/decoder streams with different chunk sizes
- multiline encoding and decoding
- RFC 4880 section 6.5 Radix-64 vectors
- RFC 4880 section 6.6 ASCII-armored message processing

## 4. Relationships

- `lowlevel/base64.*` — byte-level conversion primitives used by the public overloads.
- `encoder_stream` and `decoder_stream` — preserve incomplete Base64/Base64URL units across chunk boundaries.
- `radix64.*` — composes Base64 with CRC-24 and ASCII-armored framing; it is not a separate Base64 alphabet.
- `test/testcase/encode/testcase_base64.cpp` — round-trip, Base64URL, chunked streaming, and Radix-64 vector source coverage.

- `base64.hpp/.cpp` and `lowlevel/base64.hpp/.cpp` implement the public and byte-level paths; `encoder_stream.*` and `decoder_stream.*` add chunked processing, and `radix64.*` adds CRC-24 armor. `testcase_base64.cpp` covers round trips, URL-safe form, streaming, and Radix-64 behavior.

## 5. References

- [RFC 4648 — The Base16, Base32, and Base64 Data Encodings](https://www.rfc-editor.org/rfc/rfc4648)
