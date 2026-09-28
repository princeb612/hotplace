# Base64

`base64` implements RFC 4648 Base64 and Base64URL encoding and decoding.

The same API is used for ordinary Base64 (`+` and `/`) and Base64URL (`-` and `_` without padding), selected through `encoding_t`.

## Main operations

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

## Multiline Base64

`base64_encode_multiline()` and `base64_decode_multiline()` provide line-oriented processing for data represented across multiple lines.

The encoder accepts a requested column width. A zero width disables wrapping.

This is useful for formats where Base64 is presented as text rather than as a single uninterrupted string.

## Streaming

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

## Relation to Radix-64

Radix-64 support is implemented separately in `radix64.*`, but its encoding layer is Base64. Radix-64 adds CRC-24 and armor processing around the Base64 representation.

See [radix64.md](radix64.md).

## Tests

`test/testcase/encode/testcase_base64.cpp`

The testcase covers:

- ordinary Base64 encode/decode
- Base64URL
- encoder/decoder streams with different chunk sizes
- multiline encoding and decoding
- RFC 4880 section 6.5 Radix-64 vectors
- RFC 4880 section 6.6 ASCII-armored message processing

## Related source

- `sdk/base/encoding/base64.hpp`
- `sdk/base/encoding/base64.cpp`
- `sdk/base/encoding/lowlevel/base64.hpp`
- `sdk/base/encoding/lowlevel/base64.cpp`
- `sdk/base/encoding/encoder_stream.*`
- `sdk/base/encoding/decoder_stream.*`
- `sdk/base/encoding/radix64.*`
- `test/testcase/encode/testcase_base64.cpp`
