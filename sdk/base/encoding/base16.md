## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Base16

## 1. Role

### Introduction

`base16` implements hexadecimal encoding and decoding based on RFC 4648 Base16. Public overloads accept strings, `binary_t`, `basic_stream`, and raw byte ranges; templated overloads can write to supported stream-like containers through `encoder_stream_traits`.

## 2. Data Model

### Input and output

The low-level routines under `lowlevel/base16.*` perform byte conversion. The public `base16.*` layer supplies container overloads and output-buffer integration. `base16_encode_rfc()` and `base16_decode_rfc()` are separate helpers for RFC-style textual byte representations with separators or whitespace.

### Streaming units

A Base16 byte is represented by two hexadecimal characters. `encoder_stream` can encode each input chunk immediately. `decoder_stream` retains a single trailing character until another character arrives, so a byte split across two input chunks can be decoded as one unit.

## 3. Behavior Model

### One-shot conversion

```text
byte range / binary_t / basic_stream
       │
       └── base16_encode() ──► hexadecimal text

hexadecimal text
       │
       └── base16_decode() ──► binary_t
```

The input representation selects the appropriate overload; the low-level conversion operates on a byte range and the wrapper materializes the output representation.

For the templated output-buffer overload, the wrapper asks the low-level encoder/decoder for the required output size, reserves destination capacity, runs the conversion, and commits the written length on success. Unless `encoding_notrunc` is set, the destination is truncated first. Convenience overloads return a string or byte vector around the same conversion path.

### Practical use: round trip and chunked input

The Base16 testcase first checks the direct conversion contract: encode a byte string, decode the result, and compare the decoded bytes with the original. It also exercises the same operation through `std::string`, `binary_t`, and `basic_stream` output forms.

```cpp
auto encoded = base16_encode(sample1);
auto decoded = base16_decode(encoded);
_test_case.assert(decoded == bin_sample1, __FUNCTION__, "base16 round trip");
```

For incremental input, the testcase feeds data to `encoder_stream` and encoded text to `decoder_stream` in chunks. Chunk boundaries need not line up with the encoded byte pairs:

```cpp
encoder_stream encoder(encoding_t::encoding_base16);
encoder.write(sample.data(), 5);
encoder.write(sample.data() + 5, sample.size() - 5);
auto encoded = encoder.str();

decoder_stream decoder(encoding_t::encoding_base16);
decoder.write(encoded.data(), 3);
decoder.write(encoded.data() + 3, encoded.size() - 3);
auto decoded = decoder.data();
```

This reduced example illustrates the API sequence; the source testcase uses pseudo-random chunk sizes over all 256 byte values and asserts that the decoded data matches the original. Check each `write()` status when adapting the pattern to application code.

### RFC-style textual bytes

The RFC-oriented helpers accept human-readable byte lists such as `00:01:02:03:04:05` or `00 01 02 03 04 05`. This is a parsing/formatting convenience for displayed vectors, not a different Base16 alphabet. Ordinary `base16_decode()` expects the ordinary hexadecimal representation.

### Streaming decode flow

```text
write(encoded chunk)
      │
      ├── combine with pending character, if any
      ▼
decode complete pairs
      │
      ├── save one trailing character
      └── append decoded bytes
                │
             data()/flush()
```

The current `decoder_stream::flush()` decodes a retained suffix only when it contains two characters. A lone final hexadecimal character is not a complete byte. The stream decoder's RFC-style Base16 selector currently returns `not_supported`; the existence of the RFC helper functions does not mean that mode is implemented by `decoder_stream`.

## 5. Relationships

- [`test/testcase/encode/testcase_base16.cpp`](../../../test/testcase/encode/testcase_base16.cpp) covers ordinary conversion, stream-buffer overloads, encoder/decoder streams, odd-sized chunks, and RFC-style examples.
- `lowlevel/base16.*` implements byte-level conversion; `base16.*` exposes higher-level overloads.
- `base16rfc.cpp` handles RFC-oriented human-readable byte forms.
- `encoder_stream` and `decoder_stream` reuse Base16 conversion while handling chunk boundaries.
- `sdk/base/basic/dump_memory.*` formats diagnostic hex dumps; it is not an alternative Base16 encoder.
- The same testcase provides source-level coverage for the conversion paths above.

## 6. References

- [RFC 4648 — The Base16, Base32, and Base64 Data Encodings](https://www.rfc-editor.org/rfc/rfc4648)
