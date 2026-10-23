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

## 4. Relationships

- `test/testcase/encode/testcase_base16.cpp` covers ordinary conversion, stream-buffer overloads, encoder/decoder streams, odd-sized chunks, and RFC-style examples.
- `lowlevel/base16.*` implements byte-level conversion; `base16.*` exposes higher-level overloads.
- `base16rfc.cpp` handles RFC-oriented human-readable byte forms.
- `encoder_stream` and `decoder_stream` reuse Base16 conversion while handling chunk boundaries.
- `sdk/base/basic/dump_memory.*` formats diagnostic hex dumps; it is not an alternative Base16 encoder.
- `test/testcase/encode/testcase_base16.cpp` provides source-level coverage.

## 5. References

- [RFC 4648 — The Base16, Base32, and Base64 Data Encodings](https://www.rfc-editor.org/rfc/rfc4648)
