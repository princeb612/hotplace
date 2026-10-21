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

# Base16

## 1. Role

### Introduction

`base16` implements hexadecimal encoding and decoding based on RFC 4648 Base16.

The public API accepts common hotplace data types such as `std::string`, `binary_t`, `basic_stream`, and raw byte buffers. It can also write through `encoder_stream_traits`, allowing the same implementation to target different stream-like containers.

## 2. Data Model

### Main operations

```text
binary / string
      │
      ├── base16_encode() ──> hexadecimal string
      │
      └── base16_decode() <── hexadecimal string
```

The low-level implementation lives under `lowlevel/base16.*`; `base16.*` provides the higher-level overloads and stream-buffer integration.

`base16_compare()` is provided for hexadecimal string comparison.

### Streaming

`encoder_stream(encoding_base16)` and `decoder_stream(encoding_base16)` retain partial input/output units between calls. This allows Base16 data to be processed when the input arrives in arbitrary chunks.

The Base16 stream path is exercised by the encoding testcase with deliberately different chunk boundaries.

## 3. Behavior Model

### RFC-style helper

Hotplace also provides `base16_encode_rfc()` and `base16_decode_rfc()` for textual hexadecimal forms used by RFC examples and test material.

The RFC-style parser accepts representations containing separators or spaces, which is useful when an RFC presents bytes in a human-readable form such as:

```text
00:01:02:03:04:05
```

or:

```text
00 01 02 03 04 05
```

This helper is distinct from ordinary Base16 encoding and should not be confused with another Base16 alphabet.

### Tests

`test/testcase/encode/testcase_base16.cpp`

The testcase covers:

- ordinary encode/decode
- stream-buffer overloads
- encoder/decoder streams
- odd-size input handling
- RFC-style encode/decode examples
- RFC-style textual byte representations

The RFC cases are particularly useful as executable examples of the distinction between the normal Base16 API and the project's RFC-oriented helper.

## 4. Relationships

- `lowlevel/base16.*` implements the byte-level conversion; `base16.*` exposes overloads for strings, byte buffers, and streams.
- `base16rfc.cpp` contains the RFC-oriented human-readable byte parser/formatter. It accepts separator-oriented forms and is distinct from the ordinary two-hex-digits-per-byte API.
- `encoder_stream` and `decoder_stream` reuse the Base16 implementation while retaining incomplete units across chunk boundaries.
- `sdk/base/basic/dump_memory.*` formats diagnostic hex dumps; it is not an alternative Base16 encoder.

- `base16.hpp/.cpp` and `base16rfc.cpp` provide the public/RFC-oriented paths, while `lowlevel/base16.hpp/.cpp` implements byte conversion. `testcase_base16.cpp` exercises the caller-visible behavior.

## 5. References

- [RFC 4648 — The Base16, Base32, and Base64 Data Encodings](https://www.rfc-editor.org/rfc/rfc4648)
