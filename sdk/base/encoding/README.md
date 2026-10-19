## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Encoding

## 1. Role

### Introduction

`encoding` contains reusable encoders and decoders for textual, binary, and protocol-specific representations used throughout hotplace.

The directory has three main roles:

```text
encoding
├── data encoding
│   ├── Base16
│   ├── Base64 / Base64URL
│   └── Base128
├── protocol-specific encoding
│   ├── Radix-64 armor
│   └── HTTP/2 Huffman
└── streaming
    ├── encoder_stream
    └── decoder_stream
```

## 2. Model

### Data encodings

- [Base16](base16.md) — RFC 4648 hexadecimal encoding, including hotplace's RFC-style helper.
- [Base64](base64.md) — Base64 and Base64URL, including multiline and streaming use.
- [Base128](base128.md) — variable-length base-128 representation used by protocol data such as ASN.1 OID components, with `bignumber` support.

### Protocol-specific encoding

- [Radix-64](radix64.md) — RFC 4880 Radix-64 armor support built on Base64 plus CRC-24.
- [Huffman coding](huffman_coding.md) — generic Huffman coding and the HTTP/2 Huffman code table defined by RFC 7541.

### Streaming

- [Encoder stream](encoder_stream.md) — stateful encoding across multiple input chunks.
- [Decoder stream](decoder_stream.md) — stateful decoding across multiple encoded chunks.

The streaming classes share the same encoding implementations rather than defining separate algorithms. They retain incomplete encoding units between `write()` calls and complete them in `flush()`.

## 3. Important behavior and lifetime

### Tests

See [encoding testcase and verification notes](../../../test/testcase/encode/testcase_encoding.md) for the source-level coverage review and the supplied report summary. The main encoding tests are under `test/testcase/encode/`:

- `testcase_base16.cpp`
- `testcase_base64.cpp`
- `testcase_base128.cpp`
- `testcase_huffman.cpp`

These tests also provide practical examples of chunked streaming, RFC test vectors, Base64URL, Radix-64, and HTTP/2 Huffman processing.

## 4. Example from the source tests

See the source-test references below; do not infer runtime execution from source presence alone.

## 5. Relationships

Related components and cross-module links are listed in References where available.

## 6. References

### Related source

```text
sdk/base/encoding/
├── base16.*
├── base64.*
├── base128.*
├── radix64.*
├── huffman_coding.*
├── http_huffman_coding.*
├── encoder_stream.*
├── decoder_stream.*
├── lowlevel/
│   ├── base16.*
│   └── base64.*
└── detail/
    └── http_huffman_codes.*
```
