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

# Encoding

## 1. Role

### Introduction

`encoding` contains reusable encoders and decoders for textual, binary, and protocol-specific representations used throughout hotplace.

## 2. Data Model

### Directory map

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

### Implementation layout

The source layout separates public encoders/decoders from low-level Base16/Base64 routines and keeps the fixed HTTP/2 Huffman table under `detail/`:

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


## 3. Behavior Model

- Base16, Base64, and Base128 are data-representation utilities. A caller remains responsible for validating the meaning and constraints of the surrounding protocol field.
- Base64URL differs from ordinary Base64 in its alphabet and representation conventions; callers should select the intended variant rather than assume the encoded strings are interchangeable.
- Radix-64 composes Base64 with CRC-24 to create an armored representation. The CRC is part of that format path and is not a cryptographic authentication mechanism.
- Generic Huffman coding and HTTP/2 Huffman coding share coding concepts but have different table/configuration responsibilities. The HTTP/2 path uses the fixed code table specified by RFC 7541.
- Streaming encoding/decoding is stateful across calls. A chunk boundary is not necessarily an encoding-unit boundary, so incomplete units must be retained until more input arrives or the caller finalizes the stream.
- Base128 is consumed for ASN.1 OID component representation, but this layer does not define OID arcs or ASN.1 schema semantics.

## 4. Relationships

- [Encoding testcase and verification notes](../../../test/testcase/encode/testcase_encoding.md) describe source-level coverage for this directory. They are the appropriate place for assertions and report context.

- `base16`, `base64`, and `base128` implement the core data encodings; the low-level Base16/Base64 routines are kept separate from their higher-level overloads.
- `radix64` composes Base64 with CRC-24 from `sdk/base/basic/crc.cpp`; it is an armored representation, not a separate byte alphabet.
- `huffman_coding` supplies generic Huffman code handling, while `http_huffman_coding` loads the fixed HTTP/2 table from `detail/http_huffman_codes.*`.
- `encoder_stream` and `decoder_stream` preserve incomplete encoding units across calls and delegate completed units to the corresponding encoders/decoders.
- `base128` is consumed by ASN.1 OID encoding in `sdk/io/asn.1/`; the encoding layer owns byte representation, while ASN.1 owns OID semantics.

