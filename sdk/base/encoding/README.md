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

# Encoding

## 1. Role

### Introduction

`encoding` contains reusable encoders and decoders for textual, binary, and protocol-specific representations used throughout hotplace. It converts representations; the caller remains responsible for interpreting the resulting bytes according to the surrounding protocol or data model.

The directory contains three broad kinds of implementation:

- **Data encodings** — Base16, Base64/Base64URL, and Base128.
- **Protocol-specific encodings** — Radix-64 armor and HTTP/2 Huffman coding.
- **Stateful streams** — `encoder_stream` and `decoder_stream`, which carry partial encoding units between calls.

## 2. Data Model

### Directory map

```text
encoding
├── data encoding
│   ├── Base16
│   ├── Base64 / Base64URL
│   └── Base128
├── protocol-specific encoding
│   ├── Radix-64 armor = Base64 + CRC-24
│   └── HTTP/2 Huffman = fixed code table + bit packing
└── streaming
    ├── encoder_stream
    └── decoder_stream
```

### Input and output representations

| Representation | Role in this directory |
|---|---|
| `byte_t*` + length | Explicit byte range; appropriate when input may contain zero bytes or is not a C string. |
| `std::string` | Encoded text, or byte storage for APIs that explicitly accept a pointer and length. |
| `binary_t` | Byte-oriented input and decoded output. |
| `basic_stream` | Another supported source of bytes for the convenience overloads. |
| `encoding_t` | Selects the stream encoding, including Base16, Base64/Base64URL, and HTTP/2 Huffman. |
| `return_t` | Reports operation status for APIs that write into caller-provided output or perform multi-step work. |

Pointer-and-length overloads preserve the specified range. C-string overloads commonly derive the input length with `strlen`, so they are not interchangeable with length-delimited binary input.

### Stateful stream data

`encoder_stream` and `decoder_stream` are stateful objects. Their internal buffers are implementation state, not independent wire formats.

- **Encoder output:** `_buffer` accumulates textual output for Base16/Base64-family paths; `_bin` stores binary output used by the HTTP/2 Huffman path.
- **Encoder partial state:** `encbuf_t` stores up to two pending input bytes for Base64/Base64URL. `bitbuf_t` stores pending Huffman code bits.
- **Decoder output:** `_buffer` accumulates decoded bytes.
- **Decoder partial state:** `encbuf_t` stores incomplete textual units (one Base16 character or up to three Base64/Base64URL characters). `_huffbuf` stores the Huffman decoder's pending bit state.

The stream classes default to a 32 KiB maximum-size setting, configurable with `set_maxsize()`. The exact check is implementation-specific; it should not be interpreted as a universal limit on every internal buffer or on every encoding path.

### Base128 value and cursor

Base128 exposes overloads for `uint64`, `bignumber`, and byte-oriented values. Decoding from a byte range uses a caller-owned `pos` cursor:

- `stream` and `size` define the available byte range.
- `pos` identifies the next byte to consume and advances as bytes are read.
- The output value receives the decoded base-128 integer.


### Huffman code data

Generic `huffman_coding` maintains symbol frequencies and code mappings for learned or imported Huffman codes. The HTTP/2 path is different: `http_huffman_coding` uses the fixed code table in `detail/http_huffman_codes.*`, rather than learning a table from each input.

## 3. Behavior Model

### Base128 cursor behavior

`pos` advances as the decoder consumes bytes, allowing consecutive values to be decoded from one buffer without first slicing it into separate arrays. The encoding layer represents the integer; ASN.1 OID arc interpretation remains outside this API.

### Radix-64 checksum verification flow

Radix-64 armor returns Base64-encoded content and a separate Base64 representation of the three CRC-24 bytes. During decoding, the implementation decodes the content, calculates CRC-24 over the decoded bytes, encodes the calculated checksum, and compares it with the supplied armor checksum. This detects checksum mismatches; CRC-24 is not cryptographic authentication.

### One-shot data encoding

The convenience overloads adapt common input containers to the core encoding routines. The typical path is:

```text
caller input
  │  pointer + length, string, binary_t, or basic_stream
  ▼
encoding-specific API
  │
  ├── Base16 / Base64
  │     ▼
  │   low-level size calculation
  │     ▼
  │   reserve output capacity
  │     ▼
  │   encode or decode into output
  │
  └── Base128
        ▼
      split integer into 7-bit groups / consume groups
        ▼
      append or reconstruct integer value
  ▼
caller receives encoded text, decoded bytes, or status
```

For the templated Base16 and Base64 APIs that write to a supported stream buffer, the wrapper first asks the low-level routine for the required output size. The expected `insufficient_buffer` result provides the size; the wrapper reserves space, performs the operation, and commits the number of bytes actually written on success. Unless `encoding_notrunc` is set, the destination is truncated before processing. These steps describe this output-buffer API path, not every convenience overload.

Base64 and Base64URL share the Base64 processing path but select different representation conventions. The caller must choose the intended variant. Base16 RFC-style helper functions are separate from the ordinary Base16 conversion path.

### Stateful encoding

`encoder_stream::write()` processes each incoming chunk according to the selected `encoding_t`.

1. Validate the input pointer and apply the configured size check.
2. Select the algorithm for the chosen encoding.
3. For Base16, encode the supplied bytes immediately.
4. For Base64/Base64URL, first complete any pending three-byte input unit. Encode all remaining complete three-byte groups and retain zero to two trailing bytes in `encbuf_t`.
5. For HTTP/2 Huffman, look up each input symbol's code, append its bits to `bitbuf_t`, and emit a byte whenever eight bits have accumulated.
6. Finalize pending state when the caller requests `str()` or `bin()`, which invokes `flush()`.

The finalization step is encoding-specific. Base64 encodes a remaining partial input group. Huffman coding pads the last partial byte with one-bits, as required by the HTTP/2 Huffman representation. Base16 has no pending-unit finalization in this stream implementation.

```text
write(chunk)
   │
   ▼
select encoding
   ├── Base16 ───────────────► encode chunk
   ├── Base64/Base64URL ─────► complete groups ─► retain tail
   └── HTTP/2 Huffman ───────► append code bits ─► emit full bytes
                                                    │
str() / bin()                                       │
   └── flush pending state ◄────────────────────────┘
```

### Stateful decoding

`decoder_stream::write()` mirrors the same chunk-aware design but accumulates decoded bytes.

1. Validate the input pointer and apply the configured size check.
2. For Base16, complete two-character units and retain a trailing character.
3. For Base64/Base64URL, complete four-character units and retain the incomplete suffix.
4. For HTTP/2 Huffman, pass the chunk to the fixed-table decoder and preserve its pending bit state in `_huffbuf`.
5. When `data()` is requested, `flush()` checks or processes the remaining state before returning the decoded buffer.

The final state is not identical for all encodings. Base16 only decodes a pending unit when its retained length is two. Base64/Base64URL process a retained suffix, except that a one-character suffix is discarded by the current implementation. The HTTP/2 Huffman path checks pending padding state and can report `bad_data`. Callers should check the status of `write()`; `data()` itself returns the buffer and does not expose the return value from its internal `flush()`.

```text
write(chunk)
   │
   ▼
select encoding
   ├── Base16 ───────────────► decode pairs ─────► retain odd tail
   ├── Base64/Base64URL ─────► decode quartets ──► retain suffix
   └── HTTP/2 Huffman ───────► decode with table ─► retain bit state
                                                        │
data()                                                  │
   └── flush pending state and return bytes ◄───────────┘
```

### Radix-64 armor

`radix64_armor_encode()` performs two related encodings over the same input:

1. Encode the payload with Base64.
2. Calculate CRC-24 over the original bytes.
3. Convert the checksum to network byte order and Base64-encode its three checksum bytes.
4. Return the payload text and checksum text separately.

`radix64_armor_decode()` decodes the payload first, recalculates CRC-24 over the decoded bytes, encodes the calculated checksum in the same form, and compares it with the supplied checksum. A mismatch returns `errorcode_t::mismatch`; successful Base64 decoding alone does not establish checksum validity.

### Generic and HTTP/2 Huffman paths

Generic `huffman_coding` can learn codes from input data (`load()`, `learn()`, `infer()`) or import a predefined table. HTTP/2 Huffman coding instead uses the fixed table defined for the protocol. The stream wrapper delegates HTTP/2 symbol encoding/decoding to `http_huffman_coding`; it does not build a new Huffman tree for each HTTP/2 header field.

### Base128 decoding and error boundaries

Base128 decoding consumes bytes until it encounters a byte whose continuation bit is clear. Each byte contributes seven payload bits; a set high bit indicates that another byte follows. The cursor advances as bytes are consumed.

The fixed-width `uint64` overload rejects certain malformed or overlong encodings and returns `bad_data` if the input ends before a terminating byte. The `bignumber` overload supports larger values and includes a maximum-byte guard. These are representation-level checks; they do not validate the meaning of an ASN.1 OID or a surrounding schema.

## 4. Relationships

- [Encoding testcase and verification notes](../../../test/testcase/encode/README.md) describe source-level coverage for this directory. Test assertions and runtime evidence belong there rather than being inferred from implementation descriptions.
- [Base16](base16.md), [Base64](base64.md), and [Base128](base128.md) document the individual data-encoding APIs.
- [Radix-64](radix64.md) documents the armor/checksum wrapper built on Base64 and CRC-24 from `sdk/base/basic/crc.cpp`.
- [Huffman coding](huffman_coding.md) describes generic code handling and the HTTP/2 fixed-table path implemented by `http_huffman_coding.*`.
- [Encoder stream](encoder_stream.md) and [decoder stream](decoder_stream.md) document the stateful chunk-processing APIs.
- Low-level Base16/Base64 routines implement the core conversion operations used by the higher-level wrappers.
- `base128` is consumed by ASN.1 OID encoding in `sdk/io/asn.1/`; this directory owns the integer representation, while ASN.1 owns OID semantics.

## 5. References

- [RFC 4648 — The Base16, Base32, and Base64 Data Encodings](https://www.rfc-editor.org/rfc/rfc4648)
- [RFC 4880 — OpenPGP Message Format](https://www.rfc-editor.org/rfc/rfc4880)
- [RFC 7541 — HPACK: Header Compression for HTTP/2](https://www.rfc-editor.org/rfc/rfc7541)
