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

# Huffman Coding

## 1. Role

### Introduction

`huffman_coding` is the generic Huffman coding implementation used by hotplace for learning, importing, exporting, encoding, and decoding Huffman code tables.

The implementation can derive codes from sample data or load a pre-trained table.

## 2. Data Model

### Two ways to obtain codes

```text
sample data
    │
    ├── load()
    ├── learn()
    └── infer()
          │
          ▼
      code table
```

or:

```text
pre-trained table
       │
       ▼
    imports()
       │
       ▼
    code table
```

The latter is the path used for protocol-defined Huffman tables such as HTTP/2.

The implementation uses frequency measurement and a binary-tree representation to construct codes. It also keeps a reverse code table for decoding.

### Encoding

Huffman codes are bit-oriented rather than byte-oriented. The encoder therefore accumulates bits and emits complete bytes as they become available.

If the final code does not end on an octet boundary, padding can be inserted before the final byte.

The implementation exposes `expect()` to calculate the expected encoded size before performing the actual encoding.

### Decoding

The decoder supports both direct/manual and stream-oriented paths. The implementation keeps enough bit state to decode symbols even when symbol boundaries do not coincide with byte boundaries.

This is important for HTTP/2 Huffman because RFC 7541 defines codes with different bit lengths and an EOS-related padding rule.

## 3. Behavior Model

### HTTP/2 Huffman

`http_huffman_coding` derives from `huffman_coding` and loads the static code table defined by RFC 7541 Appendix B.

```text
huffman_coding
      ▲
      │
http_huffman_coding
      │
      └── RFC 7541 static table
```

The singleton returned by `http_huffman_coding::get_instance()` provides the protocol-specific table without requiring each caller to construct it manually.

The actual table is kept in `detail/http_huffman_codes.*`.

### Tests

`test/testcase/encode/testcase_huffman.cpp`

The testcase covers:

- learning a Huffman table from sample data
- importing a pre-trained table
- exporting generated codes
- encoding/decoding
- RFC 7541 Appendix B vectors
- HTTP/2 Huffman through encoder/decoder streams
- different stream chunk sizes

The RFC 7541 testcase is the important interoperability reference; the learning path demonstrates the generic algorithm separately.

## 4. Relationships

- `sdk/base/pattern/trie.hpp` — the generic Huffman decoder indexes bit-string codes in a trie and scans the input bits to identify the longest matching code; the trie does not calculate Huffman code lengths.
- `http_huffman_coding.*` and `detail/http_huffman_codes.*` — load the fixed RFC 7541 code table on top of the generic implementation.
- `encoder_stream` / `decoder_stream` — preserve bit-oriented state when encoded data arrives in chunks.
- `test/testcase/encode/testcase_huffman.cpp` — learning/import/export behavior and RFC 7541 vector coverage.

## 5. References

- [RFC 7541 — HPACK: Header Compression for HTTP/2](https://www.rfc-editor.org/rfc/rfc7541)
