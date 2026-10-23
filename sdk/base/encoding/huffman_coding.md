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

# Huffman Coding

## 1. Role

### Introduction

`huffman_coding` implements generic Huffman code-table construction and use: it can learn codes from sample data or import a predefined table, then use the resulting mappings for encoding and decoding. HTTP/2 Huffman coding builds on this concept but uses a fixed table specified by RFC 7541.

## 2. Data Model

### Code-construction and decoding structures

The generic implementation keeps symbol-frequency measurements, a weighted binary tree used to construct codes, symbol-to-code and code-to-symbol maps, and a trie used by the decoding path. These structures serve different stages: frequency/tree structures construct the table; the maps retain the resulting code mappings; the trie supports matching bit sequences during decoding.

### Bit-oriented representation

Huffman codes have variable bit lengths, so a symbol is not necessarily aligned to a byte boundary. The stream APIs retain partial bit state across chunk boundaries; the encoding and finalization rules are described in the Behavior Model.

The HTTP/2 implementation stores its fixed table in `detail/http_huffman_codes.*` and exposes it through `http_huffman_coding`. It does not learn a new table from each header field.

## 3. Behavior Model

```text
sample bytes ─► frequency measurement ─► weighted tree ─► code table
predefined table ────────────────────────────────────────► code table
                                                           │
                                     ┌─────────────────────┴──────────────────┐
                                     ▼                                        ▼
                                encode bits                             decode bits
```

### Learn or import a code table

For data-driven construction, callers load sample input, learn symbol frequencies, and infer the code table. Alternatively, `imports()` loads a supplied table.

```text
learned path: load(samples) ─► learn() ─► infer() ─► code mappings
fixed path:   imports(table) ──────────────────────► code mappings
```

The learned and imported paths both prepare mappings for subsequent encoding/decoding; importing does not run the frequency-learning algorithm.

### Encoding and decoding

Encoding looks up each symbol's bit code and accumulates bits until a complete output byte can be emitted. When the final bit sequence does not end on an octet boundary, the relevant caller/path must apply its required padding convention. For HTTP/2, the fixed-table wrapper uses the protocol's EOS-related one-bit padding rule.

Decoding consumes bits and identifies symbols through the decoding structure, preserving enough state to continue matching a code across byte/chunk boundaries. The trie matches bit-string codes; it does not calculate code lengths. Manual and stream-oriented flags select decoder behavior, while the HTTP/2 wrapper supplies the fixed protocol table.

### HTTP/2 path

```text
http_huffman_coding::get_instance()
                │
                ▼
      fixed RFC 7541 code table
                │
       ┌────────┴────────────────────────────────┐
       ▼                                         ▼
  ymbol lookup                       bit-sequence decode
       │                                         │
       └──── encoder_stream / decoder_stream ────┘
```

The singleton exposes the protocol-specific table to stream wrappers. Generic Huffman learning remains a separate capability.

## 4. Relationships

- `sdk/base/pattern/trie.hpp` supports bit-string matching in the generic decoder.
- `http_huffman_coding.*` and `detail/http_huffman_codes.*` provide the fixed RFC 7541 table.
- `encoder_stream` and `decoder_stream` preserve bit-oriented state across chunks.
- `test/testcase/encode/testcase_huffman.cpp` provides source-level algorithm and RFC-vector coverage, including RFC 7541 Appendix B vectors and stream chunk-boundary cases.

## 5. References

- [RFC 7541 — HPACK: Header Compression for HTTP/2](https://www.rfc-editor.org/rfc/rfc7541)
