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

The HTTP/2 implementation stores its fixed table in `detail/http_huffman_codes.*` and exposes it through `http_huffman_coding`. It imports the RFC 7541 table rather than running the generic frequency-learning path.

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

Decoding consumes bits and identifies symbols through the decoding structure, preserving enough state to continue matching a code across byte/chunk boundaries. The trie matches bit-string codes; it does not calculate code lengths.

### What `decodable()` means

`decodable()` is a narrow code-table check, not a test that arbitrary input bytes are valid. It returns `true` exactly when the shortest code in the currently loaded table is at least five bits long:

```cpp
bool huffman_coding::decodable() const {
    return (_range.getmin() > 4) ? true : false;
}
```

The five-bit boundary matters because the final octet can have one to seven padding bits. If a table permits a four-bit code, padding can complete a real codeword and the decoder cannot tell whether that symbol was intended or those bits were only padding. For example, with `A = 1010` and `B = 1111`, the tail `1010 1111` can mean `AB`, but it can also mean `A` followed by four padding bits. The byte stream alone does not distinguish the two interpretations.

HPACK's table supplies the other part of the guarantee: RFC 7541 pads with the leading bits of the reserved 30-bit EOS code (`111...111`), which is not an ordinary data symbol. Because the HPACK code table is prefix-free, that all-ones suffix is a prefix of EOS rather than a valid symbol code. Thus the five-bit minimum is a guard used by this implementation's automatic decode path, while the HPACK EOS convention explains why its padding can be recognized. The minimum-length check alone does not validate an arbitrary imported table's padding convention.

By default, `decode()` returns `errorcode_t::ambiguous` when the shortest code is four bits or shorter. `manual_decode` bypasses that guard and relaxes the final all-ones-tail check; use it only when the caller independently knows how to interpret the remaining bits. `decodable()` is useful for checking the minimum-length precondition before relying on automatic decoding.

### HPACK: fixed table used by HTTP/2

HPACK applies Huffman coding to header-name and header-value strings inside compressed header blocks. Its table is fixed by RFC 7541 Appendix B; the generic `huffman_coding` learning path is not involved. The `http_huffman_coding` singleton exposes that table and uses the shared bit-oriented encoder/decoder behavior.

```text
HTTP/2 HEADERS / CONTINUATION
            │ compressed header block
            ▼
        HPACK field decoder ─── static/dynamic table references
            │ literal string encoded with Huffman?
            ▼
    http_huffman_coding (RFC 7541 fixed table)
            │
            ├── encode: input bytes -> variable-length codes -> EOS-style padding
            └── decode: encoded bytes -> symbols; validate final padding
```

Huffman coding handles a literal string's byte representation; it does not choose whether a header field is indexed, uses a table name, or is emitted as a literal. Those choices and the stateful static/dynamic header tables belong to HPACK.

### Practical example: RFC 7541 vectors

`test/testcase/net/hpack/testcase_huffman.cpp`, in `test_huffman()`, exercises the HPACK-specific wrapper. For each input string, the test supplies the RFC's expected hexadecimal bytes, encodes the input, compares the bytes, then decodes and compares the recovered bytes with the original.

```cpp
const char* sample = "www.example.com";
const char* expect = "f1e3 c2e5 f23a 6ba0 ab90 f4ff";

auto huffcode = http_huffman_coding::get_instance();

binary_t encoded;
huffcode->encode(encoded, (byte_t*)sample, strlen(sample));
_test_case.assert(encoded == base16_decode_rfc(expect), __FUNCTION__, "encode %s", sample);

binary_t decoded;
return_t ret = huffcode->decode(decoded, encoded.data(), encoded.size());
_test_case.assert(
    (errorcode_t::success == ret) &&
    (decoded == to_binary(sample)),
    __FUNCTION__, "decode %s", sample);
```

The actual helper `do_test_huffman_codes_routine()` also logs intermediate bytes when verbose mode is enabled. The vectors include short header-like strings such as `no-cache` and `custom-key`, as well as longer text. Comparing with fixed RFC bytes matters: a round trip alone could pass even if encoder and decoder shared the same incorrect table.

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
- `http_huffman_coding.*` and `detail/http_huffman_codes.*` provide the fixed RFC 7541 table used by HPACK.
- `hpack_encoder.*` uses the HPACK-specific Huffman wrapper for literal header strings; HPACK also manages field representations and static/dynamic table state.
- `encoder_stream` and `decoder_stream` preserve bit-oriented state across chunks.
- `test/testcase/net/hpack/testcase_huffman.cpp` exercises the HTTP/2 fixed table with RFC 7541 Appendix B known-answer vectors and round-trip assertions.
- `test/testcase/encode/testcase_huffman.cpp` provides tests for the generic Huffman algorithm and stream-oriented behavior.

## 5. References

- [RFC 7541 — HPACK: Header Compression for HTTP/2](https://www.rfc-editor.org/rfc/rfc7541)
