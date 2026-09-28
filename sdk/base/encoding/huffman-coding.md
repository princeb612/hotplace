# Huffman Coding

`huffman_coding` is the generic Huffman coding implementation used by hotplace for learning, importing, exporting, encoding, and decoding Huffman code tables.

The implementation can derive codes from sample data or load a pre-trained table.

## Two ways to obtain codes

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

## Encoding

Huffman codes are bit-oriented rather than byte-oriented. The encoder therefore accumulates bits and emits complete bytes as they become available.

If the final code does not end on an octet boundary, padding can be inserted before the final byte.

The implementation exposes `expect()` to calculate the expected encoded size before performing the actual encoding.

## Decoding

The decoder supports both direct/manual and stream-oriented paths. The implementation keeps enough bit state to decode symbols even when symbol boundaries do not coincide with byte boundaries.

This is important for HTTP/2 Huffman because RFC 7541 defines codes with different bit lengths and an EOS-related padding rule.

## HTTP/2 Huffman

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

## Tests

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

## Related source

- `sdk/base/encoding/huffman_coding.hpp`
- `sdk/base/encoding/huffman_coding.cpp`
- `sdk/base/encoding/http_huffman_coding.hpp`
- `sdk/base/encoding/http_huffman_coding.cpp`
- `sdk/base/encoding/detail/http_huffman_codes.hpp`
- `sdk/base/encoding/detail/http_huffman_codes.cpp`
- `test/testcase/encode/testcase_huffman.cpp`
