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

# Decoder Stream

## 1. Role

### Introduction

`decoder_stream` is the stateful streaming layer for encoded input that arrives in multiple chunks.

It supports the same major streaming formats as `encoder_stream`:

- Base16
- Base64
- Base64URL
- RFC-style Base16
- HTTP/2 Huffman

## 2. Data Model

### Output

Decoded data is accumulated internally and returned through `data()`.

`set_maxsize()` controls the maximum output buffer size; the default is 32 KiB.

The class also provides `add()` and stream-style operators for incremental input.

## 3. Behavior Model

### Stateful processing

Encoded input does not necessarily arrive at a decoding-unit boundary.

For example, a Base64 unit contains four encoded characters, while Base16 consumes two. `decoder_stream` retains an incomplete unit and combines it with the next `write()` call.

```text
encoded chunks
     │
     ├── write(chunk 1)
     ├── write(chunk 2)
     ├── write(chunk 3)
     └── flush()
            │
            ▼
        binary data
```

Huffman decoding uses a separate string buffer because its symbols are bit-oriented rather than fixed-width character units.

### Tests

The streaming decoder is exercised by:

- `test/testcase/encode/testcase_base16.cpp`
- `test/testcase/encode/testcase_base64.cpp`
- `test/testcase/encode/testcase_huffman.cpp`

The tests feed the same encoded value using different chunk sizes and verify that the decoded result remains identical.

## 4. Relationships

### Relationship with decoders

Like `encoder_stream`, this class is an orchestration layer rather than another decoding algorithm.

```text
decoder_stream
      │
      ├── Base16 decoder
      ├── Base64 decoder
      └── HTTP/2 Huffman decoder
```

Its main responsibility is preserving partial state across input boundaries.

- The implementation is in `decoder_stream.hpp/.cpp`; it delegates to `base16.*`, `base64.*`, and `huffman_coding.*`. `testcase_base16.cpp`, `testcase_base64.cpp`, and `testcase_huffman.cpp` provide consumer-facing coverage for those decoders.
