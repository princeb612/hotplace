# Encoder Stream

`encoder_stream` is the stateful streaming layer over the encoding implementations in this directory.

It is designed for input that arrives in multiple chunks rather than as one complete buffer.

Supported encodings include:

- Base16
- Base64
- Base64URL
- RFC-style Base16
- HTTP/2 Huffman

## Stateful processing

```text
write(chunk 1)
      │
write(chunk 2)
      │
write(chunk 3)
      │
     ...
      │
    flush()
      │
      ▼
complete encoded output
```

The important implementation detail is that encoding-unit boundaries are retained between calls.

For Base64, for example, input is processed in 3-byte units. If a `write()` ends with one or two bytes left over, those bytes remain in the internal buffer and are combined with the next input chunk.

The same idea is used for bit-oriented Huffman encoding through an internal bit buffer.

## Input types

The stream supports raw byte buffers as well as common hotplace values through `operator<<()` / `add()`.

Integral values can optionally be written in big-endian form. The default is big-endian, and `set_endian()` changes that behavior.

The maximum internal output buffer is 32 KiB by default and can be changed with `set_maxsize()`.

## Relationship with encoders

`encoder_stream` does not replace `base16_encode()`, `base64_encode()`, or `huffman_coding::encode()`.

Instead it retains incomplete units and delegates complete units to those implementations:

```text
encoder_stream
      │
      ├── Base16 encoder
      ├── Base64 encoder
      └── HTTP/2 Huffman encoder
```

This keeps the encoding rules in one place while adding chunked processing.

## Tests

The streaming behavior is exercised by:

- `test/testcase/encode/testcase_base16.cpp`
- `test/testcase/encode/testcase_base64.cpp`
- `test/testcase/encode/testcase_huffman.cpp`

These tests deliberately change chunk boundaries and compare the streaming result with the ordinary encoder result.

## Related source

- `sdk/base/encoding/encoder_stream.hpp`
- `sdk/base/encoding/encoder_stream.cpp`
- `sdk/base/encoding/base16.*`
- `sdk/base/encoding/base64.*`
- `sdk/base/encoding/huffman_coding.*`
- `test/testcase/encode/testcase_base16.cpp`
- `test/testcase/encode/testcase_base64.cpp`
- `test/testcase/encode/testcase_huffman.cpp`
