# Binary Stream

`binary_stream` is the binary-oriented companion to the text-focused `basic_stream`. It is kept separate because binary accumulation and byte-oriented operations have different usage patterns from formatted text output.

The module is small; its importance is as a base abstraction used by code that needs an explicit binary stream representation rather than a textual formatter.

## Source

- `sdk/base/stream/binary_stream.hpp`
- `sdk/base/stream/binary_stream.cpp`
