# Memory Dump

`dump_memory` provides the common hexadecimal/ASCII memory representation used throughout hotplace for debugging binary data.

The formatter writes to `stream_t` and normally produces a 16-byte-per-line view containing an address, hexadecimal bytes, and printable ASCII characters.

## Formatting controls

The interface provides controls for the hexadecimal area, indentation, displayed base address, and output flags.

The main flags are:

- `dump_header` — print the dump header
- `dump_notrunc` — suppress the normal truncation behavior
- `dump_empty` — allow empty data to be represented
- `dump_nolf` — suppress the final line break

`rebase` controls the displayed address rather than changing the supplied memory pointer. The implementation preserves the project's traditional address formatting, including its lower-32-bit display behavior.

## Input types

Overloads cover raw memory as well as common hotplace data types, including:

- character buffers
- `std::string`
- `binary_t`
- `basic_stream`
- `variant_t`
- `bufferio_context_t`

This makes the function a common diagnostic entry point rather than a formatter limited to one buffer class.

## Usage in the project

Memory dumps appear throughout protocol, TLS, QUIC, DTLS, crypto, certificate, and buffer-processing code. They are particularly useful when comparing encoded data or tracing a binary transformation.

## Tests

`test/testcase/base/basic/testcase_dumpmemory.cpp`

The testcase exercises the formatter and its supported representations. Logger and buffer-I/O code also use the same dump facility.

## Related source

- `sdk/base/basic/dump_memory.hpp`
- `sdk/base/basic/dump_memory.cpp`
- `test/testcase/base/basic/testcase_dumpmemory.cpp`
