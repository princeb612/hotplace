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

# Memory Dump

## 1. Role

### Introduction

`dump_memory` provides the common hexadecimal/ASCII memory representation used throughout hotplace for debugging binary data.

The formatter writes to `stream_t` and normally produces a 16-byte-per-line view containing an address, hexadecimal bytes, and printable ASCII characters.

## 2. Data Model

### Input types

Overloads cover raw memory as well as common hotplace data types, including:

- character buffers
- `std::string`
- `binary_t`
- `basic_stream`
- `variant_t`
- `bufferio_context_t`

This makes the function a common diagnostic entry point rather than a formatter limited to one buffer class.

## 3. Behavior Model

### Formatting controls

The interface provides controls for the hexadecimal area, indentation, displayed base address, and output flags.

The main flags are:

- `dump_header` — print the dump header
- `dump_notrunc` — suppress the normal truncation behavior
- `dump_empty` — allow empty data to be represented
- `dump_nolf` — suppress the final line break

`rebase` controls the displayed address rather than changing the supplied memory pointer. The implementation preserves the project's traditional address formatting, including its lower-32-bit display behavior.

### Usage in the project

Memory dumps appear throughout protocol, TLS, QUIC, DTLS, crypto, certificate, and buffer-processing code. They are particularly useful when comparing encoded data or tracing a binary transformation.

### Tests

`test/testcase/base/basic/testcase_dumpmemory.cpp`

The testcase holds the text input constant while varying hexadecimal width, indentation, and displayed base address, then exercises `hdump()` with a label and string input. Logger and buffer-I/O code also use the same dump facility.

## 4. Relationships

- `logger_dump.cpp` connects the formatter to the logger's configured output path.
- `binary_t`, `basic_stream`, and `variant` provide supported input representations; the dump utility renders their bytes for inspection.
- Formatting output is diagnostic text, not a canonical serialization format.
- `dump_memory.hpp/.cpp` implement the formatter; `logger_dump.cpp` connects it to the logger's configured output path. `testcase_dumpmemory.cpp` covers the formatter, while logger APIs decide where the rendered diagnostic text is sent.
