## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Memory Dump

## 1. Role

### Introduction

`dump_memory` provides the common hexadecimal/ASCII memory representation used throughout hotplace for debugging binary data.

The formatter writes to `stream_t` and normally produces a 16-byte-per-line view containing an address, hexadecimal bytes, and printable ASCII characters.

## 2. Model

### Input types

Overloads cover raw memory as well as common hotplace data types, including:

- character buffers
- `std::string`
- `binary_t`
- `basic_stream`
- `variant_t`
- `bufferio_context_t`

This makes the function a common diagnostic entry point rather than a formatter limited to one buffer class.

## 3. Important behavior and lifetime

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

The testcase exercises the formatter and its supported representations. Logger and buffer-I/O code also use the same dump facility.

## 4. Example from the source tests

### Test walkthrough

`test/testcase/base/basic/testcase_dumpmemory.cpp` calls a small helper with the same text buffer and varies the hexadecimal width, indentation, and displayed base address. It then exercises `hdump()` with a label and string input.

```text
same input bytes
   ├── dump(..., hex_part=16)
   ├── dump(..., hex_part=32)
   ├── dump(..., indent=4)
   └── dump(..., rebase=0x1000)
```

This test is valuable because the input remains constant while formatting parameters change. It isolates presentation behavior from byte-content changes. For binary protocol debugging, compare the dump with the original buffer and remember that `rebase` changes the displayed address, not the memory pointer.

## 5. Relationships

- `logger_dump.cpp` connects the formatter to the logger's configured output path.
- `binary_t`, `basic_stream`, and `variant` provide supported input representations; the dump utility renders their bytes for inspection.
- Formatting output is diagnostic text, not a canonical serialization format.

## 6. References

### Related source and consumers

- `sdk/base/basic/dump_memory.hpp/.cpp`
- Test: `test/testcase/base/basic/testcase_dumpmemory.cpp`
- Related output path: `sdk/base/unittest/logger_dump.cpp`

`dump_memory` performs the formatting; logger APIs decide where the formatted diagnostic output is sent.

