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

### Output row and options

The output is text written through the caller-supplied `stream_t*`; it is not a byte container. A normal row contains a displayed address, a fixed-width hexadecimal column, and a printable-character column. The final row is padded with `--` entries when the byte count is not a multiple of `hex_part`.

The caller controls `hex_part` (bytes per row), `indent`, the displayed `rebase` address, and flags. `rebase` affects the displayed address only; it does not change the source pointer. The address format intentionally displays only the low 32 bits.

## 3. Behavior Model

### Formatting flow

Unless `dump_notrunc` is set, the destination stream is cleared before output. The implementation rejects a null stream or zero `hex_part`; null/empty input returns without rows unless `dump_empty` requests the literal `empty` marker. For non-empty input, the byte length is rounded up to a whole number of rows, then each row is rendered as address, hex bytes (padding missing columns with `--`), and printable text (non-printable bytes become `.`; percent signs are escaped for the stream formatter).

The flags control presentation:

- `dump_header` — print the byte-index header.
- `dump_notrunc` — append to the stream instead of clearing it first.
- `dump_empty` — allow empty data to be represented.
- `dump_nolf` — suppress the final line break.

The `bufferio_context_t` overload first obtains the byte pointer and length through `bufferio::get()`; the `variant_t` overload first formats the value through `vtprintf()` and then dumps those resulting bytes. These are transformations before the shared raw-byte formatter, not alternate row formats.

### Usage in the project

Memory dumps appear throughout protocol, TLS, QUIC, DTLS, crypto, certificate, and buffer-processing code. They are particularly useful when comparing encoded data or tracing a binary transformation.

Logger and buffer-I/O code also use the same dump facility.

### Row construction

```text
supported input overload
  └─ resolve byte pointer + length + display options
       ├─ optional header / label
       ├─ each output row
       │    ├─ displayed address (possibly rebased)
       │    ├─ hexadecimal byte columns
       │    └─ printable-character column
       └─ write formatted rows to stream_t
```

The displayed base address is presentation metadata; rebasing does not change the memory address being read. Likewise, the ASCII column is a diagnostic rendering of bytes, not a reversible encoding or protocol validation step.

## 4. Relationships

- `test/testcase/base/basic/testcase_dumpmemory.cpp` holds the text input constant while varying hexadecimal width, indentation, and displayed base address, then exercises `hdump()` with a label and string input.
- `logger_dump.cpp` connects the formatter to the logger's configured output path.
- `binary_t`, `basic_stream`, and `variant` provide supported input representations; the dump utility renders their bytes for inspection.
- Formatting output is diagnostic text, not a canonical serialization format.
- `dump_memory.hpp/.cpp` implement the formatter; `logger_dump.cpp` connects it to the logger's configured output path. `testcase_dumpmemory.cpp` covers the formatter, while logger APIs decide where the rendered diagnostic text is sent.
