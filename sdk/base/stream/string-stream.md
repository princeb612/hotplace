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

# String Streams

## 1. Role

The stream layer provides `ansi_string` and `wide_string` for mutable string data backed by hotplace's stream/buffer infrastructure. These classes combine string operations with the `stream_t` interface; they are not the same layer as the general scanning helpers in `sdk/base/string` or protocol-facing string handling in `sdk/io/string`.

## 2. Data Model

`ansi_string` derives from `stream_t` and delegates storage and many byte-oriented operations to `bufferio`. It supports formatted output, appending through stream operators, searching, replacement, substring extraction, trimming, cutting, line extraction, comparison, and resizing. The wide-string implementation provides the corresponding wide-character path and is integrated with the platform conversion helpers.



The API includes copy/move construction and assignment. The implementation details are not identical between ANSI and wide strings: `ansi_string` uses the common `bufferio` path, while wide-character formatting and storage have dedicated implementation files under `unicode/`.

## 3. Behavior Model

### Storage and operation path

```text
caller
  └─ ansi_string operations ─► bufferio-backed byte storage
       ├─ formatted output / append
       ├─ search / replace / trim
       └─ line / substring / resize

caller
  └─ wide_string operations ─► wide-character storage/conversion path
       ├─ formatted output / append
       └─ search / replace / trim / line extraction
```

`stream_t` is the abstract interface inherited by `ansi_string`; it is not an intermediate runtime call. The wide-string implementation has dedicated code under `unicode/` and should not be assumed to use an identical storage path.

- `test/testcase/base/stream/testcase_stream.cpp` — `test_stream_getline()` uses `ansi_string` to extract lines and asserts that four lines were returned.
- `test/testcase/base/stream/testcase_bufferio.cpp` — exercises the lower-level buffer I/O implementation used by the string-stream classes.

These references establish source-level test coverage for selected behavior, not complete coverage of every ANSI/wide-string operation or proof of execution in a particular environment.

## 4. Relationships

- [Base Stream](README.md) — stream layer overview
- [Low-Level Buffer I/O](lowlevel-bufferio.md) — storage and formatted-output machinery
- `sdk/base/string/` — general-purpose string and bounded-buffer helpers
- `ansi_string.hpp/.cpp` and `unicode/wide_string.hpp/.cpp` implement the ANSI/wide string streams; `lowlevel/bufferio.*`, `unicode/bufferio_wcs.cpp`, `unicode/printf_wcs.cpp`, and `types.hpp` supply the lower-level storage, formatting, and conversion interfaces.
- `sdk/io/string/` — I/O/protocol-facing string utilities

## 5. References

No external references are listed.
