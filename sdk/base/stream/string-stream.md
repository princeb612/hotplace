## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# String Streams

## 1. Role

The stream layer provides `ansi_string` and `wide_string` for mutable string data backed by hotplace's stream/buffer infrastructure. These classes combine string operations with the `stream_t` interface; they are not the same layer as the general scanning helpers in `sdk/base/string` or protocol-facing string handling in `sdk/io/string`.

## 2. Model

`ansi_string` derives from `stream_t` and delegates storage and many byte-oriented operations to `bufferio`. It supports formatted output, appending through stream operators, searching, replacement, substring extraction, trimming, cutting, line extraction, comparison, and resizing. The wide-string implementation provides the corresponding wide-character path and is integrated with the platform conversion helpers.

```text
ansi_string / wide_string
          │
          ▼
       stream_t
          │
          ▼
  bufferio-backed storage
          │
          ├── formatted output
          ├── search / replace / trim
          └── line and substring operations
```

The API includes copy/move construction and assignment. The implementation details are not identical between ANSI and wide strings: `ansi_string` uses the common `bufferio` path, while wide-character formatting and storage have dedicated implementation files under `unicode/`.

## 3. Important behavior and lifetime

- `test/testcase/base/stream/testcase_stream.cpp` — `test_stream_getline()` uses `ansi_string` to extract lines and asserts that four lines were returned.
- `test/testcase/base/stream/testcase_bufferio.cpp` — exercises the lower-level buffer I/O implementation used by the string-stream classes.

These references establish source-level test coverage for selected behavior, not complete coverage of every ANSI/wide-string operation or proof of execution in a particular environment.

## 4. Example from the source tests

`test_stream_getline()` constructs an `ansi_string`, repeatedly calls `getline()`, trims trailing whitespace, and asserts that four lines were returned:

```cpp
ansi_string stream(" line1 \nline2 \n  line3\nline4");
ansi_string line;
size_t pos = 0;
size_t brk = 0;
int l = 0;
while (1) {
    ret = stream.getline(pos, &brk, line);
    if (errorcode_t::success != ret) break;
    line.rtrim();
    l++;
    pos = brk + 1;
}
_test_case.assert(4 == l, __FUNCTION__, "getline");
```

This excerpt preserves the behavior tested in `testcase_stream.cpp`; the surrounding test harness and declarations are omitted.

## 5. Relationships

- [Base Stream](README.md) — stream layer overview
- [Low-Level Buffer I/O](lowlevel-bufferio.md) — storage and formatted-output machinery
- `sdk/base/string/` — general-purpose string and bounded-buffer helpers
- `sdk/io/string/` — I/O/protocol-facing string utilities

## 6. References

- `sdk/base/stream/ansi_string.hpp/.cpp`
- `sdk/base/stream/unicode/wide_string.hpp/.cpp`
- `sdk/base/stream/lowlevel/bufferio.hpp/.cpp`
- `sdk/base/stream/unicode/bufferio_wcs.cpp`
- `sdk/base/stream/unicode/printf_wcs.cpp`
- `sdk/base/stream/types.hpp` — forward declarations and conversion interfaces
