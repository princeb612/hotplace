## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Base Stream

## 1. Role

`sdk/base/stream` contains hotplace's in-memory stream, buffered byte storage, formatted-output helpers, string-stream wrappers, and descriptor-aware byte segmentation. It is a general-purpose base layer, distinct from `sdk/io/stream`, which adapts stream operations to OS-backed I/O.

## 2. Model

```text
basic_stream ──────────────► formatted text / append operations
ansi_string, wide_string ─► mutable string operations
binary_stream ────────────► primitive binary assembly
          │
          ▼
 low-level buffer / formatting helpers
          
 splitter ──────────────► fixed-size fragments + descriptors
```

These are related utilities within the same directory, not one inheritance hierarchy. `binary_stream` assembles primitive bytes; `basic_stream` focuses on text formatting; `splitter` divides byte sequences into fragments while retaining group descriptors.

## 3. Important behavior and lifetime

- Stream classes in this directory are primarily in-memory abstractions; they should not be confused with OS file streams.
- `bufferio` may reallocate or consolidate storage during mutation or retrieval, so callers should not assume a returned data pointer remains stable across subsequent operations.
- `splitter` normally owns copied or moved input data. The `splitter_noalloc` path can retain a caller-owned pointer, which must remain valid through `run()`.
- The directory contains both byte-oriented and text-oriented APIs. The selected type matters: text formatting does not automatically provide protocol framing or wire-format semantics.

## 4. Example from the source tests

`test_stream_basic_stream()` in `test/testcase/base/stream/testcase_stream.cpp` checks the custom formatting syntax and compares the generated output with an expected string:

```cpp
basic_stream bs;
valist va;
va << 256 << "hello world" << 3.141592;
bs.vaprintf(R"(value={1:04x}, value="{2:-15s}", value={3:le})", va);
_test_case.assert(
    bs == R"(value=0x0100, value="hello world    ", value=3.141592e+00)",
    __FUNCTION__, "format string syntax");
```

This is an excerpt from the project testcase and depends on the project's test harness and `valist` declarations.

## 5. Relationships

- [`basic_stream.md`](basic_stream.md) — in-memory formatted text stream.
- [`binary_stream.md`](binary_stream.md) — primitive binary assembly; direct tests were not identified in the reviewed stream testcase source.
- [`lowlevel-bufferio.md`](lowlevel-bufferio.md) — low-level storage and formatted output.
- [`string-stream.md`](string-stream.md) — ANSI and wide-character string stream classes.
- [`splitter.md`](splitter.md) — fixed-size segmentation and descriptor callbacks.
- `sdk/io/stream/` — OS/file-oriented stream adapters.
- `test/testcase/base/stream/` — source-level testcase documentation and report context.

## 6. References

- Implementation directory: `sdk/base/stream/`
- Test sources: `test/testcase/base/stream/testcase_stream.cpp`, `test/testcase/base/stream/testcase_bufferio.cpp`
- Report snapshot: `test/testcase/base/test-report-status.md` (the supplied report does not identify source revision or execution environment).
