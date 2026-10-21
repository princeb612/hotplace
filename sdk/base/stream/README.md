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

# Base Stream

## 1. Role

`sdk/base/stream` contains hotplace's in-memory stream, buffered byte storage, formatted-output helpers, string-stream wrappers, and descriptor-aware byte segmentation. It is a general-purpose base layer, distinct from `sdk/io/stream`, which adapts stream operations to OS-backed I/O.

## 2. Data Model

```text
basic_stream ──────────────► formatted text / append operations
ansi_string, wide_string ─► mutable string operations
binary_stream ────────────► primitive binary assembly
          │
          ▼
 low-level buffer / formatting helpers
          
 splitter ──────────────► fixed-size fragments + descriptors
```

These are related utilities within the same directory, not one inheritance hierarchy. The root-level [`stream_t` interface](../stream.md) defines the common operations; `basic_stream` specializes in text formatting, `binary_stream` assembles primitive bytes, and `splitter` divides byte sequences into fragments while retaining group descriptors.

## 3. Behavior Model

- Stream classes in this directory are primarily in-memory abstractions; they should not be confused with OS file streams.
- `bufferio` may reallocate or consolidate storage during mutation or retrieval, so callers should not assume a returned data pointer remains stable across subsequent operations.
- `splitter` normally owns copied or moved input data. The `splitter_noalloc` path can retain a caller-owned pointer, which must remain valid through `run()`.
- The directory contains both byte-oriented and text-oriented APIs. The selected type matters: text formatting does not automatically provide protocol framing or wire-format semantics.
- `binary_stream` assembles primitive binary values; it does not by itself define a complete protocol message layout. The caller supplies field order, widths, and validation.
- Stream buffer lifetime and input ownership are API-specific. Inspect the exact operation's return type and ownership contract before retaining a pointer or view.

## 4. Relationships

- [`stream.md`](../stream.md) — root-level abstract `stream_t` contract.
- [`basic_stream.md`](basic_stream.md) — in-memory formatted text stream.
- [`binary_stream.md`](binary_stream.md) — primitive binary assembly; direct tests were not identified in the reviewed stream testcase source.
- [`lowlevel-bufferio.md`](lowlevel-bufferio.md) — low-level storage and formatted output.
- [`string-stream.md`](string-stream.md) — ANSI and wide-character string stream classes.
- [`splitter.md`](splitter.md) — fixed-size segmentation and descriptor callbacks.
- `sdk/io/stream/` — OS/file-oriented stream adapters.
- [Stream testcase documentation](../../../test/testcase/base/stream/testcase_stream.md) — owns source-level coverage and report context. The stream tests include `testcase_stream.cpp` and `testcase_bufferio.cpp`; the supplied report snapshot does not identify source revision or execution environment, so it is not evidence that this exact tree passed.
