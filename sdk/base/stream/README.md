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

### Variant formatting with `vtprintf`

`vtprintf` is the typed-value formatting adapter in this directory. It accepts either the low-level `variant_t` representation or the `variant` wrapper from [`sdk/base/basic/variant`](../basic/variant.md), then writes a textual rendering to a caller-supplied `stream_t`.

| Input / control | Responsibility |
|---|---|
| `variant_t` or `variant` | Supplies the stored type, value, size, and flags; `variant` overload delegates through `get()`. |
| `vtprintf_style_t` | Selects presentation conventions: normal, CBOR-oriented, Base16, debug, or ASN.1. |
| `stream_t*` | Receives the rendered text; `vtprintf` does not own the output stream. |

The distinction is between **value representation** and **value presentation**. `variant` owns type-aware storage and conversion operations; `vtprintf` interprets that stored representation for display. A style changes textual conventions, not the underlying variant, and the result should not be confused with protocol encoding or `variant::to_binary()`.

## 3. Behavior Model

### Mutation and retrieval flow

```text
caller
  ├─ variant / variant_t ─► vtprintf(style) ─► stream_t ─► formatted text
  │                                      ├─ normal / debug presentation
  │                                      └─ CBOR / Base16 / ASN.1-oriented presentation
  ├─ basic_stream << variant ─► vtprintf(debugmode) ─► in-memory text buffer
  ├─ basic_stream ─► append / format / insert / cut ─► in-memory text buffer
  ├─ binary_stream ─► endian-aware integer conversion ─► binary_t
  ├─ bufferio ─► append blocks ─► get() may consolidate blocks ─► returned bytes
  └─ splitter ─► registered source groups ─► fixed-size fragments
                                          └─ callback(data, offset, size, flags, descriptor)
```

- Stream classes in this directory are primarily in-memory abstractions; they should not be confused with OS file streams.
- `bufferio` may reallocate or consolidate storage during mutation or retrieval, so callers should not assume a returned data pointer remains stable across subsequent operations.
- `splitter` normally owns copied or moved input data. The `splitter_noalloc` path can retain a caller-owned pointer, which must remain valid through `run()`.
- The directory contains both byte-oriented and text-oriented APIs. The selected type matters: text formatting does not automatically provide protocol framing or wire-format semantics.
- `binary_stream` assembles primitive binary values; it does not by itself define a complete protocol message layout. The caller supplies field order, widths, and validation.
- Stream buffer lifetime and input ownership are API-specific. Inspect the exact operation's return type and ownership contract before retaining a pointer or view.

## 4. Relationships

- [`stream.md`](../stream.md) — root-level abstract `stream_t` contract.
- [`basic_stream.md`](basic_stream.md) — in-memory formatted text stream; its `operator<<(const variant&)` uses `vtprintf_style_debugmode`.
- [`../basic/variant.md`](../basic/variant.md) — typed runtime value model consumed by `vtprintf`.
- `vtprintf.hpp/.cpp` — renders `variant_t` / `variant` to `stream_t` with style-dependent textual conventions. Used by `basic_stream`, `dump_memory`, and ASN.1/CBOR-oriented display paths; it is a formatter, not a binary encoder.
- [`binary_stream.md`](binary_stream.md) — primitive binary assembly; direct tests were not identified in the reviewed stream testcase source.
- [`lowlevel/bufferio.md`](lowlevel/bufferio.md) — low-level storage and formatted output.
- [`string-stream.md`](string-stream.md) — ANSI and wide-character string stream classes.
- [`splitter.md`](splitter.md) — fixed-size segmentation and descriptor callbacks.
- `sdk/io/stream/` — OS/file-oriented stream adapters.
- [Stream testcase documentation](../../../test/testcase/base/stream/testcase_stream.md) — owns source-level coverage and report context. The stream tests include `testcase_stream.cpp` and `testcase_bufferio.cpp`; the supplied report snapshot does not identify source revision or execution environment, so it is not evidence that this exact tree passed.

## 5. References

No external references are listed.
