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

# Binary Stream

## 1. Role

`binary_stream` is a small builder around `binary_t` for assembling binary values in a defined byte order. It is separate from `basic_stream`, whose primary purpose is formatted text output, and from protocol-specific encoders that apply a wire format's own field rules.

## 2. Data Model

The object owns a `binary_t` buffer and an endian flag. The default is big-endian. `set_endian(false)` selects the non-big-endian path used by integer serialization helpers; this setting affects integer `prefix()` and `append()` operations, not raw byte sequences or an already-encoded `binary_t`.

- `append(value)` adds a value at the end of the buffer.
- `prefix(value)` inserts a value at the beginning of the buffer.
- Integer overloads cover signed and unsigned 8-, 16-, 32-, and 64-bit values.
- Byte pointers, `std::string`, and `binary_t` can be appended as byte sequences; `binary_t` can also be prefixed.
- `get()` exposes the underlying buffer by reference; `size()`, `empty()`, and `clear()` provide basic state operations.



## 3. Behavior Model

### Append and prefix operations

```text
binary_stream
   ├── endian policy ──► integer byte conversion
   ├── prefix(value) ───► insert at buffer start
   ├── append(value) ───► append at buffer end
   └── get() ───────────► binary_t
```

- The builder's endian flag affects integer conversion overloads; callers should not assume it transforms raw byte buffers already supplied by the caller.
- `get()` exposes the owned `binary_t` object by reference, so the reference is tied to the lifetime of the `binary_stream` instance and its contained object.
- The class assembles primitive bytes only. It does not automatically add field lengths, tags, nested structure boundaries, or protocol framing.

## 4. Relationships

- `sdk/base/stream/binary_stream.hpp` implements the stream; `sdk/base/nostd/binary.hpp` defines `binary_t` and related byte-buffer helpers.
- `sdk/base/system/endian-and-wire-integers.md` — byte-order helpers and wire-format integer context.
- [`basic_stream.md`](basic_stream.md) — text formatting rather than primitive binary assembly.
- `test/testcase/base/stream/testcase_stream.cpp` and `testcase_bufferio.cpp` — related stream tests; no direct `binary_stream` use was identified in the reviewed source, so tests of `binary_t` or other stream helpers are not treated as direct coverage.
