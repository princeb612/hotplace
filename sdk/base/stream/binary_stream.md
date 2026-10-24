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

### Concrete caller path: binary parsing-table serialization

The parser's binary-table writer uses `binary_stream` to build each section before combining the sections into the final file buffer:

```cpp
binary_t bin;

// BLOCK1 - string table
{
    binary_stream bs;
    bs.set_endian(true).append(uint32(_string_index.size()));
    for (const auto& item : _string_index) {
        const auto& symbol = item.first;
        auto len = symbol.size();
        bs.append(uint16(len)).append(
            reinterpret_cast<const byte_t*>(symbol.c_str()), len);
    }

    auto size = bs.size();
    bs.prefix(uint64(size));
    binary_append(bin, bs.get());
}
```

This illustrates the intended division of responsibilities: `binary_stream` appends primitive fields in the selected byte order and prefixes the completed block with its size; `binary_append()` then copies the completed block into the file-level buffer. The writer repeats this pattern for terminal, production, action, and goto tables, then prepends a file header containing the magic value, grammar revision, endian marker, CRC-32, and payload size.

The block's field order and widths are part of the parsing-table format contract; `binary_stream` itself does not know those meanings. The writer's call to `set_endian(true)` is therefore a format decision made by the consumer, not an automatic property of the builder.

Source: `sdk/io/parser/binary_parsing_table_write.cpp`, `binary_parsing_table::write()`.

## 4. Relationships

- `sdk/base/stream/binary_stream.hpp` implements the stream; `sdk/base/nostd/binary.hpp` defines `binary_t` and related byte-buffer helpers.
- `sdk/base/system/endian-and-wire-integers.md` — byte-order helpers and wire-format integer context.
- [`basic_stream.md`](basic_stream.md) — text formatting rather than primitive binary assembly.
- `sdk/io/parser/binary_parsing_table_write.cpp` — production consumer that serializes the parser's binary parsing-table sections through `binary_stream`.
- `test/testcase/base/stream/testcase_stream.cpp` and `testcase_bufferio.cpp` — related stream tests; they are not treated as direct `binary_stream` coverage.

## 5. References

No external references are listed.
