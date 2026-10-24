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

# `basic_stream`

## 1. Role

`basic_stream` is hotplace's mutable in-memory stream for assembling text and formatted output. It extends `stream_t` and exposes stream editing and formatting operations to SDK code. It is a base utility, not an OS file stream or a protocol-specific encoder.

## 2. Data Model

The class combines buffer editing (`insert()`, `cut()`), formatted output (`printf()`, `println()`, `vprintf()` and hotplace's `vaprintf()` family), and stream composition through insertion/append operators and encoder-stream traits. `stream_policy` and `local_stream_policy` control allocation behavior.

### Buffer state and ownership

`basic_stream` owns a `bufferio_context_t*` through its private `_handle`. The handle represents the mutable in-memory byte buffer; it is not an OS file/socket handle. The default constructor obtains its initial allocation size from the singleton `stream_policy`, while the `local_stream_policy` constructor uses the supplied allocation size.

Copy construction clones the underlying buffer context, so the copy has its own mutable storage. Move construction transfers the handle and nulls the source handle. Destruction closes a non-null context. The `data()`, `c_str()`, and `size()` accessors obtain the current buffer view through `bufferio::get()`; callers should not retain a pointer across mutations that may reallocate or consolidate storage.

`stream_policy` stores the shared default allocation-size setting. `local_stream_policy` stores a per-instance allocation size. These policies influence initial buffer allocation, not the stream's formatting syntax or content semantics.

### Data and formatting interfaces

- **Byte storage:** `write()`, `fill()`, `clear()`, and `resize()` mutate the buffer; `insert()` and `cut()` edit a selected range.
- **Standard-style formatting:** `printf()`, `vprintf()`, and `println()` use the low-level formatting path.
- **Hotplace indexed formatting:** `vaprintf()` and `vaprintln()` delegate to the custom formatter and consume the project's `valist` representation.
- **Insertion operators:** primitive numeric, enum, and floating-point values use `printf_traits<char, T>`; strings, byte arrays, variants, and other stream values use their corresponding overloads. In particular, `operator<<(const variant&)` delegates to `vtprintf(this, value, vtprintf_style_t::vtprintf_style_debugmode)`, so variants are rendered with type-appropriate diagnostic text rather than appended as raw object bytes.
- **Encoding destination:** the `encoder_stream_traits<basic_stream>` specialization implements `trunc()`, `reserve()`, and `commit()` so encoding routines can write into the stream's buffer.

The standard-style formatting path and indexed `vaprintf()` path are separate interfaces. The latter supports positional fields such as `{1:04x}` and uses the type metadata retained by `valist`.


## 3. Behavior Model

### Stream operation path

```text
SDK caller
  └─ basic_stream public operation
       ├─ write / fill / clear / resize / insert / cut
       ├─ printf / vprintf ─► low-level printf helper
       ├─ vaprintf / vaprintln ─► custom sprintf helper + valist
       └─ operator<< ─► printf_traits or type-specific overload
                         └─ variant overload ─► vtprintf(debugmode)
                              │
                              ▼
                     bufferio_context_t (_handle)
                              │
                              ▼
                       mutable byte buffer
```

`stream_t` is the abstract interface inherited by `basic_stream`, not an intermediate runtime call in this flow. Buffer allocation and retrieval are delegated to `bufferio`; formatting and insertion select their own path before mutating that buffer.

- Narrow and wide formatted-output entry points are provided.
- `vaprintf()` uses hotplace's argument/value formatting model; its format syntax is not identical to standard C `printf` in every respect. The testcase exercises positional fields with hexadecimal width/zero padding, string alignment, and floating-point formatting, expecting `value=0x0100`, a padded `hello world`, and `3.141592e+00`.
- The stream can be edited after writing, so append-only assumptions should not be made when using insertion or cutting operations.
- Allocation policy is part of the stream configuration, not a separate stream format.

## 4. Relationships

- [`variant.md`](../basic/variant.md) — typed runtime values supplied to the variant insertion overload.
- `vtprintf.hpp/.cpp` — renders `variant_t` / `variant` into this stream; `basic_stream` selects debug style for `operator<<(const variant&)`. The formatter's style changes the textual presentation, not the stored value.
- `stream_t` — base abstraction inherited by `basic_stream`.
- `stream_policy.hpp` — allocation policy types; `basic_stream.hpp` contains the concrete stream interface and implementation hooks.
- `lowlevel/` — lower-level buffered output and formatting implementation.
- `string-stream.md` — string-oriented stream classes; related, but not the same abstraction.
- `sdk/io/stream/` — OS/file-oriented stream adapters.
- `test/testcase/base/stream/testcase_stream.cpp` — [testcase notes](../../../test/testcase/base/stream/testcase_stream.md) — see `test_stream_basic_stream()` for formatting and append behavior, `t_test_rule_of_5<basic_stream>()` for object-lifetime semantics, and `test_stream_i128()` for integer-formatting examples. These tests illustrate exercised behavior; this document does not assert that they were executed in a particular environment.

## 5. References

No external references are listed.
