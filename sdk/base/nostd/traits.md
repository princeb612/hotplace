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

# Traits and type adapters

## 1. Role

The traits family centralizes compile-time type classification and adaptation used by generic hotplace code. Alongside general traits in traits.hpp, focused adapters connect generic algorithms to concrete output APIs: `encoder_stream_traits<T>` for encoding into a destination buffer, and `printf_traits<BT, T>` for selecting type-correct formatting in the stream/string layer.

These adapters do not encode bytes or print values themselves. They describe how the selected destination or formatter should be used, allowing encoding and stream code to share generic templates without hard-coding each output type.

## 2. Data Model

### Type and destination adapters

- `traits.hpp` defines project type predicates and transformations used by SFINAE and generic overload selection.
- `encoder_stream_traits<T>` has a default specialization with `value = false`. Supported destination types specialize it with a `value_type` and the operations expected by encoding templates: `trunc`, `reserve`, `commit`, `preempt`, `push`, and `append`.
- The current adapter supports `std::string` and `binary_t` in `traits_encoder.hpp`. `stream.hpp` specializes the same trait for `stream_t*`, and `basic_stream.hpp` supplies its own specialization for `basic_stream`.
- `format_specifier_traits<BT, T>` associates a character type and value type with a C-style format specifier. `printf_traits<BT, T>` additionally normalizes enum/integral types and chooses the format and argument cast used by generic stream insertion.

## 3. Behavior Model

### Base16/Base64 output lifecycle: reserve and commit

The Base16/Base64 templates in `sdk/base/encoding/` use `encoder_stream_traits<T>` to write into multiple destination types through one algorithm:

1. Unless `encoding_notrunc` is set, `trunc()` clears the existing output first.
2. The encoder is called with a null output buffer to determine the required capacity. The low-level encoder reports `insufficient_buffer` when returning the required size.
3. `reserve(buffer, size_reserve)` grows the destination's logical size by that amount and returns a pointer to the newly appended region. The low-level encoder writes into that region.
4. After successful encoding, `commit(buffer, size_reserve, size_written)` removes a reserved tail only when the actual output is shorter than the reservation. It does not perform the encoding; it reconciles the destination's logical size with the encoder's reported output length.

For `std::string` and `binary_t`, `reserve` resizes the container and returns the start of the appended region. The `stream_t*` adapter performs the equivalent operation through `resize()` and `data()`; `basic_stream` has its own adapter implementation.

The wrapper calls `commit()` only after the actual conversion succeeds. If the second conversion pass fails after reservation, the wrapper does not roll back the reserved logical tail. The contract is therefore a two-pass write-and-trim protocol, not a general transaction or rollback guarantee. `commit()` also does not handle a reported `size_written` greater than `size_reserve`.

### Huffman output lifecycle: preempt and push

Huffman encoding uses a different output pattern:

1. `preempt()` provides an output-capacity hint before emission. For stream adapters where preallocation is not applicable, this operation may be a no-op.
2. `push()` appends each produced output unit to the destination as Huffman codes are emitted.

This is incremental append behavior, not the Base16/Base64 reserve-then-commit lifecycle. In particular, Huffman output is not reconciled by a final `commit()` call. The adapter operations share a trait interface, but callers must follow the protocol used by the specific encoder.

### Formatting type selection and basic_stream

`basic_stream::operator<<` routes integral, enum, and floating-point values through `printf_traits<char, T>`. The trait selects a format specifier and a compatible cast type before the value is passed to `printf()`. Enum values are normalized through their underlying type; signedness and width determine the integral representation. Character/wide-character format traits and the guarded `__int128` mappings provide additional supported cases.

This is distinct from `basic_stream`'s indexed sprintf/vaprintf formatting syntax: `printf_traits` serves the C-style formatting path used by generic insertion, while the indexed formatter parses its own per-argument format requests.

## 4. Relationships

- `sdk/base/encoding/base16.hpp` and `base64.hpp` — use `encoder_stream_traits<T>` for generic output buffers and the reserve/commit lifecycle.
- Huffman encoding — uses the preempt/push incremental output lifecycle instead.
- `sdk/base/stream/stream.hpp` and `basic_stream.hpp` — adapt stream destinations and use `printf_traits` for insertion formatting.
- `sdk/base/nostd/binary.hpp` and `set.hpp` — other examples of project traits controlling overloads and representation.
- `test/testcase/encode/` — encoding-focused testcase area; testcase scope and execution status should be recorded separately from these implementation notes.

## 5. References

No external references are listed.
