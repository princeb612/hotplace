## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
└──────────────────────────────────────────────┘
```

# Basic Utilities

## 1. Role

`sdk/base/basic` contains small cross-cutting facilities that do not belong to one protocol or one algorithm family. The directory includes memory-pool support, command-line argument registration, memory-dump formatting, function-pipeline control flow, CRC helpers, generic values, and dynamic formatting arguments.

The word *basic* describes the layer's general-purpose role; it does not mean that all components are trivial or have identical portability requirements. In particular, `valist` has ABI-sensitive implementation details, while `variant` defines a shared runtime value representation.

## 2. Model

### Component map

| Component | Main responsibility | Main implementation |
|---|---|---|
| [`builtinmemory`](builtinmemory.md) | Pool allocation, reallocation, and allocator adapters | `builtinmemory.hpp/.cpp` |
| [`cmdline`](cmdline.md) | Register and parse command-line arguments into an application option object | `cmdline.hpp` |
| [`crc`](crc.md) | CRC checksum primitive | `crc.hpp/.cpp` |
| [`dump_memory`](dump_memory.md) | Render bytes as hexadecimal and printable text for diagnostics | `dump_memory.hpp/.cpp` |
| [`function_pipeline`](function_pipeline.md) | Sequence functions according to a result/error state | `function_pipeline.hpp` |
| [`valist`](valist.md) | Collect values and reconstruct a native variadic argument list | `valist.hpp/.cpp` |
| [`variant`](variant.md) | Store and convert typed runtime values | `variant.hpp/.cpp`, `types.hpp` |

These are related by use, not by a common base class or shared object lifecycle.

### Value and diagnostic path

```text
typed C++ value
      │
      ▼
   variant
      │ to_binary(...)
      ▼
 binary_t ───────────────► base16_encode(...)
      │
      └──────────────────► dump_memory / logger diagnostics
```

A separate formatting path uses `valist` to collect arguments before a formatter consumes them:

```text
values ──► valist ──► sprintf / basic_stream ──► expected text
```

The diagrams show paths exercised by the codebase; they do not imply that every component must be used through `variant`.

## 3. Important behavior and lifetime

- **Pool ownership:** `builtinpool` can use a caller-provided fixed region or manage expandable segments. The caller must keep an externally supplied backing buffer alive for as long as the pool depends on it.
- **Command-line callbacks:** `t_cmdline_t<T>` connects registered tokens to an application-owned `T` through callbacks. Registration order, required/optional arguments, and parameter-taking options are part of the parser's behavior.
- **Pipeline state:** `function_pipeline` is not just a list of callbacks. Subsequent `run`/`walk` actions can depend on the current result, and failure-only or always-run steps have distinct purposes.
- **Dynamic `va_list`:** a native `va_list` is ABI-defined, not a portable container. `valist` contains platform-specific reconstruction and should be reviewed against each supported compiler/architecture when changing argument handling.
- **Generic values:** `variant` retains type information alongside value storage. Conversion flags matter when turning values into bytes; do not assume host-native layout is automatically the required wire representation.
- **Diagnostics:** `dump_memory` formats data for inspection; it does not establish that the bytes are valid according to a protocol or encoding specification.
- **CRC:** CRC is an integrity/checksum mechanism for formats that specify it, not a cryptographic hash or authentication primitive.

## 4. Example from the source tests

### Variant to binary

`test/testcase/base/basic/testcase_variant.cpp` begins a `variant` test, stores a `uint32` value, calls `to_binary()` with `variant_convendian | variant_trunc`, encodes the resulting bytes as Base16, and asserts the expected string `"00008000"`. It repeats the process for a 64-bit value and a `bignumber`.

This test is useful because it exposes each stage of the conversion rather than checking only a final formatted value.

### Dynamic formatting arguments

`test/testcase/base/basic/testcase_valist.cpp` appends `3.141592`, `"phi"`, and `123` to a `valist`, then passes the list to `sprintf()` with positional placeholders. The generated `basic_stream` is compared with an expected string. The testcase also combines ordinary `basic_stream::printf()` output with dynamically supplied arguments.

### Pipeline control flow

`test/testcase/base/basic/testcase_pipeline.cpp` appends a sequence of steps that records its path: parameter validation, a walk step, a `run_pipe()` calculation, another walk, a failure-only step, and an always-run final step. Comparing the recorded path with the expected path shows which callbacks ran for the chosen result.

These are source-level walkthroughs. To verify current execution status, run the relevant test target in the intended build environment.

## 5. Relationships

- `variant` and `valist` meet at generic argument storage, but `variant` models typed values while `valist` adapts a sequence of values to a compiler ABI's variadic-call convention.
- `dump_memory` is the shared formatting primitive; `logger` in `sdk/base/unittest` provides the configured diagnostic output channel and can call dump helpers.
- `crc24()` is consumed by Radix-64-related encoding code; the checksum primitive remains separate from the format-specific policy.
- `function_pipeline` coordinates execution/error flow but does not replace each operation's own error semantics.
- `builtinmemory` allocator adapters allow pool allocation to be used with container-style interfaces.

## 6. References

### Implementation

- `builtinmemory.hpp/.cpp`
- `cmdline.hpp`
- `crc.hpp/.cpp`
- `dump_memory.hpp/.cpp`
- `function_pipeline.hpp`
- `types.hpp`
- `valist.hpp/.cpp`
- `variant.hpp/.cpp`

### Test sources

- `test/testcase/base/basic/testcase_builtinmemory.cpp`
- `test/testcase/base/basic/testcase_cmdline.cpp`
- `test/testcase/base/basic/testcase_dumpmemory.cpp`
- `test/testcase/base/basic/testcase_pipeline.cpp`
- `test/testcase/base/basic/testcase_valist.cpp`
- `test/testcase/base/basic/testcase_variant.cpp`
- Command-line vectors: `test/testcase/base/basic/testvector_cmdline.cpp` and `testvector_cmdline.yml`
