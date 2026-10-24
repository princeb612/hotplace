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

# Basic Utilities

## 1. Role

`sdk/base/basic` contains cross-cutting facilities that do not belong to one protocol or one algorithm family. Its scope includes memory-pool support, command-line argument registration, memory-dump formatting, function-pipeline control flow, CRC helpers, generic values, and dynamic formatting arguments.

The word *basic* describes the layer's general-purpose role; it does not mean that all components are trivial or share one portability profile. In particular, `valist` has ABI-sensitive implementation details, while `variant` provides a shared runtime value representation.

## 2. Data Model

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
| `types.hpp` | Aggregated base includes, resource-type identifiers, and forward declarations | `basic/types.hpp` |

These components are related by use, not by a common base class or shared object lifecycle.


### Cross-cutting data boundaries

| Data or state | Representation | Ownership / lifetime contract |
|---|---|---|
| Pool allocation | builtinpool context, block descriptors, free-chain hint, and optional segment chain | The pool manages its descriptors and expandable segments; an externally supplied initial buffer remains caller-owned and must outlive the pool's use of it. |
| Parsed options | t_cmdline_t&lt;T&gt; registration map/order list and mandatory-token set; each t_cmdarg_t&lt;T&gt; holds token metadata and a callback | The parser owns its registration state and option object T; callbacks mutate that application-owned option state. |
| Generic value | variant_t type, size, flags, and union storage, wrapped by variant | Flags distinguish direct values from allocated string/binary/user data; clear/reset and conversion operations have different lifetime effects. |
| Deferred variadic arguments | valist vector of variant_t values plus an ABI-specific native view | Stored arguments are the retained representation; the native va_list view is reconstructed from them and is ABI-sensitive. |
| Pipeline result | function_pipeline&lt;T, category&gt; current native result, optional preserved return_t, continuation predicate, and counters | The pipeline owns its execution state; the selected error_traits policy defines interpretation and conversions, not the callback alone. |
| Diagnostic output | stream_t receiving the rendered memory dump | The formatter writes presentation text to the supplied stream; it does not own or validate the source bytes. |
| Checksum result | uint32 returned by crc32() or crc24() | The caller supplies the byte range and decides where the checksum is used; format-specific framing belongs to the caller. |

These are the principal intermediate representations that appear in the behavior flows below. They are separate contracts, not one shared object model.

## 3. Behavior Model

### Source-flow overview

```text
command line ─► t_cmdline_t&lt;T&gt; ─► registered callback ─► application option state

pool client ─► builtinpool ─► free region / new segment ─► allocation
                           └─ reallocate ─► in-place growth OR move to new region

typed value ─► variant / variant_t ─► conversion flags ─► binary_t ─► encoding or dump
values ──────► valist ─► ABI-specific argument reconstruction ─► formatting consumer
steps ───────► function_pipeline ─► error_traits classification ─► continue / fail / always
```

The diagram follows separate implementation paths rather than implying that the components depend on one another. In particular, `variant` conversion and `valist` formatting are distinct value-handling models, and the pipeline's continuation decision depends on its selected `error_traits` specialization.

- **Pool ownership:** `builtinpool` can use a caller-provided fixed region or manage expandable segments. The caller must keep an externally supplied backing buffer alive for as long as the pool depends on it.
- **Command-line callbacks:** `t_cmdline_t&lt;T&gt;` connects registered tokens to an application-owned `T` through callbacks. Registration order, required/optional arguments, and parameter-taking options are part of the parser's behavior.
- **Pipeline state:** `function_pipeline` is not just a list of callbacks. Subsequent `run`/`walk` actions can depend on the current result, and failure-only or always-run steps have distinct purposes.
- **Dynamic `va_list`:** a native `va_list` is ABI-defined, not a portable container. `valist` contains platform-specific reconstruction and should be reviewed against each supported compiler/architecture when changing argument handling.
- **Generic values:** `variant` retains type information alongside value storage. Conversion flags matter when turning values into bytes; host-native layout should not be assumed to match a requested wire representation.
- **Diagnostics:** `dump_memory` formats data for inspection; it does not establish that the bytes are valid according to a protocol or encoding specification.
- **CRC:** CRC is an integrity/checksum mechanism for formats that specify it, not a cryptographic hash or authentication primitive.

## 4. Relationships

- `variant` and `valist` both represent values temporarily, but `variant` models typed runtime values while `valist` adapts a sequence of values to a compiler ABI's variadic-call convention.
- `dump_memory` is a shared formatting primitive; `logger` in `sdk/base/unittest` provides a configured diagnostic output channel and can use dump helpers.
- `crc24()` is consumed by Radix-64-related encoding code; the checksum primitive remains separate from format-specific policy.
- `function_pipeline` coordinates execution/error flow but does not replace each operation's own error semantics.
- `builtinmemory` allocator adapters allow pool allocation to be used with container-style interfaces.
- Source-level coverage is organized under [`test/testcase/base/basic/`](../../../test/testcase/base/basic/README.md). The testcase overview links the focused test sources and command-line vectors; it owns detailed assertions and verification status, while this directory document describes the SDK interfaces and their relationships.

## 5. References

No external references are listed.
