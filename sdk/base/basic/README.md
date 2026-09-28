# Basic

`basic` contains small, reusable building blocks used across the hotplace SDK.

These components are not tied to one protocol or subsystem. They provide common facilities for memory management, command-line handling, diagnostic output, execution flow, variadic interfaces, and generic value representation.

## Components

| Topic | Role |
|---|---|
| [builtin memory](builtin-memory.md) | Memory pool, expansion, reallocation, and allocator adapters |
| [command line](cmdline.md) | Template-based command-line argument registration and parsing |
| [memory dump](dump-memory.md) | Hexadecimal/ASCII representation of memory and binary values |
| [function pipeline](function-pipeline.md) | Conditional execution and error-state propagation |
| [dynamic `va_list`](valist.md) | Construction of a platform-specific `va_list` from stored arguments |
| [variant](variant.md) | Common runtime value/type representation and conversion |

## Relationship

The components are mostly independent, but `variant` is an important value-oriented connection point. `valist` uses variant values as an intermediate representation, and `dump_memory` can accept variant values as generic input.

```text
                         basic
                           │
             ┌─────────────┼─────────────┐
             │             │             │
          variant     function_pipeline  builtinmemory
             │
       ┌─────┴─────┐
       │           │
    valist    dump_memory
```

`builtinmemory` provides allocation support, `function_pipeline` provides execution/error-flow control, and `cmdline` is primarily an application-facing utility.

## Tests

The corresponding testcases are under `test/testcase/base/basic/`:

- `testcase_builtinmemory.cpp`
- `testcase_cmdline.cpp`
- `testcase_dumpmemory.cpp`
- `testcase_pipeline.cpp`
- `testcase_valist.cpp`
- `testcase_variant.cpp`

Additional command-line and `valist` test vectors are kept beside their testcases.

The tests are useful as executable examples as well as regression tests. In particular, the `valist` tests record platform ABI assumptions, while the `variant` tests record protocol-oriented numeric and binary conversions.

## Related source

The primary implementation is directly under this directory:

```text
builtinmemory.hpp / builtinmemory.cpp
cmdline.hpp
dump_memory.hpp / dump_memory.cpp
function_pipeline.hpp
types.hpp
valist.hpp / valist.cpp
variant.hpp / variant.cpp
```
