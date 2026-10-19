## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Dynamic `va_list`

## 1. Role

### Introduction

`valist` provides a dynamically constructed `va_list` for code that needs to collect arguments before passing them to an existing variadic interface.

Arguments are stored as `variant_t` values. When `get()` is requested, the implementation builds the platform-specific native `va_list` representation from those stored values.

```text
C++ values
    │
    ▼
 variant_t
    │
    ▼
  valist
    │
    ▼
platform ABI-specific va_list
    │
    ▼
variadic API / formatting
```

## 2. Model

### Argument handling

`operator<<()` accepts the primitive numeric types together with pointers, strings, `basic_stream`, `binary_t`, and `variant_t`.

The stored arguments can also be inspected by index and the list can be cleared and rebuilt.

The implementation normalizes several C/C++ argument promotions before constructing the native representation. This is important because a `va_list` cannot be treated as a portable pointer-like object.

### ABI-specific construction

`build()` contains platform-specific handling for the `va_list` layouts used by the supported GCC/Linux and Microsoft compiler environments.

For the GCC x86-64 representation, the implementation handles the register-save/overflow-area model rather than assuming a simple stack-based argument list.

The source contains explicit handling for integer widths and floating-point values so that the reconstructed list matches what the receiving variadic function expects.

This ABI dependency is the main reason the implementation is more substantial than a simple wrapper around `va_list`.

### Formatting integration

The main practical use is passing dynamically assembled arguments to hotplace's formatting functions.

Arguments can be collected first and then referenced by position in a format string, including a different order from the order in which they were inserted.

Binary values can also remain typed through the intermediate `variant_t` representation and participate in the formatting system's binary formats.

## 3. Important behavior and lifetime

### ABI and argument promotions

A native `va_list` has compiler- and architecture-specific representation. The implementation includes distinct handling for supported GCC/Linux and Microsoft compiler environments; the GCC x86-64 path accounts for the register-save and overflow-area model rather than assuming that arguments form a simple stack array.

Argument promotions and exact widths matter. The stored `variant_t` values must be mapped to the representation expected by the receiving variadic function. Treating `va_list` as a portable pointer or copying its internals across ABIs is unsafe.

### Rebuild and consumption

The list can be cleared and rebuilt, and its stored values can be inspected by index. The practical flow is to append values, build the native representation, then pass it to a compatible formatting interface. The native view should not be assumed to remain valid beyond the lifetime/state for which it was built; inspect the current implementation before retaining it across mutations.

### Source tests

- `test/testcase/base/basic/testcase_valist.cpp`
- `test/testcase/base/basic/testvector_valist.cpp`
- `test/testcase/base/basic/testvector_valist.yml`

## 4. Example from the source tests

### Test walkthrough

`test/testcase/base/basic/testcase_valist.cpp` appends a floating-point value, a string, and an integer to `valist`, then passes the collected arguments to the positional formatter:

```cpp
valist va;
va << 3.141592 << "phi" << 123;

basic_stream bs;
sprintf(&bs, "value={1} value={2} value={3}", va);
```

The test compares the resulting text with `value=3.141592 value=phi value=123`. A second case appends ordinary `basic_stream::printf()` output before formatting the collected arguments, checking that the two operations can be composed.

This example demonstrates the public use path. The ABI-specific `build()` implementation is the critical place to inspect when supporting a new compiler or architecture.

## 5. Relationships

- `variant_t` is the intermediate typed-value representation; `valist` adapts stored values to the native variadic calling convention.
- `basic_stream` and formatting helpers consume the resulting argument sequence.
- `valist` is ABI-sensitive; do not infer portability from the high-level `operator<<()` interface alone.

## 6. References

### Related source and tests

- `sdk/base/basic/valist.hpp/.cpp`
- `sdk/base/basic/variant.hpp`
- `test/testcase/base/basic/testcase_valist.cpp`
- Related formatting code: `sdk/base/stream/basic_stream.hpp` and the corresponding implementation

