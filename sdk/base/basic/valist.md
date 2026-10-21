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

## 2. Data Model

### Argument handling

`operator<<()` accepts the primitive numeric types together with pointers, strings, `basic_stream`, `binary_t`, and `variant_t`.

The stored arguments can also be inspected by index and the list can be cleared and rebuilt.

The implementation normalizes several C/C++ argument promotions before constructing the native representation. This is important because a `va_list` cannot be treated as a portable pointer-like object.

### ABI-specific construction

`build()` contains platform-specific handling for the `va_list` layouts used by the supported GCC/Linux and Microsoft compiler environments.

For the GCC x86-64 representation, the implementation handles the register-save/overflow-area model rather than assuming a simple stack-based argument list.

The source contains explicit handling for integer widths and floating-point values so that the reconstructed list matches what the receiving variadic function expects.

This ABI dependency is the main reason the implementation is more substantial than a simple wrapper around `va_list`.


## 3. Behavior Model

### ABI and argument promotions

A native `va_list` has compiler- and architecture-specific representation. The implementation includes distinct handling for supported GCC/Linux and Microsoft compiler environments; the GCC x86-64 path accounts for the register-save and overflow-area model rather than assuming that arguments form a simple stack array.

Argument promotions and exact widths matter. The stored `variant_t` values must be mapped to the representation expected by the receiving variadic function. Treating `va_list` as a portable pointer or copying its internals across ABIs is unsafe.

### Rebuild and consumption

The list can be cleared and rebuilt, and its stored values can be inspected by index. The practical flow is to append values, build the native representation, then pass it to a compatible formatting interface. The native view should not be assumed to remain valid beyond the lifetime/state for which it was built; inspect the current implementation before retaining it across mutations.

### Hotplace format-string syntax

The format-string parser refers to stored arguments by **1-based position**. The order in the format string can differ from insertion order.

```text
{1:02x}  {1:3d}  {2:-10s}
```

The text after `:` is a type-specific format specifier. The examples show numeric formatting/width and a left-aligned string field; the formatter interprets the specifier according to the stored argument type.

For `binary_t` (`TYPE_BINARY`):

- `s` emits one character per byte when printable; non-printable bytes become `.`. This is a readable diagnostic view, not a lossless representation.
- `x` emits Base16/hexadecimal text; `X` uses uppercase hexadecimal digits.

For integer arguments, `x` / `X` use the formatter's `0x`-prefixed hexadecimal form, while `h` emits hexadecimal digits without the `0x` prefix.

These are `sprintf()` format semantics, not conversions performed when `valist` stores a value: `valist` retains the typed argument and the formatter applies the specifier later.

### Source tests

- `test/testcase/base/basic/testcase_valist.cpp`
- `test/testcase/base/basic/testvector_valist.cpp`
- `test/testcase/base/basic/testvector_valist.yml`

## 4. Relationships

- `variant_t` is the intermediate typed-value representation; `valist` adapts stored values to the native variadic calling convention.
- The adapter is general-purpose; `sprintf()` is one consumer of `valist`. `basic_stream::vaprintf()` and `basic_stream::vaprintln()` are convenience entry points that forward to the formatter, not the definition of the `valist` abstraction.
- `valist` is ABI-sensitive; do not infer portability from the high-level `operator<<()` interface alone. The adapter is implemented in `valist.hpp/.cpp`, uses `variant.hpp` as its intermediate representation, and is exercised by `testcase_valist.cpp`.
