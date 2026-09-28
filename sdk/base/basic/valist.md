# Dynamic `va_list`

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

## Argument handling

`operator<<()` accepts the primitive numeric types together with pointers, strings, `basic_stream`, `binary_t`, and `variant_t`.

The stored arguments can also be inspected by index and the list can be cleared and rebuilt.

The implementation normalizes several C/C++ argument promotions before constructing the native representation. This is important because a `va_list` cannot be treated as a portable pointer-like object.

## ABI-specific construction

`build()` contains platform-specific handling for the `va_list` layouts used by the supported GCC/Linux and Microsoft compiler environments.

For the GCC x86-64 representation, the implementation handles the register-save/overflow-area model rather than assuming a simple stack-based argument list.

The source contains explicit handling for integer widths and floating-point values so that the reconstructed list matches what the receiving variadic function expects.

This ABI dependency is the main reason the implementation is more substantial than a simple wrapper around `va_list`.

## Formatting integration

The main practical use is passing dynamically assembled arguments to hotplace's formatting functions.

Arguments can be collected first and then referenced by position in a format string, including a different order from the order in which they were inserted.

Binary values can also remain typed through the intermediate `variant_t` representation and participate in the formatting system's binary formats.

## Tests

- `test/testcase/base/basic/testcase_valist.cpp`
- `test/testcase/base/basic/testvector_valist.cpp`
- `test/testcase/base/basic/testvector_valist.yml`

The testcase covers formatting, binary values, empty values, argument ordering, integer-width boundaries, and ABI-sensitive register/stack alignment cases.

The ABI-boundary tests are especially important documentation for the implementation: they record the assumptions that must remain true when the native `va_list` is reconstructed.

## C++14 helper

The source also provides a variadic `vprintf` convenience path for C++14 and later. This is an additional convenience interface; the core dynamically constructed `valist` remains a separate facility.

## Related source

- `sdk/base/basic/valist.hpp`
- `sdk/base/basic/valist.cpp`
- `sdk/base/basic/variant.hpp`
- `test/testcase/base/basic/testcase_valist.cpp`
- `test/testcase/base/basic/testvector_valist.cpp`
