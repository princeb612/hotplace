# String Obfuscation

The string directory contains two related but deliberately separate obfuscation mechanisms.

## `obfuscate_string`

`obfuscate_string` stores each byte after adding a per-instance factor. When the contents are written back to `std::string`, `basic_stream` or `binary_t`, the factor is subtracted again.

The object supports assignment/append from common string/stream forms and clears its internal contents during cleanup.

This is a lightweight obfuscation utility, not cryptographic protection.

## `constexpr_obfuscate`

`constexpr_obfuscate.hpp` is guarded for C++14 or later because its compile-time constructor requires the C++14 constexpr model. It stores transformed characters in a fixed array and reconstructs the original string through `load_string()`.

This is intentionally isolated from the project's normal C++11 target. The regular project compatibility goal remains C++11; the constexpr facility is an experimental C++14+ feature.

## Tests

- `test_string_obfuscate_string()`
- `test_string_constexpr_hide()`
- `test_string_constexpr_obf()`

All are in `test/testcase/base/string/testcase_string.cpp`.
