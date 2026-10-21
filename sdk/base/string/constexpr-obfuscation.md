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

# Compile-time String Obfuscation

## 1. Role

`constexpr_obfuscate.hpp` contains a compile-time string-obfuscation facility separate from the runtime `obfuscate_string` wrapper. The header is guarded for C++14 or later; this feature is not evidence that the project's general compatibility target has moved beyond C++11.

## 2. Data Model

The facility transforms characters into a fixed-size representation during constant evaluation and provides a way to reconstruct the original string. The public macro/helper names used by the testcase include `CONSTEXPR_OBF`, `CONSTEXPR_OBF_CSTR`, `t_constexpr_obf`, and `define_constexpr_obf`.

```text
literal / constexpr input
          |
          v
compile-time transformed representation
          |
          v
explicit reconstruction for output/use
```

The purpose is to avoid leaving the original full literal as a single obvious string in the compiled image. It is not a cryptographic secrecy boundary; fragments, program logic, or runtime reconstruction may still reveal the value.

## 3. Behavior Model

The runtime wrapper supports conversion to `binary_t` and `std::string`, comparison, and append operations. The testcase initializes it with `hello world` and compares the recovered output bytes with the original character array.

### Tests

- Source: `test/testcase/base/string/testcase_string.cpp`
- Functions: `test_string_constexpr_hide()`, `test_string_constexpr_obf()`
- Test analysis and execution report: [`testcase_string.md`](../../../test/testcase/base/string/testcase_string.md)

## 4. Relationships

- [Runtime string obfuscation](obfuscation.md) covers `obfuscate_string`, which has a different storage/use model.
- The project-wide baseline remains C++11; this isolated feature is explicitly C++14+. The implementation is in `constexpr_obfuscate.hpp`; it should remain isolated from headers that must compile under the C++11 baseline.
