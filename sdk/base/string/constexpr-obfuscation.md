## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Compile-time String Obfuscation

## 1. Role

`constexpr_obfuscate.hpp` contains a compile-time string-obfuscation facility separate from the runtime `obfuscate_string` wrapper. The header is guarded for C++14 or later; this feature is not evidence that the project's general compatibility target has moved beyond C++11.

## 2. Model

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

## 3. Important behavior and lifetime

### Tests

- Source: `test/testcase/base/string/testcase_string.cpp`
- Functions: `test_string_constexpr_hide()`, `test_string_constexpr_obf()`
- Test analysis and execution report: [`testcase_string.md`](../../../test/testcase/base/string/testcase_string.md)

## 4. Example from the source tests

### Example from the testcase

`test_string_constexpr_obf()` checks the language version at compile time. Under C++14 or later it constructs several obfuscated strings and writes reconstructed values. In older language modes the testcase records `not_supported` with the message `at least c++14 required`.

The separate `test_string_constexpr_hide()` logs ordinary `constexpr char[]` strings; its unconditional assertion does not prove that the compiler binary hides those strings. The test is useful as a demonstration, not as a binary-inspection assertion.

## 5. Relationships

- [Runtime string obfuscation](obfuscation.md) covers `obfuscate_string`, which has a different storage/use model.
- The project-wide baseline remains C++11; this isolated feature is explicitly C++14+.

## 6. References

- `sdk/base/string/constexpr_obfuscate.hpp`

### Source basis

Edition 1 · Revision 1104
