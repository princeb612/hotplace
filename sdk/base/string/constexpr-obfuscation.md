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

# Compile-time String Obfuscation

## 1. Role

`constexpr_obfuscate.hpp` contains a compile-time string-obfuscation facility separate from the runtime `obfuscate_string` wrapper. The header is guarded for C++14 or later; this feature is not evidence that the project's general compatibility target has moved beyond C++11.

## 2. Data Model

The facility transforms characters into a fixed-size representation during constant evaluation and provides a way to reconstruct the original string. The public macro/helper names used by the testcase include `CONSTEXPR_OBF`, `CONSTEXPR_OBF_CSTR`, `t_constexpr_obf`, and `define_constexpr_obf`.

The compile-time object stores a transformed fixed-size representation of the literal. Its helper and macro names identify the compile-time facility; the original text is reconstructed explicitly for output or use.

The purpose is to avoid leaving the original full literal as a single obvious string in the compiled image. It is not a cryptographic secrecy boundary; fragments, program logic, or runtime reconstruction may still reveal the value.

## 3. Behavior Model

### Compile-time construction and reconstruction

```text
literal / constexpr input
          └─ constant evaluation ─► transformed fixed-size representation
                                         └─ explicit reconstruction ─► output/use
```

The compile-time wrapper supports reconstruction for output/use, comparison, and append operations.

## 5. Relationships

- `test/testcase/base/string/testcase_string.cpp` — `test_string_constexpr_hide()` and `test_string_constexpr_obf()` compare reconstructed output with the original character data; see the [testcase guide](../../../test/testcase/base/string/README.md).
- [Runtime string obfuscation](obfuscation.md) covers `obfuscate_string`, which has a different storage/use model.
- The project-wide baseline remains C++11; this isolated feature is explicitly C++14+. The implementation is in `constexpr_obfuscate.hpp`; it should remain isolated from headers that must compile under the C++11 baseline.

## 6. References

No external references are listed.
