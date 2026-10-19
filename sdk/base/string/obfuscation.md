## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Runtime String Obfuscation

## 1. Role

`obfuscate_string` is a lightweight runtime string-obfuscation wrapper. It is intended to transform how string bytes are stored in the object, not to provide cryptographic confidentiality.

## 2. Model

The implementation stores bytes transformed using an instance-specific factor. When converting or writing the value into supported output forms, the data is reconstructed. The testcase exercises output into `binary_t` and `std::string`, equality after construction, and append/equality behavior.

```text
source characters
      |
      v
obfuscate_string (transformed internal bytes)
      |
      +--> binary_t << obfuscated value --> reconstructed bytes
      +--> std::string << value ----------> reconstructed text
```

This is obfuscation rather than encryption: it should not be used to protect secrets against an attacker who can inspect the program or its runtime state.

## 3. Important behavior and lifetime

### Tests

- Source: `test/testcase/base/string/testcase_string.cpp`
- Function: `test_string_obfuscate_string()`
- Test analysis and execution report: [`testcase_string.md`](../../../test/testcase/base/string/testcase_string.md)

## 4. Example from the source tests

### Example from the testcase

`test_string_obfuscate_string()` initializes the wrapper from a character array containing `hello world`, writes it to `binary_t` and `std::string`, and compares the recovered bytes with the original array. It also compares two wrappers and exercises append behavior.

## 5. Relationships

- [Compile-time obfuscation](constexpr-obfuscation.md) documents a separate C++14+ facility.
- The module remains part of `sdk/base/string`; it is not the project's cryptographic API.

## 6. References

- `sdk/base/string/obfuscate_string.hpp`
- `sdk/base/string/obfuscate_string.cpp`

### Source basis

Edition 1 · Revision 1104
