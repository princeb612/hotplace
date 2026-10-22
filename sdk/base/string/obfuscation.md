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

# Runtime String Obfuscation

## 1. Role

`obfuscate_string` is a lightweight runtime string-obfuscation wrapper. It is intended to transform how string bytes are stored in the object, not to provide cryptographic confidentiality.

## 2. Data Model

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

## 3. Behavior Model

The runtime wrapper supports conversion to `binary_t` and `std::string`, comparison, and append operations. The testcase initializes it with `hello world` and compares the recovered output bytes with the original character array.

### Tests

- Source: `test/testcase/base/string/testcase_string.cpp`
- Function: `test_string_obfuscate_string()`
- Test analysis and execution report: [`README.md`](../../../test/testcase/base/string/README.md)

## 4. Relationships

- [Compile-time obfuscation](constexpr-obfuscation.md) documents a separate C++14+ facility.
- The module remains part of `sdk/base/string`; it is not the project's cryptographic API. The runtime implementation is in `obfuscate_string.hpp/.cpp`.
