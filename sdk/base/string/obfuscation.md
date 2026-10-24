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

# Runtime String Obfuscation

## 1. Role

`obfuscate_string` is a lightweight runtime string-obfuscation wrapper. It is intended to transform how string bytes are stored in the object, not to provide cryptographic confidentiality.

## 2. Data Model

The implementation stores bytes transformed using an instance-specific factor. When converting or writing the value into supported output forms, the data is reconstructed. The testcase exercises output into `binary_t` and `std::string`, equality after construction, and append/equality behavior.

This is obfuscation rather than encryption: it should not be used to protect secrets against an attacker who can inspect the program or its runtime state.

## 3. Behavior Model

### Construction and output flow

```text
source characters ─► obfuscate_string (transformed internal bytes)
                              ├─ binary_t << value ─► reconstructed bytes
                              └─ std::string << value ─► reconstructed text
```

The wrapper reconstructs the original content when converting or writing to supported output forms; it does not provide cryptographic confidentiality.

The runtime wrapper supports conversion to `binary_t` and `std::string`, comparison, and append operations.

## 4. Relationships

- `test/testcase/base/string/testcase_string.cpp` — `test_string_obfuscate_string()` compares reconstructed output bytes with the original character array; see the [testcase guide](../../../test/testcase/base/string/README.md).
- [Compile-time obfuscation](constexpr-obfuscation.md) documents a separate C++14+ facility.
- The module remains part of `sdk/base/string`; it is not the project's cryptographic API. The runtime implementation is in `obfuscate_string.hpp/.cpp`.

## 5. References

No external references are listed.
