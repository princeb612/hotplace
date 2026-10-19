## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Binary utilities

## 1. Role

`binary.hpp` and `binaries.hpp` provide helpers for working with `binary_t` byte sequences. They support appending bytes, strings, byte arrays, integral values and floating-point values, plus variants that constrain or extend the encoded width.

## 2. Model

```text
source value / bytes
        |
        v
binary_append* / binary_push
        |
        v
   binary_t byte sequence
        |
        +--> byte-oriented SDK code
```

The integral overloads can apply a supplied transformer such as a host/network-order conversion function. The floating-point overloads first convert through the project's IEEE-754 helpers and then append the resulting integer representation.

## 3. Important behavior and lifetime

No additional behavior or lifetime note was separately identified in the existing document.

## 4. Example from the source tests

### Example from source

The header's examples append integer values and use explicit transformers such as `hton32`; `testcase_binary.cpp` checks byte output and conversions. Use the testcase as the executable reference rather than assuming host byte order from a literal example alone.

## 5. Relationships

- `sdk/base/nostd/binary.hpp`
- `sdk/base/nostd/binaries.hpp`
- `test/testcase/base/nostd/testcase_binary.cpp`
- `sdk/base/system/ieee754.md` — floating-point representation helpers

## 6. References

- C++ object representation and byte-oriented serialization concepts; the exact byte order is determined by the selected overload/transformer.
