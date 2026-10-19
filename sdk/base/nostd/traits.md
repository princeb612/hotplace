## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Traits and type adapters

## 1. Role

The traits family supplies compile-time type classification and adapters used by generic code in hotplace. The current files include `traits.hpp`, `traits_encoder.hpp` and `traits_printf.hpp`; `cast.hpp` and `enumclass.hpp` provide adjacent type-related helpers.

## 2. Model

```text
template argument
      |
      v
traits / enable_if / type adapters
      |
      v
select valid overload or representation
```

For example, `binary.hpp` constrains integral overloads using project traits, while `set.hpp` selects a concrete set representation based on the decayed value type. These are examples of use, not a claim that every template in the SDK depends on this exact traits family.

## 3. Important behavior and lifetime

No additional behavior or lifetime note was separately identified in the existing document.

## 4. Example from the source tests

### Example and tests

`testcase_int.cpp` and `testcase_narrowcast.cpp` are related test sources. The latter is especially relevant to the project's explicit narrowing-conversion helper.

## 5. Relationships

- `sdk/base/nostd/traits.hpp`
- `sdk/base/nostd/traits_encoder.hpp`
- `sdk/base/nostd/traits_printf.hpp`
- `sdk/base/nostd/cast.hpp`
- `test/testcase/base/nostd/testcase_int.cpp`
- `test/testcase/base/nostd/testcase_narrowcast.cpp`

## 6. References

Implementation and test paths are retained in the sections above or the source tree.
