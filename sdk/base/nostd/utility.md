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

# Utility helpers

## 1. Role

This page groups small, cross-cutting helpers that do not form a single data structure: numeric text conversion (`atoi.hpp`), project-specific casting (`cast.hpp`), miscellaneous utilities (`utility.hpp`), memory helpers (`memory.hpp`) and enum-class support (`enumclass.hpp`).

## 2. Data Model

```text
text / generic value
       |
       v
conversion, cast or helper API
       |
       v
caller-specific value or operation
```

These helpers are infrastructure. Their exact contracts are defined by each function and should not be generalized into one shared error or ownership policy.

## 3. Behavior Model

### Conversion and ownership boundaries

- `atoi.hpp` provides numeric text conversion helpers; malformed or out-of-range input behavior must be checked against the specific overload rather than assumed to match every `std::` conversion.
- `cast.hpp` provides project-specific narrowing/conversion helpers. The dedicated testcase is important because truncation and range-check behavior are part of the helper contract.
- `memory.hpp` provides C++11-compatible unique ownership helpers, custom deleters, and a raw-pointer adoption wrapper. See [Memory ownership helpers](memory.md).
- `enumclass.hpp` and `utility.hpp` provide small generic helpers; they do not establish a common error policy for every conversion.
- `capacity.hpp` calculates the minimum signed byte width for an integer representation. It complements, but is not the same operation as, the unsigned bit-width helpers in `sdk/base/inline.hpp`.

## 4. Relationships

- `atoi.hpp` provides string-to-integer conversion; `cast.hpp` and `utility.hpp` provide conversion/casting helpers; `enumclass.hpp` supplies enum-class support. [Memory ownership helpers](memory.md) cover object/array ownership and custom deleters. The adjacent tests `testcase_int.cpp` and `testcase_narrowcast.cpp` cover integer classification and narrowing/conversion behavior.
