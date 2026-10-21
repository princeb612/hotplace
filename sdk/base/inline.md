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

# Inline utility helpers

## 1. Role

`inline.hpp` collects small header-defined helpers used across the base layer: bit/byte sizing, portable wrappers around selected C runtime functions, trimming, case conversion, and common string predicates. It is a utility collection rather than a single abstraction.

## 2. Data Model

The functions are defined as `static inline` overloads in namespace `hotplace`, so callers compile the implementation into the including translation unit.

Main groups include:

- `bit_length()` and `byte_capacity()` for integer bit width and minimum byte count.
- `memcpy_inline()` and `vsnprintf_inline()` for compiler/CRT-dependent function selection.
- `ltrim()` and `rtrim()` for in-place whitespace trimming.
- Case conversion and name-normalization helpers such as `lowername()` and `uppername()`.
- String prefix/suffix and related small comparison helpers.

The exact overload set depends on compiler support, including whether `uint128` is available.

## 3. Behavior Model

**Bit and byte sizing**

`bit_length(0)` returns zero. For nonzero values, overloads use compiler intrinsics where available; 64- and 128-bit values are split into high and low words to avoid requiring a single wider intrinsic. `byte_capacity()` rounds the bit count up to a whole byte.

**CRT wrappers**

`memcpy_inline()` selects `memcpy_s` only when secure CRT support is requested; otherwise it calls `memcpy`. `vsnprintf_inline()` selects the compiler/platform formatting function and may therefore inherit CRT-specific truncation/return-value behavior.

**String normalization**

The trim helpers mutate the supplied string and return it by reference. `lowername()` and `uppername()` create a normalized string from a C-string input and return an empty result for a null pointer. These functions are byte/locale-oriented helpers, not Unicode case-folding algorithms.

**Comparison helpers**

Prefix/suffix helpers operate on the selected string representation. Callers should check empty/length edge cases at their call site rather than assuming every helper implements the same policy.

## 4. Relationships

- `sdk/base/charset.hpp` — platform text aliases.
- `sdk/base/types.hpp` — shared integer aliases.
- `sdk/base/string/` — more focused string operations and obfuscation.
- `sdk/base/system/` — numeric and wire-width utilities.
