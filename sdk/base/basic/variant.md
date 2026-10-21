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

# Variant

## 1. Role

### Introduction

`variant` provides hotplace's common runtime value representation.

It represents values of different C++ and protocol-oriented types through a common interface while retaining type information, size, flags, and ownership state.

It is used as a bridge between strongly typed C++ code and components that need to handle values generically.

## 2. Data Model

### Two-layer representation

The implementation separates the low-level `variant_t` representation from the higher-level `variant` interface.

```text
variant
  │
  └── variant_t
       ├── type
       ├── size
       ├── flag
       └── union data
```

`variant_t` contains the value metadata and union storage. `variant` provides construction, assignment, ownership management, conversion, comparison, and type-query operations.

This low-level representation is also useful to components such as `valist` that need to consume generic values without owning the higher-level interface.

### Type system

`vartype_t` covers ordinary C++ values such as integers, floating-point values, characters, strings, and binary data, together with hotplace-specific representations.

Notable protocol-oriented types include:

- `TYPE_INT24` / `TYPE_UINT24`
- `TYPE_INT48` / `TYPE_UINT48`
- `TYPE_FP16`
- `TYPE_DATETIME`
- `TYPE_BIGNUMBER`
- `TYPE_BASE16`, `TYPE_BASE64`, and `TYPE_BASE64URL`
- `TYPE_MINVALUE` / `TYPE_MAXVALUE`
- user-defined types

The 24-bit and 48-bit integer types are particularly useful for protocol fields whose width is part of the wire format, such as TLS and DTLS fields.

### How the type macros fit together

The large type list is maintained once and expanded into several different C++ declarations. The goal is to avoid writing a separate enum entry, union member, and traits specialization by hand for every supported type.

Each `VARIANT_XGROUP_...` macro is a **group of type-list entries**. The letters describe which generated artifacts that group participates in:

| Group | `vartype_t` enum (E) | `vartype_union` member (M) | Integral conversion cases (I) | `variant_traits` specialization (T) | 128-bit entries (X) |
|---|---:|---:|---:|---:|---:|
| `VARIANT_XGROUP_E` | Yes | No | No | No | No |
| `VARIANT_XGROUP_EM` | Yes | Yes | No | No | No |
| `VARIANT_XGROUP_EMT` | Yes | Yes | No | Yes | No |
| `VARIANT_XGROUP_EMIT` | Yes | Yes | Yes | Yes | No |
| `VARIANT_XGROUP_EMTX` | Yes | Yes | No | Yes | Yes |

The letters are a compact description of macro expansion targets, not different runtime representations. For example, `VARIANT_XGROUP_EMIT` expands into enum values, union members, integral-conversion switch cases, and traits specializations. By contrast, `VARIANT_XGROUP_EM` deliberately omits the traits specialization.

The expansion points make the design easier to follow:

- `EXPAND_VARTYPE_ENUM` generates entries in `vartype_t`.
- `EXPAND_VARTYPE_MEMBER` generates members of `vartype_union`.
- `EXPAND_INTEGRAL_CASE` generates cases for converting supported integral values in `t_vtoi()`.
- `EXPAND_VARTYPE_TAITS` generates `variant_traits<T>` specializations (the macro name is spelled `TAITS` in the source).

In other words, the type list is the source of truth, and each expansion chooses the declarations needed for that particular group. The groups are separated because not every C++ type can safely or usefully receive every generated artifact.

### Why the groups differ across platforms

The `char` / `int8` relationship is the main example of why these groups cannot all be treated alike. On the documented Linux GCC configuration, `int8` is `int8_t` and is distinct from `char`, so both can have separate variant entries and `variant_traits` specializations. On the Windows GCC/MSVC configurations noted in the header, `int8` may alias `char`; generating both specializations would then duplicate the same C++ type specialization. The conditional `VARIANT_XGROUP_EMT_CHAR` / `VARIANT_XGROUP_EM_CHAR` macros therefore place `char` in the traits-generating group on Linux, but in the enum-and-member-only group on Windows.

`byte_t` is another deliberate exception: it aliases `unsigned char`, so it is placed in `VARIANT_XGROUP_EM` and does not get a generated `variant_traits` specialization. The group choice is about avoiding duplicate/conflicting type mappings, not about whether the type can be represented by the union.

Finally, `VARIANT_XGROUP_EMTX` holds the 128-bit integer entries. Their enum values, union members, and traits are generated only when `__SIZEOF_INT128__` is defined; the `X` marks this conditional 128-bit group.

### Generic type traits

`variant_traits<T>` associates a C++ type with its `vartype_t`, union member pointer, and flags. The generic constructors and setters use these traits with SFINAE to enable the appropriate overloads while retaining type information at compile time.

This is also where platform differences in native type widths are accounted for. For example, the `TYPE_LONG` mapping differs between 32-bit and 64-bit environments.

### Ownership

The variant flags distinguish directly stored values from values for which the variant owns allocated storage.

Important flags include:

- `vt_flag_standalone`
- `vt_flag_composite`
- `vt_flag_free`
- `vt_flag_string`
- `vt_flag_binary`
- `vt_flag_int`
- `vt_flag_float`
- `vt_flag_user_type`

`clear()` releases owned resources and returns the value to the null state. `reset()` performs a shallower representation reset and does not perform the same ownership cleanup.

The distinction matters whenever a variant contains a dynamically allocated string or binary buffer.

### Protocol-width values and conversion

The implementation provides explicit setters and binary conversion for protocol-width integer values such as 24-bit and 48-bit integers.

Conversion functions include `to_str()`, `to_hex()`, `to_bin()`, `to_int()`, `to_binary()`, and `to_string()`.

`to_binary()` can apply truncation and endian-conversion controls. This lets protocol encoders use the same generic value container while still producing the required wire representation.

### Type queries and special values

The implementation provides queries such as:

- `is_null()`
- `is_int()`
- `is_float()`
- `is_string()`
- `is_binary()`
- `is_usertype()`
- `is_minvalue()`
- `is_maxvalue()`

`minvalue()` and `maxvalue()` provide explicit sentinel values represented by `TYPE_MINVALUE` and `TYPE_MAXVALUE`.

### Coalescing

`is_coalescable_with()` checks whether another variant can logically follow the current value for coalescing purposes.

The relation is directional rather than necessarily symmetric. The implementation recognizes compatible numeric and boundary-value combinations instead of treating all values of the same broad category as interchangeable.

## 3. Behavior Model

### Big numbers

`TYPE_BIGNUMBER` integrates `bignumber` with the variant type system.

A big number can be inserted with `set_bn()` and then participate in the same conversion and formatting paths as other variant values.

The negative flag is also supported. This is useful when a protocol representation stores a magnitude separately from the semantic sign.

### Tests

`test/testcase/base/basic/testcase_variant.cpp`

The testcase covers protocol-oriented integer conversion, endian conversion and truncation, `bignumber` conversion and formatting, and negative-value handling.

One concrete assertion stores `32768` as `uint32`, converts it with `variant_convendian | variant_trunc`, Base16-encodes the resulting `binary_t`, and checks `00008000`. The tests demonstrate how a generic variant value is turned back into a protocol-oriented binary representation.

## 4. Relationships

- `valist` uses variant values to retain heterogeneous arguments before formatting.
- `binary_t` is the byte-container used by binary conversion; Base16 encoding is used by the testcase to make the bytes inspectable.
- Higher-level protocol code defines field meaning and ordering; `variant` supplies value/type conversion primitives. The main implementation is in `variant.hpp/.cpp` with shared declarations in `types.hpp`; `testcase_variant.cpp` provides conversion examples, while `valist.hpp/.cpp` is a consumer of heterogeneous values. The testcase is a concrete conversion example, not a universal statement that every `vartype_t` has a defined binary representation for every flag combination.
