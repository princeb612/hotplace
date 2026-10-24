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

The distinction between direct storage and owned allocation matters whenever a variant contains a dynamically allocated string or binary buffer. In particular, `vt_flag_free` indicates that the corresponding value requires release, while `vt_flag_standalone` versus `vt_flag_composite` describes whether the value can be represented without a separate size component. Attribute flags (`vt_flag_int`, `vt_flag_float`, `vt_flag_string`, `vt_flag_binary`, and `vt_flag_user_type`) classify the stored value; they are not ownership indicators.

### Protocol-width values and conversion

The implementation provides explicit setters and binary conversion for protocol-width integer values such as 24-bit and 48-bit integers.

Conversion functions include `to_str()`, `to_hex()`, `to_bin()`, `to_int()`, `to_binary()`, and `to_string()`.

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

## 3. Behavior Model

### Value lifecycle and conversion flow

Construction or assignment establishes the type, size, flags, and union representation. For dynamically owned values, the ownership flags determine how replacement and cleanup release the prior storage. `clear()` releases owned resources and returns the value to the null state; `reset()` performs a shallower representation reset and must not be treated as equivalent cleanup.

`to_binary()` reads the stored type/value and applies the requested controls, such as truncation and endian conversion, to produce a `binary_t` representation. The result is a byte representation for the caller; it does not change the semantic meaning of the protocol field or make host-native layout a wire-format guarantee.

```text
typed C++ value
  └─ variant_traits<T> selects vartype + union member + flags
       └─ variant / variant_t stores type, size, flags, data
            ├─ query / compare / coalescing
            ├─ to_str / to_int / to_hex / to_bin
            └─ to_binary(controls) → binary_t bytes
clear() → release owned data → TYPE_NULL
reset() → shallow state reset (not an ownership-cleanup substitute)
```

### Binary conversion and coalescing

`to_binary()` can apply `variant_trunc` and `variant_convendian` controls. These are operation controls, not persistent value attributes: truncation and endian conversion affect the produced `binary_t`, not the stored type metadata.

`is_coalescable_with()` checks whether another variant can logically follow the current value for coalescing purposes. The relation is directional rather than necessarily symmetric; the implementation recognizes compatible numeric and boundary-value combinations instead of treating all values of the same broad category as interchangeable.

### Concrete caller path: protocol-width binary conversion

The testcase demonstrates that `variant` can retain a typed value while producing bytes with explicit endian/truncation controls:

```cpp
binary_t bin;
std::string hex;
variant value;

value.clear().set((uint32)32768);
value.to_binary(bin, variant_convendian | variant_trunc);
hex = base16_encode(bin);
_test_case.assert(hex == "00008000", __FUNCTION__, "base16");
```

The stored value remains a `uint32`; `variant_convendian | variant_trunc` controls the output representation, and Base16 is used only to make the resulting bytes inspectable. The testcase also checks a 64-bit value and a `bignumber`, so this example should not be read as proof that every type has a meaningful binary representation under every control combination.

Source: `test/testcase/base/basic/testcase_variant.cpp`.

### Big numbers

`TYPE_BIGNUMBER` integrates `bignumber` with the variant type system.

A big number can be inserted with `set_bn()` and then participate in the same conversion and formatting paths as other variant values.

The negative flag is also supported. This is useful when a protocol representation stores a magnitude separately from the semantic sign.

## 5. Relationships

- `test/testcase/base/basic/testcase_variant.cpp` covers protocol-oriented integer conversion, endian conversion and truncation, `bignumber` conversion/formatting, and negative-value handling. One assertion stores `32768` as `uint32`, converts with `variant_convendian | variant_trunc`, Base16-encodes the resulting `binary_t`, and checks `00008000`; this is a concrete example, not a guarantee for every type/flag combination.
- `valist` uses `variant_t` as the retained representation for heterogeneous arguments before it reconstructs the platform-specific native `va_list`; this is an argument-passing path, not the stream-formatting path.
- [`vtprintf`](../stream/README.md#variant-formatting-with-vtprintf) consumes either `variant_t` or `variant` and writes a textual representation to a `stream_t`. The value type and flags come from `variant`; `vtprintf_style_t` selects presentation conventions such as normal, CBOR-oriented, Base16, debug, or ASN.1 output. It does not replace `variant::to_binary()` and is not a wire encoder.
- `basic_stream::operator<<(const variant&)` delegates to `vtprintf` with debug style, while other callers can select a protocol-oriented display style explicitly. This is why the same value can have different textual renderings without changing its stored representation.
- `binary_t` is the byte-container used by binary conversion; Base16 encoding is used by the testcase to make the bytes inspectable.
- Higher-level protocol code defines field meaning and ordering; `variant` supplies value/type conversion primitives. The main implementation is in `variant.hpp/.cpp` with shared declarations in `types.hpp`; `testcase_variant.cpp` provides conversion examples, while `valist.hpp/.cpp` is a consumer of heterogeneous values. The testcase is a concrete conversion example, not a universal statement that every `vartype_t` has a defined binary representation for every flag combination.

## 6. References

No external references are listed.
