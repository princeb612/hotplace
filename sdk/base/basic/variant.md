# Variant

`variant` provides hotplace's common runtime value representation.

It represents values of different C++ and protocol-oriented types through a common interface while retaining type information, size, flags, and ownership state.

It is used as a bridge between strongly typed C++ code and components that need to handle values generically.

## Two-layer representation

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

## Type system

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

## Generic type traits

`variant_traits<T>` associates a C++ type with its `vartype_t`, union member, and flags.

The generic setter interface uses these traits together with SFINAE to reduce repetitive overloads while retaining type information at compile time.

This is also where platform differences in native type widths are accounted for. For example, the `TYPE_LONG` mapping differs between 32-bit and 64-bit environments.

## Ownership

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

## Protocol-width values and conversion

The implementation provides explicit setters and binary conversion for protocol-width integer values such as 24-bit and 48-bit integers.

Conversion functions include `to_str()`, `to_hex()`, `to_bin()`, `to_int()`, `to_binary()`, and `to_string()`.

`to_binary()` can apply truncation and endian-conversion controls. This lets protocol encoders use the same generic value container while still producing the required wire representation.

## Big numbers

`TYPE_BIGNUMBER` integrates `bignumber` with the variant type system.

A big number can be inserted with `set_bn()` and then participate in the same conversion and formatting paths as other variant values.

The negative flag is also supported. This is useful when a protocol representation stores a magnitude separately from the semantic sign.

## Type queries and special values

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

## Coalescing

`is_coalescable_with()` checks whether another variant can logically follow the current value for coalescing purposes.

The relation is directional rather than necessarily symmetric. The implementation recognizes compatible numeric and boundary-value combinations instead of treating all values of the same broad category as interchangeable.

## Relationship with other components

`variant` is one of the more widely shared value abstractions in the SDK.

For example:

```text
                  variant
                 /   |   \
                /    |    \
          formatting valist dump_memory
                         \
                          generic values
```

`valist` uses `variant_t` as an intermediate representation before rebuilding the platform-specific `va_list`. `dump_memory` accepts variant values as generic input, and formatting/conversion code can operate on the same representation.

## Tests

`test/testcase/base/basic/testcase_variant.cpp`

The testcase covers protocol-oriented integer conversion, endian conversion and truncation, `bignumber` conversion and formatting, and negative-value handling.

These tests are useful examples of how a generic variant value is turned back into a protocol-oriented binary representation.

## Related source

- `sdk/base/basic/variant.hpp`
- `sdk/base/basic/variant.cpp`
- `sdk/base/basic/types.hpp`
- `sdk/base/basic/valist.hpp`
- `test/testcase/base/basic/testcase_variant.cpp`
