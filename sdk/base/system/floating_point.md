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

# Exact floating-point arithmetic

## 1. Role

### Introduction

`floating_point` is hotplace's abstraction for arithmetic that needs an exact decimal or rational representation rather than the approximation semantics of native `float`/`double`.

It is not a general replacement for native floating-point types. It is a separate exact-arithmetic facility built on `bignumber`, and should be understood together with that integer foundation.

The two representations serve different forms of exact arithmetic:

```text
0.1 + 0.2   = 0.3
0.1 + 1/3   = 13/30
1/2 + 1/3   = 5/6
```

Decimal representation is convenient for base-10 values; rational representation preserves values as ratios of integers. These examples explain the intent of supporting both without adding separate test cases solely to demonstrate the distinction.

## 2. Data Model

### Representation hierarchy

```text
bignumber
  ├── decimal_float  (mantissa, base-10 exponent)
  ├── rational_float (numerator, denominator)
  └── floating_point (public abstraction over either representation)
```

`bignumber` supplies arbitrary-width integer operations. `decimal_float` represents a value as a `bignumber` mantissa and a base-10 exponent; `rational_float` represents an exact numerator/denominator pair of `bignumber` values.

```text
decimal value  = mantissa x 10^exponent
rational value = numerator / denominator
```

`floating_point` is the common public abstraction that can hold either representation.

## 3. Behavior Model

### Parsing the input representation

A string containing `/` is interpreted as a rational expression; other numeric expressions are interpreted as decimal values. Mixed decimal/rational operations can consequently select the rational representation.

### Arithmetic behavior

The implementation supports:

- addition
- subtraction
- multiplication
- division
- comparison
- string formatting
- conversion to rational representation

Decimal operands remain decimal when the operation can be represented in the decimal form. Mixed decimal/rational operations use the rational representation.

Division by zero is rejected. Decimal division that is not exactly representable as a decimal result can therefore become a rational result.

The decimal implementation uses `bignumber::pow10()` to align exponents during addition/subtraction, but bounds this work with `MAX_PRECISION = 1024`. When the exponent difference is outside ±1024, it skips potentially expensive power-of-ten scaling and takes a fallback path instead of exact decimal alignment.

**Important implementation limitation:** the current fallback returns the left operand when `diff > 1024`; when `diff < -1024`, both `add()` and `subtract()` construct a result from the negated right-hand mantissa. These extreme-gap branches are not general exact-arithmetic results; the addition branch in particular should be reviewed before relying on its mathematical meaning. The 1024 bound is a performance guard with observable semantics, not an optimization that always preserves exactness.

## 4. Relationships

- `test/testcase/base/system/testcase_floatingpoint.cpp`, `testvector_floatingpoint.cpp`, and `testvector_floatingpoint.yml` exercise exact decimal/rational cases and large decimal values.
### Relationship to other system types

`bignumber` supplies the integer foundation; `floating_point` combines decimal and rational forms into a higher-level arithmetic interface. The implementations are `decimal_float.hpp/.cpp`, `rational_float.hpp/.cpp`, and `floating_point.hpp/.cpp`; `testcase_floatingpoint.cpp` and its vector files cover source-level arithmetic cases.

## 5. References

No external references are listed.
