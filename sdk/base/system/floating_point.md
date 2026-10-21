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

# Exact floating-point arithmetic

## 1. Role

### Introduction

`floating_point` is hotplace's abstraction for arithmetic that needs an exact decimal or rational representation rather than the approximation semantics of native `float`/`double`.


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

`floating_point` is the common public abstraction that can hold either representation. A string containing `/` is interpreted as a rational expression; other numeric expressions are interpreted as decimal values.
## 3. Behavior Model

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

### Why this exists

The important distinction is between **exact decimal/rational arithmetic** and native binary floating-point arithmetic.

For example, the tests intentionally exercise:

```text
0.1 + 0.2   = 0.3
0.1 + 1/3   = 13/30
1/2 + 1/3   = 5/6
```

Large decimal values are also tested, including arithmetic around `1000000000000000.1`, where retaining the decimal representation is part of the purpose of the type.

This is therefore not intended as a general replacement for `float` or `double`. It is a separate exact-arithmetic facility built on top of `bignumber`.

### Tests

Primary tests:

- `test/testcase/base/system/testcase_floatingpoint.cpp`
- `test/testcase/base/system/testvector_floatingpoint.cpp`
- `test/testcase/base/system/testvector_floatingpoint.yml`

The testcase covers decimal/rational construction and arithmetic, while the YAML-driven test vector covers a broader set of add/subtract/multiply/divide cases.

### Status

This is an implementation-specific exact-arithmetic utility in `sdk/base/system`. It should be understood together with `bignumber`, rather than as a general floating-point library.

## 4. Relationships

### Relationship to other system types

`bignumber` supplies the integer foundation; `floating_point` combines decimal and rational forms into a higher-level arithmetic interface. The implementations are `decimal_float.hpp/.cpp`, `rational_float.hpp/.cpp`, and `floating_point.hpp/.cpp`; `testcase_floatingpoint.cpp` and its vector files cover source-level arithmetic cases.
