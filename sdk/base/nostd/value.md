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

# `t_value<T>` — Deferred Value

## 1. Role

### Introduction

`sdk/base/nostd/value.hpp` provides `t_value<T>`, a C++11 utility for holding a typed value that may be populated later. It combines a cached value with `std::promise<T>` / `std::future<T>` state and is used by the ASN.1 parameterized semantic prototype to represent values associated with formal parameters.

## 2. Data Model

### State representation

The object tracks whether it is deferred, whether the local value is cached, and an optional name. It combines a cached `T` value with `std::promise<T>` / `std::future<T>` state. Copying intentionally does not copy the promise/future: the copy captures the source's current value state instead.

## 3. Behavior Model

### State transitions

```text
t_value<T>
  ├─ immediate value ─► set_value(value) ─► cached value
  └─ deferred value
       ├─ defer(name) ─► reset promise/future; mark uncached
       ├─ get_future() ─► obtain future view
       ├─ set_value(value) ─► fulfill promise and cache value
       └─ value() ─► retrieve/cache future result when available
```

`value()` returns the cached/current value; if a deferred future is valid, it attempts to obtain the result and cache it.

### Exception behavior

The implementation is intentionally described as **not exception-sensitive**. `value()` catches exceptions while retrieving the future result, and `set_value()` catches failures while fulfilling the promise. Those failures are not propagated to callers through these methods; callers should not treat `t_value<T>` as an exception-reporting future abstraction.

### Use in parameterized ASN.1

`asn1_parameter::value<T>(templ, param, name)` registers a parameter descriptor on the template and returns a deferred `t_value<T>` named for the parameter. A semantic object can use that deferred value in a constraint or default expression before the actual parameter value is bound by the prototype's specialization flow.

This is a low-level utility contract, not a claim that ASN.1 notation parsing and parameter substitution are fully integrated.

## 4. Relationships

- `sdk/io/asn.1/basic/semantic/parameterized/asn1_parameterized_type.hpp` — creates deferred parameter values that can be referenced before a specialization binds the actual value.
- `std::promise` / `std::future` — the deferred value mechanism used internally; this class deliberately catches retrieval/fulfillment exceptions rather than exposing a full future error contract.
- `test/testcase/asn.1/parameterized/testcase_parameterized.cpp` — source-level usage in the parameterized ASN.1 prototype.
