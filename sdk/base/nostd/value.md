# `t_value<T>` — Deferred Value

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1104
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```

`sdk/base/nostd/value.hpp` provides `t_value<T>`, a C++11 utility for holding a typed value that may be populated later. It combines a cached value with `std::promise<T>` / `std::future<T>` state and is used by the ASN.1 parameterized semantic prototype to represent values associated with formal parameters.

## State and flow

```text
t_value<T>
  |
  +-- immediate value
  |     `-- set_value(value) -> cached value
  |
  `-- deferred value
        |
        +-- defer(name)
        |     `-- reset promise/future, mark uncached
        |
        +-- get_future()
        |
        +-- set_value(value)
        |     `-- fulfill promise and cache value
        |
        `-- value()
              `-- retrieve/cache future result when available
```

The object tracks whether it is deferred, whether the local value is cached, and an optional name. `value()` returns the cached/current value; if a deferred future is valid, it attempts to obtain the result and cache it. Copying intentionally does not copy the promise/future: the copy captures the source's current value state instead.

## Exception behavior

The implementation is intentionally described as **not exception-sensitive**. `value()` catches exceptions while retrieving the future result, and `set_value()` catches failures while fulfilling the promise. Those failures are not propagated to callers through these methods; callers should not treat `t_value<T>` as an exception-reporting future abstraction.

## Use in parameterized ASN.1

`asn1_parameter::value<T>(templ, param, name)` registers a parameter descriptor on the template and returns a deferred `t_value<T>` named for the parameter. A semantic object can use that deferred value in a constraint or default expression before the actual parameter value is bound by the prototype's specialization flow.

This is a low-level utility contract, not a claim that ASN.1 notation parsing and parameter substitution are fully integrated.

## Related source

- `sdk/base/nostd/value.hpp`
- `sdk/io/asn.1/basic/semantic/parameterized/asn1_parameterized_type.hpp`

## Related tests

- `test/testcase/asn.1/parameterized/testcase_parameterized.cpp`
