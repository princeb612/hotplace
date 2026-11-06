## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1123                    │
│ Source basis: Revision 1123                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# `t_value<T>` — Named Value Holder

## 1. Role

### Introduction

`sdk/base/nostd/value.hpp` provides `t_value<T>`, a small C++11 wrapper that stores a value together with an optional name. It offers value access, assignment, naming, and value-based comparisons. It is not a deferred-evaluation, future, promise, or cache abstraction.

## 2. Data Model

### Stored state

The object contains two members:

- `_value` — the stored `T` value, default-initialized when no value is supplied.
- `_name` — an optional `std::string` name.

Copy and move operations transfer or copy these two members. There is no deferred flag, cached-result flag, promise, or future state.

## 3. Behavior Model

### Value and name operations

- Constructors accept a default value, a `const T&`, or an rvalue; value constructors may also receive a name.
- `value()` returns the stored value, and the conversion operator exposes the same value conversion.
- `set_value()` and assignment replace the stored value.
- `set_name()`, `get_name()`, and `is_named()` manage and inspect the optional name.
- Relational operators compare the stored values, not the names.

The behavior is direct:

```text
t_value<T>
  ├─ construct / assign ─► store T
  ├─ set_value(value) ───► replace T
  ├─ value() ────────────► return T
  └─ set_name(name) ─────► store optional name
```

### Use in parameterized ASN.1

The helper `asn1_parameter::value<T>(templ, param, name)` adds the formal parameter descriptor to the parameterized type and returns a `t_value<T>` initialized with a default value and the supplied name. The returned wrapper does not represent an unresolved future and does not perform deferred binding by itself.

This helper and the loader's reconstruction of formal parameter definitions are separate from applying actual arguments to instantiate a parameterized type.

## 4. Relationships

- `sdk/io/asn.1/basic/semantic/parameterized/asn1_parameter.hpp` — creates named `t_value<T>` wrappers while registering formal parameter metadata.
- `sdk/io/asn.1/basic/semantic/parameterized/asn1_parameterized_type.hpp` — owns the parameterized type and its formal parameter types.
- `test/testcase/asn.1/parameterized/testcase_parameterized.cpp` — source-level tests for parameterized ASN.1 behavior.

## 5. References

No external references are listed.
