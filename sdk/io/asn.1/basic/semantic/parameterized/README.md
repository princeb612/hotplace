## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Parameterized ASN.1 Semantic Prototype

## 1. Role

The module identity is described by the implementation notes retained below.

## 2. Model

### Main types

- `asn1_parameterized_type` — stores parameter descriptors and values, defines a parameterized object, and creates a specialized copy through `specialize()`.
- `asn1_paramtype` / `asn1_paramvalue` — describe parameter declarations and actual values.
- `asn1_parameter` — represents a parameter reference inside a semantic object and provides `value<T>()` to create a deferred `t_value<T>` associated with a named parameter.

A typical direct semantic prototype follows this pattern:

```text
asn1_parameterized_type::define()
          |
          +-- build a semantic ASN.1 object
          |      |
          |      `-- asn1_parameter::value<T>() for a deferred parameter value
          |
          v
      specialize(name, actual values)
          |
          v
  specialized semantic object
```

`define()` accepts either an explicit parameter/type list and object, or a callback that builds the object with access to the template descriptor. `specialize()` clones the underlying semantic object and associates actual parameter values with the specialization.

### Revision 1104 implementation boundary

The direct semantic testcase includes examples such as `FRAME`, `TLV-BUFFER`, `COMMAND-ENVELOPE`, and parameterized values used in constraints/defaults. The active `test_parameterized1()` path exercises these object-model prototypes.

This does **not** establish complete end-to-end parameterized ASN.1 support. The parser/loader/publisher probe in `test_parameterized2()` remains disabled from the testcase entry point, and `asn1_publisher::prepare_parameterized()` handlers are still an early semantic reconstruction step. Parameter binding, substitution, notation reconstruction, and robust instantiated-type behavior should be documented as incomplete until the integrated path is enabled and verified.

### Related implementation

- `asn1_parameterized_type.hpp/.cpp`
- `asn1_parameter.cpp`
- `asn1_paramtype.cpp`
- `asn1_paramvalue.cpp`
- `sdk/io/asn.1/runtime/asn1_publisher_parameterized.cpp`

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

### Related tests

- `test/testcase/asn.1/parameterized/testcase_parameterized.cpp`

## 5. Relationships

Related modules and boundaries are recorded below where identified in the existing notes.

## 6. References

Source references and related documents are retained below where available.
