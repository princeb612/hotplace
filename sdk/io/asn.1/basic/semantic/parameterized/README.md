## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1132                    │
│ Source base : Revision 1132                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Parameterized ASN.1 Semantic Prototype

## 1. Role

`basic/semantic/parameterized` contains a direct semantic prototype for parameterized ASN.1 types, parameter declarations/values and specialization. It should be read as a bounded implementation area, not as a claim that the full parser → loader → publisher path supports all parameterized notation.

## 2. Data Model

### Main types

- `asn1_parameterized_type` — stores parameter descriptors and values, defines a parameterized object, and creates a specialized copy through `specialize()`.
- `asn1_paramtype` / `asn1_paramvalue` — describe parameter declarations and actual values.
- `asn1_parameter` — represents a parameter reference inside a semantic object and provides `value<T>()` to register formal-parameter metadata and return an immediately initialized, named `t_value<T>` value holder.

## 3. Behavior Model

### Current implementation boundary

The direct semantic testcase includes examples such as `FRAME`, `TLV-BUFFER`, `COMMAND-ENVELOPE`, and parameterized values used in constraints/defaults. The active `test_parameterized1()` path exercises these object-model prototypes. The same testcase group also actively runs `test_parameterized2()` and `test_parameterized3()`, which exercise bounded parser/loader/publisher reconstruction paths.

The active `test_parameterized2()` path loads an inline `FRAME` template/instantiation through `asn1_loader::load()` and publishes the resulting parse tree; it asserts the reconstructed module notation. `test_parameterized3()` loads `example6.asn1` through `asn1_loader::load_file()`, publishes it, and asserts the module kind, module name, and reconstructed representation for `Envelope {INTEGER}`. These are real parser/loader/publisher integration tests, but their scope is deliberately narrow: `example7.asn1` remains commented out, and the tests do not establish complete parameterized ASN.1 support, all formal/actual parameter combinations, nested instantiation, or exhaustive binding/substitution behavior.


### Define and specialize a prototype

A typical direct semantic prototype follows this pattern:

```text
asn1_parameterized_type::define()
          |
          +-- build a semantic ASN.1 object
          |      |
          |      `-- asn1_parameter::value<T>() registers a named formal parameter
          |
          v
      specialize(name, actual values)
          |
          v
  specialized semantic object
```

`define()` accepts either an explicit parameter/type list and object, or a callback that builds the object with access to the template descriptor. `specialize()` clones the underlying semantic object and associates actual parameter values with the specialization.


`define()` establishes the reusable semantic prototype; `specialize()` clones that prototype and associates actual parameter values. The `t_value<T>` returned by `asn1_parameter::value<T>()` is not deferred and does not perform substitution: it stores a default-initialized value and the parameter name. Revision 1122 removed the former future/promise behavior from `t_value<T>`. The active parser/loader/publisher cases establish the specific reconstruction and module-representation behavior described above. They do not prove exhaustive parameterized notation coverage or every runtime use of specialized types.

## 4. Relationships

- [Semantic ASN.1 model](../README.md) — shared semantic object hierarchy.
- [ASN.1 publisher](../../../runtime/asn1_publisher.md) — parser-tree reconstruction handlers and current integration boundary.
- `asn1_parameterized_type.hpp/.cpp`
- `asn1_parameter.cpp`, `asn1_paramtype.cpp`, `asn1_paramvalue.cpp`
- `sdk/io/asn.1/runtime/asn1_publisher_parameterized.cpp`
- `test/testcase/asn.1/parameterized/testcase_parameterized.cpp`
