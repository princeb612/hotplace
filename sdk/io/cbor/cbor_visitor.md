# CBOR Visitors

## Role

The visitor layer provides alternate representations of an already parsed `cbor_object` tree.

```text
             cbor_object tree
                    │
              cbor_visitor
              /           \
             /             \
            ▼               ▼
 concise visitor      diagnostic visitor
     │                       │
     ▼                       ▼
 encoded CBOR            readable form
```

This avoids coupling the object model to one output representation.

## Base visitor

`cbor_visitor` defines the traversal interface.

Concrete visitors receive `cbor_object` instances and produce their respective output.

## Concise representation

`cbor_concise_visitor` produces the compact CBOR binary representation.

It is useful when an object tree already exists and the caller wants the encoded data without directly managing `cbor_encode`.

## Diagnostic representation

`cbor_diagnostic_visitor` produces a human-readable diagnostic representation through `stream_t`.

This is useful for debugging and for comparing the object tree with the notation used by RFC CBOR examples.

## Why this is separate from encoding

The project keeps three concerns distinct:

```text
cbor_object
    │
    ├── semantic/object structure
    │
    ├── cbor_encode / concise visitor
    │       └── binary representation
    │
    └── diagnostic visitor
            └── human-readable representation
```

That separation is particularly useful when checking a test vector:

```text
encoded CBOR
    ↓
reader
    ↓
object tree
    ↓
diagnostic representation
```

and then:

```text
object tree
    ↓
encoder / concise visitor
    ↓
encoded CBOR
```

## Related source

- `cbor_visitor.*`
- `cbor_object.*`
- `cbor_encode.*`
- `cbor_publisher.*`

## Related tests

- `test/testcase/cbor/testcase_rfc7049.cpp`
- `test/testcase/cbor/testvector_cbor.cpp`
- `test/testcase/cbor/sample.cpp`

## Related reference

- `rfc8949-examples.md` — retained RFC 8949 Appendix A encoded examples
