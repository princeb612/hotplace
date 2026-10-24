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

# CBOR Visitors

## 1. Role

Describes visitor-based representations of CBOR objects, including concise binary output and diagnostic notation.

## 2. Data Model

### Visitor interface

The visitor layer operates on an existing `cbor_object` tree. It does not own a separate CBOR value model.

- `cbor_visitor` defines the visitor boundary.
- `cbor_concise_visitor` retains a caller-provided `binary_t*` output target.
- `cbor_diagnostic_visitor` retains a caller-provided `stream_t*` output target.

Both concrete visitor constructors reject a null output target by throwing an exception. The output objects are supplied by the caller; the visitor stores the pointer rather than constructing an independent output buffer/stream.

### Representation dispatch

```text
cbor_object tree
      │
      ├── cbor_concise_visitor ──► binary_t
      │
      └── cbor_diagnostic_visitor ──► stream_t
```

Each visitor's `visit(cbor_object*)` calls the object's `represent()` method with the selected output target. Concrete object classes determine how their own values and children are represented.

## 3. Behavior Model

### Visitor execution

1. The caller creates an output target and passes its address to the appropriate visitor.
2. The caller dispatches an object through the visitor interface.
3. The visitor forwards the target to `object->represent(...)`.
4. The concrete object's representation implementation writes its value and, where applicable, recursively represents children in the selected form.

```text
caller creates output target
          │
          ▼
construct visitor(target)
          │
          ▼
visit(object)
          │
          ▼
object.represent(target)
          │
          ├── concise visitor ──► CBOR bytes
          └── diagnostic visitor ──► readable diagnostic notation
```

The concise output is a CBOR encoding; diagnostic output is text intended for inspection. They may describe the same logical object, but are not interchangeable wire formats. This visitor interface is distinct from the low-level `cbor_encode` overloads even though both can produce binary output.

### Test interpretation

The RFC-oriented testcase builds values or object trees and uses `cbor_publisher` to obtain both diagnostic and concise output, then compares concise bytes against expected hex. The YAML-vector testcase parses encoded bytes and publishes both forms; it compares bytes first and uses diagnostic text for selected cases where multiple valid floating-point widths represent the same value. These are source-level verification paths; this documentation update did not execute the tests.

## 4. Relationships
### Related source

- `cbor_visitor.*` — visitor interface and concrete output-target adapters.
- `cbor_object.*` — `accept()` and object representation boundary.
- `cbor_encode.*` — direct value/object binary encoding.
- `cbor_publisher.*` — higher-level output facade used by sample/test code.

### Related tests

- `test/testcase/cbor/testcase_rfc7049.cpp`
- `test/testcase/cbor/testvector_cbor.cpp`
- `test/testcase/cbor/sample.cpp`

### Related document

- [CBOR reader and encoder](cbor-reader-encoder.md) — parse and encode paths leading into and out of the object tree.

## 5. References
- [RFC 8949 — CBOR](https://www.rfc-editor.org/rfc/rfc8949), including diagnostic notation and encoded data-item examples.
