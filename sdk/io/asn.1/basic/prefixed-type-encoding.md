## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source base : Revision 1132                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Prefixed Type Encoding

## 1. Role

This note connects ASN.1 tagged-type notation with the identifier and length octets emitted by the DER encoder. It focuses on the distinction between `IMPLICIT` tagging, which replaces the inner type's tag, and `EXPLICIT` tagging, which wraps the inner encoding in another tagged TLV.

## 2. Data Model

An ASN.1 tag combines a tag class, a primitive/constructed bit, and a tag number. The identifier uses a single octet for tag numbers below 31; larger tag numbers use the high-tag-number form, with base-128 groups and a continuation bit. The tag is followed by a length and the encoded content.

`asn1_tagged_type` stores an `asn1_tag` and the semantic object being tagged. The tag mode may be `IMPLICIT`, `EXPLICIT`, or `AUTOMATIC`; `AUTOMATIC` is resolved through the containing module's tag default, and `asn1_tag::is_implicit(nullptr)` falls back to `EXPLICIT`. 

```text
tagged type
    |
    +-- tag class + tag number + IMPLICIT/EXPLICIT mode
    |
    +-- inner ASN.1 object
             |
             v
         DER content
```

## 3. Behavior Model



- For `IMPLICIT` tagging, `asn1_tagged_type::update_linkage()` suppresses the inner object's tag so the outer tag replaces it.
- For `EXPLICIT` tagging, the inner tag remains, producing a wrapper around the inner TLV.
- The encoder delegates identifier encoding to `asn1_tag` / `asn1_encode`, represents the inner object, and writes the outer length unless the tag is suppressed as part of the enclosing representation.
- `asn1_der_visitor` performs `update_linkage()` before representation and requires a non-null module to resolve `AUTOMATIC` mode and references. The module-aware `module.publish(name, &bin_der)` path in the example supplies it; the direct object/value binary-publish wrappers pass null and are unsafe in the current implementation.
- Constructed-bit propagation depends on the tagged object's nested structure and explicit wrappers; the constructed bit is not simply synonymous with the existence of an ASN.1 tag.

The source tests cover low- and high-tag-number identifier forms (including 31, 32, 127, 128, 16383 and 16384) and reject selected truncated/non-terminated high-tag sequences. This is focused coverage, not exhaustive DER canonicality or overflow validation: `read_identifier()` does not check `uint64` tag-number overflow or every non-minimal high-tag form. `read_length()` accepts definite short/long forms and rejects the indefinite marker; the separate `indef()` / `end_contents()` helpers only provide write-side indefinite framing. The [tagging examples in the structural document](structural/README.md#developer-notes) are static DER/TLV-tree/weakly-typed-AST illustrations. The strongly typed IMPLICIT/EXPLICIT decode-and-re-encode assertions are in `testcase_basic3.cpp` and use the module-aware `module.publish()` path.

### Real-code example: compare IMPLICIT replacement with EXPLICIT wrapping

`test/testcase/asn.1/testcase_basic3.cpp` constructs tagged types, publishes them through an `asn1_module`, and compares the re-encoded DER with the original bytes. The important caller-level distinction is visible in the schema declarations:

```cpp
auto type2 = asn1_referenced_type::define(
    "Type2", new asn1_tagged_type(asn1_class_application, 3, asn1_implicit,
                                   asn1_referenced_type::refer("Type1")));
auto type3 = asn1_referenced_type::define(
    "Type3", new asn1_tagged_type(asn1_class_context, 2, asn1_explicit,
                                   asn1_referenced_type::refer("Type2")));
```

The caller chooses the tagging mode when defining the semantic type. Later `module.publish(name, &bin_der)` exercises the encoding path; round-trip comparison checks the resulting representation. This is more informative than testing tag-number encoding alone because it shows how the mode enters the object model and reaches DER output.

## 4. Relationships
- [Structural representation and tagging examples](structural/README.md) — concrete DER and object-tree examples.
- [ASN.1 object model](asn1-object-model.md) — semantic objects and their representation visitors.
- `sdk/io/asn.1/basic/semantic/asn1_tagged_type.hpp/.cpp` — tag replacement, wrapper behavior, and linkage propagation.
- `sdk/io/asn.1/basic/asn1_encode.hpp` — identifier and length encoding.
- `test/testcase/asn.1/testcase_basic1.cpp` — X.690 identifier, length, and tagged-type encoding cases.

## 5. References
- ITU-T X.690, especially clauses 8.1–8.14, for BER/DER identifier, length, and tagged-type encoding rules.
