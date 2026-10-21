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

# Prefixed Type Encoding

## 1. Role

This note connects ASN.1 tagged-type notation with the identifier and length octets emitted by the DER encoder. It focuses on the distinction between `IMPLICIT` tagging, which replaces the inner type's tag, and `EXPLICIT` tagging, which wraps the inner encoding in another tagged TLV.

## 2. Data Model

An ASN.1 tag combines a tag class, a primitive/constructed bit, and a tag number. The identifier uses a single octet for tag numbers below 31; larger tag numbers use the high-tag-number form, with base-128 groups and a continuation bit. The tag is followed by a length and the encoded content.

`asn1_tagged_type` stores an `asn1_tag` and the semantic object being tagged. Its representation path delegates identifier encoding to `asn1_tag` / `asn1_encode`, then represents the inner object.

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
- The encoder writes the outer identifier, encodes the inner object, and writes the outer length unless the tag is suppressed as part of the enclosing representation.
- Constructed-bit propagation depends on the tagged object's nested structure and explicit wrappers; the constructed bit is not simply synonymous with the existence of an ASN.1 tag.

The source tests cover low- and high-tag-number identifier forms, including malformed high-tag encodings. The examples in [tagging examples in the structural document](structural/README.md#development-notes) compare the resulting DER bytes with weakly typed TLV trees and strongly typed semantic representations.

## 4. Relationships

- [Structural representation and tagging examples](structural/README.md) — concrete DER and object-tree examples.
- [ASN.1 object model](asn1-object-model.md) — semantic objects and their representation visitors.
- `sdk/io/asn.1/basic/semantic/asn1_tagged_type.hpp/.cpp` — tag replacement, wrapper behavior, and linkage propagation.
- `sdk/io/asn.1/basic/asn1_encode.hpp` — identifier and length encoding.
- `test/testcase/asn.1/testcase_basic1.cpp` — X.690 identifier, length, and tagged-type encoding cases.

## 5. References

- ITU-T X.690, especially clauses 8.1–8.14, for BER/DER identifier, length, and tagged-type encoding rules.
