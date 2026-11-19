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


# ASN.1 Structural Representation

## 1. Role

This note explains the distinction between a structural view of encoded ASN.1 data and a strongly typed semantic view. It complements the concrete DER/TLV examples in [Development Notes](#developer-notes) rather than duplicating those examples.

## 2. Data Model

The weakly typed path starts from encoded TLV bytes. `asn1_bytestream::read()` first builds a generic `t_tree<asn1_tlv_t>` containing identifier/tag, TLV offset, value offset and content length. The schema-less `asn1_weakly_typed` path then creates `asn1_primitive_node` / `asn1_constructed_node` structural nodes and infers weakly typed semantic objects from the encoded tags. These structural representations preserve tag class, tag number, primitive/constructed bit, length and nested TLV relationships without requiring schema-level names or declared types. The separate `asn1_strongly_typed` path also uses the bytestream TLV tree, but traverses a supplied schema and fills an `asn1_value`; it does not pass through the `asn1_node` tree.

The strongly typed path starts from an ASN.1 schema and represents declared types, references, tag modes, named fields, and semantic values. That schema provides meaning that cannot always be inferred from the bytes alone.

## 3. Behavior Model

### Structural decoding and schema interpretation

```text
                         DER bytes
                            |
                            v
                    asn1_bytestream
                            |
                            | t_tree<asn1_tlv_t>
                 +----------+-----------+
                 |                      |
                 v                      v
       asn1_weakly_typed       asn1_strongly_typed
          (schema-less)          + ASN.1 schema
                 |                      |
                 v                      v
         asn1_node tree             asn1_value
                 |                      |
                 v                      v
       inferred semantic objects   schema-bound values
```



The two views answer different questions:

- The structural tree describes what is encoded: identifier octets, lengths, primitive values, and constructed children.
- The semantic model describes what the data means under a schema: named types, constructed components, referenced types, and explicit/implicit tagging.
- `IMPLICIT` tagging replaces the inner type's identifier, while `EXPLICIT` tagging wraps the complete inner TLV. The byte-level examples are collected in [Development Notes](#developer-notes).

The current `asn1_bytestream` path is definite-length oriented: `asn1_encode::read_length()` rejects the indefinite-length marker. It checks TLV child boundaries and uses the identifier/length readers, but it is not a complete DER conformance validator for primitive contents, schema constraints, references, or named component semantics. Do not treat a structural parse as proof that those checks have been performed.

## 4. Relationships
- [ASN.1 node model](../asn1-node.md) — structural nodes and their ownership/traversal contract.
- [ASN.1 object model](../asn1-object-model.md) — strongly typed semantic objects.
- [tagging examples in Development Notes](#developer-notes) — DER bytes, TLV trees, and tagged semantic forms.
- `sdk/io/asn.1/basic/semantic/` — type and value hierarchy.
- `test/testcase/asn.1/testvector_der.cpp` — weakly typed DER read, notation/value publication, and full-input-consumption checks; it logs re-encoded bytes but does not assert byte-for-byte equality.
- `test/testcase/asn.1/testcase_basic3.cpp` — module-aware strongly typed IMPLICIT/EXPLICIT tag decoding and DER re-encoding comparisons. There are no direct tests of the structural node API.

## 5. References
- ITU-T X.690 — BER/DER encoding rules for TLV structure and tagged encodings.

## 6. Developer Notes
The following byte-level examples are retained here because they illustrate the distinction described above without requiring a separate reference page. They are examples of particular encodings, not a coverage claim. The `weakly-typed TLV tree` is the bytestream's offset/length tree; the `weakly-typed AST` is a later semantic projection and is not the same object as `asn1_node`.

### DER/TLV examples retained from the tagging study

### Type2 ::= [APPLICATION 5] IMPLICIT Type1

- DER
  - 65 0A 1A 05 4A 6F 6E 65 73 01 01 FF
- weakly-typed TLV tree
  - [x] TL 65 0A
  - node 1 I 0x60 (APPLICATION+CONSTRUCTED) T 5 ([APPLICATION 5]) L 10
    - [x] TL 1A 05 V 4A 6F 6E 65 73
    - node 2 I 0x00 (UNIVERSAL) T 26 (VisibleString) L 5
    - [x] TL 01 01 V FF
    - node 3 I 0x00 (UNIVERSAL) T 1 (BOOLEAN) L 1
- weakly-typed AST
  - NODE1 tagged type
    - tag type
      - [APPLICATION 5] IMPLICIT
    - SEQUENCE
      - NODE2 VisibleString
      - NODE3 BOOLEAN

### Type4 ::= [3] EXPLICIT Type3

- DER
  - A3 0B A2 09 A1 07 1A 05 4A 6F 6E 65 73
- weakly-typed TLV tree
  - [x] TL A3 0B
  - node 1 I 0xA0 (CONTEXT+CONSTRUCTED) T 3 ([3]) L 11
    - [x] TL A2 09
    - node 2 I 0xA0 (CONTEXT+CONSTRUCTED) T 2 ([2]) L 9
      - [x] TL A1 07
      - node 3 I 0xA0 (CONTEXT+CONSTRUCTED) T 1 ([1]) L 7
        - [x] TL 1A 05 V 4A 6F 6E 65 73
        - node 4 I 0x00 (UNIVERSAL) T 26 (VisibleString) L 5
- weakly-typed AST
  - NODE1 tagged type
    - tag type
      - [3] EXPLICIT
    - NODE2 tagged type
      - tag type
        - [2] EXPLICIT
      - NODE3 tagged type
        - tag type
          - [1] EXPLICIT
        - NODE4 VisibleString

### Type1 ::= [APPLICATION 128] IMPLICIT INTEGER

- DER
  - 5f 81 00 01 00
- weakly-typed TLV tree
  - [x] TL 5F 81 00 01 V 00
  - node 1 I 0x40 (APPLICATION) T 128 ([APPLICATION 128]) L 1
- weakly-typed AST
  - NODE1 tagged type
    - tag type
      - [APPLICATION 128]
    - ANY
