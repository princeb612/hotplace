## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# ASN.1

## 1. Role

The module identity is described by the implementation notes retained below.

## 2. Model

### Directory map

- `basic/` — ASN.1 notation, types, tagging, constraints, structural representation, and parameterized semantic prototypes
- `compiler/` — compiler-oriented ASN.1 processing and generation flow
- `loader/` — loading and interpretation flow
- `runtime/` — `asn1_module` representation, the `asn1_modules` registry, parser/publisher flow, and examples
- `advisor/` — ASN.1 entity/class/mode dictionaries and shared parser/publisher providers

The loader currently represents the first implemented step of the ASN.1 file-to-parse-tree path; publishing the resulting tree into runtime objects is exercised separately.

### Detailed documents

- [ITU-T X.680 notation](basic/itu-t_x680.md)
- [Prefixed type encoding](basic/prefixed-type-encoding.md)
- [Subtype notation and value sets](basic/semantic/constraints/subtype-notation.md)
- [Structural representation](basic/structural/structural.md)
- [Compiler flow](compiler/compiler-flow.md)
- [Loader flow](loader/loader-flow.md)
- [Runtime examples](runtime/runtime-examples.md)

### Implementation records

- [ASN.1 object model](basic/asn1-object-model.md)
- [ASN.1 structural node model](basic/asn1-node.md)
- [ASN.1 visitor architecture](basic/asn1-visitor.md)
- [ASN.1 constraints](basic/semantic/constraints/asn1_constraints.md)
- [ASN.1 module](runtime/asn1_module.md)
- [ASN.1 parser](runtime/asn1_parser.md)
- [ASN.1 publisher](runtime/asn1_publisher.md)
- [ASN.1 loader](loader/asn1_loader.md)
- [ASN.1 compiler direction](compiler/asn1-compiler.md)

## 3. Important behavior and lifetime

No separate lifetime or behavior contract was stated in the existing notes beyond the material retained below.

## 4. Example from the source tests

### Related tests

- `test/testcase/asn.1/`
- `test/testcase/asn.1/runtime/`
- `test/testcase/io/parser/`

## 5. Relationships

### Related areas

- `sdk/io/parser/` — grammar parsing and parse-tree construction
- `sdk/io/asn.1/basic/` — ASN.1 semantic and structural model
- `sdk/io/asn.1/runtime/` — module schema/type/object representation
- `sdk/crypto/` — ASN.1-derived cryptographic formats used by the project

## 6. References

### References

- ITU-T X.680–X.693 — ASN.1 notation and encoding rules
- RFC 5280 — Internet X.509 PKI Certificate and CRL Profile
- RFC 5652 — Cryptographic Message Syntax (CMS)
- RFC 5912 — ASN.1 Modules for PKIX
- RFC 2986 — PKCS #10
- Olivier Dubuisson, *ASN.1 — Communication between Heterogeneous Systems*
- Burton S. Kaliski, *A Layman's Guide to a Subset of ASN.1, BER, and DER*
- John Larmouth, *ASN.1 Complete*

The original study/reference material is retained in the detailed documents rather than being discarded during the README restructuring.
