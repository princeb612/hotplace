# ASN.1

## Publication

```text
hotplace source-tree documentation
Edition 1 · Revision 1097
Documented with GPT-5.6 Luna
— source identity, implementation detail & relationships
```

ASN.1 support in hotplace covers notation, parsing, basic type/constraint representation, structural nodes, runtime representation, loading, and compiler-oriented processing.

## Directory map

- `basic/` — ASN.1 notation, types, tagging, constraints, and structural representation
- `compiler/` — compiler-oriented ASN.1 processing and generation flow
- `loader/` — loading and interpretation flow
- `runtime/` — runtime object/type representation and examples
- `resource/` — parser configuration/resource sources used by the ASN.1 parser setup

The loader currently represents the first implemented step of the ASN.1 file-to-parse-tree path; publishing the resulting tree into runtime objects is exercised separately.

## Detailed documents

- [ITU-T X.680 notation](basic/itu-t_x680.md)
- [Prefixed type encoding](basic/prefixed-type-encoding.md)
- [Subtype notation and value sets](basic/semantic/constraints/subtype-notation.md)
- [Structural representation](basic/structural/structural.md)
- [Compiler flow](compiler/compiler-flow.md)
- [Loader flow](loader/loader-flow.md)
- [Runtime examples](runtime/runtime-examples.md)

## Implementation records

- [ASN.1 object model](basic/asn1-object-model.md)
- [ASN.1 structural node model](basic/asn1-node.md)
- [ASN.1 visitor architecture](basic/asn1-visitor.md)
- [ASN.1 constraints](basic/semantic/constraints/asn1_constraints.md)
- [ASN.1 runtime](runtime/asn1_runtime.md)
- [ASN.1 loader](loader/asn1_loader.md)
- [ASN.1 compiler direction](compiler/asn1-compiler.md)

## Related areas

- `sdk/io/parser/` — grammar parsing and parse-tree construction
- `sdk/io/asn.1/basic/` — ASN.1 semantic and structural model
- `sdk/io/asn.1/runtime/` — runtime schema/type/object representation
- `sdk/crypto/` — ASN.1-derived cryptographic formats used by the project

## Related tests

- `test/testcase/asn.1/`
- `test/testcase/asn.1/runtime/`
- `test/testcase/io/parser/`

## References

- ITU-T X.680–X.693 — ASN.1 notation and encoding rules
- RFC 5280 — Internet X.509 PKI Certificate and CRL Profile
- RFC 5652 — Cryptographic Message Syntax (CMS)
- RFC 5912 — ASN.1 Modules for PKIX
- RFC 2986 — PKCS #10
- Olivier Dubuisson, *ASN.1 — Communication between Heterogeneous Systems*
- Burton S. Kaliski, *A Layman's Guide to a Subset of ASN.1, BER, and DER*
- John Larmouth, *ASN.1 Complete*

The original study/reference material is retained in the detailed documents rather than being discarded during the README restructuring.
