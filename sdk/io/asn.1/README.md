## Publication

```text
┌───────────────────────────────────────────────┐
│ hotplace source tree                          │
│ Edition 1 · Revision 1105                     │
│ Source basis: Revision 1105                   │
│ Documented with GPT-6                         │
│ — source structure, implementation & behavior │
└───────────────────────────────────────────────┘
```
# ASN.1

## 1. Role

`sdk/io/asn.1` implements the project's ASN.1 notation, semantic and structural models, loading/compiler direction, and runtime parsing/encoding support. It builds on `sdk/io/parser` but adds ASN.1-specific type, tagging, constraint, module and object semantics; the generic parser does not itself define ASN.1 meaning.

## 2. Data Model

### Directory map

- `basic/` — ASN.1 notation, types, tagging, constraints, structural representation, and parameterized semantic prototypes
- `compiler/` — compiler-oriented ASN.1 processing and generation flow
- `loader/` — loading and interpretation flow
- `runtime/` — `asn1_module` representation, the `asn1_modules` registry, parser/publisher flow, and examples
- `advisor/` — ASN.1 entity/class/mode dictionaries and shared parser/publisher providers

The loader currently represents the first implemented step of the ASN.1 file-to-parse-tree path; publishing the resulting tree into runtime objects is exercised separately.

## 3. Behavior Model

The major boundary is notation/grammar → parse structure → ASN.1 semantic/structural model → loaded module/runtime objects → ASN.1 encoding/decoding. These stages are related but should not be described as one automatically complete compiler pipeline: the loader is the first implemented step in the file-to-parse-tree path, while publishing a tree into runtime objects is exercised separately.

Current runtime names include `asn1_module` and the `asn1_modules` registry; older names such as `asn1_module_context` belong to earlier implementation history. Check `CHANGELOG` before describing naming/evolution.

### Processing stages and evidence boundaries

The test sources exercise separate stages rather than one complete, automatically connected pipeline: notation parsing through LALR/GLR with runtime-built or imported tables; ASN.1 runtime parsing of assignments and constraints; parse-tree-to-semantic publishing; file loading and imported-symbol resolution; and focused object-model linkage. A parser assertion does not establish semantic linkage, and a publisher test does not prove support for every notation feature.

## 4. Relationships

### Related areas

- `sdk/io/parser/` — grammar parsing and parse-tree construction
- `sdk/io/asn.1/basic/` — ASN.1 semantic and structural model
- `sdk/io/asn.1/runtime/` — module schema/type/object representation
- `sdk/crypto/` — ASN.1-derived cryptographic formats used by the project
- The detailed documents below retain the notation notes, implementation records, and study material that would otherwise overwhelm this directory overview.

### Component documents and implementation records

These focused pages preserve implementation detail that would make the directory model difficult to scan in one pass.

- [ASN.1 Basic developer notes](basic/README.md) — includes the retained X.680 notation study
- [Prefixed type encoding](basic/prefixed-type-encoding.md)
- [Subtype notation and value sets](basic/semantic/constraints/subtype-notation.md)
- [Structural representation](basic/structural/README.md) — includes the retained DER/TLV tagging examples
- [Compiler developer notes](compiler/README.md)
- [Loader developer notes](loader/README.md)
- [ASN.1 Runtime](runtime/README.md) — includes runtime examples in Development Notes
- [ASN.1 object model](basic/asn1-object-model.md)
- [ASN.1 structural node model](basic/asn1-node.md)
- [ASN.1 visitor architecture](basic/asn1-visitor.md)
- [ASN.1 constraints](basic/semantic/constraints/asn1_constraints.md)
- [ASN.1 module](runtime/asn1_module.md)
- [ASN.1 parser](runtime/asn1_parser.md)
- [ASN.1 publisher](runtime/asn1_publisher.md)
- [ASN.1 loader](loader/README.md)
- [ASN.1 compiler direction](compiler/README.md)

## 5. References

- ITU-T X.680–X.693 — ASN.1 notation and encoding rules
- RFC 5280 — Internet X.509 PKI Certificate and CRL Profile
- RFC 5652 — Cryptographic Message Syntax (CMS)
- RFC 5912 — ASN.1 Modules for PKIX
- RFC 2986 — PKCS #10
- Olivier Dubuisson, *ASN.1 — Communication between Heterogeneous Systems*
- Burton S. Kaliski, *A Layman's Guide to a Subset of ASN.1, BER, and DER*
- John Larmouth, *ASN.1 Complete*

