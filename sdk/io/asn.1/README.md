## Publication

```text
┌───────────────────────────────────────────────┐
│ hotplace source tree                          │
│ Edition 1 · Revision 1107                     │
│ Source basis: Revision 1107                   │
│ Documented with GPT-6                         │
│ — source structure, implementation & behavior │
└───────────────────────────────────────────────┘
```

# ASN.1

## 1. Role

`sdk/io/asn.1` implements ASN.1-specific layers on top of the generic parser: notation and semantic models, structural nodes, constraints, module loading, parse-tree reconstruction, and runtime module/type/object operations. The generic parser recognizes grammar and builds a parse tree; it does not assign ASN.1 semantics by itself.

The directory contains layers with different completion boundaries. The compiler directory is a design artifact rather than a completed `asn1c` executable, and grammar coverage should not be confused with complete semantic reconstruction or runtime support.

## 2. Data Model

### Directory map

| Directory | Main responsibility |
|---|---|
| `basic/` | ASN.1 semantic types and objects, structural nodes, tags, constraints, and visitor interfaces |
| `runtime/` | ASN.1 parser adapter, parse-tree publisher, module/type/object runtime, and module registry |
| `loader/` | File/stream entry point connecting source loading to parser stages |
| `advisor/` | Shared ASN.1 provider, including parser/publisher access and ASN.1 dictionaries |
| `compiler/` | Compiler and C++ generation design notes; not a completed compiler implementation |

### Main concepts

- **Syntax:** lexer tokens, grammar symbols, and `parse_tree` belong to `sdk/io/parser`.
- **ASN.1 structure:** structural nodes preserve notation-oriented structure; semantic objects represent ASN.1-specific type/value relationships and constraints.
- **Module model:** `asn1_module` stores module definitions and import/export information; `asn1_modules` is the collection/registry used to find modules.
- **Semantic reconstruction:** `asn1_publisher` walks the generic parse tree and builds ASN.1 objects and module information.
- **Encoding representation:** BER/DER-oriented structural/TLV representation is distinct from notation parsing and module reconstruction.

## 3. Behavior Model

### Follow one implementation path

```text
ASN.1 source file / notation
        |
        v
asn1_loader -- source acquisition
        |
        v
asn1_parser
   +-- to_tokens() -----------> parser_token[]
   +-- to_parsetree() --------> parse_tree
                                      |
                                      v
                              asn1_publisher::build()
                                      |
                       +--------------+--------------+
                       v              v              v
                 module rules   type/reference   constraints
                 IMPORTS/EXPORTS assignments     semantic nodes
                       +--------------+--------------+
                                      v
                                  asn1_module
                                      |
                                      v
                             asn1_modules registry
                                      |
                                      v
                         lookup / reference resolution /
                         runtime representation and value paths
```

The stages are independently callable. The loader can expose tokens or a parse tree before publishing; the parser adapter can stop after syntax construction; and the publisher consumes a parse tree to reconstruct semantic/runtime objects. This separation helps locate failures in lexical recognition, grammar parsing, semantic reconstruction, or module resolution.

### Evidence boundaries

Test sources cover distinct but related behaviors: parser handling of assignments and constraints; publisher reconstruction from parse trees; file loading; imported/exported symbol relationships; and focused semantic-object linkage. A grammar test does not prove the corresponding notation becomes a fully linked runtime type. Direct semantic-object tests do not prove end-to-end parsing and parameter substitution.

Parameterized ASN.1 is a particular boundary: grammar productions and direct semantic prototypes exist, but they should not be described as a complete parser-to-runtime template-instantiation pipeline without enabled end-to-end tests and implementation evidence.

## 4. Relationships
### Follow the source and tests

- [ASN.1 Basic](basic/README.md) — semantic/structural models and retained X.680 study notes.
- [ASN.1 Runtime](runtime/README.md) — module model and parser-to-publisher flow.
- [ASN.1 parser adapter](runtime/asn1_parser.md) — tokenization, parse-tree construction, and semantic hand-off.
- [ASN.1 publisher](runtime/asn1_publisher.md) — shift/reduce visitor and semantic reconstruction.
- [ASN.1 module](runtime/asn1_module.md) — module definitions, imported symbols, lookup, and reference resolution.
- [ASN.1 loader developer notes](loader/asn1_loader.md) — file acquisition and staged loading.
- [ASN.1 compiler developer notes](compiler/asn1-compiler.md) — intended generation architecture and design-only status.
- [Object model](basic/asn1-object-model.md), [structural node model](basic/asn1-node.md), [visitor architecture](basic/asn1-visitor.md), and [constraint evaluator](basic/semantic/constraints/asn1_constraints.md).
- `test/testcase/asn.1/runtime/` — parser and staged publisher cases.
- `test/testcase/asn.1/loader/testcase_loader.cpp` — integrated file → parse tree → publish → module-resolution path.

## 5. References
- ITU-T X.680–X.693 — ASN.1 notation and encoding rules.
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) — Internet X.509 PKI Certificate and CRL Profile.
- [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652) — Cryptographic Message Syntax (CMS).
- [RFC 5912](https://www.rfc-editor.org/rfc/rfc5912) — ASN.1 Modules for PKIX.
- [RFC 2986](https://www.rfc-editor.org/rfc/rfc2986) — PKCS #10.
- Olivier Dubuisson, *ASN.1 — Communication between Heterogeneous Systems*.
- Burton S. Kaliski, *A Layman's Guide to a Subset of ASN.1, BER, and DER*.
- John Larmouth, *ASN.1 Complete*.
