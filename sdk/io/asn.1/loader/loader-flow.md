# Developer Notes — ASN.1 Loader Flow Sketch - Gemini

> based on Revision 1085

### 1. overview & architecture

`asn1_loader` is a dynamic runtime interpreter that dynamically links ASN.1 notation (schema) files with DER codec binaries, enabling the analysis, parsing, and validation of data structures at runtime without the need for separate C++ code generation or recompilation.

- Schema-Guided Parsing: Dynamically maps the Tag, Length, and Value components of a DER byte stream to semantic field nodes based on schema definitions.
- Symbol Reference Resolution: Automatically resolves symbol references—such as `COMPONENTS OF`, `CHOICE`, Type References, and OIDs—using a runtime symbol table.
- Zero Code-Gen: Constructs a runtime Semantic Object Tree using only the schema and binary data, eliminating the need for static C++ struct definitions.
- Constraint : Evaluates the runtime validity of schema constraints, such as `SIZE`, `RANGE`, and `SINGLE-VALUE`.

### 2. pipeline flow

The Loader's data processing flow is divided into the Schema Build Phase and the Evaluation & Decoding Phase.

```
Plaintext
[ASN.1 Schema (.asn1)]
       │
       ▼
(1. asn1_parser) ────────► [Semantic AST / Symbol Table]
                                   │
                                   ├─────────────────────────────┐
                                   ▼                             ▼
[DER Binary (.crt/.der)] ─► (2. asn1_builder) ──► (3. Symbol Resolver & Constraints)
                                                                 │
                                                                 ▼
                                                  [Semantic Object Tree Node]
                                                                 │
                                                       (asn1_visitor)
                                                                 │
                                                                 ▼
                                                    [Tree Dump / Data Access]
```

- 1. Schema Build Phase
  - asn1_parser: Parses the .asn1 schema text to generate a Semantic Object AST.
  - asn1_module_context: Performs symbol binding and reference resolution for parsed Type, Value, OID, and Constraint information.
- 2. Evaluation & Decoding Phase
  - asn1_builder: Interprets the DER byte stream (asn1_bytestream) based on the target type schema information to generate a node tree.
  - asn1_constraint_evaluator: Verifies whether the generated nodes satisfy the schema specification constraints.
  - asn1_visitor: Outputs the parsed tree via an OpenSSL-style text dump (asn1_notation_visitor) or DER binary re-serialization (asn1_der_visitor).

### 3. abstraction

| Category | Key Files / Classes | Role and Mechanism |
| -- | -- | -- |
| Parser | asn1_parser, asn1_parser_grammar | Parses Notation text to generate AST nodes (asn1_object) |
| Runtime Context | asn1_module_context, asn1_publisher | Manages symbol table; performs Type Reference lookup and resolution |
| Data Builder | asn1_builder, asn1_bytestream | Reads DER stream based on target schema types and binds data to nodes |
| Constraint | asn1_constraint_evaluator | Validates constraints (e.g., Range, Size, Union) at runtime |
| Visitor Pipeline | asn1_notation_visitor, asn1_der_visitor | Performs text dumping and DER serialization of the parsed tree |

### 4. sketch

```
[Input Phase]                          [Core Pipeline & Processing]                        [Output / Query Phase]

┌──────────────┐                       ┌─────────────────────────────────────┐
│ ASN.1 Schema │ ────────────────────> │ 1. Load & Parse Schema              │
│ (.asn1)      │                       │    (asn1_parser)                    │
└──────────────┘                       └─────────────────────────────────────┘
                                                          │
                                                          ▼
                                       ┌─────────────────────────────────────┐
                                       │ 2. Build Symbol Repository          │
                                       │    (asn1_module_context)            │
                                       └─────────────────────────────────────┘
                                                          │
                                                          ▼
┌──────────────┐ Entry Point           ┌─────────────────────────────────────┐
│ DER Binary   │ ────────────────────> │ 3. Schema-Guided Decoding           │
│ (.crt / .der)│ (e.g. TBSCertificate) │    (asn1_builder)                   │
└──────────────┘                       └─────────────────────────────────────┘
                                                          │
                                                          ▼
                                       ┌─────────────────────────────────────┐             ┌──────────────────────────┐
                                       │ 4. Dynamic Node Tree Generation     │ ──────────> │ Dynamic Query Access     │
                                       │    (asn1_object / SEQUENCE)         │             │ e.g. (*node)["serial"]   │
                                       └─────────────────────────────────────┘             └──────────────────────────┘
                                                          │
                                                          ▼
                                       ┌─────────────────────────────────────┐             ┌──────────────────────────┐
                                       │ 5. Evaluate Schema Constraints      │ ──────────> │ Validation Pass / Fail   │
                                       │    (asn1_constraint_evaluator)      │             │ SIZE, RANGE, UNION check │
                                       └─────────────────────────────────────┘             └──────────────────────────┘
                                                          │
                                                          ▼
                                       ┌─────────────────────────────────────┐             ┌───────────────────────────┐
                                       │ 6. Visit & Dump Output              │ ──────────> │ OpenSSL Style Tree Dump   │
                                       │    (asn1_notation_visitor)          │             │ Pretty-printed Text Output│
                                       └─────────────────────────────────────┘             └───────────────────────────┘
```


Parsed Output (Tree Dump Example)
```
Plaintext
TBSCertificate ::= SEQUENCE {
    version [0] EXPLICIT INTEGER ::= 2 (v3)
    serialNumber CertificateSerialNumber ::= 0x14A2B9...
    signature AlgorithmIdentifier ::= {
        algorithm OBJECT IDENTIFIER ::= 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
    }
    issuer Name ::= CHOICE {
        rdnSequence RDNSequence ::= { ... }
    }
    validity Validity ::= {
        notBefore Time ::= UTCTime "260101000000Z"
        notAfter Time ::= UTCTime "280101000000Z"
    }
    subject Name ::= { ... }
}
```

### 5. Development Roadmap & Reference Standards

- 1. X.509 PKI Integration (Phase 1)
  - RFC 5280: X.509 v3 certificate and CRL profile schema binding.
  - RFC 5912: Schema loading and reference resolution verification based on PKIX modules updated to 1998/2008 ASN.1 notation.
  - OpenSSL Interoperability: Cross-verification between OpenSSL-issued X.509 binaries and parsing dump results.
- 2. Compiler Engine Linkage (Phase 2)
  - Integration with the asn1_compiler layer, which accepts the asn1_module_context AST tree (constructed by asn1_loader) and generates static C++11 structs and TLV codec source code.
