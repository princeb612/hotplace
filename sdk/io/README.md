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

# I/O and Data Representation

## 1. Role

`sdk/io` groups facilities that operate at representation, parsing, and operating-system I/O boundaries. It is a collection of related but distinct subsystems, not one universal serialization framework or a mandatory end-to-end pipeline.

The layer includes:

- binary field-layout descriptions and representation helpers;
- file-backed stream operations and OS-facing I/O facilities;
- tokenization, URL decomposition, and character conversion;
- grammar-based lexical and syntactic parsing;
- CBOR object representation and byte conversion;
- ASN.1 notation, semantic models, loading/compiler paths, and runtime parsing/encoding.

Higher-level modules decide how these facilities are composed for a particular protocol or application. A helper's presence in `sdk/io` does not itself imply protocol-level validation or full conformance to a referenced standard.

## 2. Data Model

### Directory map

```text
sdk/io
├── basic/
│   ├── payload field layout and OID conversion
│   ├── JSON loading and compression wrappers
├── stream/
│   └── file-backed implementation of the common stream interface
├── string/
│   └── tokenization, URL handling, character conversion
├── parser/
│   └── lexical analysis, grammar, parsing tables, LALR/GLR, parse tree
├── cbor/
│   └── CBOR object model, reader, encoder, visitors
├── asn.1/
│   └── notation, semantic/structural models, loader/compiler, runtime
└── system/
    └── sockets, multiplexing, netlink, registry and PE helpers
```

### How the directories divide responsibility

- `basic` contains small representation-boundary utilities. `payload` describes an ordered binary field layout; OID helpers convert between textual notation and integer nodes; JSON and compression components wrap their respective libraries.
- `stream` adapts the common stream interface to files and platform resources. It is distinct from the in-memory streams and formatting facilities in `sdk/base/stream`.
- `string` provides lightweight tokenization, URL parsing/escaping, and platform character conversion. Tokenization is not grammar-aware syntax analysis.
- `parser` separates lexical tokenization, grammar representation, parsing-table generation/import, parser execution, and syntax-tree construction. It does not assign ASN.1 domain semantics to the resulting syntax.
- `cbor` provides a format-specific object model and conversion between CBOR bytes and values/representations. It is separate from the generic grammar parser.
- `asn.1` builds ASN.1-specific notation, type and constraint semantics, module/runtime representation, and parsing/encoding behavior on parser-related infrastructure.
- `system` contains OS-facing facilities whose implementation and lifecycle may depend on the target platform, including socket/event mechanisms and Windows- or Linux-specific helpers.

## 3. Behavior Model

### Similar-looking operations have different contracts

- `payload` describes a known binary field layout and can be used for both writing and reading. It is not a grammar parser.
- `basic/oid` converts between dotted OID text and integer-node sequences. ASN.1 BER/DER OBJECT IDENTIFIER encoding belongs to the ASN.1 encoding path.
- `parser` builds syntax structures from tokens and grammar rules. ASN.1-specific types, references, tags, and constraints are interpreted by the ASN.1 layer.
- `cbor` and `asn.1` are independent format-specific systems. They share lower-level utilities but do not form one common serialization pipeline.
- `sdk/base/stream` provides in-memory stream/buffer facilities; `sdk/io/stream` adapts the common stream contract to external files and platform APIs.

### Lifetime and platform boundaries

Resource ownership must be read at the component boundary rather than inferred from the directory name. File streams may own native handles, mappings, or locks; parsed objects and format-specific trees have their own ownership rules. OS-facing components can expose platform-specific behavior even when a common wrapper is present.

Likewise, a standards reference documents the intended format or behavior but does not prove complete implementation of every feature in that standard. Use the focused component document and implementation source to establish the actual supported path.

## 4. Relationships

### Dependency direction

```text
higher-level protocols / crypto / applications
                    │
                    ▼
                 sdk/io
     ┌────────┬────────┬──────────┐
     │ fields │ parser │ formats  │
     │ streams│ strings│ OS I/O   │
     └────────┴────────┴──────────┘
                    │
                    ▼
       sdk/base and platform libraries
```

This is an architectural orientation map, not a complete include graph or a claim that every component depends on every other component.

### Cross-module relationships

- `sdk/base` supplies common types, in-memory streams, containers, string/encoding helpers, and graph-structured-stack storage used by selected I/O components.
- `sdk/io/parser` provides grammar and parse-tree infrastructure used by the ASN.1 processing path; the ASN.1 layer owns ASN.1-specific semantics.
- `sdk/io/basic/payload` and URL/string helpers are reused by higher-level network and protocol code where a known field layout or URL representation is appropriate.
- `sdk/io/cbor` and `sdk/io/asn.1` each implement their own format-specific representation and conversion path.
- The [CBOR Appendix A examples](cbor/rfc8949-examples.md) and [ASN.1 notation study notes](asn.1/basic/README.md#development-notes) connect the directory overviews to retained component-level study material.
- Component-level source references and implementation details are maintained in the corresponding directory documents. Test-specific coverage and run evidence belong in the relevant testcase documentation, which is currently being reviewed separately.

## 5. References

### Standards and specifications

- [RFC 8949 — Concise Binary Object Representation (CBOR)](https://www.rfc-editor.org/rfc/rfc8949).
- [RFC 7049 — Concise Binary Object Representation (CBOR)](https://www.rfc-editor.org/rfc/rfc7049), the earlier CBOR specification relevant to historical compatibility.
- ITU-T X.680 — ASN.1 notation.


## 6. Development Notes

- The directory map is intentionally a responsibility map, not a dependency graph. In particular, the ASN.1 and CBOR implementations should not be described as one mandatory pipeline.
- When documenting behavior, distinguish the source implementation from the behavior defined by a referenced standard. A citation alone does not imply full conformance.
- Preserve the distinction between general-purpose facilities and protocol-specific interpretation: the former provides representation or mechanics, while higher layers decide what those results mean.
