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

The directories use different intermediate representations. These objects are not interchangeable even when they all ultimately carry bytes or describe structured data.

### Core representations

| Representation | What it retains | Boundary |
|---|---|---|
| payload / payload_member | Ordered fields, current values, optional group membership and length references | Known binary layout; does not define a grammar |
| oid_t | Numeric OID arcs as std::vector<uint32> | Textual OID nodes; not BER/DER bytes |
| lexical_context / lexical_token | Ordered token IDs and source spans into the original input buffer | Lexical output; token text depends on source-buffer lifetime |
| cfg_grammar / parsing table | Symbols, productions, ACTION/GOTO entries and parser-state transitions | Reusable syntax-recognition rules, not source input |
| parse_tree / parse_treenode | Grammar symbols, terminal values and ordered child nodes | Syntactic structure; not ASN.1 semantic objects |
| cbor_object tree | CBOR scalar/container values, pairs and tags | CBOR logical values independent of their original byte layout |
| ASN.1 semantic objects and asn1_module | ASN.1 types, values, references, constraints, module/import/export relationships | ASN.1 meaning reconstructed from syntax or built directly |
| stream_t / file_stream | Byte access through common in-memory or file-backed interfaces | Byte transport/access, not a format-specific value tree |
| OS event payloads | Backend-specific event/completion fields and callback context | Event dispatch contract; payload interpretation depends on epoll vs IOCP |

### Directory map

    sdk/io
    ├── basic/   payload fields, OID nodes, JSON trees, compressed bytes
    ├── stream/  file handles, file positions, mappings and locks
    ├── string/  token text, URL fields, character conversion
    ├── parser/  source spans → tokens → grammar tables → syntax tree
    ├── cbor/    encoded bytes ↔ CBOR object tree ↔ alternate output
    ├── asn.1/   notation → syntax → ASN.1 semantic/module objects
    └── system/  sockets, event callbacks, queues and OS-specific handles

The map summarizes the main retained data at each boundary; it does not mean every operation traverses every directory.

## 3. Behavior Model

### Distinct processing paths

    Known binary field layout
        payload members ───────────────► binary bytes
              ▲                              │
              └──────── read / decode ───────┘

    Source text
        └─► lexical_context / tokens
                └─► grammar + ACTION/GOTO table
                        └─► parser engine
                                └─► parse_tree
                                        └─► consumer-specific semantic reconstruction
                                                └─► ASN.1 objects / modules

    CBOR bytes ──► cbor_reader ──► cbor_object tree ──► publisher / visitor output
    hotplace value or CBOR object ──► cbor_encode ──► CBOR bytes

    JSON text/file ──► Jansson parser ──► json_t* ──► caller-managed JSON operations
    input bytes + selected framing ──► zlib ──► output bytes

    file_stream ──► OS file handle / mapping / lock
    socket or OS event source ──► backend-specific callback payload ──► caller's event handling

These are separate paths. Payload is for a known field layout; the generic parser recognizes grammar; CBOR and ASN.1 own different format-specific models. A parsed syntax tree does not itself validate ASN.1 semantics, and converting bytes to a format-specific object does not establish application-level validity.

### Lifecycle and decision points

1. **Select the representation boundary.** Use field layout for known binary fields, a grammar/parser for tokenized source syntax, or a format-specific reader for CBOR/ASN.1 data.
2. **Build or import reusable structure.** Parser tables can be generated from a grammar or imported from a serialized table. That table is not the token stream or parse tree.
3. **Interpret at the correct layer.** ASN.1 semantic objects, references, constraints and module relationships are reconstructed above the generic parser. Higher-level consumers similarly decide what CBOR, JSON, URL or OID values mean in their own protocol.
4. **Respect resource lifetime.** Token spans refer to source storage; Jansson trees are reference-counted; file streams can own native handles, mappings and locks; OS callbacks may refer to active socket/session contexts. The component-specific lifecycle contract governs when these can be released.
5. **Check platform-specific behavior.** A common API may conceal different underlying mechanics: Linux epoll reports readiness while Windows IOCP reports completion of submitted overlapped I/O. Their callback data must not be interpreted as identical.

The detailed documents below record the actual component-level flow and supported behavior. A standard reference or a conceptual diagram is not, by itself, evidence of complete conformance or test execution.

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
- The [CBOR Appendix A examples](cbor/rfc8949-examples.md) and [ASN.1 notation study notes](asn.1/basic/README.md#developer-notes) connect the directory overviews to retained component-level study material.
- Component-level source references and implementation details are maintained in the corresponding directory documents. Test-specific coverage and run evidence belong in the relevant testcase documentation, which is currently being reviewed separately.

## 5. References
### Standards and specifications

- [RFC 8949 — Concise Binary Object Representation (CBOR)](https://www.rfc-editor.org/rfc/rfc8949).
- [RFC 7049 — Concise Binary Object Representation (CBOR)](https://www.rfc-editor.org/rfc/rfc7049), the earlier CBOR specification relevant to historical compatibility.
- ITU-T X.680 — ASN.1 notation.


## 6. Developer Notes
- The directory map is intentionally a responsibility map, not a dependency graph. In particular, the ASN.1 and CBOR implementations should not be described as one mandatory pipeline.
- When documenting behavior, distinguish the source implementation from the behavior defined by a referenced standard. A citation alone does not imply full conformance.
- Preserve the distinction between general-purpose facilities and protocol-specific interpretation: the former provides representation or mechanics, while higher layers decide what those results mean.
