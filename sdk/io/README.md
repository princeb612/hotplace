## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# I/O and Data Representation

## 1. Role

`sdk/io` contains facilities that turn data between representations and provide the parsing or operating-system I/O mechanisms used by higher layers. It is not one single serialization framework: it groups several distinct facilities whose boundaries are visible in the subdirectories.

- `basic/` — payload field descriptions, OID text/node conversion, compression wrappers, and JSON loading helpers.
- `stream/` — file-backed implementation of the common stream interface.
- `string/` — tokenization, URL handling, and platform character conversion.
- `parser/` — grammar parsing, lexer/parser infrastructure, and parsing-table support.
- `cbor/` — CBOR data model, reader/encoder, visitor, and RFC examples.
- `asn.1/` — ASN.1 notation, object model, semantic/structural analysis, loader/compiler, and runtime parsing/encoding.
- `system/` — operating-system-oriented facilities such as sockets, multiplexing, netlink, and Windows PE/registry access.

The directory is therefore best understood as a collection of representation and I/O building blocks. The higher-level protocol modules decide how these facilities are composed for a particular protocol.

## 2. Model

### Directory map and conceptual flow

```text
text / bytes / file / grammar
          │
          ├── basic/   payload, OID, JSON, compression
          ├── string/  tokenization, URL decomposition
          ├── stream/  file-backed stream operations
          ├── parser/  grammar → parse structure
          ├── cbor/    CBOR object model ↔ encoded bytes
          └── asn.1/   notation → model/compiler/runtime → encoded bytes
                         │
                         ▼
                higher-level SDK modules
```

This diagram is a map of responsibilities, not a claim that every path passes through every subdirectory. For example, the ASN.1 runtime and CBOR reader/encoder are separate format-specific systems; they share lower-level utilities but do not form one common pipeline.

## 3. Important behavior and lifetime

The subdirectories have different behavioral contracts, so their detailed rules belong in the corresponding component documents. A few cross-directory distinctions are important:

- `sdk/base/stream` provides common in-memory stream and formatting abstractions; `sdk/io/stream` adapts that interface to files and platform APIs.
- `sdk/io/basic/payload` describes a known binary field layout and can be used in both directions; it is not a grammar parser.
- `sdk/io/parser` handles grammar/parse structure, while `sdk/io/asn.1` builds ASN.1-specific semantics and runtime facilities on top of parser-related machinery.
- `sdk/io/basic/oid` converts between dotted OID text and integer nodes; ASN.1 BER/DER OBJECT IDENTIFIER encoding belongs to the ASN.1 encoding implementation.

## 4. Example from the source tests

Use the tests according to the subsystem being investigated rather than treating this directory as having one representative test:

- `test/testcase/io/basic/testcase_payload.cpp` — constructs a payload field sequence, writes it, changes group selection, then reads a known byte sequence using a length reference.
- `test/testcase/io/basic/testcase_oid.cpp` — loads the OID dictionary, looks up a dotted OID, converts ASN.1-braced notation to node values, and performs a second lookup.
- `test/testcase/io/stream/testcase_filestream.cpp` — opens/truncates a file, maps it, writes through the mapped bytes, then seeks and reads back.
- `test/testcase/io/string/testcase_string.cpp` — checks URL decomposition for default and explicit ports, paths, queries, and fragments.
- `test/testcase/io/cbor/` and `test/testcase/asn.1/` — format-specific tests for CBOR and ASN.1 behavior.

These are starting points for tracing the implementation; the relevant module documents describe the call path and what each assertion establishes.

## 5. Relationships

- `sdk/base/` — shared data types, streams, string/encoding helpers, patterns, and runtime support.
- `sdk/crypto/` — consumes JSON helpers, compression, OID conversion, and ASN.1 facilities in JOSE/COSE and certificate-related code.
- `sdk/net/` — uses payload, URL decomposition, compression, streams, and ASN.1-related protocol structures.
- `test/testcase/io/` and `test/testcase/asn.1/` — concrete executable examples of these facilities.

## 6. References

- RFC 8949 — Concise Binary Object Representation (CBOR); see `cbor/rfc8949-examples.md`.
- RFC 7049 — earlier CBOR specification, relevant to historical compatibility context.
- ITU-T X.680 — ASN.1 notation; see `asn.1/basic/itu-t_x680.md`.
- RFCs and standards specific to parser, ASN.1, and protocol behavior are listed in their component documents rather than duplicated here.

## 7. Developer Notes

- The source-tree map is intentionally a responsibility map, not a dependency graph. Some listed modules are independent format implementations and should not be described as a single mandatory pipeline.
- When documenting a behavior, distinguish what the source currently implements from what the referenced standard defines. A reference does not imply full conformance to every part of that standard.
