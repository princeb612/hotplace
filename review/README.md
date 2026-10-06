# Hotplace Architecture Review

This directory contains cross-cutting reviews of the hotplace source tree.

The documents here are not replacements for the source-tree `README.md` files and are not a second edition of `/docs`. They provide a different view: architecture, relationships between modules, implementation evolution, and connections that are difficult to capture inside one directory.

## Source Baseline

- Source revision: 1097
- Review scope: source-tree architecture and development relationships
- Companion study area: `/docs`
- Source-tree documentation: directory/module `README.md` and topic Markdown files

## 1. Three Documentation Layers

Hotplace documentation can be understood as three complementary layers:

```text
                         hotplace documentation
                                  │
             ┌────────────────────┼────────────────────┐
             │                    │                    │
             ▼                    ▼                    ▼
        source-tree             /docs               /review
          docs                study flow       architecture review
             │                    │                    │
             │                    │                    │
      "what is here?"       "how did I learn?"   "how are these
             │                    │                things connected?"
             │                    │                    │
             ▼                    ▼                    ▼
       directory/module       conceptual         cross-cutting
       identity + details    progression       relationships/evolution
```

### Source-tree documentation

The Markdown files under `sdk/`, `test/`, and related directories describe the actual location and identity of implementation components.

Typical questions:

- What is this directory?
- What does this module do?
- Which source files belong here?
- What tests or references are related?

### `/docs`

`/docs` is the conceptual study and reconstruction path.

It records subjects in a deliberate learning order rather than mirroring the source tree.

The existing publication identity remains:

```text
┌──────────────────────────────────────────────┐
│ hotplace study                               │
│ Edition 1 · Revision 10xx                    │
│ Documented with GPT-5.6 Luna                 │
│ — study, reconstruction & review             │
└──────────────────────────────────────────────┘
```

### `/review`

`/review` is a persistent architecture-review layer.

It does not use an Edition number. Its baseline is simply the source revision being reviewed.

```text
┌──────────────────────────────────────────────┐
│ hotplace architecture review                 │
│ Revision 1097                                │
│ Documented with GPT-5.6 Luna                 │
│ — architecture, evolution & relationships    │
└──────────────────────────────────────────────┘
```

The review layer is therefore expected to evolve from revision to revision without becoming "Edition 2", "Edition 3", and so on.

## 2. Current Review Map

The current documents cover several different cross-cutting relationships.

```text
                                  hotplace
                                     │
        ┌────────────────────────────┼─────────────────────────────┐
        │                            │                             │
        ▼                            ▼                             ▼
      parser                        ASN.1                        crypto
        │                            │                             │
        │                     ┌──────┴──────┐                ┌─────┴─────┐
        │                     │             │                │           │
        ▼                     ▼             ▼                ▼           ▼
 parser evolution       semantic/runtime constraints     advisor   Authenticode
        │                     │             │                │           │
        └─────────────────────┴─────────────┘                │           │
                                      │                      │           │
                                      ▼                      ▼           ▼
                                data / identity        tls_advisor    OpenSSL
                                      │                      │           │
                                      └──────────┬───────────┘           │
                                                 ▼                       │
                                            TLS / DTLS / QUIC            │
                                                 │                       │
                                                 ▼                       │
                                          network/session                │
                                                                         │
                                                                         ▼
                                                               PE / PKCS#7 / X.509
```

## 3. Review Documents

### `hotplace-parser-evolution.md`

**Primary relationship**

```text
lexer
  ↓
CFG / grammar
  ↓
LALR(1)
  ↓
Aho-Corasick parser-switching experiment
  ↓
GLR
  ↓
large parsing table
  ↓
binary `.ptb` parsing table
```

**Source-tree connections**

- `sdk/io/parser/`
- `test/tool/makeparsingtable`
- `etc/parsingtable/`
- ASN.1 parser resources

**Study connection**

This review complements the parser material in `/docs` by recording why the parser architecture changed, rather than only explaining what LALR/GLR means.

---

### `asn1-parser-semantic-runtime.md`

**Primary relationship**

```text
ASN.1 notation
  ↓
parser
  ↓
parse tree
  ↓
semantic construction
  ↓
asn1_runtime
  ↓
runtime object
```

**Source-tree connections**

- `sdk/io/parser/`
- `sdk/io/asn.1/basic/`
- `sdk/io/asn.1/loader/`
- `sdk/io/asn.1/compiler/`
- `sdk/io/asn.1/runtime/`
- ASN.1 testcase sources

**Important distinction**

```text
parseable
   ≠
semantically implemented
   ≠
fully supported feature
```

This distinction is especially important for the loader work beginning around revision 1096.

---

### `asn1-constraint-set-model.md`

**Primary relationship**

```text
ASN.1 constraint tree
        ↓
asn1_constraint_evaluator<T>
        ↓
t_set_runtime<T>
        ├── string_set
        └── t_range_set<t_range_value<T>>
```

**Source-tree connections**

- `sdk/io/asn.1/basic/semantic/constraints/`
- `sdk/base/nostd/range_set*`
- `sdk/base/nostd/string_set*`
- `test/testcase/asn.1/testcase_constraints.cpp`
- `test/testcase/base/nostd/testcase_set.cpp`

**Architectural point**

The set engine is not an ASN.1-specific container. ASN.1 constraints are one important consumer of a generic value-set abstraction.

The same range machinery also has a relationship with QUIC ACK-range processing.

---

### `binary-construction-abstraction.md`

**Primary relationship**

```text
binary construction
      │
      ├── binary_stream
      ├── payload
      ├── protocol builders
      └── parsing-table generation
```

**Source-tree connections**

- `sdk/base/stream/`
- `sdk/io/basic/payload`
- HTTP/TLS/QUIC implementations
- parsing-table generation tools

**Architectural point**

Hotplace repeatedly needs small, purpose-specific binary construction mechanisms. The review records the common pattern without forcing them into one generic serialization framework.

---

### `network-session-architecture.md`

**Primary relationship**

```text
socket
  ↓
network_session
  ↓
network_stream
  ↓
network_protocol
```

with platform event handling:

```text
multiplexer
 ├── epoll
 ├── IOCP
 └── platform abstraction
```

**Source-tree connections**

- `sdk/io/system/`
- `sdk/net/`
- TLS/HTTP/QUIC protocol implementations

**Architectural point**

The review separates hotplace's transport/session abstraction from protocol-specific stream semantics. In particular, a QUIC stream is not automatically identical to a hotplace `network_stream`.

---

### `tls-dtls-quic-development-path.md`

**Primary relationship**

```text
TLS
 ↓
key schedule / crypto validation
 ↓
record / handshake / extensions
 ↓
DTLS
 ↓
QUIC
```

**Source-tree connections**

- `sdk/net/tls/`
- `sdk/net/dtls/`
- `sdk/net/quic/`
- crypto implementation
- payload
- network/session

**Architectural point**

This is primarily a development/study history. It should be read together with `tls_advisor` documentation, but the two documents answer different questions:

```text
development-path
    → how the implementation/study progressed

tls_advisor
    → how protocol identifiers/resources are represented now
```

---

### `crypto-advisor-tls-advisor-review-rev1096.md`

**Primary relationship**

```text
protocol / crypto identifiers
             │
      ┌──────┴──────┐
      ▼             ▼
crypto_advisor   tls_advisor
      │             │
      └──────┬──────┘
             ▼
      crypto / protocol implementation
             │
             ▼
        OpenSSL / EVP
```

**Source-tree connections**

- `sdk/crypto/advisor/`
- `sdk/net/tls/tls_advisor.*`
- crypto primitives
- TLS / QUIC resource definitions
- OpenSSL integration

**Architectural point**

`crypto_advisor` and `tls_advisor` are not simply parent and child dictionaries.

`crypto_advisor` organizes crypto identity/resource information such as digest, key, curve, signature, JOSE/COSE and related namespaces.

`tls_advisor` organizes protocol-specific TLS/QUIC identifiers and resources such as cipher suites, groups, extensions, handshake types, alerts, QUIC frames and transport parameters.

They intersect at the point where protocol identifiers refer to cryptographic mechanisms.

---

### `hotplace-authenticode-verification.md`

**Primary relationship**

```text
PE
 ↓
authenticode_plugin_pe
 ↓
Authenticode digest
 ↓
PKCS#7 / SpcIndirectDataContent
 ↓
signer / certificate verification
 ↓
OpenSSL
```

**Source-tree connections**

- `sdk/crypto/authenticode/`
- `sdk/io/stream/file_stream`
- `sdk/io/string/`
- OpenSSL integration
- ASN.1 / PKCS#7 concepts

**Architectural point**

Authenticode is a deliberately narrow verification subsystem.

It uses ASN.1/PKCS#7 as a data-format and protocol concept, but its current implementation path uses OpenSSL's PKCS#7/X.509 APIs rather than hotplace's ASN.1 runtime.

---

## 4. Major Cross-Cutting Connections

The current review set can be summarized by the following relationships.

### Parser → ASN.1

```text
parser engine
    ↓
grammar / parsing table
    ↓
ASN.1 notation
    ↓
parse tree
    ↓
semantic construction
```

The parser review explains the evolution of the engine and parsing-table architecture.

The ASN.1 review explains what happens after syntax recognition.

---

### ASN.1 → Generic Sets

```text
ASN.1 constraints
       ↓
constraint evaluator
       ↓
generic set runtime
       ↓
range_set / string_set
```

This relationship demonstrates a reusable base abstraction emerging from a protocol-specific problem.

---

### Binary Construction → Protocols

```text
binary_stream / payload
             │
     ┌───────┼────────┐
     ▼       ▼        ▼
    TLS     HTTP2     QUIC
```

The same architectural idea appears in multiple protocol implementations, but the concrete abstractions are not necessarily identical.

---

### Crypto Identity → Protocol Identity

```text
crypto_advisor
      │
      ├── digest
      ├── key
      ├── curve
      └── signature
             │
             ▼
         tls_advisor
             │
      ┌──────┼───────┐
      ▼      ▼       ▼
 cipher    group   extension
 suite
```

This is the current 1096 view of the advisor layer.

---

### Protocol state → wire unit

The DTLS and QUIC publisher/arrangement components add a useful architectural observation:

```text
protocol state
     │
     ├── construction → publisher → wire unit
     │
     └── reconstruction → arrange → usable input
```

`dtls_record_publisher`, `dtls_record_arrange`, and `quic_packet_publisher` are not
being treated as one class family. They are evidence of a repeated boundary in which
protocol-specific semantics are materialized into, or reconstructed from, wire-oriented
units.

This is a stronger review observation than simply noting that the components live in
different directories: the architectural interest is the responsibility boundary itself.

### TLS → DTLS → QUIC

There are two different relationships:

```text
development history:
TLS → DTLS → QUIC
```

and:

```text
current resource representation:
                 tls_advisor
                /           \
              TLS           QUIC
```

The first describes evolution.

The second describes current source architecture.

They should not be conflated.

---

### Authenticode → Existing Infrastructure

```text
PE verification
     │
     ├── file_stream
     ├── crypto/OpenSSL
     ├── URL handling
     └── PKCS#7/X.509
```

This is a compact example of a feature being assembled from infrastructure that already exists elsewhere in the project.

## 5. Relationship to the Study Flow

The `/docs` study flow can be viewed as a conceptual progression:

```text
base
 ↓
io
 ↓
parser
 ↓
ASN.1
 ↓
crypto
 ↓
network protocols
```

The review layer cuts across that sequence:

```text
                   ┌─────────────────────┐
                   │      /docs flow     │
                   └──────────┬──────────┘
                              │
                              ▼
       base ── io ── parser ── ASN.1 ── crypto ── net
        │       │       │        │        │        │
        └───────┴───────┴────────┴────────┴────────┘
                              │
                              ▼
                           /review
                    cross-cutting relations
```

This is why a review document should not duplicate a whole module's README.

It should explain a connection that becomes visible only when several parts are considered together.

## 6. What Belongs in `review/`

Good candidates:

- architecture spanning multiple directories
- development/evolution history
- reusable abstractions discovered through implementation
- relationships between protocol layers
- source-tree ↔ `/docs` relationships
- implementation decisions that are spread across multiple modules
- distinctions between similar-looking components

Poor candidates:

- a second copy of a module README
- generic protocol tutorials
- complete RFC summaries
- exhaustive API references
- speculative future architecture
- generic software-engineering advice

The source-tree documentation remains the authoritative local description of a module.

`/review` is the connective layer.

## 7. Revision Discipline

Each review document should identify the source revision it describes.

For revision 1097:

```text
Source Baseline: Revision 1097
```

When the implementation changes materially:

```text
Revision 1097
      ↓
source changes
      ↓
new review pass
      ↓
Revision 10xx
```

The review documents should not imply that every statement remains valid forever.

In particular, parser production names, ASN.1 loader capabilities, protocol resource tables, and implementation status can change between revisions.

## 8. Current Review Status

At revision 1097, the review layer has established these major axes:

```text
1. Parser evolution
2. ASN.1 semantic/runtime construction
3. ASN.1 constraint → generic set engine
4. Binary construction abstractions
5. Network session architecture
6. TLS / DTLS / QUIC development path
7. crypto_advisor / tls_advisor / OpenSSL relationship
8. Authenticode cross-cutting verification path
```

These review axes form the current architecture-review map. The 1097 pass adds a more explicit protocol-state → wire-unit boundary observation without creating another subsystem-specific review file.

The next review pass should therefore focus on **cross-referencing and correction**, rather than automatically creating another document for every subsystem.

## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace architecture review                 │
│ Revision 1097                                │
│ Documented with GPT-5.6 Luna                 │
│ — architecture, evolution & relationships    │
└──────────────────────────────────────────────┘
```
