# hotplace study

**Edition 1 · Revision 1084**

> A compact study map of the hotplace project.
> The documents record concepts, relationships, development traces,
> and verification work; the source remains the authority for the
> current implementation.

## Document Guide

- [Document Guide](guide/document-guide.md)

The document structure and writing rules are defined once in the guide.
Topic documents use that structure without repeating the guide.

## Topic Map

The documents are grouped by the question they primarily own. The grouping
is not a dependency hierarchy: a topic may use another layer without owning
its concepts.

### Foundation

- [Error Model](error/README.md)
- [Payload](payload/README.md)

`error` describes the common error/result model. `payload` describes the
generic binary field-layout and reader/writer substrate used by higher-level
protocol and security structures.

### Cryptographic and Security Semantics

- [Cryptography](crypto/README.md)
- [TLS](tls/README.md)
- [COSE / JOSE](cose_jose/README.md)
- [ASN.1 Semantic Construction](asn1/README.md)

`crypto` owns cryptographic keys and operations. TLS, JOSE, and COSE use that
substrate but own their own protocol/security-object semantics. ASN.1 owns
notation, parsing, semantic construction, and runtime schema/object meaning.

### Network and Protocol Processing

- [Network Server](network_server/README.md)
- [HTTP Server](http_server/README.md)
- [HTTP/2](http2/README.md)
- [HPACK](hpack/README.md)
- [HTTP/3](http3/README.md)
- [QUIC](quic/README.md)

These documents describe progressively higher protocol meaning over transport
I/O. `network_server` owns session, scheduling, stream accumulation, protocol
detection, framing consumption, and dispatch; individual protocol documents
own their protocol semantics.

### Observation and Reproduction

- [PCAPNG / Capture-Replay](pcapng/README.md)

PCAPNG is treated as an observation and verification boundary rather than as
a protocol layer. Captures connect live interoperability work with
reproducible protocol test vectors.

## Relationship

The overall relationship is better understood as **several interacting
dimensions**, rather than one linear stack.

```text
                         APPLICATION / OBJECT SEMANTICS
        ┌──────────────────────┬───────────────────────┬─────────────────────┐
        │                      │                       │                     │
      ASN.1                 COSE / JOSE              HTTP/1.x             HTTP/2
        │                      │                       │                     │
        │                      │                       │                   HPACK
        │                      │                       │                     │
        │                      └──────────┐            │                     │
        │                                 │            │                     │
        │                              crypto          │                     │
        │                                 │            │                     │
        │                              TLS ────────────┴─────────────────────┤
        │                                 │                                  │
        │                                 │                              HTTP/3
        │                                 │                                  │
        │                                 └──────────────┐                 QUIC
        │                                                ▼                   │
        │                                                ◄───────────────────┘
        │                                                │
        └────────────────────────────────────────────────┘
                                                         │
                                              network_server
                                                         │
                                      ┌──────────────────┴──────────────────┐
                                      │                                     │
                                     TCP                                   UDP
                                      │                                     │
                                      └──────────────────┬──────────────────┘
                                                         │
                                                      I/O/session
                                                         │
                                                      payload
```

The diagram is intentionally conceptual:

- **ASN.1** describes a language-to-semantic-object path. It is not simply
  another network layer.
- **Payload** is a reusable binary representation mechanism. It supports
  protocol/security structures but does not own their semantics.
- **Crypto** is the shared cryptographic substrate: key material, hashing,
  MAC, encryption, signature, key exchange/KEM, and related algorithm
  selection. PQC fits here as additional cryptographic operations and key
  types.
- **TLS** owns handshake, transcript, key schedule, record protection, and
  its
  transport integration. It consumes `crypto` rather than defining the
  underlying cryptographic algorithms.
- **COSE / JOSE** own security-object and algorithm-container semantics,
  including their use of keys, signatures, MACs, encryption, and
  Base64URL/CBOR/JSON representations.
- **QUIC** owns packets, frames, streams, packet protection, and the
  integration of TLS handshake bytes into QUIC. HTTP/3 is above QUIC.
- **HTTP/2 / HPACK** form a protocol-specific branch: HTTP/2 owns frames and
  connection/stream semantics; HPACK owns header compression.
- **network_server** owns the execution boundary around transport I/O:
  socket/multiplexer, session, event queue, stream accumulation, protocol
  detection, framing, consumption, and dispatch.
- **PCAPNG** cuts across the stack. It records actual wire behavior and can
  later become a reproducible capture-replay test vector.

### Layer Ownership

A useful way to read the repository is:

```text
meaning
  │
  ├── ASN.1 notation / schema semantics
  ├── COSE / JOSE security-object semantics
  ├── HTTP protocol semantics
  └── TLS / QUIC protocol state
        │
        ▼
representation
  │
  └── payload / encoding / protocol field layout
        │
        ▼
cryptographic substrate
  │
  └── crypto
        │
        ├── TLS
        ├── COSE
        ├── JOSE
        └── PQC algorithms
        │
        ▼
transport execution
  │
  └── network_server
        │
        ├── TCP
        ├── UDP / DTLS
        └── QUIC
        │
        ▼
observation / verification
  │
  └── PCAPNG / capture-replay
```

This is not a strict call graph. It is a **topic ownership map**: each arrow
means that the upper topic may depend on concepts from the lower topic, while
the lower topic should not absorb the upper topic's protocol semantics.

## Important Cross-Topic Relationships

### Security stack

```text
COSE / JOSE
     │
     ├── key representation
     ├── signature / MAC
     ├── encryption
     └── algorithm identifiers
     │
     ▼
   crypto
     │
     ├── classical algorithms
     └── PQC
          ├── ML-KEM
          ├── ML-DSA
          └── related hybrid/key/signature mechanisms
```

TLS follows a different security-object model but shares the same
cryptographic substrate:

```text
TLS
 │
 ├── handshake
 ├── authentication
 ├── key schedule
 ├── record protection
 └── QUIC integration
       │
       ▼
     crypto
```

The commonality is therefore **cryptographic operation and key material**, not
that TLS, JOSE, and COSE are the same protocol.

### HTTP stack

```text
HTTP/1.x ────────────────┐
                         │
HTTP/2 ── HPACK ─────────┤
                         │
HTTP/3 ── QUIC ──────────┘
                         │
                         ▼
                    application
```

HTTP/2 and HTTP/3 share HTTP-level intent but use different transport and
framing mechanisms. HPACK belongs specifically to HTTP/2; HTTP/3 uses QUIC
and its own header-compression path.

### Transport / security boundary

```text
TCP
 │
 └── TLS ──► application protocol

UDP
 ├── DTLS ─► application protocol
 └── QUIC
       ├── packet / frame / stream
       ├── TLS handshake integration
       └── HTTP/3
```

The important boundary is that TLS and QUIC are related, but QUIC is not
merely "TLS over UDP": QUIC carries TLS handshake bytes in CRYPTO frames and
has its own packet protection and transport state.

### Observation boundary

```text
live client/server
       │
       ▼
transport + protocol processing
       │
       ▼
PCAPNG capture
       │
       ├── human/debug observation
       └── YAML / replay test vector
                    │
                    ▼
             deterministic verification
```

This makes PCAPNG a bridge between **implementation behavior** and
**reproducible study/test evidence**, rather than a lower protocol layer.

## Reading the Repository

The recommended reading direction is not a single fixed sequence.

For protocol execution:

```text
network_server
    → HTTP / QUIC
    → TLS
    → crypto / payload
```

For cryptographic/security semantics:

```text
crypto
    → TLS
    → COSE / JOSE
    → PQC-related work
```

For binary representation:

```text
payload
    → protocol/security structures
    → TLS / QUIC / HTTP
```

For schema and semantic construction:

```text
ASN.1 notation
    → parser
    → semantic construction
    → runtime object/schema
```

For implementation verification:

```text
live interoperability
    → PCAPNG
    → capture-replay
    → testcase / vector
```

These are complementary reading paths through the same project, not competing
architectures.

## Relationship vs. History

The relationship map describes **what concepts depend on or interact with what
other concepts**. It should not be read as a development chronology.

Development history is reconstructed separately from the project's recorded
history, primarily through `CHANGELOG.md`. A later topic appearing higher in
this map does not imply that it was developed later.

## Publication

```text
┌──────────────────────────────────────┐
│ hotplace study                       │
│ Edition 1 · Revision 1084            │
│ Documented with GPT-5.6 Luna         │
│ — study, reconstruction & review     │
└──────────────────────────────────────┘
```
