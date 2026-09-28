# Study Flow — Draft

## Why preserve this

The sequence `HTTP/2 → HPACK → QPACK → QUIC → TLS → QUIC → ASN.1` can look arbitrary if it is read only as a dependency graph. It was instead a development and study flow in which each RFC topic exposed a mechanism that required a deeper independent study.

This context is important because the project is a vehicle for learning protocol mechanisms by studying RFCs and implementing them, not a project whose entire architecture was designed in advance as a strict stack.

## Development / study flow

```text
Independent RFC studies
    │
    ├── JOSE
    ├── COSE
    └── ...
          │
          ▼
       HTTP/2
          │
        HPACK
          │
        QPACK
          │
      "HTTP/3가 바로 안 나오네?"
          │
          ▼
         QUIC
          │
        CRYPTO
          │
         TLS
          │
      handshake / extensions /
      transcript / key schedule
          │
          ▼
         QUIC
          │
       network integration
          │
        deferred
          │
          ▼
        ASN.1
```

A compact form is useful as a navigation anchor:

```text
HTTP/2
  ↓
HPACK
  ↓
QPACK
  ↓
QUIC
  ↓
TLS
  ↓
QUIC
  ↓
ASN.1
```

## Meaning of the detours

### HTTP/2 → HPACK

While studying HTTP/2, HPACK became sufficiently deep that it was useful to treat header compression as an independent study subject rather than as a small HTTP/2 implementation detail.

### HPACK → QPACK

QPACK continued the header-compression study in the HTTP/3 context, but studying QPACK did not immediately produce an HTTP/3 implementation. The investigation therefore moved to the underlying transport: QUIC.

### QUIC → TLS

QUIC carries TLS handshake information through CRYPTO frames. Understanding QUIC therefore exposed TLS handshake and extension semantics as a separate prerequisite.

### TLS → QUIC

TLS then became an independent study area: handshake, extensions, transcript, key schedule, record/protection concepts, and protocol state. After that study, the investigation returned to QUIC with a clearer understanding of its TLS integration.

### QUIC → network integration

Network-server integration was intentionally deferred rather than treated as proof that all QUIC work had to be completed before studying another subject.

### → ASN.1

The study then moved to ASN.1, where notation, grammar, parsing, semantic construction, runtime schema/object models, and eventually source generation became the new deep subject.

## What this diagram is not

This is **not**:

- a strict build dependency graph;
- a claim that one protocol layer completely contains the next;
- a predetermined project roadmap;
- evidence that every later topic was required before the next topic could begin.

It is a reconstruction of the actual learning/development path and explains why apparently unrelated study areas appeared in sequence.

## Candidate destinations

- Root `docs/README.md` as a short reading/history note.
- `docs/guide/document-guide.md` only if the reading philosophy needs this distinction.
- Individual topic READMEs should keep only the local reason needed to understand that topic; do not duplicate the full flow.
