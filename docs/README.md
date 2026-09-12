# hotplace study

**Edition 1 · Revision 1078**


> A compact study map of the hotplace project.
> The documents record concepts, relationships, development traces,
> and verification work; the source remains the authority for the
> current implementation.

## Document Guide

- [Document Guide](guide/document-guide.md)

The document structure and writing rules are defined once in the guide.
Topic documents use that structure without repeating the guide.

## Topic Map

- [Error Model](error/README.md)
- [COSE / JOSE](cose_jose/README.md)
- [HPACK](hpack/README.md)
- [HTTP/2](http2/README.md)
- [QUIC](quic/README.md)
- [TLS](tls/README.md)

The map will grow only when a topic deserves its own document.

## Relationship

```text
                 ┌──────────┐
                 │ HTTP/2   │
                 │  Frame   │
                 └────┬─────┘
                      │
                 Header Block
                      │
                   ┌──▼───┐
                   │ HPACK│
                   └──┬───┘
                      │
                 study path
                      ▼
                   QPACK
                      │
                    HTTP/3
                      │
                    QUIC
                   ╱   ╲
                 TLS   UDP
```

The diagram shows relationships, not ownership. Each topic document
defines the questions it owns and links to the document that owns
adjacent questions.

## Publication

```text
┌──────────────────────────────────────┐
│ hotplace study                       │
│ Edition 1 · Revision 1076            │
│ Documented with GPT-5.6 Luna         │
│ — study, reconstruction & review     │
└──────────────────────────────────────┘
```