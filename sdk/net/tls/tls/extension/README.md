## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# TLS extensions

## 1. Role

The extension layer represents typed extension data used during TLS negotiation. It provides structures for extension payloads; the handshake/session logic decides which extensions are offered, validated, negotiated, or acted upon.

## 2. Data Model

An extension is identified by an extension type and length-delimited extension data. The extension type determines the payload structure. Extensions appear within applicable handshake messages such as ClientHello and ServerHello, and TLS 1.3 uses EncryptedExtensions for server-selected parameters that belong there.

```text
handshake message
  -> extension list
       ├─ extension type
       ├─ extension length
       └─ type-specific payload
```

Extension metadata lookup is related to, but distinct from, parsing an extension's payload. `tls_advisor` provides type/hint metadata; the extension implementation represents and interprets the selected extension data.

## 3. Behavior Model

The parser reads the length-delimited extension list and dispatches each payload according to its type. The handshake/session layer then applies protocol/version and role-specific rules. A syntactically recognized extension is not necessarily supported or valid in every message, role, or TLS version; callers must enforce those contextual rules.

ALPN influences application-protocol selection, while QUIC transport parameters feed QUIC session configuration. Their presence in TLS handshake messages does not make the extension module responsible for HTTP routing or QUIC packet construction.

## 4. Relationships

- Parent module: [TLS implementation](../README.md).
- [Handshake messages](../handshake/README.md) — extension container within handshake messages.
- [TLS advisor](../../advisor/README.md) — extension type metadata and hints.
- [TLS session support](../../session/README.md) — negotiation state and selected parameters.
- [TLS protection](../../protection/README.md) — selected algorithms and handshake transcript.
- [QUIC integration](../../quic/README.md) — QUIC transport parameters and TLS 1.3 handshake integration.
- [HTTP/2](../../../http/http2/README.md) — ALPN-selected HTTP/2 protocol path.

## 5. References

- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 7301 — TLS Application-Layer Protocol Negotiation (ALPN)](https://www.rfc-editor.org/rfc/rfc7301)
