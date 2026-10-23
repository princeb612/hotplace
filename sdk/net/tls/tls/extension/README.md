## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Documented with GPT-6                        │
│ Source basis: Revision 1107                  │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# TLS extensions

## 1. Role

The extension layer represents typed extension data nested inside handshake messages. It is responsible for the extension envelope and type-specific payload representation; the surrounding handshake/session logic decides whether an extension is permitted, meaningful, negotiable, or actionable for the current role and protocol version.

Extension type metadata from `tls_advisor` is not itself the payload parser. The advisor maps identifiers to protocol hints; concrete extension objects read and write extension values.

## 2. Data Model

A `tls_extension` is associated with its parent `tls_handshake` and carries an extension type, body size, header range, and total encoded size. Its interface separates `read()`/`write()` from overridable header/body routines. The handshake owns the extension collection, and the extension's parent link provides the context in which its payload is interpreted.

```text
tls_handshake
  └─ tls_extensions
       └─ tls_extension
            ├─ extension type
            ├─ declared body length
            ├─ parent-handshake association
            └─ type-specific payload fields
```

Important intermediate data:

- **Extension envelope:** type and length delimit one extension payload within the parent handshake's extension list.
- **Typed payload:** extension-specific fields such as ALPN protocol names, supported versions/groups, key shares, PSK identities/binders, or QUIC transport parameters.
- **Parent handshake:** provides message context; the same extension identifier may be subject to different role/version/message rules depending on where it appears.
- **Negotiated result:** parsed offer values and selected negotiated values are distinct state. The extension object represents the received or composed value; session/protection or QUIC integration owns the negotiated result.

## 3. Behavior Model

### Parse path

1. A handshake parser reaches an extension list and invokes the extension reader with the parent handshake, direction, input range, and mutable position.
2. The extension envelope parser reads the type and declared payload length, bounding the extension body.
3. Type-specific parsing constructs or selects a concrete representation and decodes its payload.
4. The completed extension is retained in the parent handshake's extension collection. The parser's job is to represent the received value; contextual validation and negotiation remain with the calling protocol path.
5. Session logic interprets the extension in context: for example, offered versus selected protocol versions, client versus server role, and whether the extension is allowed in that message.

### Write path

1. The caller attaches a typed extension object to a handshake and fills its payload fields.
2. The extension writer serializes the payload, computes its body length, and writes the type/length envelope.
3. The parent handshake serializes the extension list as part of its own body. The handshake's outer length is therefore distinct from each extension's length.
4. The complete handshake bytes are passed to the selected TLS record, DTLS publication, or QUIC CRYPTO-frame path.

### Parse result versus negotiated result

```text
extension type + declared length
             |
             v
      bounded payload bytes
             |
             v
     concrete extension parser
             |
             v
      typed extension fields
             |
             +----------------------+
             |                      |
        syntax/length error      parse succeeds
             |                      |
         reject input                v
                           handshake/session context
                         role + message + TLS version
                                      |
                            +---------+---------+
                            |                   |
                       permitted/useful      not permitted
                            |                   |
                    negotiation consumer    reject/ignore/error
                            |
                 protection / ALPN / QUIC state
```

The final contextual branch is not decided by the envelope parser alone. A payload can be structurally decoded yet still be invalid or unusable for the current handshake message, endpoint role, or negotiated protocol version.

### Context and limits

A recognized extension identifier does not prove that its payload is supported or valid in every handshake message, role, or TLS version. Parsing, protocol validation, negotiation, and applying the negotiated result are separate steps.

ALPN contributes to application-protocol selection; it does not route HTTP requests. QUIC transport parameters contribute to QUIC connection configuration; they do not construct packets. Those consumers remain outside the extension representation layer.

## 5. Relationships

- Parent module: [TLS implementation](../../README.md).
- [Handshake messages](../handshake/README.md) — extension collection and enclosing message context.
- [TLS advisor](../../advisor/README.md) — extension identifiers and protocol hints.
- [TLS session support](../../session/README.md) — negotiation state and selected parameters.
- [TLS protection](../../protection/README.md) — negotiated algorithms, transcript, and key schedule.
- [QUIC integration](../../quic/README.md) — QUIC transport parameters and TLS 1.3 handshake integration.
- [HTTP/2](../../../http/http2/README.md) — ALPN-selected application protocol path.

## 6. References

- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 7301 — TLS Application-Layer Protocol Negotiation (ALPN)](https://www.rfc-editor.org/rfc/rfc7301)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
