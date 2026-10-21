## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# TLS message model

## 1. Role


`sdk/net/tls/tls` is the wire-message model for TLS and DTLS. It separates the three major protocol objects used by the implementation:

```text
TLS / DTLS
   │
   ├── record
   │     └── carries handshake / alert / application data
   │
   ├── handshake
   │     └── ClientHello / ServerHello / Certificate / Finished ...
   │
   └── extension
         └── SNI / ALPN / key_share / PSK / supported_versions ...
```

The classes are primarily responsible for representing, encoding and decoding protocol messages. Cryptographic state is handled by `protection/`, while session-level sequencing and transport integration are handled by `session/` and the surrounding network layer.

## 2. Data Model

### Record layer

The record classes represent TLS record content and the DTLS-specific ciphertext path.

Important implementation areas include:

- `tls_record` / `tls_records`
- `tls_record_handshake`
- `tls_record_application_data`
- `tls_record_alert`
- `tls_record_change_cipher_spec`
- `dtls13_ciphertext`
- record builders

Conceptually:

```text
handshake / application / alert
             │
             ▼
        TLS record
             │
       protection
             │
             ▼
       wire ciphertext
```

DTLS adds transport-specific sequencing and fragmentation concerns; those are complemented by the session-level DTLS record arrangement/publishing code.

### Handshake layer

The handshake model is divided into a common collection and message-specific classes. The implementation contains both TLS 1.2-era messages and TLS 1.3 messages, including:

- ClientHello / ServerHello
- HelloRetryRequest-related handling
- EncryptedExtensions
- Certificate / CertificateVerify
- Finished
- NewSessionTicket
- ClientKeyExchange / ServerKeyExchange
- DTLS HelloVerifyRequest
- fragmented DTLS handshake support

The builder/collection classes provide the common construction and dispatch boundary.

A useful implementation view is:

```text
record
  ↓
handshake collection
  ↓
message-specific handshake object
  ↓
extension / key / certificate fields
```

The RFC documents in this directory remain the protocol-study references; this document records how those concepts map to hotplace classes.

### Extension layer

TLS extensions are represented independently so that ClientHello, ServerHello and related messages can compose extension objects without embedding every extension into the handshake class itself.

Implemented examples include:

- SNI
- ALPN / ALPS
- supported_versions
- supported_groups
- key_share
- signature_algorithms
- pre_shared_key
- psk_key_exchange_modes
- early_data
- QUIC transport parameters
- encrypted_client_hello
- certificate compression
- status_request

The extension builder/collection classes form the common dispatch boundary.

## 3. Behavior Model

The record, handshake and extension objects are different representation layers. A record carries a content type and version/length framing; a handshake record can contain a sequence of handshake messages; each handshake message has its own type-specific fields, some of which contain an extension collection. Builders/collections provide the construction and dispatch boundary, while message-specific classes own field encoding/decoding.

Do not confuse the message object model with handshake state: whether a message is expected, which keys protect it, and what state transition follows are session/protection concerns. DTLS fragmentation/reordering is also a session/transport concern even though it carries the same handshake message family.

## 4. Relationships



- `sdk/net/tls/tls/record/`
- `sdk/net/tls/tls/handshake/`
- `sdk/net/tls/tls/extension/`
- `sdk/net/tls/protection/`
- `sdk/net/tls/session/`
- [TLS/DTLS/QUIC overview](README.md)
- [TLS protection/session model](tls-protection-and-session.md)
- [TLS 1.2 summary](rfc5246.md)
- [TLS 1.3 summary](rfc8446.md)
- [DTLS 1.3 summary](rfc9147.md)
- `tls/record/`, `tls/handshake/`, and `tls/extension/` — concrete message representations.
- `protection/` — transcript hash, key schedule and record protection.
- `session/` — session state and DTLS/QUIC publication/arrangement.
- `advisor/` — protocol identifier and parameter lookup.
- `test/testcase/tls/` — construction, alert, HelloRetryRequest and TLS 1.2/1.3 source examples.

## 5. References

- [RFC 5246 — TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246)
- [RFC 6347 — DTLS 1.2](https://www.rfc-editor.org/rfc/rfc6347)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 9147 — DTLS 1.3](https://www.rfc-editor.org/rfc/rfc9147)
