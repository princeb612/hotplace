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
# TLS protection and session model

## 1. Role


The TLS implementation separates protocol messages from the state that makes those messages secure and usable over a transport.

```text
TLS messages
    │
    ├── record / handshake / extension
    │
    ▼
protection
    │
    ├── transcript hash
    ├── key schedule
    ├── key block / traffic secrets
    ├── AEAD / CBC-HMAC
    └── header protection
    │
    ▼
session / transport integration
```

This boundary is important when reading the source: a handshake class describes a protocol message, while `tls_protection` calculates or applies the cryptographic state needed to protect that message or record.

## 2. Data Model

### Protection

The `protection/` implementation contains the calculation and encryption paths for TLS/DTLS protection.

Major components include:

- `tls_protection`
- `tls_protection_context`
- `tls_protection_calc`
- finished / key-block / PSK calculations
- transcript hashing
- AEAD encryption
- CBC-HMAC encryption
- QUIC header protection

The existing study documents provide detailed notes for the key schedule, transcript hash and MtE/EtM comparison. They should remain as the detailed study layer rather than being duplicated here.

### Session

The `session/` layer holds stateful processing above individual protocol objects.

Current implementation areas include:

- `tls_session`
- DTLS record arrangement/publishing
- QUIC packet publishing
- `quic_session`
- QUIC stream support
- SSLKEYLOG import/export

The session layer therefore connects protocol state to actual transport processing:

```text
socket / network stream
        │
        ▼
      session
        │
   ┌────┼────────────────┐
   ▼    ▼                ▼
 TLS   DTLS            QUIC
   │    │                │
   ▼    ▼                ▼
records / handshake / protection
```

### SSLKEYLOG

The session area also contains SSLKEYLOG import/export helpers. These are useful for external packet-analysis workflows because the key material can be associated with captured traffic without making the packet capture itself part of the TLS object model.

## 3. Behavior Model

Protection and session state span multiple messages. Transcript hashes evolve as handshake messages are processed; key schedule outputs depend on protocol version and handshake branch; record/packet encryption consumes the resulting protection context. Do not treat a test of one TLS 1.2 AEAD record as evidence of TLS 1.3 key-schedule coverage, or vice versa.

Session-owned DTLS/QUIC helpers are transport-specific. DTLS record publishing/arrangement addresses record fragmentation/order, while QUIC packet publication operates on QUIC packets and frames. SSLKEYLOG data is sensitive traffic-secret material and should be handled as a secret, even when used only for packet analysis.

## 4. Relationships



- `protection/tls_protection*.cpp`
- `session/tls_session.cpp`, `session/dtls_record_arrange.cpp`, `session/dtls_record_publisher.cpp`
- `session/quic_packet_publisher.cpp`, `session/quic_session.cpp`, `session/quic_streams.cpp`
- `session/sslkeylog_exporter.cpp`, `session/sslkeylog_importer.cpp`
- [TLS protection overview](protection/README.md)
- [TLS session overview](session/README.md)
- [TLS/DTLS/QUIC overview](README.md)
- [TLS message model](tls-message-model.md)
- [TLS advisor](tls_advisor.md)
- [QUIC/TLS integration](quic-tls-integration.md)
### Related areas

- `../basic/` — socket and OpenSSL transport adapters
- `../session/` — stateful TLS/DTLS/QUIC processing
- `../quic/` — QUIC packet/frame implementation
- `sdk/crypto/` — underlying HKDF, HMAC, AEAD and signature/key operations

## 5. References

- [RFC 5246 — TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
