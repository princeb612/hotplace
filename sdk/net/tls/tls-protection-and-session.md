# TLS protection and session model

## Role

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

## Protection

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

## Session

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
   ┌────┼───────────────┐
   ▼    ▼               ▼
 TLS   DTLS            QUIC
   │    │                │
   ▼    ▼                ▼
records / handshake / protection
```

## SSLKEYLOG

The session area also contains SSLKEYLOG import/export helpers. These are useful for external packet-analysis workflows because the key material can be associated with captured traffic without making the packet capture itself part of the TLS object model.

## Related areas

- `../basic/` — socket and OpenSSL transport adapters
- `../session/` — stateful TLS/DTLS/QUIC processing
- `../quic/` — QUIC packet/frame implementation
- `sdk/crypto/` — underlying HKDF, HMAC, AEAD and signature/key operations

## Related tests

- `testcase_tls12_aead.cpp`
- `testcase_rfc8448_2.cpp`
- `testcase_rfc8448_5.cpp`
- `testcase_rfc8448_6.cpp`
- `testcase_rfc8448_7.cpp`
- `testcase_pre_master_secret.cpp`
- `testcase_dtls_record_arrange.cpp`
