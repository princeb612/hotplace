# TLS message model

## Role

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

## Record layer

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

## Handshake layer

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

## Extension layer

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

## Related source

- `sdk/net/tls/tls/record/`
- `sdk/net/tls/tls/handshake/`
- `sdk/net/tls/tls/extension/`
- `sdk/net/tls/protection/`
- `sdk/net/tls/session/`

## Related tests

Representative tests include:

- `testcase_construct_tls.cpp`
- `testcase_construct_dtls12_1.cpp`
- `testcase_construct_dtls12_2.cpp`
- `testcase_construct_dtls13.cpp`
- `testcase_helloretryrequest.cpp`
- `testcase_alert.cpp`
- `testcase_understand_tls12.cpp`
- `testcase_understand_tls13.cpp`
