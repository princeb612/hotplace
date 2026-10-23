## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# OpenSSL Socket Adapter

## 1. Role

The OpenSSL backend adapts the common `client_socket`/`server_socket` contract to TLS and DTLS using OpenSSL context/session objects. The server adapter is the backend-selection/configuration boundary used by the server socket builder; it is not the generic network-server event loop or the TLS protocol model.

## 2. Data Model

### Context and socket data

`openssl_tls_context` stores reusable OpenSSL configuration through the `SSL_CTX` boundary: TLS/DTLS method, protocol-version flags, certificate/private-key settings, cipher/group configuration and peer verification. `openssl_tls` and the concrete socket classes bind this configuration to endpoint-specific SSL/session operations.

```text
openssl_tls_context
  └─ reusable SSL_CTX configuration

per-connection endpoint
  ├─ openssl_tls wrapper / SSL session
  └─ native socket + transport context
```

### Server adapter and builder

`openssl_server_socket_adapter` implements the common `server_socket_adapter` interface and represents the OpenSSL backend choice. Its supported scheme set is TLS and DTLS; QUIC and QUIC2 are not supported by this adapter. The corresponding `trial_server_socket_adapter` shares the interface but supports TLS, DTLS, QUIC, and QUIC2. The shared interface therefore hides a common selection API, not identical scheme support or implementation behavior.

## 3. Behavior Model

### 3.1 Scheme mapping and socket construction
The builder applies certificate/key, cipher, group, and verification settings to the selected concrete socket. The OpenSSL adapter's `get_adapter_scheme()` accepts TLS and DTLS and adds `socket_scheme_openssl`; the builder then selects `openssl_tls_server_socket` or `openssl_dtls_server_socket`. QUIC/QUIC2 selection belongs to the trial adapter.


```text
requested TLS / DTLS scheme
            |
            v
openssl_server_socket_adapter::get_adapter_scheme()
            |
            v
add socket_scheme_openssl
            |
            v
server_socket_builder
            |
            +-- TLS  -> openssl_tls_server_socket
            |
            +-- DTLS -> openssl_dtls_server_socket
```

The OpenSSL adapter supports TLS and DTLS only. QUIC/QUIC2 are not mapped to this backend; the trial adapter owns that selection path.

### 3.2 TCP/TLS versus UDP/DTLS

- **TLS:** TCP supplies an ordered byte stream. The OpenSSL TLS socket reads/writes TLS-protected data through the stream connection.
- **DTLS:** UDP supplies datagrams. The OpenSSL DTLS socket retains datagram semantics and peer-address handling; it is not ordinary TLS records sent over UDP.
- **QUIC:** not supported by this OpenSSL adapter. The QUIC path uses the trial adapter/composer and `sdk/net/tls/quic/` implementation.

### 3.3 Handoff to network_server

```text
http_server_builder / server configuration
       │ chooses adapter
       ▼
openssl_server_socket_adapter
       │ scheme mapping + context startup/shutdown
       ▼
server_socket_builder -> concrete TLS/DTLS server socket
       ▼
network_server
       │ accept / multiplexer / TLS-accept / session lifecycle
       ▼
network_session -> network_stream -> network_protocol
```

The adapter creates or retrieves the configured server socket and delegates backend-specific startup/shutdown. `network_server` owns the listening/event lifecycle and session orchestration above it. The TLS accept/handshake stage is a separate network-server worker path; it should not be conflated with the adapter's scheme mapping.

### 3.4 ALPN configuration

The current `enable_alpn()` implementation explicitly handles `h2` by enabling HTTP/2 ALPN on the TLS server context. Other strings return `not_supported`; this is not a general arbitrary-ALPN implementation.

This document describes the integration boundary. TLS handshake messages, extensions, records, key schedule, and QUIC protection belong under `sdk/net/tls/`.

## 4. Relationships
- `openssl_tls_context.hpp/.cpp`, `openssl_tls.hpp/.cpp`
- `openssl_tls_client_socket.hpp/.cpp`, `openssl_tls_server_socket.hpp/.cpp`
- `openssl_dtls_client_socket.hpp/.cpp`, `openssl_dtls_server_socket.hpp/.cpp`
- `openssl_server_socket_adapter.hpp/.cpp`
- `../server_socket_adapter.hpp/.cpp`, `../server_socket_builder.hpp/.cpp` — common adapter contract and concrete socket selection.
- [OpenSSL socket implementation](README.md) — backend classes and their roles.
- [Trial implementation](../trial/README.md) and [trial composer](../trial/trial-socket-composer.md) — alternate experimental backend and QUIC handshake path.
- [Socket model](../socket-model.md) — common socket contract and scheme bits.
- [Network server](../../server/README.md) — accept/event/session orchestration.
- [TLS/DTLS/QUIC layer](../../tls/README.md) — protocol/session behavior.
- [Certificate setup](self-signed-certificate.md) — local certificate-generation note.

## 5. References
No external references are currently listed.
