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
# OpenSSL Socket Adapter

## 1. Role

The OpenSSL backend adapts the common `client_socket`/`server_socket` contract to TLS and DTLS using OpenSSL context/session objects. The server adapter is the backend-selection/configuration boundary used by the server socket builder; it is not the generic network-server event loop or the TLS protocol model.

## 2. Data Model

### Context and socket separation

`openssl_tls_context` configures the reusable OpenSSL `SSL_CTX` boundary, including TLS/DTLS method selection, protocol-version flags, certificate/private-key loading, cipher/group configuration, and peer verification. The `openssl_tls` wrapper and concrete socket classes bind that context to individual client/server transport operations.

```text
openssl_tls_context
        │ configuration / SSL_CTX
        ▼
     openssl_tls
        │ per-connection SSL state
        ▼
  ┌───────────────────────────┐
  │ TLS socket: TCP stream    │
  │ DTLS socket: UDP datagram │
  └───────────────────────────┘
```

### Server adapter and builder

`openssl_server_socket_adapter` implements the common `server_socket_adapter` interface. Its `get_adapter_scheme()` accepts TLS and DTLS and adds the `socket_scheme_openssl` marker; QUIC and QUIC2 are unsupported by this adapter. The `server_socket_builder` then selects `openssl_tls_server_socket` for TLS or `openssl_dtls_server_socket` for DTLS and applies the certificate/key, cipher, group, and verification settings.

The corresponding `trial_server_socket_adapter` shares the adapter interface but supports TLS, DTLS, QUIC, and QUIC2 by adding `socket_scheme_trial`. The shared interface therefore hides a common selection API, not identical scheme support or implementation behavior.

## 3. Behavior Model

### TCP/TLS versus UDP/DTLS

- **TLS:** TCP supplies an ordered byte stream. The OpenSSL TLS socket reads/writes TLS-protected data through the stream connection.
- **DTLS:** UDP supplies datagrams. The OpenSSL DTLS socket retains datagram semantics and peer-address handling; it is not ordinary TLS records sent over UDP.
- **QUIC:** not supported by this OpenSSL adapter. The QUIC path uses the trial adapter/composer and `sdk/net/tls/quic/` implementation.

### Handoff to network_server

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
- [Certificate setup](openssl/self-signed-certificate.md) — local certificate-generation note.

## 5. References

No external references are currently listed.
