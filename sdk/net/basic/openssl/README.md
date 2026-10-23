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
# OpenSSL secure sockets

## 1. Role

`sdk/net/basic/openssl` provides the OpenSSL-backed TLS/DTLS socket implementations and the server adapter that selects them for a requested secure scheme. It connects native socket I/O with OpenSSL context and per-connection protocol state; the protocol message/session model itself belongs under `sdk/net/tls/`.

## 2. Data Model

```text
reusable configuration: openssl_tls_context / SSL_CTX
per-connection state:   openssl_tls wrapper + SSL/session
transport endpoint:     concrete TLS or DTLS socket
factory boundary:       openssl_server_socket_adapter
```

`openssl_tls_context` holds reusable OpenSSL configuration: TLS/DTLS method, protocol-version bounds, certificate/private key, cipher/group configuration and peer-verification settings. The wrapper and concrete socket bind that configuration to endpoint-specific SSL/session operations. The adapter maps schemes and delegates lifecycle integration; the builder configures the concrete socket. Neither is the TLS record state machine.

## 3. Behavior Model

### 3.1 Scheme selection and transport

`openssl_server_socket_adapter::get_adapter_scheme` accepts TLS and DTLS schemes and adds the `socket_scheme_openssl` backend marker. QUIC and QUIC2 are not supported by this adapter. The subsequent server-socket builder chooses the concrete class from the transport scheme and backend marker.

- **TLS** is selected as a stream-oriented TCP secure socket. The accepted connection carries an ordered byte stream, and TLS state is managed by the OpenSSL-backed socket/context.
- **DTLS** is selected as a datagram-oriented UDP secure socket. Datagram boundaries and peer addressing remain relevant; it is not just TLS over a UDP socket.
- **QUIC/QUIC2** are not handled by this adapter. Their transport and TLS-handshake integration is in the trial/QUIC path and `sdk/net/tls/quic/`.

### 3.2 Connection to the network server

```text
HTTP/server configuration
  │ chooses an adapter implementation
  ▼
openssl_server_socket_adapter
  │ maps TLS/DTLS scheme to OpenSSL backend
  ▼
server_socket_builder
  │ creates configured secure server socket
  ▼
network_server
  │ accept/event handling and session hand-off
  ▼
network_session / network_stream / protocol
```

The adapter is the configuration/factory boundary; `network_server` owns the broader server lifecycle and event/session orchestration. For HTTP, `http_server_builder` chooses and configures the adapter, while the HTTP server supplies protocol-level behavior above the network layer.

### 3.3 ALPN boundary

The current adapter implementation explicitly handles `h2` by enabling HTTP/2 ALPN on the TLS server socket context. Other protocol strings return `not_supported`. Do not describe this method as a general arbitrary-ALPN registry without checking the implementation.

## 4. Relationships
- `openssl_tls_client_socket.hpp/.cpp`, `openssl_tls_server_socket.hpp/.cpp`
- `openssl_dtls_client_socket.hpp/.cpp`, `openssl_dtls_server_socket.hpp/.cpp`
- `openssl_tls_context.hpp/.cpp`, `openssl_tls_context_sdk.cpp`
- `openssl_server_socket_adapter.hpp/.cpp`
- `../server_socket_adapter.hpp/.cpp` and `../server_socket_builder.hpp/.cpp` — common adapter and concrete-socket selection.
- [Naive sockets](../naive/README.md) — direct TCP/UDP transport without secure protocol state.
- [Trial implementations](../trial/README.md) and [trial socket composer](../trial/trial-socket-composer.md) — separate experimental TLS/DTLS/QUIC composition.
- [Network server](../../server/README.md) — event/session orchestration above the selected server socket.
- [TLS/DTLS/QUIC implementation](../../tls/README.md) — protocol messages, protection, and session behavior.
- [Certificate-generation instructions](../../../../etc/cert/README.md) and [self-signed certificate](../self-signed-certificate.md) — local certificate setup.

## 5. References
No external references are currently listed.
