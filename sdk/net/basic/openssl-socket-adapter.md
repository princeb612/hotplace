# OpenSSL Socket Adapter

`sdk/net/basic/openssl` adapts the common socket layer to OpenSSL TLS/DTLS connections.

## Context and socket separation

`openssl_tls_context` owns/configures an OpenSSL `SSL_CTX` and provides the reusable TLS/DTLS configuration boundary. It supports:

- TLS or DTLS method selection
- TLS 1.2 / TLS 1.3 selection where supported
- certificate/private-key loading
- certificate chain loading
- cipher and group configuration
- verification mode
- ALPN HTTP/2 support

The socket classes then bind this context to the transport socket:

```text
openssl_tls_context
        ↓
openssl_tls / SSL object
        ↓
openssl_tls_client_socket
openssl_tls_server_socket
openssl_dtls_client_socket
openssl_dtls_server_socket
```

The common `client_socket` / `server_socket` contract remains the entry point for network I/O.

## Server adapter

`openssl_server_socket_adapter` bridges the OpenSSL server-side connection handling with the generic `server_socket`/session path. This keeps OpenSSL-specific accept/handshake details out of the higher network server abstraction.

## Scope

This directory is an integration layer, not the implementation record for TLS itself. TLS handshake messages, extensions, records, key schedule, and QUIC protection belong under `sdk/net/tls/`.

## Related implementation

- `openssl_tls_context.hpp/.cpp`
- `openssl_tls.hpp/.cpp`
- `openssl_tls_client_socket.hpp/.cpp`
- `openssl_tls_server_socket.hpp/.cpp`
- `openssl_dtls_client_socket.hpp/.cpp`
- `openssl_dtls_server_socket.hpp/.cpp`
- `openssl_server_socket_adapter.hpp/.cpp`

## Related notes

- `self-signed-certificate.md` remains as the existing certificate-generation/setup note.
