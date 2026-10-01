# Trial Socket and TLS Composer

`sdk/net/basic/trial` is the experimental composition layer used while developing secure socket and handshake flows.

It is deliberately separate from the stable `naive` transport and OpenSSL adapter implementations.

## Main roles

- `trial_*_client_socket` / `trial_*_server_socket` — experimental socket implementations
- `secure_client_socket` / `secure_prosumer` — secure transport composition
- `client_socket_prosumer` — producer/consumer style socket integration
- `tls_composer` — composition of TLS handshake messages and transport behavior
- `tls_composer_tls_handshake.cpp` — TLS handshake path
- `tls_composer_dtls_*` / related paths — DTLS experiments
- `tls_composer_quic_handshake.cpp` — TLS handshake material used by QUIC

The important point is that `trial` is not another permanent protocol layer. It is where experimental combinations are assembled before or alongside the more established network/session implementation.

## QUIC relationship

The QUIC composer path demonstrates the boundary between transport and TLS:

```text
QUIC connection
    ↓
TLS handshake composition
    ↓
TLS handshake messages / crypto data
    ↓
QUIC CRYPTO frames
```

The actual QUIC packet/frame implementation belongs under `sdk/net/tls/quic/`.

## Source

- `trial_*_socket.*`
- `secure_client_socket.*`
- `secure_prosumer.*`
- `client_socket_prosumer.*`
- `tls_composer.*`
- `tls_composer_construct.cpp`
- `tls_composer_tls_handshake.cpp`
- `tls_composer_quic_handshake.cpp`

## Status

This directory is experimental by design. The document records the current implementation boundary and should not be interpreted as a statement that every trial path is the primary production path.
