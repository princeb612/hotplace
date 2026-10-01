# Socket Model

The basic network socket layer separates the common socket contract from concrete transport and security implementations.

## Class hierarchy

```text
basic_socket
├── client_socket
│   ├── naive TCP/UDP clients
│   ├── OpenSSL TLS/DTLS clients
│   └── trial clients
└── server_socket
    ├── naive TCP/UDP servers
    ├── OpenSSL TLS/DTLS servers
    └── trial servers
```

`basic_socket` exposes the properties shared by the implementations:

- whether TLS is supported
- socket type (`SOCK_STREAM` / `SOCK_DGRAM`)
- reference counting
- `socket_scheme_t`-based scheme identification

`client_socket` provides the common client operations (`connect`, `open`, `read`, `send`, `recvfrom`, `sendto`, and close) while `server_socket` provides listen/accept and server-side I/O operations.

The concrete class therefore selects transport and security without changing the common caller-facing model.

## Scheme model

The implementation uses combinations such as:

```text
TCP + CLIENT
UDP + SERVER
TLS + OPENSSL + CLIENT
DTLS + OPENSSL + SERVER
TLS + TRIAL + CLIENT
```

This scheme information is useful to higher layers when they need to distinguish transport, security backend, and endpoint role.

## Boundary with higher layers

`basic` is intentionally below the protocol/session layers:

```text
HTTP / application
        ↓
TLS / QUIC / network session
        ↓
sdk/net/basic
        ↓
OS socket API
```

The `server` layer builds sessions and network streams above this abstraction; `tls` adds protocol-specific TLS/DTLS/QUIC behavior.

## Source

- `basic_socket.hpp/.cpp`
- `client_socket.hpp/.cpp`
- `server_socket.hpp/.cpp`
- `server_socket_adapter.hpp/.cpp`
- `server_socket_builder.hpp/.cpp`

## Tests

The common socket classes are exercised mainly through the concrete network test programs rather than a single exhaustive `basic_socket` unit test. `test/testcase/net/basic/` contains the current basic-network tests.
