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
# Socket Model

## 1. Role

The basic network socket layer separates the common socket contract from concrete transport and security implementations.

## 2. Data Model

### Class hierarchy

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

### Scheme model

The implementation uses combinations such as:

```text
TCP + CLIENT
UDP + SERVER
TLS + OPENSSL + CLIENT
DTLS + OPENSSL + SERVER
TLS + TRIAL + CLIENT
```

This scheme information is useful to higher layers when they need to distinguish transport, security backend, and endpoint role.

## 3. Behavior Model

### Common contract versus backend behavior

The common socket classes expose the caller-facing operations and scheme identity, while concrete implementations decide how native sockets and secure backends are created and driven. A caller should not assume that every operation is meaningful for both stream and datagram sockets; for example, peer-address-oriented `sendto`/`recvfrom` belongs to datagram use, while connected stream operations follow the connected endpoint.

### Resource lifetime

The native socket and any TLS/DTLS backend context have resource lifetimes that must be respected by the wrapper's open/close path. Reference counting allows higher-level code to retain socket objects across callbacks or session handling, but it does not by itself imply that an already-closed native handle remains usable.

### Backend distinction

`naive/` implements direct TCP/UDP operations, `openssl/` integrates secure socket operations with OpenSSL, and `trial/` is an experimental composition area. Keep capability claims tied to the concrete backend and build configuration.

## 4. Relationships



- `basic_socket.hpp/.cpp`
- `client_socket.hpp/.cpp`
- `server_socket.hpp/.cpp`
- `server_socket_adapter.hpp/.cpp`
- `server_socket_builder.hpp/.cpp`
- [Network basic testcases](../../../test/testcase/net/basic/README.md)
- [Basic socket overview](README.md)
- [Naive socket wrappers](naive/README.md)
- [OpenSSL socket adapter](openssl-socket-adapter.md)
- [Trial socket composition](trial-socket-composer.md)
- [Network server](../server/README.md)
### Boundary with higher layers

```text
HTTP / application protocol
          ↓
server session and/or secure transport
          ↓
sdk/net/basic socket abstraction
          ↓
OS socket API
```

- `sdk/net/server/` builds session and event-processing behavior above sockets.
- `sdk/net/tls/` implements TLS/DTLS/QUIC-specific processing and may use secure socket backends.
- `sdk/net/http/` consumes the appropriate transport/session path for HTTP protocol processing.

The diagram is a responsibility stack, not a required call sequence for every application.

## 5. References

No external references are currently listed.