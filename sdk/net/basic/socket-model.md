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

### Common socket state and contracts

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

`basic_socket` exposes shared TLS capability, native socket type (`SOCK_STREAM` / `SOCK_DGRAM`), reference-counted object lifetime and `socket_scheme_t` transport/security/backend/role bits.

`client_socket` defines client-side connect/open/read/send/receive/close contracts. `server_socket` defines listener setup, listen/accept and server-side I/O. The exact native handle and secure-context state belongs to each concrete backend, not to a universal protocol-session object.

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

### 3.1 Common operation path

```text
caller selects scheme / configures endpoint
                 |
                 v
     concrete client_socket or server_socket
                 |
                 v
          open / connect / listen
                 |
                 v
     native stream or datagram operations
                 |
                 v
     close / backend-specific cleanup
```

The common API hides the concrete implementation, not transport semantics. Connected stream operations read/write an ordered byte stream; datagram operations preserve message boundaries and may require an explicit peer address. Callers must use operations supported by the selected concrete socket.

### 3.2 Resource lifetime

The native socket and any TLS/DTLS backend context have lifetimes that must be respected by the wrapper's open/close path. Reference counting allows higher-level code to retain a socket object across callbacks or session handling, but it does not imply that an already-closed native handle remains usable.

### 3.3 Backend distinction

`naive/` implements direct TCP/UDP operations, `openssl/` integrates secure socket operations with OpenSSL, and `trial/` is an experimental composition area. Capability claims belong to the concrete backend and build configuration, not the shared interface alone.

## 5. Relationships
- `basic_socket.hpp/.cpp`
- `client_socket.hpp/.cpp`
- `server_socket.hpp/.cpp`
- `server_socket_adapter.hpp/.cpp`
- `server_socket_builder.hpp/.cpp`
- [Network basic testcases](../../../test/testcase/net/basic/README.md)
- [Basic socket overview](README.md)
- [Naive socket wrappers](naive/README.md)
- [OpenSSL socket adapter](openssl/openssl-socket-adapter.md)
- [Trial socket composition](trial/trial-socket-composer.md)
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

## 6. References
No external references are currently listed.