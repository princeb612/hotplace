## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1106                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Basic Network Socket Layer

## 1. Role

`basic` provides the low-level socket contracts and concrete transport backends used by the higher network layers. It separates socket lifecycle and I/O from server orchestration, session state, protocol framing, and application handling.

- `basic_socket`, `client_socket`, `server_socket` define the common socket contracts.
- `naive/` implements direct TCP/UDP transport.
- `openssl/` integrates TLS/DTLS through OpenSSL.
- `trial/` composes socket I/O, producer/consumer buffering, protocol session state, and handshake publication.
- `ipaddr/` provides address-based access-control rules.

These backends share some interfaces, but TCP/TLS stream I/O, UDP/DTLS datagram I/O, and QUIC packet processing are not interchangeable.

## 2. Data Model

### Common socket contract

`basic_socket` is the shared identity/lifetime layer. It exposes socket type, TLS capability, scheme metadata and reference-counted object lifetime. `client_socket` and `server_socket` add endpoint-specific operations rather than defining a protocol session.

| Model | Main data and responsibility |
|---|---|
| `basic_socket` | Socket type, TLS capability, scheme bits and object reference count |
| `client_socket` | Client endpoint operations: open/connect, stream read/send, datagram receive/send and close |
| `server_socket` | Listener operations: open/bind/listen, accept and server-side I/O |
| `server_socket_adapter` | Maps a requested scheme to a backend-qualified scheme; adapter-level startup/shutdown integration |
| `server_socket_builder` | Uses scheme and supplied configuration to construct/configure the concrete server socket |
| `ipaddr_acl` | Independent address-rule set and whitelist/blacklist policy; not socket state |

### Concrete backend families

```text
client_socket                       server_socket
  ├─ naive TCP / UDP                  ├─ naive TCP / UDP
  ├─ OpenSSL TLS / DTLS               ├─ OpenSSL TLS / DTLS
  └─ trial transport / secure path    └─ trial TLS / DTLS / QUIC
```

The shared hierarchy expresses a common calling contract, not equal capabilities. TCP is stream-oriented; UDP is datagram-oriented; TLS and DTLS preserve their underlying transport semantics; QUIC has its own packet and frame model. Concrete backend state is described in the child documents.

## 3. Behavior Model

### 3.1 Server backend selection and hand-off

```text
application/server configuration
        |
        v
server_socket_adapter::get_adapter_scheme()
        |
        v
transport + security + backend scheme bits
        |
        v
server_socket_builder
        |
        v
concrete server_socket
        |
        v
network_server
        |
        v
accept / event processing / session hand-off
        |
        v
network_session / network_stream / protocol
```

The adapter maps the requested scheme to a backend marker; the builder creates and configures the concrete socket; `network_server` owns listener events, accept processing and session hand-off. The adapter and builder do not implement the TLS handshake or application protocol.

### 3.2 Backend-specific transport path

- **naive:** TCP reads/writes an ordered byte stream; UDP sends/receives discrete datagrams and may carry a peer address.
- **OpenSSL:** TCP is paired with TLS; UDP is paired with DTLS. The OpenSSL socket/context owns secure transport operations.
- **trial:** socket I/O and producer/consumer buffering feed session processing. Session status changes drive `tls_composer`, which publishes TLS records, DTLS records or QUIC packets depending on the path.
- **QUIC:** uses UDP as its datagram carrier, but its packet/frame layer and TLS 1.3 handshake integration are distinct from DTLS.

### 3.3 Address admission is a separate policy step

`ipaddr_acl` normalizes and evaluates a peer address, returning an allow/deny result. The server/socket caller chooses where to invoke it and enforces the result; the ACL is not automatically installed as a socket filter.

The applet sources show concrete selection points: `tlsserver` and `dtlsserver` add either `socket_scheme_openssl` or `socket_scheme_trial`; `httpserver1` and `httpserver2` configure an adapter through `http_server_builder`; `netclient` exposes `-T` for the trial client path. These paths share the socket contract, but not universal protocol/certificate compatibility.

## 4. Relationships
- [Socket model](socket-model.md) — shared client/server contracts and scheme metadata.
- [Naive sockets](naive/README.md) — direct TCP/UDP.
- [OpenSSL sockets](openssl/README.md) and [OpenSSL socket adapter](openssl/openssl-socket-adapter.md) — TLS/DTLS backend selection.
- [Trial implementations](trial/README.md) and [trial socket composer](trial/trial-socket-composer.md) — prosumer and handshake flow.
- [IP address and ACL](ipaddr/README.md) — module API, normalized address/rule model, whitelist/blacklist behavior, and conflict resolution.
- [Network server](../server/README.md) — accept, multiplexer, session, stream, and protocol orchestration.
- [TLS/DTLS/QUIC](../tls/README.md) — protocol state, record protection, and QUIC packet/frame handling.

## 5. References
No external references are currently listed.

## 6. Developer Notes
### Class-family orientation

This is a compact orientation map, not a UML inheritance claim.

```text
basic_socket
  client_socket
    naive_tcp_client_socket / naive_udp_client_socket
    openssl_tls_client_socket / openssl_dtls_client_socket
    client_socket_prosumer
      secure_client_socket
        trial_tls_client_socket / trial_dtls_client_socket
      trial_tcp_client_socket / trial_udp_client_socket
  server_socket
    naive_tcp_server_socket / naive_udp_server_socket
    openssl_tls_server_socket / openssl_dtls_server_socket
    trial_tls_server_socket / trial_dtls_server_socket / trial_quic_server_socket

server_socket_adapter
  openssl_server_socket_adapter
  trial_server_socket_adapter
```

Read the socket contract first, then the backend selected by the scheme. For trial handshake details, trace socket I/O, session status updates, and composer publication together.
