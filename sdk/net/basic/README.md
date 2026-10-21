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

```text
basic_socket
  ├─ client_socket
  │    ├─ naive TCP / UDP clients
  │    ├─ OpenSSL TLS / DTLS clients
  │    └─ trial clients + prosumer composition
  └─ server_socket
       ├─ naive TCP / UDP servers
       ├─ OpenSSL TLS / DTLS servers
       └─ trial secure/QUIC server sockets

Selection / policy helpers
  server_socket_adapter -> server_socket_builder
  ipaddr_acl
```

The adapter maps a configured scheme to a backend; the builder constructs the concrete socket. Neither object is the handshake state machine. `ipaddr_acl` is a separate policy evaluator: it returns an allow/deny decision for an address, and the caller enforces that decision. Its rule representation, IPv4/IPv6 handling, and conflict semantics are documented in [IP address ACL](ipaddr/README.md); the [ipaddr module README](ipaddr/README.md) covers the module boundary rather than duplicating the algorithm.

## 3. Behavior Model

The server layer selects a socket through the adapter/builder path and then passes the socket into `network_server`, which owns accept/event processing and session hand-off.

- **naive:** TCP uses stream operations; UDP uses datagrams with peer addresses.
- **OpenSSL:** TCP is paired with TLS, while UDP is paired with DTLS.
- **trial:** transport I/O and handshake/session state are composed through prosumer and composer helpers. QUIC uses UDP datagrams but has QUIC packet/frame handling and TLS 1.3 handshake integration; it is not DTLS.
- **ACL:** evaluate the peer address at the relevant admission boundary and act on the result. The ACL does not install itself as a socket filter.

## 4. Relationships

- [Socket model](socket-model.md) — shared client/server contracts and scheme metadata.
- [Naive sockets](naive/README.md) — direct TCP/UDP.
- [OpenSSL sockets](openssl/README.md) and [OpenSSL socket adapter](openssl/openssl-socket-adapter.md) — TLS/DTLS backend selection.
- [Trial implementations](trial/README.md) and [trial socket composer](trial/trial-socket-composer.md) — prosumer and handshake flow.
- [IP address ACL](ipaddr/README.md) — rule storage, IPv4/IPv6 handling, whitelist/blacklist defaults, and determination behavior.
- [IP ACL module](ipaddr/README.md) — module API and implementation organization.
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
