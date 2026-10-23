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
# Network socket and TLS/QUIC trial implementations

## 1. Role

`sdk/net/basic/trial` is the experimental integration path for composing socket I/O, producer/consumer buffering, TLS/DTLS session state, and QUIC handshake packets. Unlike `naive/`, it is not only a direct transport wrapper; unlike `openssl/`, it does not delegate the complete TLS/DTLS socket protocol implementation to OpenSSL.

## 2. Data Model

```text
server-side factory: trial_server_socket_adapter + server_socket_builder
transport endpoints: trial TCP / UDP / TLS / DTLS / QUIC sockets
composition state:   client_socket_prosumer / secure_client_socket /
                     secure_prosumer
protocol state:      tls_session + tls_protection
handshake driver:    tls_composer
publication helpers: TLS record / DTLS record / QUIC packet publishers
```

The trial adapter marks TLS, DTLS, QUIC and QUIC2 schemes with `socket_scheme_trial`; the builder uses that scheme to choose the concrete server socket. The objects above are cooperating layers: factory metadata selects an endpoint, prosumer objects coordinate I/O and buffering, session/protection objects retain protocol state, and the composer drives handshake construction. Plain TCP/UDP server implementations remain in `naive/`.

## 3. Behavior Model

### 3.1 Connection to network_server

```text
HTTP/server configuration
  │ selects trial_server_socket_adapter
  ▼
server_socket_builder
  │ constructs trial TLS / DTLS / QUIC server socket
  ▼
network_server
  │ accept / multiplexer / TLS-accept and event loops
  ▼
network_session / network_stream / protocol
```

The adapter and builder create the concrete socket. `network_server` remains responsible for the server lifecycle, event/multiplexer coordination, and session hand-off. The trial socket and session/composer code implement the transport-specific I/O and handshake behavior below that orchestration layer.

### 3.2 Distinguishing TCP/TLS, UDP/DTLS, and QUIC

- **TCP trial socket:** `trial_tcp_*_socket` uses stream socket operations through `client_socket_prosumer`. Reads are byte-stream reads; they do not preserve application message boundaries.
- **TLS trial socket:** `trial_tls_*_socket` uses a stream socket and a TLS session. Application data is represented as TLS records before it is sent over the stream.
- **UDP trial socket:** `trial_udp_*_socket` uses datagram operations and peer addresses.
- **DTLS trial socket:** `trial_dtls_*_socket` uses a datagram socket and DTLS session state. It serializes application data into DTLS records and sends via `sendto`; the composer delegates DTLS record publication/fragmentation to `dtls_record_publisher`.
- **QUIC trial socket:** QUIC uses UDP datagrams but is neither TLS-over-UDP nor DTLS. The QUIC packet publisher carries TLS 1.3 handshake data in QUIC CRYPTO frames and owns QUIC packet construction.

### 3.3 Producer/consumer and handshake flow

The prosumer layer coordinates socket input/output and buffering. Incoming bytes are consumed by the session-processing path, which updates `tls_session` and its handshake status. The composer waits for those status changes, constructs the next handshake flight, serializes it through the TLS/DTLS record path or QUIC packet path, and invokes the supplied callback to send/publish the bytes. The callback, socket read path, and status updates are separate responsibilities; a complete flow requires tracing all of them.

The trial implementation is experimental. In particular, the existence of TLS/DTLS/QUIC classes should not be interpreted as proof of feature parity or complete production-ready handshakes across all versions and paths.

## 4. Relationships
- `trial_server_socket_adapter.hpp/.cpp` — scheme mapping and adapter API.
- `trial_*_socket.hpp/.cpp` — concrete transport-specific socket operations.
- `client_socket_prosumer.hpp/.cpp`, `secure_client_socket.hpp/.cpp`, `secure_prosumer.hpp/.cpp` — socket I/O, queueing, and secure-data composition.
- `tls_composer.hpp/.cpp`, `tls_composer_construct.cpp`, `tls_composer_tls_handshake.cpp`, `tls_composer_quic_handshake.cpp` — handshake construction and publication flow; see [trial socket composer](trial-socket-composer.md).
- `../server_socket_adapter.hpp/.cpp` and `../server_socket_builder.hpp/.cpp` — common adapter and concrete-socket factory.
- [Naive sockets](../naive/README.md) — direct TCP/UDP transport.
- [OpenSSL sockets](../openssl/README.md) — separate OpenSSL-backed TLS/DTLS backend.
- [Network server](../../server/README.md) — server event/session orchestration.
- [TLS/DTLS/QUIC implementation](../../tls/README.md) — session state, record protection, DTLS publisher, and QUIC packet/frame layer.

## 5. References
No external references are currently listed.

## 7. Developer Notes

The trial adapter maps TLS/DTLS/QUIC/QUIC2 to the trial backend, while the OpenSSL adapter maps only TLS/DTLS to OpenSSL. Keep this backend-selection difference visible when documenting server configuration; the two adapters share an interface but not the same scheme support.
