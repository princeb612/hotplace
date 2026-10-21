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

# Trial Socket and TLS Composer

## 1. Role

The trial backend composes socket I/O, asynchronous producer/consumer buffering, TLS/DTLS session state, and handshake construction. The socket classes provide transport-specific send/receive operations; `secure_prosumer` and `secure_client_socket` connect those operations to secure session processing; `tls_composer` constructs handshake flights and publishes encoded output through callbacks.

The composer is not a socket, does not own the network destination, and does not parse arbitrary incoming bytes itself. Its progress depends on the receive/session path updating handshake status.

## 2. Data Model

### Secure socket and prosumer relationship

```text
trial_tls_server_socket / secure_client_socket
                   │
                   ▼
          secure_prosumer
          ├─ socket input/output integration
          ├─ producer / consumer coordination
          └─ buffers received and outgoing data
                   │
                   ▼
              tls_session
              ├─ handshake status
              ├─ protocol/version state
              └─ tls_protection
                   ▲
                   │ observes status / constructs next flight
              tls_composer
                   │ encoded bytes via callback
                   ▼
             send/publish path
```

On the server, `trial_tls_server_socket` is selected by `trial_server_socket_adapter` and `server_socket_builder`; `network_server` owns accept/event orchestration and invokes the socket's TLS-accept path before attaching the established session to normal processing. The secure prosumer/composer relationship supplies the protocol-specific work below that server orchestration.

On the client, `secure_client_socket` uses the client prosumer path. `secure_prosumer` connects socket activity to the session processing path and coordinates the composer callback. These are cooperating objects and asynchronous paths, not necessarily one nested synchronous call stack.

### Transport-specific publication

| Session type | Encoding/publication path | Transport behavior |
|---|---|---|
| TLS | Handshake messages → TLS records | TCP byte stream |
| DTLS | Handshake messages → DTLS records → fragmentation/publication | UDP datagrams with peer address |
| QUIC / QUIC2 | TLS 1.3 handshake bytes → CRYPTO frames → QUIC packets | UDP datagrams with QUIC packet/stream state |

QUIC is not TLS-over-UDP or DTLS. The handshake messages and key schedule are related to TLS 1.3, but QUIC has its own packet-number spaces, packet protection, and frame encoding.

## 3. Behavior Model

### Client handshake flow

The client calls `tls_composer::handshake(from_client, timeout, callback)`. The composer constructs a ClientHello and then waits for state transitions produced by the receive/session path.

```text
handshake(from_client)
  -> construct ClientHello and extensions
  -> serialize handshake
       TLS  -> TLS record(s)
       DTLS -> DTLS record publisher / fragmentation
  -> callback sends encoded output
  -> receive path parses peer response and updates tls_session status
  -> composer waits for expected status
  -> handle ServerHello / HelloRetryRequest
  -> wait for server handshake prerequisites
  -> construct client flight for negotiated TLS version
  -> publish client flight
  -> wait for expected Finished status
```

DTLS may first receive HelloVerifyRequest and resend ClientHello with a cookie. TLS 1.3 and TLS 1.2 have different handshake prerequisites and client flights; they must not be collapsed into one generic flight. The wait conditions are status flags set by session processing, not direct reads performed by the composer.

The QUIC client path is separate. It places ClientHello in CRYPTO data inside an Initial packet, uses `quic_packet_publisher`, and waits for TLS-derived handshake status. It does not serialize an ordinary TLS record around the handshake. Some QUIC client-flight operations remain incomplete/commented in the current trial source, so class existence must not be read as proof of a complete general-purpose QUIC client.

### Server handshake flow

`tls_composer::session_status_changed(status, from_server, timeout, callback)` is the server-side entry point when the parser advances session state.

```text
incoming bytes / packet
  -> secure prosumer receive path
  -> TLS/DTLS or QUIC parser
  -> tls_session status changes
  -> tls_composer::session_status_changed(...)
       ClientHello
         -> TLS/DTLS phase 1, or QUIC server handshake
         -> construct server handshake flight
         -> serialize/publish through selected transport path
       ClientFinished
         -> TLS 1.2 phase 2 may emit CCS + Finished
         -> TLS 1.3 server flight has Finished in phase 1
```

For DTLS, phase 1 may emit HelloVerifyRequest before a cookie-validated ClientHello proceeds. For QUIC, server handshake data is published in QUIC packets containing CRYPTO frames. The public role-specific methods are asymmetric: client `handshake(from_client, ...)` is not a general server entry point, and the client-side status callback path is not implemented symmetrically.

### Callback and lifetime boundary

The composer callback is the hand-off for already encoded output. TLS passes record bytes; DTLS delegates record fragmentation/publication; QUIC delegates packet/frame construction. The callback's caller decides how bytes are sent. Keep three independently traceable paths in mind: socket I/O, session-status advancement, and record/packet publication.

## 4. Relationships

- `secure_prosumer.hpp/.cpp` — secure I/O composition and status coordination.
- `secure_client_socket.hpp/.cpp` and `trial_tls_server_socket.hpp/.cpp` — client/server secure socket integration.
- `client_socket_prosumer.hpp/.cpp` — asynchronous socket I/O and buffering.
- `tls_composer.hpp/.cpp` — handshake dispatch and callback boundary.
- `tls_composer_construct.cpp` — ClientHello and extension construction.
- `tls_composer_tls_handshake.cpp` — TLS/DTLS handshake flights and status waits.
- `tls_composer_quic_handshake.cpp` — QUIC-specific handshake and packet publication.
- `../server_socket_adapter.hpp/.cpp`, `../server_socket_builder.hpp/.cpp` — backend selection.
- [Trial backend](README.md), [network server](../../server/README.md), and [TLS implementation](../../tls/README.md).

## 5. References

No external references are currently listed.

## 6. Developer Notes

The `trial` prefix marks an experimental composition path, not guaranteed feature parity with OpenSSL. Review a concrete handshake by following the receive path and state update as carefully as the outgoing composer flight.
