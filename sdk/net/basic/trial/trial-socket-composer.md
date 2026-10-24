## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Trial Socket and TLS Composer

## 1. Role

The trial backend composes socket I/O, asynchronous producer/consumer buffering, TLS/DTLS session state, and handshake construction. The socket classes provide transport-specific send/receive operations; `secure_prosumer` and `secure_client_socket` connect those operations to secure session processing; `tls_composer` constructs handshake flights and publishes encoded output through callbacks.

The composer is not a socket, does not own the network destination, and does not parse arbitrary incoming bytes itself. Its progress depends on the receive/session path updating handshake status.

## 2. Data Model

The diagram below is a responsibility map, read from the network edge toward handshake construction and then back toward output. Each row names a component boundary and the work assigned to it; the arrows describe conceptual dependency/flow, not a single synchronous call stack.

```text
  NETWORK EDGE
  trial socket / secure_client_socket
  - transport-specific send/receive operations
                 |
                 v
  I/O + BUFFER COORDINATION
  client_socket_prosumer / secure_prosumer
  - moves received and outgoing data between socket I/O and secure processing
  - coordinates producer/consumer work
                 |
                 v
  PROTOCOL STATE
  tls_session + tls_protection
  - handshake progress, negotiated protocol/version, and traffic protection
                 ^
                 | status is updated by receive/session processing
                 |
  HANDSHAKE CONSTRUCTION
  tls_composer
  - chooses the next handshake action from the current session status
  - constructs and serializes handshake output
                 |
                 v
  OUTPUT HAND-OFF
  callback carrying encoded bytes
  - gives the prepared bytes to the caller's send/publish path
  - transport-specific code handles TLS records, DTLS datagrams,
    or QUIC packets/CRYPTO frames
```

In short, the socket moves bytes, the prosumer coordinates I/O and buffering, the session/protection objects hold protocol state, and the composer reacts to that state to build the next handshake output. The callback is only the hand-off point; it does not itself mean the bytes have reached the peer.

The server-side adapter/builder selects and exposes a socket implementation; it is not the handshake driver. The detailed execution order and transport-specific publication paths are described in Behavior Model.

## 3. Behavior Model

### Transport-specific publication

| Session type | Encoding/publication path | Transport behavior |
|---|---|---|
| TLS | Handshake messages → TLS records | TCP byte stream |
| DTLS | Handshake messages → DTLS records → fragmentation/publication | UDP datagrams with peer address |
| QUIC / QUIC2 | TLS 1.3 handshake bytes → CRYPTO frames → QUIC packets | UDP datagrams with QUIC packet/stream state |

QUIC is not TLS-over-UDP or DTLS. Its handshake messages and key schedule are related to TLS 1.3, but QUIC has its own packet-number spaces, packet protection, and frame encoding.

### 3.1 Client handshake flow

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

### 3.2 Server handshake flow

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

### Direct message construction versus handshake orchestration

The construction testcases exercise a lower-level path than the composer's role-specific handshake drivers. Keep these two uses distinct:

- `tls_composer::construct_client_hello(...)` and `construct_server_hello(...)` construct a typed handshake object and its fields/extensions. They do not by themselves wrap it in a record, serialize wire bytes, send it, or complete a handshake.
- The caller owns the next step: attach the returned handshake to the applicable record/ciphertext representation, then serialize it or hand it to a publisher.
- `tls_composer::handshake(...)` and `session_status_changed(...)` are orchestration entry points. They use session status and protocol/version-specific flow to decide which message or flight to construct and publish.

#### Construction path shown by the TLS testcase

```text
testcase_construct_tls.cpp
  -> create tls_session + tls_record_handshake
  -> tls_composer::construct_client_hello / construct_server_hello
       -> typed handshake + extensions
  -> record << handshake
  -> record.write(direction, bytes)
  -> testcase checks the returned status
```

The testcase repeats this pattern for selected TLS 1.2/1.3 groups and versions. Other messages are assembled through record builders and `add(...)` callbacks; where protection is required, construction depends on the session's applicable protection state. The source's successful status check is not automatically a byte-for-byte known-answer assertion.

#### DTLS construction paths

```text
DTLS 1.2 testcase
  -> construct handshake / record collection
  -> construct_record_fragmented(...)
  -> DTLS record publisher
  -> callback sends individual datagrams

DTLS 1.3 testcase
  -> construct handshake content
  -> dtls13_ciphertext / DTLS 1.3 record representation
  -> record.write(direction, bytes)
  -> testcase status check
```

The two DTLS 1.2 testcases also explore different record grouping modes: individual handshake records versus multiple handshakes grouped for publication and then rearranged/reassembled on the receive side. This tests the datagram-specific record path, not just TLS-over-TCP framing. DTLS 1.3 uses its own ciphertext/record representation and should not be described as the same fragmentation path.

These are deliberately direct construction exercises: they isolate message/record creation and selected session-state dependencies. They are not substitutes for following the live composer handshake, which additionally waits for peer-driven session status and chooses the next flight. Conversely, the live composer overview should not be duplicated in each testcase document.

### 3.3 Callback and lifetime boundary

The composer callback is the hand-off for already encoded output. TLS passes record bytes; DTLS delegates record fragmentation/publication; QUIC delegates packet/frame construction. The callback's caller decides how bytes are sent. Keep three independently traceable paths in mind: socket I/O, session-status advancement, and record/packet publication.

### Real-code example: trace from server option to publication path

`test/applet/tlsserver/run_server.cpp` selects the trial backend when `option_flag_trial` is set, builds the server socket, and then uses `network_server` callbacks for application data. The callback's `session->send(...)` is above the composer: it submits bytes to the session and does not manually serialize TLS records, DTLS records, or QUIC packets.

```text
trial backend selected
  -> server socket / TLS session
  -> tls_composer handshake and publication
       TLS  -> TLS records
       DTLS -> DTLS records / datagram publication
       QUIC -> CRYPTO frames / QUIC packets
  -> network/session transport
  -> application callback
```

Use the applet to understand the caller lifecycle and this composer model to inspect transport-specific serialization. This is not evidence that every TLS/DTLS/QUIC option has identical feature support.

## 5. Relationships
- `secure_prosumer.hpp/.cpp` — secure I/O composition and status coordination.
- `secure_client_socket.hpp/.cpp` and `trial_tls_server_socket.hpp/.cpp` — client/server secure socket integration.
- `client_socket_prosumer.hpp/.cpp` — asynchronous socket I/O and buffering.
- `tls_composer.hpp/.cpp` — handshake dispatch and callback boundary.
- `tls_composer_construct.cpp` — ClientHello and extension construction.
- `tls_composer_tls_handshake.cpp` — TLS/DTLS handshake flights and status waits.
- `tls_composer_quic_handshake.cpp` — QUIC-specific handshake and packet publication.
- `../server_socket_adapter.hpp/.cpp`, `../server_socket_builder.hpp/.cpp` — backend selection.
- [Trial backend](README.md), [network server](../../server/README.md), and [TLS implementation](../../tls/README.md).
- [TLS/DTLS construction testcases](../../../../test/testcase/tls/README.md) — direct construction, serialization, fragmentation, and assertion boundaries; see also `testcase_construct_tls.cpp`, `testcase_construct_dtls12_1.cpp`, `testcase_construct_dtls12_2.cpp`, and `testcase_construct_dtls13.cpp`.

## 6. References
No external references are currently listed.

## Developer Notes
The `trial` prefix marks an experimental composition path, not guaranteed feature parity with OpenSSL. Review a concrete handshake by following the receive path and state update as carefully as the outgoing composer flight.
