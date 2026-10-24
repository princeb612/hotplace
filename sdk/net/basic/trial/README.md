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

### 3.3 Producer/consumer: the two queues have different jobs

The word *prosumer* covers two distinct stages. `client_socket_prosumer` moves bytes between the operating-system socket and a raw receive queue; `secure_prosumer` interprets those bytes as TLS-family records and exposes only application-data payloads to the caller. They are not duplicate queues.

```text
socket / OS completion
        |
        | recv() / recvfrom()                 Windows: IOCP completion
        v
client_socket_prosumer::_mplexer_key.buffer
        |
        | enqueue(socket_buffer_t)
        v
_rq  +  _rlock
(raw socket bytes + datagram peer address)
        |
        | do_secure()
        |   secure socket: drain _rq via do_consume()
        v
secure_prosumer::_mbs
(accumulated record bytes; may retain an incomplete TLS record)
        |
        | parse records using tls_record_builder
        | record->read(direction, stream, size, pos)
        +-------------------------------+
        | handshake / alert / other     | application_data
        | record processing updates     | extract decrypted record payload
        | session/protection state      v
        |                         _mq + _mlock
        |                         (application bytes
        |                          + optional peer address)
        |                                |
        |                                | _msem.wait()
        |                                v
        |                         secure_client_socket::read()
        |                         / recvfrom()
        v
  tls_session status changes
  (tls_composer can wait for them)
```

#### 3.3.1 `client_socket_prosumer`: socket I/O and the raw queue

- **Open/connect and start-up.** Stream sockets are created and connected by `connect()`; datagram sockets are created by `open()`, which saves the peer address. Both start the consumer machinery before calling `do_handshake()`. The base implementation of `do_handshake()` is a no-op; the secure subclass starts the TLS-family handshake.
- **Read readiness/completion.** `start_consumer()` binds the socket to the platform multiplexer, starts a worker thread running its event loop, and initiates the Windows overlapped read where applicable. Linux handles `mux_read` / `mux_dgram` events with `recv()` / `recvfrom()`; Windows queues the completed buffer and posts the next asynchronous read.
- **Raw buffering.** Each successful receive is copied into a `socket_buffer_t` and enqueued in `_rq` under `_rlock`. Datagram entries also retain the sender address. For a non-secure socket, the receive path signals `_rsem`; for a secure socket, it instead calls `do_secure()` to pass available raw bytes to the secure processing stage.
- **Plain reads vs secure reads.** A plain `do_read()` waits on `_rsem` and copies bytes from the front of `_rq`; a partial read cuts the consumed prefix and leaves the remainder queued. For secure sockets, `do_read()` is overridden to read from `secure_prosumer::consume()`, not directly from `_rq`. The protected `do_consume()` drains the raw queue into a byte stream and carries the queued peer address alongside it.
- **Sending.** The base `send()` is stream-only and writes the supplied bytes to the socket; `sendto()` is datagram-only. These are byte transport operations, not TLS record construction. Secure subclasses decide whether application bytes need to be wrapped before reaching these methods.
- **Shutdown.** `close()` invokes `do_shutdown()`, stops/unbinds the multiplexer consumer, then invokes `do_close()`. The hooks are virtual: secure sockets use the shutdown hook to send `close_notify` and wait for the peer status, while the base hooks are no-ops.

#### 3.3.2 `secure_prosumer`: record parsing and application-data delivery

1. **Collect the raw input.** `secure_client_socket::do_secure()` calls `secure_prosumer::produce()` with a callback that drains `client_socket_prosumer::_rq` through `do_consume()`. The received bytes are appended to `_mbs`; `produce()` does not itself perform a socket read.
2. **Select the framing path.** For TLS and QUIC session types, the accumulated bytes are parsed as a sequence of records from the current `pos`. After parsing, only the consumed prefix is cut from `_mbs`, leaving unconsumed bytes for the next receive. For DTLS, the input is first passed through the session's `dtls_record_arrange`; each ready datagram/record unit returned by `arrange.consume()` is then parsed. The datagram peer address is retained for queued application data.
3. **Parse each record.** The first byte selects the TLS content type and `tls_record_builder` builds the corresponding record parser. `record->read(dir, stream, size, pos)` consumes the encoded record and performs its normal record/session processing. Handshake, alert, and other record types are processed by that record path but are not placed in the application read queue by this method.
4. **Queue application payloads.** When a successfully read record is `application_data`, its decoded payload is copied to a new `socket_buffer_t` and enqueued in `_mq` under `_mlock`; the optional peer address is copied with it. The semaphore `_msem` signals that application data is available. This is the boundary between protocol records and bytes returned to the application.
5. **Deliver bytes to the caller.** `secure_client_socket::do_read()` calls `secure_prosumer::consume()`. It waits on `_msem`, copies up to the caller's buffer size from the front of `_mq`, and preserves any unread suffix. For datagram socket types it also copies the queued peer address. `more_data` indicates that additional queued application data remains.

#### 3.3.3 Handshake and application writes use the reverse path

```text
Handshake:
tls_composer::handshake(from_client, timeout, callback)
  -> construct / serialize handshake flight
  -> callback(bin) -> secure_client_socket::do_send(bin)
  -> concrete TLS / DTLS socket chooses transport send

Application write:
caller bytes
  -> trial_tls_client_socket::send()
       wrap as TLS application_data record
       -> client_socket_prosumer::send() -> TCP stream
  -> trial_dtls_client_socket::sendto()
       wrap as DTLS application_data record
       (DTLS 1.3 uses dtls13_ciphertext)
       -> client_socket_prosumer::sendto() -> UDP datagram
```

The handshake callback and application `send()` are separate paths: `tls_composer` sends already-constructed handshake bytes through `do_send()`, while the concrete secure socket wraps application bytes into an application-data record. The QUIC client currently selects TLS 1.3 and uses the QUIC packet/session path; it should not be read as TLS records being sent directly over UDP.

#### 3.3.4 How to read the model

- `_rq` is a **transport-input queue**. It contains bytes received from the socket, before the secure record layer processes them.
- `_mbs` is a **record-input accumulator**. It allows a stream receive to end in the middle of a record without discarding the incomplete suffix.
- `_mq` is an **application-output queue** from the secure record parser's perspective: it contains application payloads ready for the caller, not encrypted wire records.
- `_rsem` wakes plain-socket readers; `_msem` wakes secure application readers. Secure sockets route received input through `do_secure()` rather than using the plain-read semaphore as their application-data notification.
- The event-loop callback, secure record parsing, and caller's `read()` are separate execution stages. A socket receive does not mean that application data is immediately available: the bytes may be handshake/control records, an incomplete TLS record, or DTLS input not yet ready to be consumed.

The trial implementation is experimental; this model describes the current source path and should not be interpreted as a claim of complete TLS/DTLS/QUIC protocol conformance.

### Real-code entry point: the trial TLS server path

`test/applet/tlsserver/run_server.cpp` is the easiest caller to follow from the public socket scheme into the trial implementation. With the trial option selected, the applet adds `socket_scheme_trial`; otherwise it selects `socket_scheme_openssl`. Both are passed through the server socket builder and then opened by `network_server`.

```text
TLS server options
  -> socket scheme + TLS version flags
  -> server_socket_builder::set(...).build()
  -> network_server listener / accept / session callback
  -> trial TLS session and composer, when trial is selected
```

The applet callback echoes application bytes with `session->send(...)`; it does not implement the handshake. Follow `trial_tls_server_socket`, `tls_session`, and `tls_composer` from the backend path to inspect how handshake status drives outbound records. The example establishes an integration route, not feature parity with OpenSSL or complete TLS conformance.
## 5. Relationships
- `trial_server_socket_adapter.hpp/.cpp` — scheme mapping and adapter API.
- `trial_*_socket.hpp/.cpp` — concrete transport-specific socket operations.
- `client_socket_prosumer.hpp/.cpp`, `secure_client_socket.hpp/.cpp`, `secure_prosumer.hpp/.cpp` — socket I/O, queueing, and secure-data composition.
- `tls_composer.hpp/.cpp`, `tls_composer_construct.cpp`, `tls_composer_tls_handshake.cpp`, `tls_composer_quic_handshake.cpp` — handshake construction and publication flow; see [trial socket composer](trial-socket-composer.md).
- `../server_socket_adapter.hpp/.cpp` and `../server_socket_builder.hpp/.cpp` — common adapter and concrete-socket factory.
- [Naive sockets](../naive/README.md) — direct TCP/UDP transport.
- [OpenSSL sockets](../openssl/README.md) — separate OpenSSL-backed TLS/DTLS backend.
- [Network server](../../server/README.md) — server event/session orchestration.
- [TLS/DTLS/QUIC implementation](../../tls/README.md) — session state, record protection, DTLS publisher, and QUIC packet/frame layer.

## 6. References
No external references are currently listed.

## Developer Notes
The trial adapter maps TLS/DTLS/QUIC/QUIC2 to the trial backend, while the OpenSSL adapter maps only TLS/DTLS to OpenSSL. Keep this backend-selection difference visible when documenting server configuration; the two adapters share an interface but not the same scheme support.
