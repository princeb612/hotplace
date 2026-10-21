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

# Network session

## 1. Role

`network_session` binds a socket to per-connection state and buffering. It is the unit scheduled between producer and consumer work in `network_server`; it is not the session manager and does not itself define HTTP framing.

## 2. Data Model

A session owns/references socket information, `_stream` for raw received data, `_request` for protocol-composed messages, `network_session_data` for application/session key-value state, an associated server socket, and optional HTTP/2 state. It is reference-counted because manager lookups, queues, and callbacks may overlap in lifetime.

For TCP/TLS, `network_session_manager::connected()` creates/registers one session per accepted socket, keyed by socket handle. The manager indexes and coordinates sessions; each session owns its per-connection buffers and state.

UDP/DTLS differs because a listening socket is shared. UDP carries peer address alongside datagram data. DTLS uses a cookie/per-peer session path and performs DTLS handshake processing for the peer-specific state. It should not be modeled as one accepted TCP-like socket per peer.

## 3. Behavior Model

### Producer to consumer

```text
accepted socket
  -> session_manager.connected()
  -> network_session::connected()
  -> multiplexer binding

read event
  -> session_manager.find(socket)
  -> network_session::produce(...)
  -> _stream queues raw bytes
  -> session scheduled by priority
  -> network_session::consume(protocol_group, ...)
  -> network_stream frames bytes
  -> completed data appended to _request
  -> consumer callback
```

`produce()` records input; it does not promise that one call equals one request. `consume()` delegates message framing to registered protocols. See [network-stream-and-protocol.md](network-stream-and-protocol.md) for how partial messages are retained and complete messages extracted.

### Lifetime and close

The close path removes a session from the manager's normal lookup path before the remaining socket/multiplexer resources are released. This ordering matters because producer work and queued consumer callbacks can overlap. Reference counting protects the object's lifetime across those concurrent references; it does not eliminate the need to order deregistration and resource release correctly.

### Send and datagram identity

`send()` writes through the associated server socket; `sendto()` supplies an explicit peer address for datagram output. UDP input preserves peer identity in `network_stream_data`; DTLS additionally tracks per-peer security state. Session priority affects producer/consumer scheduling, while protocol parsing can also assign priority to message data.

`get_session_data()` exposes application/session state. `get_http2_session()` exposes optional HTTP/2-specific state; neither is required for every generic session.

## 4. Relationships

- `network_session.hpp/.cpp` — session lifecycle, buffering and send path.
- [Network server](README.md) — session manager, workers and event lifecycle.
- [Network server model](network-server-model.md) — orchestration path.
- [Network stream and protocol](network-stream-and-protocol.md) — raw bytes to framed messages.
- [Basic socket layer](../basic/README.md) — transport backend.
- [DTLS record arrangement](../tls/dtls_record_arrange.md), [DTLS publisher](../tls/dtls_record_publisher.md), [QUIC packet publisher](../tls/quic_packet_publisher.md), and [TLS session support](../tls/session/README.md).
- `sdk/net/http/` — HTTP/2 state and HTTP message semantics layered above generic session buffering.

## 5. References

No external references are currently listed.
