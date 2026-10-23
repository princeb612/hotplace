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

# Network session

## 1. Role

`network_session` binds transport socket state to per-connection buffering and protocol work. It is the unit scheduled between producer and consumer work in `network_server`; it is not the session manager and does not itself define HTTP framing.

## 2. Data Model

### Per-session state

```text
network_session
  ├─ session metadata
  │    ├─ event socket / socket context
  │    ├─ peer address
  │    ├─ priority
  │    └─ platform read buffer (netbuffer_t)
  ├─ _stream  : raw transport input (network_stream)
  ├─ _request : protocol-composed messages (network_stream)
  ├─ network_session_data : application/session key-value state
  ├─ server_socket reference
  └─ optional HTTP/2 session state
```

`_stream` and `_request` are both `network_stream` objects but have different roles: `_stream` is the raw transport-input queue, while `_request` stores protocol-composed message units. They are separate buffers because transport read boundaries and protocol message boundaries are not equivalent.

A session is reference-counted because the manager, producer/consumer queue, and callback work can overlap in lifetime. The reference count protects object lifetime; it does not replace correct ordering of manager deregistration, multiplexer unbinding, and socket release.

### Stream versus datagram session identity

The session identity model differs by transport:

- **TCP/TLS:** the stream session is associated with the accepted event socket and its peer/socket context.
- **Plain UDP:** the listener session is keyed by the shared listening socket; datagram peer addresses travel with queued input rather than creating a TCP-like session per peer.
- **DTLS:** peer-specific security state is tracked separately from the listener-level datagram session, using a peer-address-derived cookie and a dedicated datagram-session map.

The creation and lookup operations that establish these identities are described in Behavior Model.

## 3. Behavior Model

### Accepted stream connection

```text
server_socket accept / successful TLS accept
  -> network_session_manager::connected(event_socket, peer, ...)
  -> allocate network_session(server_socket)
  -> apply configured TCP buffer size
  -> network_session::connected(...)
       store socket context + peer address
  -> register/bind session with multiplexer
  -> producer can find session by event socket
```

The session manager serializes map operations under its session lock. A successful lookup increments the session reference before returning it to producer/consumer work. Duplicate registration for the same event socket is rejected rather than silently replacing an existing stream session.

### Producer to consumer

```text
read event/completion
  -> session_manager.find(event socket)
  -> network_session::produce(queue, ...)
  -> choose stream or datagram path by socket type
       stream: read bytes (TLS may repeat SSL reads)
       datagram: retain peer address with received datagram
  -> _stream.produce(bytes, peer-if-present)
  -> schedule session by its priority
  -> network_session::consume(protocol_group, ...)
  -> _stream.read(protocol_group, _request)
  -> completed protocol units become available in _request
  -> consumer callback
```

The Linux producer path reads into the session's configured buffer; the Windows completion path can supply the transferred bytes and size. For TLS stream sockets, the session uses the socket wrapper's readiness/read mode and drains available SSL plaintext before scheduling the session. `produce()` buffers transport data; it does not promise that one invocation equals one request. The stream/protocol layer owns message boundaries.

### Datagram and DTLS session lookup

Plain UDP input retains the peer address with the datagram but uses the listener-level session keyed by the shared listening socket. It does not allocate a TCP-like connected session for every sender.

For DTLS, `get_dgram_cookie_session()` derives a cookie from the peer address and checks `_dgram_session_map` for the corresponding peer-specific session. If no session exists, the manager creates and opens the DTLS session state, then advances the handshake through the DTLS path. This peer-specific security session is distinct from the listener-level datagram session.

### Send path

`send()` writes through the session's associated server socket and event socket context. `sendto()` supplies an explicit peer address for datagram output. The choice follows the transport model: a connected stream session sends to its established peer, while datagram output needs a destination address. The method does not itself construct HTTP or other application framing.

### Lifetime and close

```text
manager.find(stream socket) -> addref -> producer work -> release
manager-held reference remains in _session_map
session_closed()
  -> ready_to_close(socket): erase lookup entry, return manager-held pointer
  -> multiplexer unbind
  -> mux_disconnect callback
  -> release manager-held reference
other in-flight references -> release independently
```

`find()` increments the reference count while holding the manager lock. `ready_to_close()` removes the map entry under the same lock but does not itself release the returned session; `session_closed()` unbinds the socket, dispatches the disconnect callback, and then releases that manager-held reference. Removing the entry prevents later normal lookups from acquiring the session through that key, but it does not invalidate references already held by in-flight work.

The manager destructor calls `shutdown()`, which releases entries in both `_session_map` and `_dgram_session_map` and clears the maps. `network_server::close()` does not call this method directly: the manager cleanup occurs as the context is deleted, after the explicit worker-stop, protocol-registry, server-socket-reference, and multiplexer-close steps. This order matters when reading lifetime behavior; the reference count protects object lifetime, while the server coordinates lookup removal and transport deregistration.

### Session extensions

`get_session_data()` exposes application/session key-value state without forcing application data into the generic transport buffers. `get_http2_session()` exposes optional HTTP/2-specific state; generic TCP/TLS sessions do not require it.

## 4. Relationships
- `network_session.hpp/.cpp` — session lifecycle, buffering, reference counting, and send path.
- [Network server](README.md) — manager, workers, and event lifecycle.
- [Network server execution model](network-server-model.md) — orchestration path.
- [Network stream and protocol](network-stream-and-protocol.md) — raw bytes to framed messages.
- [Basic socket layer](../basic/README.md) — transport backend and socket contract.
- [DTLS record arrangement](../tls/dtls_record_arrange.md), [DTLS publisher](../tls/dtls_record_publisher.md), [QUIC packet publisher](../tls/quic_packet_publisher.md), and [TLS session support](../tls/session/README.md).
- `sdk/net/http/` — HTTP/2 state and HTTP message semantics layered above generic session buffering.

## 5. References
No external references are currently listed.
