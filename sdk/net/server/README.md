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

# Network server

## 1. Role

`sdk/net/server` is the transport/session orchestration layer between concrete sockets in `sdk/net/basic` and protocol/application handlers such as HTTP. It coordinates platform events, accept and TLS-accept work, producer/consumer queues, session lifetime, raw byte buffering, protocol framing, and callbacks. It is not itself an HTTP parser or TLS record implementation.

## 2. Data Model

```text
network_server
  ├─ platform multiplexer + event callback
  ├─ accept path: server_socket::accept / tls_accept
  ├─ worker groups: tls_accept / producer / consumer
  ├─ network_session_manager
  │    └─ network_session (per accepted stream socket)
  │         ├─ _stream  : raw transport bytes
  │         ├─ _request : protocol-composed messages
  │         └─ optional http2_session
  └─ network_protocol_group
       └─ network_protocol implementations
```

The multiplexer reports readiness/completion; it does not parse messages. The session manager indexes and coordinates session lifetime. Each session owns per-connection state and buffers. The stream/protocol layer turns arbitrary transport reads into protocol-framed messages, and the consumer callback receives interpreted data.

### Platform multiplexer inventory

The implemented server paths use `multiplexer_epoll` on Linux and `multiplexer_iocp` on Windows. A `multiplexer_kqueue` class/reference exists, but that alone does not establish a supported macOS/BSD server path. This is an implementation-status note, not a platform support promise.

## 3. Behavior Model

### End-to-end stream path

```text
socket readiness/completion
  -> platform multiplexer callback
  -> producer work
       session_manager.find(socket)
       session.produce(...)
       network_stream::produce(raw bytes)
       enqueue session by priority
  -> consumer work
       dequeue session
       session.consume(protocol_group, ...)
       network_stream frames buffered bytes
       network_protocol_group selects a protocol
       network_protocol::read_stream identifies a message boundary
       completed message is placed in _request
  -> consumer callback (message + session context)
  -> HTTP/application dispatch
```

The three detailed documents below are complementary views of this same path. [Network server model](network-server-model.md) describes worker and lifecycle orchestration; [network session](network_session.md) explains per-connection state and lifetime; [network stream and protocol](network-stream-and-protocol.md) explains byte buffering, protocol selection, and message framing.

A TCP read can split a message or coalesce multiple messages. The protocol layer—not the multiplexer and not the socket read size—defines message boundaries. UDP/DTLS differs because peer identity accompanies datagrams and DTLS maintains per-peer secure state rather than one accepted TCP-like socket per peer.

### Session manager and lifetime

For TCP/TLS, `network_session_manager::connected()` creates/registers a session for the accepted socket; the server binds the session to the multiplexer. Producer work finds the session by socket, while consumer work processes its buffered stream. Close handling removes the session from the manager's normal lookup path before releasing remaining bindings/resources. The manager indexes sessions; a session owns per-connection buffers and state. Reference counting covers overlap between manager lookups, queues, and callbacks.

### TLS accept queue and concurrency

```text
accept -> optional accept-control callback -> accept_queue
       -> tls_accept_threads (1..*)
       -> server_socket::tls_accept
       -> session accepted / manager registration
       -> multiplexer binding
       -> normal producer -> session -> consumer path
```

TCP accept and TLS handshake are separate stages. A dedicated TLS-accept worker group keeps handshake work out of the ordinary event callback and can be scaled independently. With no explicit configuration, `network_server::open()` defaults TLS accept concurrency to 1; `http_server_builder` supplies a default of 2. Accepted sockets may accumulate in the queue if handshakes arrive faster than workers complete them. Raising concurrency may improve throughput but also increases simultaneous handshake resource use.

### HTTP connection

`http_server` owns/configures a `network_server`, registers HTTP protocol handling, and provides HTTP-specific callbacks and routing. `http_server_builder` selects the socket adapter, configures addresses, TLS/certificates, protocol options and concurrency, then builds/starts the server. The network layer handles socket/session/event work; the HTTP layer interprets requests and dispatches application behavior.

### Applet progression: multiplexer to network_server

The runnable examples show the integration boundary in stages. `test/applet/tcpserver1` and `udpserver1` register sockets with the platform multiplexer and handle events directly. `tcpserver2` and `udpserver2` use `network_server` for listener contexts, event loops, and callbacks. `tlsserver` and `dtlsserver` configure secure socket implementations through that server path. `httpserver1` and `httpserver2` then use `http_server` to add HTTP request handling and routing. These applets are source examples of the layers working together; their presence alone does not state that every runtime combination was tested.

## 4. Relationships

- `network_server.hpp/.cpp` — multiplexer, worker loops, protocol registration, shutdown.
- [Network server model](network-server-model.md) — detailed worker/lifecycle view.
- [Network session](network_session.md) — session ownership, stream/datagram state, lifetime.
- [Network stream and protocol](network-stream-and-protocol.md) — buffering, protocol selection and framing.
- `network_protocol.hpp/.cpp`, `network_protocol_group.hpp/.cpp` — protocol abstraction and registry.
- [Basic socket layer](../basic/README.md) — socket backends and adapters.
- [HTTP server and protocol layer](../http/README.md) — HTTP server, builder, routing and protocol-specific handling.
- [TLS/DTLS/QUIC](../tls/README.md) — secure protocol/session processing.
- `test/testcase/net/sample.cpp`, `test/applet/tcpserver1/`, `test/applet/tcpserver2/` — source examples, not a runtime verification claim.

## 5. References

No external references are currently listed.

## 6. Developer Notes

The class relationship is a responsibility map, not an inheritance diagram:

```text
network_server
  ├─ multiplexer
  ├─ network_protocol_group -> network_protocol
  └─ network_session_manager -> network_session -> network_stream

server_socket selected by adapter/builder
  ├─ naive TCP / UDP
  ├─ OpenSSL TLS / DTLS
  └─ trial TLS / DTLS / QUIC
```
