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

`sdk/net/server` is the transport/session orchestration layer between concrete sockets in `sdk/net/basic` and protocol/application handlers such as HTTP. It coordinates platform events, accept and TLS-accept work, producer/consumer queues, session lifetime, raw-byte buffering, protocol framing, and callbacks. It is not itself an HTTP parser or a TLS record implementation.

The directory README is the integrated view. [Network server execution model](network-server-model.md) details worker orchestration; [network session](network_session.md) details per-connection state; [network stream and protocol](network-stream-and-protocol.md) details buffering, protocol selection, and framing.

## 2. Data Model

### Server composition overview

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

This is the composition overview: the following sections describe the shared server context and worker coordination, then the per-session buffers and protocol-framing model. The accept and worker execution paths are detailed in the Behavior Model below; UDP/DTLS follows a shared-listener datagram path rather than one accepted stream socket per peer.

### Server context and worker coordination

```text
network_multiplexer_context_t
  ├─ listening socket context + server_socket
  ├─ platform multiplexer context
  ├─ callback routine + callback parameter
  ├─ event concurrency
  ├─ accept queue + accept queue lock
  ├─ TLS-accept / producer / consumer worker groups
  ├─ event_queue : priority scheduling of network_session
  ├─ network_session_manager
  └─ network_protocol_group
```

The context is the shared coordination object passed to worker routines. `server_conf` stores keyed settings such as event, TLS-accept, producer/network, and consumer concurrency plus TCP/UDP buffer sizes. It also carries HTTP-facing options, but those are interpreted by the HTTP layer. With no explicit configuration, `network_server::open()` uses event concurrency 1024, TLS-accept concurrency 1, producer concurrency 1, and consumer concurrency 2. `http_server_builder` initializes its own defaults, so the effective values depend on the construction path.

The implemented multiplexer paths are `multiplexer_epoll` on Linux and `multiplexer_iocp` on Windows. A kqueue class/reference exists, but it does not by itself establish a supported macOS/BSD server path.

### Session and message data

```text
network_session (per stream connection)
  ├─ socket/session metadata, peer address, priority
  ├─ netbuffer_t : platform read buffer
  ├─ _stream    : queued raw transport input
  ├─ _request   : protocol-composed messages
  ├─ network_session_data : application/session key-value state
  └─ optional http2_session

network_stream_data
  ├─ owned byte buffer + size
  ├─ optional UDP peer address
  ├─ priority + linked-list/reference-count state
  └─ queue membership

network_protocol_group
  └─ protocol_id -> reference-counted network_protocol
       ├─ is_kind_of(prefix)
       ├─ read_stream(buffer, message_size, state, priority)
       └─ framing constraints
```

The multiplexer reports readiness/completion; it does not parse messages. The session manager indexes sessions and coordinates lifetime. A session owns per-connection state and the two streams; the raw stream stores received bytes, while the request stream stores complete protocol units produced by framing. Protocol implementations determine message boundaries and can report parsing state and priority.

TCP/TLS uses a session associated with an accepted socket. UDP/DTLS uses a shared listening socket and preserves peer identity with datagram data; DTLS additionally creates peer-specific security state. Do not model UDP/DTLS as one accepted TCP-like socket per peer.

## 3. Behavior Model

### TCP accept and secure accept

```text
listening socket
  -> platform-specific accept/event path
  -> optional accept-control callback
       STOP -> reject and close accepted socket
       CONTINUE -> continue
  -> clear TCP: session_accepted(...)
     TLS: accept_queue -> TLS-accept worker
                       -> server_socket::tls_accept(...)
                       -> session_accepted(...)
  -> session manager registration
  -> multiplexer binding
  -> ordinary producer/consumer path
```

On Windows, the source has a dedicated accept-thread path for stream sockets; other event/accept details depend on the platform backend. For secure stream sockets, TCP accept and TLS handshake are distinct stages. The TLS-accept queue isolates handshake work from ordinary event handling. The configured worker count permits independent handshake concurrency; if handshakes arrive faster than workers complete them, queued sockets can accumulate. More workers increase concurrent handshake resource use as well as processing capacity.

### Read, queue, frame, callback

```text
socket readiness/completion
  -> producer work
       session_manager.find(event socket)
       network_session::produce(...)
       read transport/TLS bytes
       network_stream::produce(...)
       schedule session by priority
  -> consumer work
       dequeue session
       network_session::consume(protocol_group, ...)
       _stream -> network_stream framing loop
       protocol_group selects interpreter
       protocol::read_stream determines message size/state
       complete message -> _request
  -> user callback with message and session context
  -> HTTP/application dispatch
```

One read is not one message. TCP can split a message across reads or combine several messages into one read. The stream layer accumulates queued nodes, invokes protocol framing, emits complete messages, and retains any trailing bytes needed for a subsequent message. If a protocol reports an incomplete prefix/message, the stream waits for more input; malformed, failed, or oversized states follow the stream's invalid-input cleanup path.

With no protocol registered, the stream can transfer queued data directly. With protocols registered, the protocol group selects an interpreter and framing controls how data is placed in the request stream. The consumer callback is the boundary where completed transport data is handed to higher-level behavior.

### Session lifetime and shutdown

```text
accepted connection
  -> session manager registers session
  -> manager lookup returns a referenced session
  -> producer/consumer queues and callbacks may hold references
  -> close path removes normal lookup entry
  -> socket/multiplexer/session resources are released
```

The manager is an index, not the owner of protocol semantics. Session references can overlap across manager lookups, queues, and callbacks, so reference counting and deregistration order both matter. `network_server::close()` closes the listener, signals and joins worker groups, clears registered protocols, releases the server socket, closes the multiplexer, invalidates the context signature, and deletes the context. Shutdown must also account for pending TLS-accept queue entries and in-flight session work.

### Datagram and DTLS path

A datagram read preserves its source address in `network_stream_data`. The session manager maintains a listening-socket datagram session path; DTLS cookie handling derives a peer-specific key/session and drives the DTLS handshake. This differs from TCP/TLS's accepted-socket lifecycle. QUIC is not implemented as DTLS: it uses UDP transport but has its own packet/session processing in the trial TLS/QUIC layer.

### HTTP connection

`http_server` configures and owns the `network_server` integration, registers HTTP protocol handling, and supplies HTTP-specific callbacks and routing. `http_server_builder` chooses the socket adapter, addresses, TLS/certificates, protocol options, and concurrency settings. The network layer handles socket/session/event work; the HTTP layer interprets requests and dispatches application behavior.

### Applet progression

`test/applet/tcpserver1` and `udpserver1` show direct multiplexer handling. `tcpserver2` and `udpserver2` introduce `network_server` for listener contexts, event loops, and callbacks. `tlsserver` and `dtlsserver` configure secure socket implementations through the server path. `httpserver1` and `httpserver2` add HTTP handling and routing. These are source examples of layer integration, not a claim that every runtime combination has been executed.

### Real-code entry point: network server callbacks

`test/applet/tcpserver2/run_server.cpp` demonstrates the server layer without HTTP or TLS framing. It configures a `network_server`, opens IPv4/IPv6 listeners, registers an accept-control callback, and starts consumer/event loops.

```text
echo_server()
  -> configure server_conf and naive_tcp_server_socket
  -> network_server.open(AF_INET / AF_INET6, ...)
  -> set_accept_control_handler(...)
  -> consumer_loop_run(...) + event_loop_run(...)
  -> consumer_routine(mux_connect / mux_read / mux_disconnect)
```

The associated `consumer_routine` handles the three event types; on read, this simple echo example sends received bytes back through the event socket. Read the callback and the full `echo_server()` together: the former shows the application boundary, while the latter shows listener setup and loop ownership. The applet also configures `ipaddr_acl` and uses the accept callback to decide whether to continue or reject a connection.
## 5. Relationships
- `network_server.hpp/.cpp` — context, worker loops, protocol registration, and shutdown.
- [Network server execution model](network-server-model.md) — worker and lifecycle orchestration.
- [Network session](network_session.md) — per-connection state, buffering, and lifetime.
- [Network stream and protocol](network-stream-and-protocol.md) — raw bytes to framed messages.
- [Basic socket layer](../basic/README.md) and [socket model](../basic/socket-model.md) — transport contracts and backend selection.
- [HTTP server and protocol layer](../http/README.md) — HTTP server, builder, routing, and protocol handling.
- [TLS/DTLS/QUIC](../tls/README.md) — secure protocol/session processing.
- `test/testcase/net/sample.cpp`, `test/applet/tcpserver1/`, `test/applet/tcpserver2/` — source examples.

## 6. References
No external references are currently listed.

## Developer Notes
The class relationship is a responsibility map, not an inheritance diagram:

```text
network_server
  ├─ multiplexer + callback context
  ├─ worker groups + event_queue
  ├─ network_protocol_group -> network_protocol
  └─ network_session_manager -> network_session -> network_stream

server_socket selected by adapter/builder
  ├─ naive TCP / UDP
  ├─ OpenSSL TLS / DTLS
  └─ trial TLS / DTLS / QUIC
```
