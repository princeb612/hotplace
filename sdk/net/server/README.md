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

### `server_conf` and `netserver_config_t` in actual use

`server_conf` is a typed key-value map: `netserver_config_t` identifies a setting and the stored value is `uint16`. The enum groups settings used by two layers. The first four control `network_server` worker/multiplexer setup; the HTTP-related keys are read by `http_server_builder` and `http_server`; the final two size the buffers created by the session manager.

#### Network worker and multiplexer settings

| Key | Meaning in the implementation | Default / effective behavior |
|---|---|---|
| `serverconf_concurrent_event` | Passed to `multiplexer.open()` as its concurrency/capacity argument when `network_server::open()` creates the multiplexer context. | `server_conf`: 1024; `open(..., conf=nullptr, ...)`: 1024. The source comment says this matters to Linux epoll and is ignored by Windows IOCP. It is not the producer-thread count. |
| `serverconf_concurrent_tls_accept` | Configures the TLS-accept worker group created by `network_server::open()`; it is started automatically for stream sockets whose server socket reports TLS support. | `server_conf`: 1; no supplied config: 1. The HTTP builder overrides this to 2. It does not create TLS workers for every socket type; the automatic creation path is the stream/TLS path. |
| `serverconf_concurrent_network` | Producer/network worker count. On Windows, `network_server::open()` uses it to size the producer thread group. `http_server::start()` also reads it and passes it to `event_loop_run()`. | `server_conf`: 2. With no config, the Windows fallback is 1. On Linux, producer capacity is set to 1 in `open()` (and the TLS/DTLS datagram path is explicitly single-producer), so setting this key does not increase the configured producer capacity there. |
| `serverconf_concurrent_consume` | Configures the consumer worker group; `http_server::start()` reads it and starts that many consumer loops per HTTP listener context. | `server_conf`: 2; no supplied config: 2. The HTTP builder also initializes it to 2. |

The counts are not interchangeable: event/multiplexer configuration, TLS handshake work, transport production, and protocol/application consumption are separate stages.

```text
network_server::open(conf)
  ├─ concurrent_event       -> multiplexer.open(...)
  ├─ concurrent_tls_accept  -> TLS-accept worker group
  ├─ concurrent_network    -> producer group capacity on Windows
  │                           Linux: producer capacity is fixed at 1
  └─ concurrent_consume    -> consumer group capacity

HTTP:
  http_server::start()
    ├─ concurrent_network  -> event_loop_run(handle, producers)
    └─ concurrent_consume  -> consumer_loop_run(handle, consumers)
```

#### HTTP server settings

These keys are not general listener switches interpreted by `network_server::open()`. The HTTP builder reads them in `build()`, then chooses which socket schemes and address families to pass to `http_server::startup_server()`.

| Key | Actual use | `http_server_builder` initial value |
|---|---|---:|
| `serverconf_enable_ipv4` | Enables separate HTTP service listeners using `AF_INET`. | 0 (disabled) |
| `serverconf_enable_ipv6` | Enables separate HTTP service listeners using `AF_INET6`. | 0 (disabled) |
| `serverconf_verify_peer` | Passed to adapter startup for TLS and QUIC schemes as the peer-verification setting. Set through `set_tls_verify_peer()`. | 0 |
| `serverconf_enable_http` | Enables the plain HTTP service; its port is read from `serverconf_port_http`. | 0 (disabled) |
| `serverconf_enable_https` | Enables secure HTTP service setup. HTTP/1.1 or HTTP/2 causes TLS startup; HTTP/3 causes QUIC startup. | 0 (disabled) |
| `serverconf_port_http` | Port supplied to each enabled IPv4/IPv6 plain HTTP listener. | 80 |
| `serverconf_port_https` | Port supplied to each enabled IPv4/IPv6 HTTPS and HTTP/3 listener. | 443 |
| `serverconf_enable_h1` | Combined with `serverconf_enable_h2`, determines whether the builder starts the TLS path for HTTPS. The ALPN selection falls back to `http/1.1` whenever neither HTTP/3 nor HTTP/2 is enabled; that fallback does not separately test this flag. | 1 |
| `serverconf_enable_h2` | Adds the HTTP/2 protocol to each HTTP server context and enables the HTTP/2 request path. It also participates in choosing TLS startup and ALPN. | Not explicitly set by the builder; absent key reads as 0 in this configuration path. |
| `serverconf_enable_h3` | Enables the QUIC-based HTTP/3 startup path and selects `h3` ALPN. The builder currently uses `serverconf_port_https` for its listener port. | Not explicitly set by the builder; absent key reads as 0 in this configuration path. |

The builder only enters its service-setup block when at least one address family is enabled. Consequently, enabling HTTP/HTTPS without enabling IPv4 or IPv6 does not create a listener. The protocol flags also do not independently enable a service: `serverconf_enable_https` gates the secure-service setup, while `serverconf_enable_h1` / `serverconf_enable_h2` select the TLS path and `serverconf_enable_h3` selects the QUIC path. HTTP/3 classes and flags should not be read as proof of a complete, general-purpose HTTP/3 server implementation.

#### TCP and UDP buffer settings

| Key | Actual use | Default / zero behavior |
|---|---|---|
| `serverconf_tcp_bufsize` | Read by `network_session_manager::connected()`; applied to the newly created stream session's `netbuffer_t`. | The `server_conf` constructor does not set it. A missing/zero value is passed to `set_bufsize(0)`, whose call site documents zero as “use default buffer size.” |
| `serverconf_udp_bufsize` | Read when creating the shared datagram session and peer-specific DTLS cookie sessions; applied to each session buffer. | Not set by the `server_conf` constructor. Zero requests the buffer's default size. |

These settings control the session's application-side network buffer configuration. They do not, by themselves, configure the operating system's TCP socket buffers or change the UDP path MTU.

#### Why the defaults differ by construction path

```text
server_conf()
  event=1024, tls_accept=1, network=2, consume=2
  tcp_bufsize / udp_bufsize and HTTP keys: not initialized here
       |
       +--> network_server::open(..., &conf, ...)
       |      reads configured values; Linux producer capacity is still 1
       |
       +--> http_server_builder()
              initializes HTTP flags/ports and overrides
              tls_accept=2, network=2, consume=2
                    |
                    +--> build() copies config to http_server
                           |
                           +--> startup_server() per enabled service/family
                           +--> start() starts producer and consumer loops
```

When `network_server::open()` receives a null `conf`, it supplies fallback values for the four worker/multiplexer settings. That is a separate path from passing a default-constructed `server_conf`: the latter has `serverconf_concurrent_network=2`, while the Linux producer group is nevertheless configured for one worker. The HTTP builder also has its own defaults and copies its configuration into the created `http_server`. For this reason, the effective configuration should be read from the caller's construction path and the consuming code, not from the enum declaration alone.

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
### IPv4 and IPv6 listener model

`network_server` does not infer a dual-stack listener from an address. Its `open()` accepts an explicit address family and passes it to the selected `server_socket::open()`. The caller can create one context for `AF_INET` and another for `AF_INET6`, each with its own listening socket, multiplexer context, callback registration, and event/consumer loops.

```text
application setup
  ├─ network_server.open(handle_ipv4, AF_INET, port, ...)
  │    └─ IPv4 listener + context
  └─ network_server.open(handle_ipv6, AF_INET6, port, ...)
       └─ IPv6 listener + context

each context independently:
  accept/read event -> session manager -> producer/consumer -> callback
```

The concrete example is `test/applet/tcpserver2/run_server.cpp`: it opens both families on the selected port, installs the accept-control handler for each handle, starts the consumer and event loops for both, and closes both contexts during cleanup. This is **two explicitly opened listeners**, not proof that one IPv6 socket also accepts IPv4-mapped connections. Whether the two binds can coexist on the same port depends on the socket backend and operating-system IPv6/dual-stack settings.

The peer address is carried through the socket/session path as socket-address data; the accept callback can pass that address to `ipaddr_acl::determine()` to make an admission decision. Listener-family support and ACL address-representation support are separate concerns: the ACL implementation documents that IPv6 matching requires `__SIZEOF_INT128__` and otherwise reports IPv6 input as unsupported.

For HTTP, `http_server_builder::enable_ipv4()` and `enable_ipv6()` are separate settings, both disabled by default. When enabled, the builder calls `startup_server()` separately with `AF_INET` and/or `AF_INET6` for the selected HTTP services. Enabling IPv6 in the builder is therefore an explicit listener configuration, not automatic dual-stack behavior.

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
