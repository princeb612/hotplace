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

# Network server execution model

## 1. Role

This document focuses on `network_server` worker orchestration and lifecycle. Read it with [network_session.md](network_session.md) for per-connection state and [network-stream-and-protocol.md](network-stream-and-protocol.md) for byte buffering and protocol framing.

## 2. Data Model

### Shared context

`network_multiplexer_context_t` is the object shared by event, accept, producer, TLS-accept, and consumer routines. It carries the listening socket and selected `server_socket`, multiplexer handle, callback and user parameter, event concurrency, worker groups, accept queue and lock, priority event queue, `network_session_manager`, and `network_protocol_group`. It is coordination state rather than the state of an individual connection.

### Queues and worker groups

| State | Purpose | Data crossing the boundary |
|---|---|---|
| `accept_queue` | Holds accepted TCP sockets while secure acceptance is pending | accepted socket and peer address |
| `event_queue` | Schedules sessions for consumer processing | referenced `network_session`, ordered by priority |
| producer workers | Read transport data and append it to a session stream | bytes plus optional peer address |
| consumer workers | Frame queued bytes and dispatch completed messages | session, protocol group, request stream |
| TLS-accept workers | Run the secure accept/handshake stage | queued socket -> secure socket context/session |

The implemented server paths use `multiplexer_epoll` on Linux and `multiplexer_iocp` on Windows. A kqueue class/reference exists, but should not be treated as evidence of a supported macOS/BSD server path.

The configuration keys include event, TLS-accept, producer/network, and consumer counts, plus TCP/UDP buffer sizes. Without an explicit configuration, `network_server::open()` uses event concurrency 1024, TLS-accept concurrency 1, producer concurrency 1, and consumer concurrency 2. `http_server_builder` initializes its own defaults (event 1024, TLS-accept 2, producer 2, consumer 2); actual concurrency depends on which layer supplies the configuration.

## 3. Behavior Model

### Open and worker initialization

```text
network_server::open(...)
  -> server_socket::open(listener)
  -> create platform multiplexer
  -> allocate network_multiplexer_context_t
  -> configure queues, worker groups and callback context
  -> session_manager.set_server_conf(conf)
  -> addref server_socket
  -> start platform-specific accept work when required
  -> start TLS-accept workers for secure stream sockets
  -> return context handle
```

The listener setup differs by transport: TCP/TLS uses a stream bind/listen path, while UDP/DTLS binds a datagram socket. The Linux DTLS path explicitly constrains producer concurrency to one for the supported epoll handshake flow. Producer/consumer work loops are created through the corresponding `*_loop_run()` methods rather than being synonymous with merely opening the listener.

### Accept and handshake

```text
accept routine
  -> accept socket + peer address
  -> optional accept-control callback
       STOP -> close socket
       CONTINUE -> continue
  -> plain socket -> session_accepted(...)
  -> secure socket -> enqueue accept_context
                    -> TLS-accept worker
                    -> server_socket::tls_accept(...)
                    -> success: session_accepted(...)
                    -> failure: server_socket::tls_accept_fails(...)
```

The separate TLS-accept stage exists because a handshake may take substantially longer than accepting a TCP socket. The worker removes one item from the protected queue before calling `tls_accept`; successful handshakes enter the normal session path. Backend-specific failure cleanup is delegated to `tls_accept_fails`.

### Producer path: event to raw stream

```text
multiplexer event/completion
  -> identify event socket
  -> session_manager.find(event socket)
  -> add a temporary session reference
  -> network_session::produce(...)
       -> transport read (or TLS read loop)
       -> network_stream::produce(bytes, optional peer)
       -> priority event_queue.push(session)
  -> release temporary reference
```

The platform backends deliver read data differently: the Linux path reads through the socket wrapper into the session buffer; the Windows completion path can pass the transferred buffer and size. TLS processing may perform repeated SSL reads while data remains available, then schedules the session when data has been produced. The producer stage buffers input; it does not decide application message boundaries.

### Consumer path: raw stream to callback

```text
consumer worker
  -> pop next session from event_queue
  -> network_session::consume(protocol_group, ...)
  -> _stream.read(protocol_group, _request)
  -> network_stream framing loop
  -> protocol_group.is_kind_of(prefix)
  -> protocol.read_stream(...)
  -> complete message(s) in _request
  -> callback with message + session context
```

The priority queue schedules sessions, not individual TCP packets as independent requests. A single consumer pass may yield multiple complete messages; incomplete trailing data remains buffered. Protocol selection and message framing are owned by `network_protocol_group`, `network_protocol`, and `network_stream`, not by the event backend.

### Shutdown and ownership

The implemented `network_server::close(context)` order is:

```text
close listening socket
  -> Windows: signal/wait accept workers
  -> cleanup_tls_accept()
  -> signal/wait TLS-accept workers
  -> signal/wait producer workers
  -> signal/wait consumer workers
  -> protocol_group.clear()
  -> release context's server_socket reference
  -> close multiplexer
  -> invalidate context signature
  -> delete context
       -> network_session_manager destructor
            -> shutdown(): release and clear stream/datagram map entries
```

The ordering above is the literal `close()` sequence; the manager's `shutdown()` is not called as an explicit earlier step. It runs when deleting the context destroys its manager member. A stream disconnect follows a different path: `session_closed()` first removes the socket from the manager lookup map, then unbinds it from the multiplexer, invokes the disconnect callback, and releases the map-held session reference.

A manager lookup returns a referenced session, so work already holding a reference can outlive removal from the lookup map. Conversely, `close()` waits for the worker groups before clearing protocol references and closing the multiplexer, and context destruction then releases sessions still retained by manager maps. These are distinct lifetime stages: worker quiescence, lookup deregistration, multiplexer unbinding/closure, and reference-counted object destruction should not be conflated.

### Real-code example: listener setup and event loops

`test/applet/tcpserver2/run_server.cpp` shows the caller-side lifecycle: construct `network_server` and a `naive_tcp_server_socket`, call `open()` for IPv4/IPv6, register `accept_handler`, then start consumer and event loops. The callback handles connect/read/disconnect events and echoes read bytes.

```text
configure server_conf + socket
  -> network_server.open(...)
  -> set_accept_control_handler(...)
  -> consumer_loop_run(...) + event_loop_run(...)
  -> consumer_routine(event, session, bytes)
```

Compare this with `test/applet/tlsserver/run_server.cpp` to see the same orchestration around a secure socket. The applet owns configuration and application behavior; `network_server` owns the listener/event/session machinery.

## 5. Relationships
- `network_server.hpp/.cpp` — context fields and worker routines.
- [Server overview](README.md) — integrated socket-to-application flow.
- [Network session](network_session.md) — session state and lifetime.
- [Network stream and protocol](network-stream-and-protocol.md) — framing path.
- [Socket model](../basic/socket-model.md) — common socket contract.
- [HTTP server](../http/README.md) — higher-level protocol/callback layer.

## 6. References
No external references are currently listed.
