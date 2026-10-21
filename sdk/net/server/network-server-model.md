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

# Network server execution model

## 1. Role

This document focuses on `network_server` worker orchestration and lifecycle. Read it with [network_session.md](network_session.md) for per-connection state and [network-stream-and-protocol.md](network-stream-and-protocol.md) for byte buffering and protocol framing.

## 2. Data Model

```text
network_server context
  ├─ server socket + platform multiplexer
  ├─ session manager
  ├─ protocol group
  ├─ accept / TLS-accept work
  ├─ producer queue and threads
  └─ consumer queue and threads
```

Linux uses the implemented `multiplexer_epoll` path; Windows uses `multiplexer_iocp`. A kqueue class/reference exists but should not be treated as evidence of a supported macOS/BSD server path.

The configured concurrency keys include event, TLS accept, producer/network, and consumer counts, along with TCP/UDP buffer sizes. When `network_server::open()` receives no configuration, source defaults are event 1024, TLS accept 1, producer 1, and consumer 2. `http_server_builder` initializes its own defaults (event 1024, TLS accept 2, producer 2, consumer 2), so effective concurrency depends on the caller's configuration path.

## 3. Behavior Model

### Worker and session path

```text
accept worker
  -> accept socket
  -> optional accept-control callback
  -> accept_queue (secure sockets)
  -> TLS-accept worker(s)
  -> session_manager.connected / session registration

multiplexer read event
  -> producer worker
  -> session_manager.find(socket)
  -> network_session::produce(...)
  -> network_stream queues raw bytes
  -> session scheduled by priority

consumer worker
  -> dequeue session
  -> network_session::consume(protocol_group, ...)
  -> protocol framing
  -> callback with interpreted message and session context
```

For TLS server sockets, TCP accept and TLS handshake are distinct work stages. The configured TLS-accept worker count supports one or more workers; the queue may become a bottleneck when handshake arrivals exceed processing capacity. More workers can increase parallel handshake work, at the cost of additional CPU and memory pressure.

The session manager and the stream/protocol layer have separate responsibilities. The manager indexes and coordinates session lifetime; the session owns per-connection state; `network_stream` buffers bytes; the protocol group selects a registered interpreter; and the protocol determines message boundaries. See the linked focused documents rather than treating these as interchangeable links.

### Lifecycle and shutdown

```text
open
  -> initialize socket, multiplexer, session manager, protocol group
  -> start accept / TLS-accept / event / producer / consumer work
  -> event_loop_break / consumer_loop_break / tls_accept_loop_break
  -> close and release registrations/context
```

Shutdown must account for queued session references and worker loops. Stopping one thread does not by itself prove all session references or multiplexer bindings have been released.

## 4. Relationships

- `network_server.hpp/.cpp` — worker loops and context lifecycle.
- [Network server overview](README.md) — integrated end-to-end path.
- [Network session](network_session.md) — state, ownership and lifetime.
- [Network stream and protocol](network-stream-and-protocol.md) — raw bytes to framed messages.
- [Socket model](../basic/socket-model.md) — socket contracts.
- [HTTP server](../http/README.md) — higher-level protocol and callback layer.

## 5. References

No external references are currently listed.
