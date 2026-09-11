# network_server

```text
┌──────────────────────────────────────┐
│ hotplace study                       │
│ Edition 1 · Revision 1076            │
│ Documented with GPT-5.6 Luna         │
│ — study, reconstruction & review     │
└──────────────────────────────────────┘
```

## Context

`network_server` is the server-side orchestration point where socket I/O, multiplexer events, session ownership, stream/datagram assembly, protocol processing, and application dispatch meet.

The important subject is therefore the **processing model** rather than any individual class.

```text
                    network_server
                           │
             ┌─────────────┼─────────────┐
             │             │             │
        server socket   multiplexer   session manager
             │             │             │
             │        I/O events         │
             │             ↓             │
             │          producer         │
             │             ↓             │
             └────── network_session ────┘
                           │
                 ┌─────────┴─────────┐
                 ↓                   ↓
          network_stream          datagram
                 │                   │
                 ↓                   ↓
              consume             protocol
                 │
                 ↓
          protocol group
                 │
                 ↓
             application
```

This layer is where hotplace's common server machinery becomes reusable across plain TCP/UDP and secure TLS/DTLS paths.

## History

The repository provides useful comparison points:

```text
tcpserver1 / udpserver1
    └── direct multiplexer-oriented path

tcpserver2 / udpserver2
    └── network_server path

tlsserver / dtlsserver
    └── network_server + server_socket_builder
```

The purpose of these examples is not to establish an inferred chronology, but to expose the evolution of the server-side abstraction and the boundary between low-level event handling and protocol processing.

## Conceptual

### Event → session → message

The central processing model is:

```text
I/O event
   ↓
server event handling
   ↓
session produce
   ↓
stream / datagram assembly
   ↓
session consume
   ↓
protocol parsing
   ↓
application dispatch
```

The important separation is:

```text
OS I/O
   │
   ▼
transport/session
   │
   ▼
bytes
   │
   ▼
protocol message
   │
   ▼
application
```

A socket event is not itself a protocol event. A read is not necessarily a complete message. `network_server` coordinates the transitions without making the socket layer responsible for protocol semantics.

### Producer / consumer separation

```text
multiplexer
    │
    │ I/O event
    ▼
 producer
    │
    ▼
network_session::produce()
    │
    ├── TLS / plain stream
    └── DTLS / plain datagram
    │
    ▼
 stream / datagram state
    │
    ▼
 event queue
    │
    ▼
 consumer
    │
    ▼
network_session::consume()
    │
    ▼
protocol group
```

This separation is one of the useful architectural ideas in the current implementation. Production is concerned with receiving and preparing transport data; consumption is concerned with interpreting it.

### Event queue and priority

The consumer side uses a session event queue. The queue is not simply a socket-read queue: protocol processing can influence the priority with which session work is processed.

```text
received data
     ↓
session becomes work
     ↓
event queue
     ↓
priority-aware processing
     ↓
consume
     ↓
protocol result
```

The benefit is that protocol-level urgency can affect scheduling while the multiplexer/socket layer remains protocol-independent.

### Stream boundary ≠ protocol boundary

`network_stream` is **not a ring buffer**.

Its role is to retain received chunks and assemble enough input for protocol-aware interpretation.

```text
socket reads
    │
    ├── chunk A
    ├── chunk B
    └── chunk C
          ↓
    network_stream
          ↓
      t_chain
          ↓
    basic_stream
          ↓
 protocol detection
          ↓
network_protocol::read_stream()
          ↓
 ┌────────┬────────┬────────┬────────┐
 │complete│ forged │ crash  │ large  │
 └────────┴────────┴────────┴────────┘
```

A protocol message may end inside a queued chunk, while additional bytes for the next message are already present. Therefore the consumed length can be smaller than the available input, and the remainder must survive for the next consume operation.

This is a protocol-message assembly mechanism, not a fixed-size circular storage abstraction.

### Stream and datagram are different boundaries

```text
TCP
  socket reads
       ↓
  byte stream
       ↓
  protocol framing
       ↓
  message

UDP
  datagram
       ↓
  datagram processing
       ↓
  protocol message
```

For TCP, transport boundaries do not provide message boundaries. For UDP, the datagram boundary already exists at the transport interface.

### Security remains below protocol dispatch

```text
TLS
 │
 ▼
TCP stream
 │
 ▼
network_session
 │
 ▼
network_stream
 │
 ▼
protocol

DTLS
 │
 ▼
UDP datagram
 │
 ▼
network_session
 │
 ▼
protocol
```

This keeps TLS/DTLS as transport-security processing rather than application protocol processing.

## Structural

### Orchestration

The current server context combines:

- multiplexer handle and concurrency
- callback configuration
- listening/server socket
- TLS accept synchronization
- producer / accept / TLS / consumer activity
- session manager
- session event queue
- accept control

Conceptually:

```text
                         server context
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
      multiplexer         server socket       session manager
          │                   │                   │
          ▼                   ▼                   ▼
       events          accept / read       active sessions
          │                                       │
          └───────────────┬───────────────────────┘
                          ▼
                    worker processing
                          │
                    event queue
                          │
                          ▼
                       consume
```

### Session

`network_session` is the connection-specific state holder between transport activity and protocol processing.

It owns or coordinates:

```text
server_socket
network_stream
request / protocol state
optional higher-level session state
```

For stream transport it can perform TLS/plain reads and push resulting data into the stream/event processing path. For datagrams it handles DTLS/plain datagram processing.

### Session manager

The manager maintains active stream sessions by transport identity and datagram/DTLS sessions using peer/address information.

Session close is a lifecycle operation rather than merely deleting an object:

```text
session close
    ↓
remove from manager
    ↓
unbind from multiplexer
    ↓
application callback
    ↓
release
```

The ordering is part of the architectural concern because the session participates in both the I/O system and the application-visible server state.

### Socket abstraction and construction

The socket layer separates logical scheme selection from concrete provider/implementation:

```text
logical socket scheme
          ↓
server_socket_builder
          ↓
provider / implementation
          ↓
server_socket
          ↓
network_server
```

The current family includes naive TCP/UDP, OpenSSL TLS/DTLS, trial TLS/DTLS, and the current trial QUIC socket path.

The useful abstraction is therefore not “TLS socket class” but:

```text
transport + security + provider
             ↓
        server_socket
```

## Flow

### TCP

```text
multiplexer
    ↓
read event
    ↓
network_server
    ↓
network_session::produce()
    ↓
plain/TLS read
    ↓
network_stream
    ↓
event queue
    ↓
network_session::consume()
    ↓
protocol group
    ↓
application
```

### UDP / DTLS

```text
UDP event
    ↓
session lookup / creation
    ↓
plain/DTLS datagram processing
    ↓
protocol processing
    ↓
application
```

### Multiple protocol messages in one read

```text
one socket read
       │
       ▼
┌─────────────────────────────┐
│ message A │ message B │ ... │
└─────────────────────────────┘
       │
       ├── consume A
       │
       └── preserve B ...
```

### Partial message

```text
read #1
   ↓
partial message
   ↓
network_stream retains it
   ↓
read #2
   ↓
complete message
   ↓
protocol dispatch
```

These two cases explain why `network_stream` must retain state across individual I/O events.

## Study & Verification

The server applets expose the architecture in executable form:

```text
tcpserver1 / udpserver1
        │
        └── direct multiplexer-oriented comparison

tcpserver2 / udpserver2
        │
        └── network_server processing

tlsserver / dtlsserver
        │
        └── secure server paths

http server applets
        │
        └── higher-level protocol use
```

The durable questions for studying the implementation are:

- How does an I/O event become session work?
- Where is transport security removed from the protocol layer?
- How are partial stream messages retained?
- How can multiple messages from one read be consumed?
- Why is production separated from consumption?
- How does the event queue affect session scheduling?
- What ordering is required when a session closes?
- Which responsibilities belong to `server_socket`, `network_session`, and `network_server`?
- Where does QUIC currently stop short of common `network_server` integration?

Source anchors:

```text
sdk/net/server/
  network_server.*
  network_session.*
  network_session_manager.*
  network_stream.*
  network_protocol.*
  network_protocol_group.*
  server_conf.*
  types.hpp
```

## Status

| Area | Revision 1076 |
|---|---|
| TCP server path | Implemented |
| UDP server path | Implemented |
| Multiplexer integration | Implemented |
| Session management | Implemented |
| Stream assembly | Implemented |
| TLS server path | Implemented |
| DTLS server path | Implemented |
| HTTP server use | Present |
| QUIC integration through network_server | Not complete |
| `network_stream` as ring buffer | Not applicable |

The important current boundary is therefore clear: the common server/session architecture is established, while complete QUIC integration into that architecture remains unfinished.

## Related topics

```text
                         network_server
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
             TLS             DTLS         application
              │                │           protocols
              ▼                ▼                │
             TCP              UDP              ▼
                                              HTTP
                                                │
                                               HTTP/2
```

QUIC is related to the transport/security side but should remain a bounded adjacent topic until its integration with the common server/session model is complete.

## Related Documents

- [HTTP Server](../http_server/README.md)
- [TLS](../tls/README.md)
- [QUIC](../quic/README.md)
- [PCAPNG](../pcapng/README.md)
