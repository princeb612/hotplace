# network_server

```text
┌──────────────────────────────────────┐
│ hotplace study                       │
│ Edition 1 · Revision 1090            │
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

## Why this layer exists

A socket read is too low-level to be the unit of server processing, while an application message is too high-level to be known by the transport layer. `network_server` exists between those two points.

```text
socket / multiplexer
        ↓
     session
        ↓
  accumulated bytes
        ↓
 protocol framing/state
        ↓
 application message
```

The central problem is therefore **where to preserve transport-independent execution state while allowing each protocol to define its own message boundaries**. This explains the session, stream, protocol-group, and dispatch boundaries described below.

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

The network server is organized around a session-oriented processing model. I/O multiplexing determines **when a session should be processed**, the stream layer preserves **what bytes have arrived**, and the protocol layer determines **how those bytes form meaningful units**.

```text
I/O readiness
      ↓
network_session
      ↓
network_stream
      ↓
protocol recognition
      ↓
protocol framing / state
      ↓
application callback
```

The important boundary is therefore not the socket read itself, but the transition from transport bytes to protocol meaning.

```text
transport delivery
      ↓
session scheduling
      ↓
byte accumulation
      ↓
protocol interpretation
      ↓
application meaning
```

### Responsibility Boundaries

| Layer | Responsibility |
|---|---|
| socket / multiplexer | detect transport readiness and deliver I/O events |
| network_session | represent the ongoing connection as a schedulable unit |
| event_queue | schedule session work |
| network_stream | accumulate and preserve received bytes |
| network_protocol_group | recognize which protocol can interpret the bytes |
| network_protocol | establish protocol-specific boundaries and state |
| application callback | consume the interpreted result |

This separation allows transport-specific behavior, stream accumulation, protocol framing, and application dispatch to evolve independently.

### One Read Is Not One Message

A read operation only reports available transport data. It does not imply a protocol boundary.

```text
one read
   ├── partial protocol unit
   ├── exactly one unit
   └── multiple units
```

The stream therefore preserves the input until the protocol layer can determine the appropriate boundary.

### Protocol Interpretation Is Layered

Protocol meaning is recovered progressively rather than in one step:

```text
transport
   ↓
record / packet
   ↓
protocol unit
   ↓
protocol state
   ↓
application message
```

For example, TLS records carry TLS handshake messages, while HTTP/2 frames carry HTTP/2 protocol events. QUIC uses packets and frames while carrying TLS handshake bytes through CRYPTO frames.

The network server's common session/stream machinery stops at the boundary where concrete protocol semantics take over.

## Cross-Topic Boundary

`network_server` provides the execution context in which protocol layers consume transport input; it does not own the semantics of those protocols.

```text
network_server
  │
  ├── TCP stream ──► TLS record ──► HTTP/1.1 or HTTP/2
  │
  ├── UDP datagram ──► DTLS / protocol-specific processing
  │
  └── UDP datagram ──► QUIC packet/frame ──► HTTP/3
```

The important distinction is that the common server layer owns **when and where processing occurs**, while TLS, QUIC, HTTP/2, and HTTP/3 own **what the bytes mean**. The current HTTP/3 server path is especially important to read as a boundary: QUIC endpoint selection exists, but the HTTP/3 request-consumption path is not yet connected to `http_server` in the same way as HTTP/1.1 and HTTP/2.

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

### TLS Accept Prosumer Model

TLS acceptance is a distinct producer/consumer boundary before a secure session exists. TCP `accept()` is kept separate from the potentially longer `ssl_accept()` operation.

```text
TCP listen socket
      │
      ▼
 producer / accept
      │
      │ TCP accept()
      ▼
 accept_queue
      │
      ▼
 TLS accept worker(s)
      │
      │ ssl_accept()
      ▼
 network_session
      │
      ▼
 session event queue
      │
      ▼
 normal consumer(s)
```

The two queues have different responsibilities:

| Queue | Boundary | Purpose |
|---|---|---|
| `accept_queue` | accepted socket → secure session | defer TLS handshake work |
| session `event_queue` | session I/O → protocol processing | schedule produce/consume work |

`server_conf` exposes `serverconf_concurrent_tls_accept`. This multiplicity applies to the TLS-accept stage rather than TCP `accept()` itself:

```text
                    accept_queue
                         │
             ┌───────────┼───────────┐
             ▼           ▼           ▼
          worker 1    worker 2    worker N
             │           │           │
             └───────────┼───────────┘
                         ▼
                    tls_accept()
                         │
                         ▼
                  session_accepted()
```

The current source also gives the queue an explicit lifecycle. During shutdown, TLS accept workers are stopped and pending entries are drained/closed rather than being left outside the server lifecycle.

Conceptually, the TCP/TLS path is therefore:

```text
accept TCP client
      │
      ▼
accept control / address policy
      │
      ├── plain TCP ───────────────► session_accepted()
      │
      └── TLS
           │
           ▼
      accept_context → queue
           │
           ▼
      TLS accept worker
           │
           ▼
      server_socket::tls_accept()
           │
           ▼
      session_accepted()
```

This is different from the ordinary session consumer path. The first queue crosses the **socket → secure session** boundary; the second crosses the **session I/O → protocol** boundary.

### Stream boundary is not protocol boundary

A network stream only supplies an ordered byte sequence. The protocol layer decides what those bytes mean and where a complete message ends.

```text
TCP stream
   │
   ▼
network_stream
   │
   ├── queued chunks
   ├── t_chain
   └── basic_stream
   │
   ▼
protocol detection / framing
   │
   ├── incomplete
   ├── complete
   ├── forged
   ├── crash
   └── too large
   │
   ▼
consume(message_size)
   │
   └── preserve remainder
```

Consequently, a stream read is not necessarily one protocol message. One read may contain a partial message or several complete messages.

### Payload assembly becomes protocol framing

If `network_stream` is viewed only as a payload assembler, it looks like a generic byte-buffer utility. Its more interesting role appears when the surrounding protocol layers are placed on top of it.

Different protocols impose different boundaries on the byte sequence:

```text
                    ordered / packetized input
                              │
             ┌────────────────┼────────────────┐
             │                │                │
             ▼                ▼                ▼
          TCP stream       TLS record       UDP datagram
             │                │                │
             ▼                ▼                ▼
       network_stream    TLS parser       QUIC packet
             │                │                │
             │          ┌─────┴─────┐          │
             │          │           │          │
             │       record      handshake     │
             │          │           │          │
             │          │      extensions      │
             │          │                      │
             ▼          ▼                      ▼
        HTTP/1.x     TLS-protected         QUIC frames
        message      application data          │
             │                                 │
             ▼                                 ▼
        HTTP/2 frame                        HTTP/3 data
```

The important point is that **payload and framing are relative to a layer**.

For example, an HTTP/2 frame is a message boundary at the HTTP/2 layer, but its bytes are carried inside TLS application-data records when HTTP/2 runs over TLS. A TLS handshake message is itself framed inside TLS records, and its extension fields are further structured inside the handshake message.

QUIC is deliberately different: QUIC packets are packetized over UDP, and TLS 1.3 handshake bytes are carried in QUIC `CRYPTO` frames. They are not wrapped in ordinary TLS records inside QUIC.

Thus the same byte-oriented infrastructure participates in several distinct framing models:

```text
HTTP/2 over TCP + TLS

HTTP/2 frame
      │
      ▼
TLS application-data record
      │
      ▼
TCP byte stream
      │
      ▼
network_stream


TLS handshake over TCP

TLS handshake message
      │
      ▼
TLS record
      │
      ▼
TCP byte stream
      │
      ▼
network_stream


HTTP/3 / QUIC

HTTP/3 frame
      │
      ▼
QUIC packet / QUIC frame
      │
      ▼
UDP datagram


TLS handshake over QUIC

TLS handshake message
      │
      ▼
QUIC CRYPTO frame
      │
      ▼
QUIC packet
      │
      ▼
UDP datagram
```

This explains why the server infrastructure should not be documented as merely "reading a payload". It provides the transport/session boundary from which protocol-specific framing can be applied.

### One read does not imply one protocol unit

The same principle appears repeatedly at different layers:

```text
transport input
      │
      ▼
accumulate bytes / packet
      │
      ▼
identify protocol unit
      │
      ├── incomplete ──► wait for more input
      │
      └── complete
             │
             ▼
        consume exactly
        one protocol unit
             │
             ▼
        preserve remainder
```

Examples:

- TCP may split one TLS record across multiple reads.
- One TCP read may contain several TLS records.
- A TLS record may contain handshake bytes that must be accumulated until a complete handshake message is available.
- One HTTP/2 frame may arrive together with the next frame.
- A QUIC UDP datagram may contain multiple QUIC frames, while a QUIC frame may carry only part of a higher-level stream message.

The boundary therefore moves upward as each protocol interprets the bytes produced by the layer below.

### Layered framing model

A useful way to read the current network stack is:

```text
application message
       │
       ▼
protocol framing
       │
       ├── HTTP/1.x message
       ├── HTTP/2 frame
       └── HTTP/3 frame
       │
       ▼
security / transport framing
       │
       ├── TLS record
       └── QUIC packet / frame
       │
       ▼
transport delivery
       │
       ├── TCP byte stream
       └── UDP datagram
```

TLS handshake extensions fit inside this hierarchy rather than beside it:

```text
TLS record
   │
   ▼
TLS handshake message
   │
   ▼
extension vector
   │
   ├── extension type
   └── extension-specific payload
```

For QUIC, the lower relationship changes:

```text
QUIC packet
   │
   ▼
CRYPTO frame
   │
   ▼
TLS handshake bytes
   │
   ▼
TLS handshake message
   │
   ▼
TLS extension
```

The protocol stack is therefore better understood as **successive interpretation of boundaries**, not as one universal stream parser.


### I/O Multiplexing to Protocol Processing: One Session Abstraction

The common processing unit across the I/O and protocol layers is `network_session`, rather than an individual socket read or protocol message.

```text
OS / transport
      ↓
socket + multiplexer
      ↓
network_session
      ├── accept path → TLS accept
      └── event path  → event_queue
      ↓
network_stream
      ↓
network_protocol_group
      ↓
network_protocol
      ↓
application callback
```

The accept queue and the session event queue therefore represent different lifecycle boundaries:

```text
accepted socket
      ↓
accept_queue
      ↓
TLS accept / session establishment
      ↓
network_session
      ↓
event_queue
      ↓
protocol processing
```

#### Raw Stream and Composed Request

`network_session` keeps two `network_stream` objects with different roles:

```text
network_session
 ├── _stream   raw received stream
 └── _request  composed/processed request stream
```

`produce()` places newly received data into `_stream`. `consume()` reads `_stream` through the protocol-aware stream path and produces the data that reaches the callback.

```text
socket read
    ↓
_stream
    ↓
network_stream::read(protocol_group, ...)
    ↓
_request
    ↓
callback
```

This separates **arrival** from **protocol consumption**. A transport read is therefore not assumed to be an application message.

#### Event Queue Schedules Sessions

`network_server` owns an `event_queue` based on `t_mlfq<network_session>`. `network_session::produce()` schedules the session when new stream data is available, using the session priority.

```text
new input
   ↓
session->produce(...)
   ↓
stream receives data
   ↓
event_queue.push(session)
   ↓
consumer
   ↓
session->consume(...)
```

The queue is consequently a **work scheduler**, while `network_stream` remains the **data accumulator**.

#### From Transport Input to Protocol Callback

The resulting path is:

```text
transport input
      ↓
network_session
      ↓
network_stream
      ↓
protocol framing / read_stream
      ↓
network_stream_data
      ↓
network_server callback
```

The callback boundary is therefore different from the socket-read boundary: data reaches the application after stream and protocol processing.

#### Relation to TLS and Protocol Framing

The session abstraction connects the earlier TLS-accept boundary to the protocol-framing boundary:

```text
accept / TLS accept
        ↓
network_session
        ↓
producer
        ↓
transport / security read
        ↓
network_stream
        ↓
event_queue
        ↓
consumer
        ↓
protocol detection / framing
        ↓
application callback
```

The event machinery does not need to know protocol message boundaries. Transport/security handling, stream accumulation, protocol interpretation, and application dispatch remain separate responsibilities.

### Protocol Detection and Dispatch Boundary

`network_protocol_group` is the boundary between accumulated bytes and a concrete `network_protocol`.

```text
network_stream
      ↓
accumulated bytes
      ↓
network_protocol_group::is_kind_of()
      │
      ├── more data
      ├── matched protocol
      └── invalid / no match
      ↓
network_protocol
      ↓
read_stream()
```

The group determines whether the available input is sufficient to identify a protocol and selects the protocol object that can consume it. This keeps protocol recognition out of the generic session and queue machinery.

#### Detection Is Incremental

Protocol detection operates on the bytes currently accumulated in the stream. A recognizer may require more input before a decision can be made.

```text
read event
   ↓
network_stream
   ↓
current accumulated bytes
   ↓
is_kind_of()
   ├── more_data → keep accumulating
   ├── matched   → protocol::read_stream()
   └── invalid   → error / discard path
```

This is especially important for stream transports, where a single read may contain only a prefix of a recognizable protocol unit.

#### Detection and Framing Are Separate Decisions

Protocol detection answers:

> Which protocol should interpret these bytes?

Protocol framing answers:

> How many bytes form the next complete unit of that protocol?

```text
bytes
  ↓
protocol detection
  ↓
concrete protocol
  ↓
protocol framing / read_stream
  ↓
message boundary
```

The distinction prevents `network_stream` from becoming a collection of protocol-specific parsers. The stream layer accumulates data and provides the handoff boundary; the concrete protocol interprets its own framing.

#### Relation to the Layered Framing Model

The detection boundary sits between generic session handling and protocol-specific framing:

```text
TCP / TLS / UDP input
        ↓
network_session
        ↓
network_stream
        ↓
protocol_group
        │
        ├── detect
        ↓
concrete protocol
        │
        ├── HTTP/1.x
        ├── HTTP/2
        ├── TLS
        └── other registered protocols
        ↓
protocol framing
```

The overall processing model is therefore:

```text
transport delivery
      ↓
session scheduling
      ↓
byte accumulation
      ↓
protocol recognition
      ↓
protocol framing
      ↓
application/protocol message
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

## Cross-Topic Verification

Verification at the network-server boundary is different from protocol-vector verification. The server layer is primarily exercised through executable I/O paths, while TLS, QUIC, and HTTP topics provide protocol-specific vectors and captures.

```text
protocol vectors / captures
          │
          ▼
   protocol implementation
          │
          ▼
    network_server
          │
   ┌──────┼────────┐
   ▼      ▼        ▼
  TCP    TLS/DTLS  QUIC
   │      │        │
   └──────┴────────┘
          ▼
      session/event
          │
          ▼
      application
```

PCAPNG is therefore useful for checking the traffic observed around this boundary, but it does not replace the network-server tests that verify session scheduling, stream retention, event ordering, and transport integration. The current QUIC boundary remains incomplete at the common `network_server` level.

## Status

| Area | Revision 1090 |
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
             TCP              UDP               ▼
                                              HTTP
                                                │
                                               HTTP/2
```

QUIC is related to the transport/security side but should remain a bounded adjacent topic until its integration with the common server/session model is complete.
