# network_server

```text
┌──────────────────────────────────────┐
│ hotplace study                       │
│ Edition 1 · Revision 1083            │
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
             │          ┌─────┴─────┐           │
             │          │           │           │
             │       record      handshake      │
             │          │           │           │
             │          │      extensions       │
             │          │                       │
             ▼          ▼                       ▼
        HTTP/1.x     TLS-protected          QUIC frames
        message      application data            │
             │                                  │
             ▼                                  ▼
        HTTP/2 frame                         HTTP/3 data
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


### Network Session as the Processing Unit

The server's producer/consumer boundary is organized around `network_session`, not around individual read buffers.

```text
I/O event
   │
   ▼
network_server
   │
   ▼
network_session::produce()
   │
   ├── stream socket
   │      └── TLS/plain read
   │
   └── datagram socket
          └── UDP/DTLS receive
   │
   ▼
network_stream
   │
   ▼
event_queue
   │
   ▼
network_session::consume()
   │
   ▼
request stream
   │
   ▼
protocol interpretation
```

The queue therefore schedules a session that has work to process. The received bytes remain associated with that session's stream.

### Raw Stream and Composed Request

`network_session` keeps two `network_stream` objects with different roles:

```text
network_session
 ├── _stream   raw received stream
 └── _request  composed/processed request stream
```

`produce()` places newly received data into `_stream`. `consume()` then reads `_stream` into `_request` through `network_stream::read(protocol_group, ...)` and returns the resulting `network_stream_data` chain.

This separates **arrival** from **protocol consumption**:

```text
socket read
    ↓
_stream
    ↓
network_stream::read()
    ↓
_request
    ↓
network_stream::consume()
    ↓
callback
```

The distinction is important because transport reads do not necessarily correspond to protocol messages.

### Event Queue Schedules Sessions

`network_server` owns an `event_queue` based on `t_mlfq<network_session>`. `network_session::produce()` pushes the session when new stream data is available, using the session priority.

```text
new input
   ↓
session->produce(...)
   ↓
stream receives data
   ↓
event_queue.push(session priority, session)
   ↓
consumer
   ↓
event_queue.pop(...)
   ↓
session->consume(...)
```

The queue is consequently a **work scheduler**, while `network_stream` is the **data accumulator**.

The session is reference-counted while crossing this producer/consumer boundary. The consumer releases the session after its queued work is consumed.

### Stream Accumulation Is the Framing Boundary

`network_stream::produce()` stores each received buffer as a `network_stream_data` object. `network_stream::write()` can either transfer the queued data directly or invoke protocol-aware `do_writep()`.

Protocol-aware processing accumulates queued buffers into a `basic_stream`, then asks `network_protocol_group::is_kind_of()` whether the accumulated bytes identify a protocol and whether more data is required.

```text
network_stream_data
       │
       ▼
  basic_stream
       │
       ▼
protocol_group::is_kind_of()
       │
       ├── more_data ──→ accumulate more input
       │
       └── success
              │
              ▼
      network_protocol::read_stream()
              │
              ▼
        protocol_state
              │
       ┌──────┼─────────┐
       ▼      ▼         ▼
   complete  error    more work
       │
       ▼
 message_size
       │
       ▼
 remaining bytes stay queued
```

A single socket read may therefore produce only part of a protocol unit, or several protocol units. The stream layer preserves this distinction instead of assuming a one-read/one-message relationship.

### From Transport Input to Protocol Callback

After `network_session::consume()` has processed the stream, the consumer receives a chain of `network_stream_data`. Each resulting buffer is dispatched through the server callback with the session, socket information, data pointer, size, and address.

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

This makes the callback boundary different from the socket-read boundary: the callback sees data after the stream/protocol processing stage.

### Relationship to TLS and Protocol Framing

The session pipeline provides the missing middle layer between the earlier TLS accept model and protocol framing model:

```text
accept / TLS accept
        ↓
network_session
        ↓
producer
        ↓
transport/security read
        ↓
network_stream
        ↓
event_queue
        ↓
consumer
        ↓
request stream
        ↓
protocol framing
        ↓
HTTP / TLS / other protocol handling
        ↓
callback
```

For stream transports, TLS is consumed before application protocol framing when the session uses a TLS-capable server socket. For datagram transports, the corresponding path preserves the datagram address while feeding the stream abstraction.

The resulting architecture can be understood as three separate responsibilities:

```text
I/O scheduling       data accumulation       protocol interpretation
─────────────        ────────────────        ───────────────────────
multiplexer          network_stream          network_protocol_group
producer             network_session         network_protocol
event_queue          request stream           callback
```

The separation allows the same session/event machinery to support different transport and protocol combinations without making the event queue itself aware of protocol message boundaries.

### Protocol Group as Detection and Dispatch Boundary

`network_stream` does not need to know the concrete application protocol in advance. The protocol group provides the detection boundary between accumulated bytes and a concrete `network_protocol`.

```text
network_stream
      │
      ▼
 accumulated bytes
      │
      ▼
network_protocol_group::is_kind_of()
      │
      ├── more data
      │
      ├── matched protocol
      │
      └── invalid / no match
      │
      ▼
network_protocol
      │
      ▼
read_stream()
```

The group therefore has two related responsibilities: determine whether the available bytes are sufficient to identify a protocol, and select the protocol object that should consume the stream.

This keeps protocol recognition out of the generic session and queue machinery.

### Detection Is Incremental

Protocol detection is performed against the bytes currently available in the stream. A protocol recognizer can report that more data is required before a decision can be made.

```text
read event
   ↓
network_stream
   ↓
current accumulated bytes
   ↓
is_kind_of()
   ├── more_data ──→ keep accumulating
   │
   ├── matched ────→ protocol::read_stream()
   │
   └── invalid ────→ error / discard path
```

This is important for TCP and TLS because a transport read boundary is not a protocol boundary. The first read may contain only a prefix of a recognizable message.

The same abstraction also supports protocol groups containing multiple candidate protocol handlers: recognition happens before the selected protocol's stream reader consumes the data.

### Detection and Framing Are Separate Decisions

Protocol detection answers:

> Which protocol should interpret these bytes?

Protocol framing answers:

> How many bytes form the next complete unit of that protocol?

The stream pipeline consequently has two stages:

```text
bytes
  │
  ▼
protocol detection
  │
  ▼
concrete protocol
  │
  ▼
protocol framing / read_stream
  │
  ▼
message boundary
```

This distinction prevents `network_stream` from becoming a collection of protocol-specific parsers. It owns accumulation and the handoff boundary; the concrete protocol owns interpretation of its own framing.

### Relation to the Layered Framing Model

The detection boundary sits between generic transport/session handling and protocol-specific framing:

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
        │
        ▼
concrete protocol
        │
        ├── HTTP/1.x
        ├── HTTP/2
        ├── TLS
        └── other registered protocols
        │
        ▼
protocol framing
```

For QUIC, packet parsing is a more explicit transport/protocol boundary because QUIC packets already carry their own packet structure. The same conceptual distinction remains useful: identify the protocol context first, then let the concrete reader interpret its framing.

The resulting architecture is therefore not simply a byte stream parser. It is a staged interpretation pipeline:

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

## Network Server Conceptual Model

The network-server path can be understood as a sequence of responsibility boundaries rather than as a sequence of class calls.

```text
                         NETWORK SERVER
                              │
                    ┌─────────┴─────────┐
                    │                   │
                 Accept              Existing session
                    │                   │
                    └─────────┬─────────┘
                              ▼
                       network_session
                              │
                       scheduling/event
                              ▼
                       network_stream
                              │
                       byte accumulation
                              ▼
                  network_protocol_group
                              │
                     protocol detection
                              ▼
                       network_protocol
                              │
                     protocol framing
                              ▼
                        message_size
                              │
                     generic consumption
                              ▼
                  concrete protocol/session
                              │
                    protocol state/meaning
                              ▼
                       application dispatch
```

The layers can be summarized by the question each one answers:

| Boundary | Question |
|---|---|
| Accept | Who is connecting? |
| Session | Which connection/session is being serviced? |
| Event queue | When should that session be processed? |
| Stream | Which bytes have arrived and remain unconsumed? |
| Protocol group | Which protocol can own these bytes? |
| Protocol | Where is the next complete protocol unit? |
| Protocol state | What does that unit mean in the protocol state machine? |
| Application | What should the application do with the resulting meaning? |

This model also clarifies several boundaries that otherwise look similar.

**Detection is not framing.** Detection selects a protocol from accumulated bytes. Framing determines the next consumable unit after a protocol has been selected.

**Framing is not interpretation.** `message_size` identifies the boundary to consume; protocol-specific state gives the consumed unit its meaning.

**A transport read is not a protocol message.** TCP may fragment one protocol unit across reads or combine several protocol units in one read. The stream layer therefore has to preserve accumulation and remainder independently of transport read boundaries.

**A protocol unit is not necessarily an application message.** HTTP/2 demonstrates this directly: a complete frame can update connection/stream state without yet representing a complete application request.

The resulting conceptual contract is:

```text
transport
   │
   │ delivery
   ▼
session
   │
   │ scheduling
   ▼
stream
   │
   │ accumulated bytes
   ▼
protocol group
   │
   │ ownership
   ▼
protocol
   │
   │ boundary
   ▼
stream consumption
   │
   │ complete protocol unit
   ▼
protocol state
   │
   │ meaning
   ▼
application
```

This is the stable architectural view of the current network-server implementation: **lower layers manage delivery and boundaries; higher layers recover protocol and application meaning.**
