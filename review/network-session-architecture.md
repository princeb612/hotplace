# Hotplace Network Session Architecture

## Source Baseline

- Source revision: 1097
- Review question: how does the session boundary separate network lifecycle from protocol-specific wire construction and reconstruction?

## 1. Perspective

It is difficult to see the overall structure of hotplace's network layer if it is viewed simply as a collection of `socket` wrappers.

The more useful view is the progression from a socket to `network_session`, which represents a communication unit, followed by a separation between streams and protocols.

Conceptually:

```text
socket
   ↓
network_session
   ↓
network_stream
   ↓
network_protocol
```

When multiple sessions have to be managed simultaneously, a multiplexer and accept/producer/consumer roles are added around this structure.

```text
                    multiplexer
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
           session     session     session
              │          │          │
            stream     stream     stream
              │          │          │
           protocol   protocol   protocol
```

This document reviews that hierarchy from the perspective of hotplace's network architecture.

---

## 2. The Socket Is Only the Starting Point

A socket is the actual communication endpoint provided by the operating system.

POSIX systems use socket/file-descriptor APIs, while Windows uses the Winsock family of APIs.

From the application protocol's perspective, however, an fd alone is not enough.

```text
fd / socket
    ↓
connection state
    ↓
read / write state
    ↓
protocol context
    ↓
session
```

The first purpose of a network abstraction is therefore to establish a boundary between OS-specific socket APIs and higher-level network logic.

In hotplace, the socket and multiplexer layers under `sdk/io/system` and the network abstractions under `sdk/net` share this responsibility.

---

## 3. `network_session`

`network_session` can be viewed as the central abstraction for handling one connection or communication unit at a higher level.

Conceptually:

```text
network_session
    ├── connection state
    ├── endpoint / socket relationship
    ├── stream handling
    └── protocol relationship
```

The important point is that a session is not simply another name for a socket.

A socket is an OS resource; a session is closer to an abstraction representing the lifecycle and state of a network communication.

```text
OS resource
    ↓
socket
    ↓
network_session
    ↓
application/network logic
```

This boundary allows higher-level code to avoid depending directly on socket-descriptor details.

---

## 4. `network_stream`

A stream concept appears above the session.

```text
session
   ↓
stream
```

A stream is suitable for representing a continuous data flow in an actual protocol.

For connection-oriented protocols, the following model is natural:

```text
connection
    ↓
one or more data flows
```

`network_stream` can therefore be understood as the intermediate layer between session lifecycle and actual data transfer.

```text
network_session
       │
       ├── state / lifecycle
       │
       ▼
network_stream
       │
       ├── read
       ├── write
       └── data flow
```

This separation lets protocol implementations focus on the data flow they process rather than on which socket happens to carry it.

---

## 5. `network_protocol`

The protocol layer adds the semantic meaning of the communication.

```text
network_session
       ↓
network_stream
       ↓
network_protocol
```

At this layer, concepts such as the following are interpreted:

- message
- frame
- packet
- handshake
- application data

The responsibilities can therefore be summarized as:

```text
socket
  └─ OS communication endpoint

session
  └─ connection/lifecycle abstraction

stream
  └─ data flow abstraction

protocol
  └─ wire/application semantics
```

This separation is especially useful when different protocols such as TLS, HTTP/2, and QUIC are implemented on top of a common network foundation.

---

## 6. The Position of the Multiplexer

Handling multiple connections requires more than processing each socket independently in a blocking manner.

The hotplace system layer provides platform-specific I/O multiplexing abstractions.

```text
POSIX
 ├─ epoll
 └─ ...

Windows
 └─ IOCP
```

At a higher level:

```text
                multiplexer
                     │
       ┌─────────────┼─────────────┐
       ▼             ▼             ▼
    socket A      socket B      socket C
       │             │             │
    session A     session B     session C
```

The multiplexer does not own the protocol semantics of a session.

Its role is closer to efficiently reporting:

> Which endpoint has an I/O event?

---

## 7. Accept and Session Creation

On the server side, an incoming connection produces a new communication endpoint from the existing listening socket.

Conceptually:

```text
listening socket
       ↓
     accept
       ↓
new socket
       ↓
network_session
       ↓
network_stream / protocol
```

The accept layer can therefore be viewed as the boundary that discovers a new connection and attaches it to the session lifecycle.

This allows server logic to focus on how a new session should be initialized rather than on the operating system's accept call itself.

---

## 8. Producer / Consumer Perspective

As the network architecture grows, it can become useful to separate I/O events from actual data processing.

Conceptually:

```text
I/O / event source
        ↓
     producer
        ↓
       queue
        ↓
     consumer
        ↓
 protocol/session processing
```

A producer creates and forwards data or events, while a consumer connects them to actual processing.

This does not mean that every network path must use exactly the same producer/consumer structure.

The important architectural direction is that **I/O readiness can be separated from protocol processing**.

---

## 9. Overall Structure

Putting the preceding pieces together gives an approximate architecture:

```text
                       application / protocol
                                │
                                ▼
                       network_protocol
                                │
                                ▼
                        network_stream
                                │
                                ▼
                       network_session
                                │
                                ▼
                         socket / endpoint
                                │
                                ▼
                         OS I/O subsystem
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                 ▼
             epoll             IOCP             ...
              │                 │
              └───────── multiplexer ─────────────┘
                                │
                                ▼
                         event processing
                                │
                         producer/consumer
```

The actual implementation has more detailed relationships than this diagram, but these are the core connections worth retaining when reconstructing the architecture.

---

## 10. Relationship to the Protocol Stack

An interesting aspect of hotplace's network architecture is that multiple protocols can be built above session/stream abstractions.

For example:

```text
socket
   ↓
network_session
   ↓
network_stream
   ↓
TLS / DTLS
   ↓
application protocol
```

QUIC requires a different mapping because the protocol itself strongly defines connection, packet, and stream concepts.

```text
QUIC connection
   ├── packet
   ├── frame
   └── stream
```

Therefore, `network_stream` should not be treated as a one-to-one mapping to every protocol's wire-level stream. It is better understood as hotplace's internal abstraction for a data flow.

---

## 11. Session and Protocol Should Remain Separate

If protocol implementation directly manages the socket lifecycle, unrelated responsibilities can quickly become mixed together:

```text
socket open
connect
read
write
TLS handshake
HTTP parsing
timeout
close
```

With separate abstractions, the responsibilities become clearer:

```text
session
 └─ connection lifecycle

stream
 └─ data transfer

protocol
 └─ protocol semantics
```

This separation fits hotplace's development style, where protocol study is repeatedly extended into working implementations.

---

## 12. Session Boundary and Wire Construction

The session abstraction is not only a place to keep connection lifecycle state. It also provides a useful boundary at which protocol-specific material can be turned into, or reconstructed from, wire-oriented units.

The DTLS and QUIC implementations make this relationship visible.

```text
higher-level protocol state
          │
          ▼
   session-level boundary
          │
      ┌───┴────┐
      ▼        ▼
 construction  reconstruction
      │        │
  publisher   arrange
      │        │
      ▼        ▼
 wire output  usable records
```

For DTLS, the send and receive directions are deliberately different problems. `dtls_record_publisher` turns handshake/record material into DTLS records, while `dtls_record_arrange` deals with ordering and reconstruction concerns that arise when records arrive through a datagram transport.

```text
DTLS send
TLS / handshake record
        ↓
dtls_record_publisher
        ↓
DTLS records / datagrams

DTLS receive
datagram input
        ↓
dtls_record_arrange
        ↓
ordered / usable records
        ↓
TLS processing
```

QUIC makes the same boundary visible in a different form. `quic_packet_publisher` materializes protocol material into a QUIC packet, where TLS handshake data becomes CRYPTO-frame material rather than a TLS record, while application data and transport control are represented by other QUIC frames.

```text
TLS handshake / application / transport state
                    │
                    ▼
          quic_packet_publisher
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
    CRYPTO       STREAM        ACK / PADDING
       │            │            │
       └────────────┼────────────┘
                    ▼
               QUIC packet
```

The architectural point is not that DTLS and QUIC share one publisher class. It is that the session-level protocol boundary provides a place where semantic protocol state is materialized into wire units without making the lower network foundation responsible for protocol-specific layout.

---

## 13. Platform Abstraction and Its Relationship to the Network Layer

Hotplace targets both older Linux environments and Windows, so upper-level code needs to avoid directly depending on platform-specific network APIs as much as practical.

The resulting boundary can be summarized as:

```text
platform-specific API
        ↓
sdk/io/system
        ↓
socket / multiplexer abstraction
        ↓
sdk/net
        ↓
session / stream / protocol
```

This is more than a portability wrapper. It is also a boundary that separates responsibilities within the network subsystem.

---

## 14. Practical Meaning of the Structure

The architecture can be summarized very simply:

```text
"An I/O event occurred"
        ↓
multiplexer / event layer

"Which connection is this?"
        ↓
network_session

"Which data flow is involved?"
        ↓
network_stream

"What do these bytes mean?"
        ↓
network_protocol
```

Moving upward means moving from OS resources toward protocol semantics.

---

## 15. Connections to Other Network Subsystems

This structure connects directly to the TLS/DTLS/QUIC review material.

```text
Network foundation
       │
       ├── socket
       ├── multiplexer
       ├── session
       └── stream
              │
              ▼
          TLS / DTLS
              │
              ▼
             QUIC
              │
              ▼
       HTTP / application
```

The layering relationship between TLS and QUIC is not literally a simple serial stack, so this diagram should only be read as a memory aid for the fact that protocol implementations build on the network foundation.

---

## 16. Related Code

### I/O Foundation

- `sdk/io/system/socket`
- `sdk/io/system/multiplexer`
- `sdk/io/system/epoll`
- `sdk/io/system/iocp`
- platform-specific network code

### Network Abstraction

- `sdk/net/network_session`
- `sdk/net/network_stream`
- `sdk/net/network_protocol`
- accept / producer / consumer implementations

### Higher-Level Protocols

- TLS / DTLS
- HTTP/HTTP2
- QUIC

When reading the source after this document, it is often easier to start from `network_session` and move downward or upward rather than beginning at the socket layer.

---

## 17. Current Status

The most important architectural boundary in the current structure is:

```text
OS / platform
      ↓
I/O abstraction
      ↓
socket / multiplexer
      ↓
network session
      ↓
network stream
      ↓
protocol semantics
```

Server-side accept handling and event producer/consumer roles connect the session lifecycle to I/O processing.

Rather than treating this as one large network framework, it is more accurate to view it as the result of **separating network responsibilities while implementing multiple protocols directly in hotplace**.

---

## 18. In One Sentence

Hotplace's network architecture can be summarized as:

> **A structure that separates socket-level code from protocol interpretation through session → stream → protocol layers, while connecting I/O for multiple connections through multiplexing and event processing.**
