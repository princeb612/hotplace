# HTTP/3 — Study Boundary & Current State

> Edition 1 · Revision 1090

## Context

HTTP/3 is the application protocol carried by QUIC. In this project, its meaningful
relationship is not simply `HTTP/3 → QUIC`, but a chain in which QUIC provides the
transport and stream machinery, while HTTP/3 defines the HTTP-specific streams,
frames, control information, and connection semantics above it.

```text
HTTP/2
  │
  └── Header Block ── HPACK

HTTP/3
  │
  ├── Request / Response Streams
  ├── HTTP/3 Frames
  ├── Control Stream
  └── QPACK
          │
          ▼
        QUIC
          │
        UDP
```

The current source contains an HTTP/3 frame/protocol area, but this document does
**not** describe HTTP/3 as a completed implementation. Its purpose in Edition 1 is
to preserve the current study boundary and the relationship between HTTP/3, QUIC,
and QPACK. The HTTP server builder can select a QUIC service and `h3` ALPN, but the
current `http_server::consume()` path dispatches HTTP/1.1 and HTTP/2 requests; it does
not yet provide an equivalent HTTP/3 request-consumption path.

## History

HTTP/3 appears naturally after the study of HTTP/2, HPACK, QUIC, and QPACK. The
project's current history records QUIC study around RFC 9001/9369 and HTTP/2 study
around RFC 7541/7540/9113. The HTTP/3 area is therefore treated as a connected
study/implementation area rather than as evidence of a completed HTTP/3 stack.

No additional chronology is inferred here where the available record does not
establish it.

## Conceptual

The important distinction is between the transport supplied by QUIC and the HTTP
semantics supplied by HTTP/3.

- **QUIC** provides streams, packet transport, reliability, ordering within streams,
  and transport-level control.
- **HTTP/3 frames** carry HTTP protocol information over QUIC streams.
- **Control Stream** carries connection-level HTTP/3 control information.
- **QPACK** provides the header-field representation mechanism for HTTP/3.
- **Request/response streams** carry the HTTP message exchange using HTTP/3 frames.

The most important relationship for this project is therefore:

```text
QUIC stream
    │
    ▼
HTTP/3 frame sequence
    │
    ├── HEADERS ──► QPACK encoded field section
    ├── DATA
    └── other HTTP/3 control frames
```

HTTP/3 should not be used as a second name for QUIC. The two layers have different
responsibilities and should remain separate in the documentation.

### Reading Path

The simplest way to enter this topic is to start where QUIC has already delivered
ordered stream bytes:

```text
QUIC packet / protection
        ↓
QUIC stream delivery
        ↓
HTTP/3 frame boundary
        ↓
HTTP/3 control / request semantics
        ↓
HTTP message meaning
```

QPACK belongs at the header-field representation boundary inside this path. It
does not replace HTTP/3 semantics, and it does not become part of QUIC transport.

Its relationship to HPACK is useful for orientation: both address efficient HTTP
header-field representation, but QPACK is defined for HTTP/3 and the QUIC
multiplexed transport model rather than being an HTTP/2 HPACK implementation
carried forward unchanged.

## Cross-Topic Boundary

At the protocol level, HTTP/3 starts at the QUIC stream boundary rather than at a TCP byte-stream boundary. In the current hotplace server integration, the QUIC endpoint configuration exists one step earlier, while HTTP/3 request dispatch remains a study/implementation boundary. QUIC owns packetization, transport state, and stream delivery; HTTP/3 interprets stream bytes as HTTP/3 frames and control/request semantics.

```text
UDP
 ↓
QUIC packet / frame
 ↓
QUIC stream
 ↓
HTTP/3 frame
 ↓
HTTP semantics
```

TLS remains part of QUIC's handshake and key-material path, but HTTP/3 does not consume ordinary TLS records. This distinction is important when relating the HTTP/3, QUIC, and TLS documents.

## Structural

The current HTTP/3 source area is organized around frame representation and frame
construction.

```text
sdk/net/http/http3/

http3_frame
    │
    ├── DATA
    ├── HEADERS
    ├── SETTINGS
    ├── GOAWAY
    ├── CANCEL_PUSH
    ├── MAX_PUSH_ID
    ├── PUSH_PROMISE
    ├── PRIORITY_UPDATE
    ├── ORIGIN
    ├── METADATA
    └── UNKNOWN
```

The frame layer uses QUIC-style variable-length integers for HTTP/3 frame type and
length fields. A builder is also present for constructing frame representations.

Current source anchors:

- `sdk/net/http/http3/`
- `sdk/net/http/http3/http3_frame.*`
- `sdk/net/http/http3/http3_frames.*`
- `sdk/net/http/http3/http3_frame_builder.*`
- `sdk/net/http/http3/types.hpp`

These names are navigation anchors only; the conceptual roles above are the stable
part of this document.

## Flow

### Receiving HTTP/3 data

```text
QUIC stream bytes
      │
      ▼
HTTP/3 frame boundary
      │
      ├── type
      ├── length
      └── payload
             │
             ▼
       frame interpretation
             │
       ┌─────┴─────┐
       ▼           ▼
    HEADERS       DATA
       │           │
       ▼           ▼
     QPACK       content
```

### HTTP/3 and QUIC

```text
HTTP request
     │
     ▼
HTTP/3 stream
     │
     ▼
HTTP/3 frames
     │
     ▼
QUIC stream data
     │
     ▼
QUIC packetization / protection
     │
     ▼
UDP
```

This flow is useful for keeping ownership clear: packetization and protection
belong to QUIC/TLS documentation; HTTP message framing belongs here.

## Study & Verification

The current HTTP/3 source should be read together with the surrounding study areas.

### HPACK and QPACK as a reading bridge

The easiest way to connect the HTTP/2 and HTTP/3 documents is to keep the
problem constant while changing the surrounding protocol model:

```text
HTTP/2 frame
    ↓
Header Block
    ↓
HPACK

HTTP/3 frame
    ↓
Field Section
    ↓
QPACK
    ↓
QUIC stream / multiplexing
```

This comparison explains why QPACK appears in the HTTP/3 story without making
HPACK and QPACK one implementation layer.

### Related studies

- HTTP/2 frame study: `test/testcase/net/http/testcase_http2_frame.cpp`
- HTTP/2 vectors: `test/testcase/net/http/testvector_http2.cpp`
- HPACK study: `test/testcase/net/hpack/`
- QUIC packet/frame study: `sdk/net/tls/quic/`
- HTTP/3 frame source: `sdk/net/http/http3/`

The existing HTTP/3 source therefore provides useful implementation material, but
the available project record does not justify describing the complete HTTP/3
protocol stack as implemented and verified.

A useful future study path is:

```text
HTTP/2 Frame
    │
    ├── Header Block → HPACK
    │
    ▼
HTTP/3 Frame
    │
    ├── Header Field Section → QPACK
    │
    ▼
QUIC Stream
    │
    ▼
QUIC Packet
```

This keeps HTTP/3 as a bridge between the already-studied HTTP/2/HPACK world and
the QUIC/QPACK implementation areas without overstating project completion.

## Cross-Topic Verification

HTTP/3 verification must be read as a layered path because the current project does not claim a complete HTTP/3 stack. Existing QUIC capture replay demonstrates the lower boundary, while HTTP/3 frame/QPACK work provides protocol-specific study material.

```text
real HTTP/3 traffic
        │
      PCAPNG
        │
   QUIC packet replay
        │
   QUIC streams
        │
 HTTP/3 frame study
        │
      QPACK
```

This is a verification relationship, not a claim of end-to-end HTTP/3 server support. The current status boundary remains explicit in this document.

## Status

| Area | Current state |
|---|---|
| HTTP/3 frame source | Present |
| Frame construction | Present |
| QUIC relationship | Studied / implemented on QUIC side |
| QPACK relationship | Connected study area |
| Complete HTTP/3 stack | Not claimed |
| HTTP/3 server integration | Not claimed |
| HTTP/3 end-to-end verification | Not claimed |

The important status statement for Edition 1 is:

> **HTTP/3 is a connected study and source area, not a completed project
> implementation.**

That distinction should remain visible until the implementation and verification
actually progress.

## Related Documents

```text
HTTP/2 ──► HPACK
   │
   ▼
HTTP/3 ──► QPACK
   │
   ▼
 QUIC ──► TLS ──► UDP
```

- HPACK: header compression in HTTP/2
- HTTP/2: HTTP/2 frame and protocol context
- QPACK: header compression for HTTP/3
- QUIC: transport and packet/frame layer
- TLS: cryptographic handshake and protection used by QUIC

## Publication

```text
┌──────────────────────────────────────┐
│ hotplace study                       │
│ Edition 1 · Revision 1090            │
│ Documented with GPT-5.6 Luna         │
│ — study, reconstruction & review     │
└──────────────────────────────────────┘
```
