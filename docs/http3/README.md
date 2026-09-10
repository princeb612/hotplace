# HTTP/3 — Study Boundary & Current State

> Edition 1 · Revision 1076

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
and QPACK.

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
- **QPACK** provides HTTP field compression for HTTP/3.
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
│ Edition 1 · Revision 1076            │
│ Documented with GPT-5.6 Luna         │
│ — study, reconstruction & review     │
└──────────────────────────────────────┘
```
