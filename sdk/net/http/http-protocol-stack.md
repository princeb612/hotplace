## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# HTTP protocol stack

## 1. Role

This document explains the protocol-framing adapters that let the generic network server distinguish HTTP/1.x message boundaries from HTTP/2 connection preface and frame boundaries. It focuses on the transport-to-protocol boundary, not routing or application semantics.

## 2. Data Model

### Protocol adapter roles

HTTP framing uses the generic `network_protocol` contract, with protocol-specific implementations registered in a `network_protocol_group`.

| Component | State or representation owned |
|---|---|
| `network_stream` | Queued input bytes, including incomplete trailing input |
| `network_protocol_group` | Registered protocol instances indexed by protocol identifier; protocol-selection boundary |
| `http_protocol` | HTTP/1.x recognition and message-framing rules |
| `http2_protocol` | HTTP/2 connection-preface and frame-boundary rules |
| `http2_frame` family | HTTP/2 frame header and type-specific fields |
| `http2_session` | Per-stream request assembly state and HPACK dynamic-table context |
| `http_request` / `http_response` | Shared semantic HTTP messages, distinct from framed byte ranges |

The generic protocol interface reports message-size and framing-state information to its caller. It does not own application routing.

### Capability boundary

The HTTP/3 frame/QPACK classes are available building blocks, but the current server protocol registry and response composer do not provide a complete end-to-end HTTP/3 request/response path. Concrete HTTP/1.x and HTTP/2 framing conditions are described in Behavior Model.

## 3. Behavior Model

### Protocol dispatch overview

```text
network bytes
    ↓
network_stream
    ↓
network_protocol_group
    ├── http_protocol  → HTTP/1.x message boundary
    └── http2_protocol → HTTP/2 preface/frame boundary
```

This is the high-level selection boundary: the protocol group delegates framing to the selected adapter. The detailed call path below shows how buffered bytes and incomplete/trailing input are handled after selection.

### Generic framing call path

```text
network_session::_stream
  -> network_stream::read(protocol_group, target)
  -> network_stream::do_writep(...)
  -> network_protocol_group::is_kind_of(prefix)
  -> selected network_protocol::read_stream(...)
  -> message_size + protocol_state_t
  -> consume complete bytes / preserve trailing bytes
  -> target stream (_request for the normal HTTP server path)
```

The generic server does not dispatch based on one socket read. It builds a view of queued bytes, asks the protocol group to select an interpreter, and uses the interpreter's reported message size and state to consume only a complete unit. If the end of a message falls inside a queued node, the remaining bytes are retained for the next pass. That is what allows a persistent HTTP/1.x connection to carry several messages and a single message to span multiple reads.

### HTTP/1.x framing sequence

```text
buffered bytes
  -> find CRLF-CRLF header terminator
  -> inspect Content-Length
       absent -> current implementation completes at header boundary
       present -> wait for header bytes + declared body length
  -> complete framed message
  -> http_request::open() or http_response::open()
```

This describes the current implementation's framing path, not every framing rule in RFC 9112. In particular, the existence of an HTTP/1.x adapter alone does not establish support for every transfer-coding, chunked-body, or ambiguous-length case. Keep such claims tied to the implementation and its tests.

### HTTP/2 connection and session overview

```text
HTTP/2 connection preface
        ↓
SETTINGS (connection setup/control exchange; not a per-request gate)
        ↓
HTTP/2 frames
        ↓
http2_session
   ├── stream id / flags
   ├── partial headers
   └── connection-level HPACK dynamic table context
        ↓
http_request (when the session's completion condition is met)
```

This overview emphasizes the session's assembly state. SETTINGS is part of connection setup and control, not a requirement that each request wait for a separate SETTINGS step. Stream IDs, flags, and partial header fragments are tracked for request assembly; HPACK dynamic-table state is shared compression context, not an independent table per stream. The detailed flow below records the current implementation's exact request-exposure condition.

### HTTP/2 frame-to-request sequence

```text
network_stream::do_writep()
  -> http2_protocol::read_stream(): initial preface + SETTINGS, then one frame at a time
  -> target request stream
  -> http_server::consume()
  -> network_session::get_http2_session()
  -> http2_session::consume(): process one frame
       -> per-stream http_request in _headers
       -> HEADERS / CONTINUATION: decode fragment into shared request
       -> DATA: append body bytes
       -> OR flags into _flags[stream_id]
       -> END_HEADERS + END_STREAM both observed?
            yes -> copy request out, erase stream state
            no  -> no application callback for this frame
```

The protocol/framing layer emits one HTTP/2 frame at a time, not one request. In `http2_session::consume()`, the request state is indexed by stream ID and retains the shared HPACK dynamic-table reference. HEADERS and CONTINUATION fragments are passed to the frame-specific compressed-header reader and their decoded fields are added to that same request; DATA appends body bytes. The decoded pseudo-headers remain in the HTTP header collection: `http_request::get_method()` reads `:method`, while `:path` is also opened into `http_uri`. The implementation accumulates frame flags for the stream and returns a new `http_request` only when the accumulated flags contain **both** `END_HEADERS` and `END_STREAM`. It then erases that stream's flags and request state. A `RST_STREAM` also clears the stored state without exposing a completed request. This is the current implementation's request-exposure predicate, not a claim that this path validates every HTTP/2 stream-state or conformance rule.

Thus frame completion is a transport/framing boundary, while request exposure is a separate session-level condition. SETTINGS, PING, GOAWAY, RST_STREAM, and WINDOW_UPDATE affect connection or stream behavior rather than directly contributing request body bytes.

### HTTP/3 frame-to-semantics path

The HTTP/3 source has frame representations and QPACK components, but the full server path remains incomplete. The intended conceptual chain is QUIC stream bytes → HTTP/3 frame boundaries → QPACK field-section decoding → HTTP semantics. QUIC packet boundaries are not HTTP/3 frame boundaries, and frame parsing alone does not provide a complete request lifecycle.

### Failure and incompleteness boundary

The generic stream layer can retain input when the protocol reports insufficient data and clear queued invalid input for states such as `forged`, `crash`, or `large`. The exact interpretation of malformed headers, invalid frame fields, body-length conflicts, or protocol-specific errors belongs to the relevant HTTP parser/session implementation; do not attribute all validation to `network_protocol_group` or the multiplexer.

## 5. Relationships

- `http1/http_protocol.hpp/.cpp` — HTTP/1.x framing implementation.
- `http2/http2_protocol.hpp/.cpp` — HTTP/2 preface and frame framing.
- `http2/http2_frame*.*` and `http2/http2_session.*` — frame codec and per-stream request state.
- `../../test/testcase/net/http/testcase_http.cpp`
- `../../test/testcase/net/http/testcase_http2_frame.cpp` and `testvector_http2.cpp`
- [HTTP overview](README.md), [HTTP core model](http-core-model.md), and [HTTP server/client flow](http-server-client.md).
- [HTTP/1.x](http1/README.md), [HTTP/2](http2/README.md), and [HTTP/3](http3/README.md).
- [Network stream and protocol](../server/network-stream-and-protocol.md) and [network server](../server/network-server-model.md) — generic framing and session boundaries.
- [TLS/QUIC transport](../tls/README.md) — transport-side QUIC implementation.

## 6. References

- [RFC 9112 — HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112) — message framing over a byte stream.
- [RFC 9113 — HTTP/2](https://www.rfc-editor.org/rfc/rfc9113) — connection preface, frame structure, streams, and protocol state.
- [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114) and [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000) — HTTP/3 framing and transport boundaries.