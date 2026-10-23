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

# HTTP/2 frame and protocol implementation

## 1. Role

`http2` implements HTTP/2's binary frame model, connection-preface recognition, frame parsing/serialization, per-stream state, and HPACK integration. It connects the generic network stream/protocol layer to the shared HTTP request/response model and then to the HTTP server's application callback/router path.

## 2. Data Model

### Frame model

Every HTTP/2 frame starts with a fixed 9-byte header: 24-bit payload length, type, flags, and a 31-bit stream identifier. Concrete frame classes represent the body according to type and flags.

- `DATA` carries message body bytes.
- `HEADERS` and `CONTINUATION` carry compressed header-block fragments.
- `PRIORITY`, `RST_STREAM`, `SETTINGS`, `PUSH_PROMISE`, `PING`, `GOAWAY`, `WINDOW_UPDATE`, and `ALTSVC` represent control, flow-control, or extension frames.

Not every frame belongs to one request/response. The frame type and stream identifier distinguish message-contributing frames from connection/stream control.

### Payload representation

Concrete frame bodies use `hotplace::io::payload` to declare binary fields and conditional groups. For example, DATA represents optional Pad Length, data, and padding; HEADERS represents optional padding/priority fields and the compressed header fragment.

The reusable `payload` codec belongs to `sdk/io/basic`. It describes field layouts; it does not own HTTP/2 state transitions or HTTP request semantics.

### Shared HTTP objects

`http_uri`, `http_header`, `http_request`, and `http_response` are the shared HTTP semantic model, not HTTP/2 frame classes. A request carries URI/method/header/body data; an HTTP/2 response also retains the stream context required by the response path.

### Session objects

```text
network_session
  ├─ raw network_stream
  └─ optional http2_session
       ├─ stream ID -> flags / partial headers / body state
       └─ HPACK dynamic-table state

http2_protocol : network_protocol
  └─ connection preface and frame boundaries
```

The generic `network_session` owns transport buffering and lifetime. `http2_session` tracks HTTP/2-specific connection/stream processing and HPACK state. They are associated layers, not duplicate versions of the same session.

## 3. Behavior Model

### Frame serialization boundary

```text
concrete http2_frame object
          |
          v
payload fields / conditional groups
          |
          v
encoded or decoded frame body
          |
          v
HTTP/2 frame header + body
          |
          v
complete HTTP/2 frame bytes
```

The shared `hotplace::io::payload` codec describes field layout. The HTTP/2 frame class supplies the type-specific layout; the codec does not decide connection or stream state transitions.

### From incoming bytes to router

```text
network_server producer
  -> network_session::produce()
  -> network_stream (_stream: raw bytes)
  -> http2_protocol identifies preface / frame-length boundaries
  -> frame parser
  -> http2_session consumes frames
       ├─ HEADERS + CONTINUATION assembly
       ├─ HPACK decode and dynamic-table updates
       ├─ DATA body accumulation
       └─ stream/message completion checks
  -> shared http_request (URI + headers + body)
  -> http_server consume/application callback
  -> optional http_router::route(request)
  -> selected handler callback
  -> http_response
  -> HTTP/2 response HEADERS/DATA frames
  -> network/session send path
```

A socket read may contain part of a frame or multiple frames. Frame length, not read boundaries, determines frame parsing. The fixed 9-byte frame header supplies a 24-bit payload length; the parser must wait for the declared payload before decoding the frame body. A HEADERS block can span CONTINUATION frames, and a request can span multiple frames; completion depends on header-block and stream flags. One frame is not one request.

### Per-frame to per-request state transition

```text
one complete framing unit delivered to http_server::consume()
  (initial preface + SETTINGS together; subsequent frames individually)
  -> http2_session::consume()
  -> _headers[stream_id] holds the in-progress http_request
  -> HEADERS / CONTINUATION: decode this frame's fragment into that request
  -> DATA: append this frame's body bytes
  -> _flags[stream_id] |= frame flags
  -> accumulated flags contain END_HEADERS and END_STREAM?
       yes -> copy request to caller; erase _headers/_flags entry
       no  -> return no request for this frame
  -> http_server invokes the configured callback only for a non-null request
```

The source does not build a separate byte buffer named as an assembled header block in `http2_session`: each HEADERS or CONTINUATION frame is handed to its compressed-header reader, and decoded fields are added to the same stream-indexed `http_request` while the HPACK dynamic table is shared by the session. The decoded pseudo-headers remain in the common header collection; `http_request::get_method()` reads `:method`, while `:path` is also opened into `http_uri`. DATA frames append body content. Completion is tracked by OR-ing frame flags for that stream; the request is copied out only after **both** `END_HEADERS` and `END_STREAM` have been observed. `RST_STREAM` clears the stored stream state without returning a request. This describes the current implementation's request-exposure predicate, not a claim that every HTTP/2 stream-state or conformance rule is validated here.

The frame parser, HPACK decoder, and `http2_session` therefore have separate responsibilities. A valid frame can be a control frame rather than a request fragment; an individual decoded header fragment does not by itself complete a request; and a completed request still needs the HTTP server callback before application routing occurs.

The router is not reached directly by the frame parser. The HTTP server's consume path must receive a completed HTTP request and dispatch it through the configured application callback; the application may call `http_router` or handle the request itself.

### Enabling HTTP/2

`http_server_builder`'s `enable_h2(true)` configures the HTTP server for HTTP/2, but the option alone is not a frame parser or a router invocation. The configured server must also use a compatible transport/protocol setup (normally HTTPS with ALPN negotiation for HTTP/2, or the applicable prior-knowledge path), register the HTTP/2 protocol/session path, and then process bytes through the flow above. TLS negotiates the application protocol; HTTP/2 session processing interprets frames after the transport/session path delivers them. A successful TLS handshake by itself does not mean an HTTP/2 request has been assembled.

### HPACK boundary

HTTP/2 frames determine the stream and boundaries of compressed header fragments. HPACK interprets the field representations and updates its compression context. The resulting fields populate the shared HTTP model; the HTTP router works with request semantics, not raw HPACK instructions.

## 5. Relationships

- `http2_frame.hpp/.cpp`, `http2_frame_builder.hpp/.cpp`, and `http2_frame_*.hpp/.cpp` — frame serialization and parsing.
- `http2_protocol.hpp/.cpp` — protocol recognition and frame framing.
- `http2_session.hpp/.cpp` — per-stream state and request assembly.
- `sdk/io/basic/payload.hpp/.cpp` — binary field-layout codec.
- [HTTP core model](../http-core-model.md), [HTTP protocol stack](../http-protocol-stack.md), and [HTTP server](../README.md).
- [HPACK](../hpack/README.md) and [compression](../compression/README.md).
- [Network session](../../server/network_session.md), [stream/protocol](../../server/network-stream-and-protocol.md), and [network server](../../server/README.md).
- `test/testcase/net/http/testcase_http2_frame.cpp` and `testvector_http2.cpp` — source-level frame/vector cases.

## 6. References

- [RFC 9113 — HTTP/2](https://www.rfc-editor.org/rfc/rfc9113)
