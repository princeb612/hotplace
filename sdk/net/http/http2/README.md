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

# HTTP/2 frame and protocol implementation

## 1. Role

`http2` implements HTTP/2's binary frame model, connection-preface recognition, frame parsing/serialization, per-stream state, and HPACK integration. It connects the generic network stream/protocol layer to the shared HTTP request/response model and then to the HTTP server's application callback/router path.

## 2. Data Model

### Frame model

Every HTTP/2 frame starts with a fixed 9-byte header: 24-bit payload length, type, flags, and a 31-bit stream identifier. Concrete frame classes interpret the body based on type and flags.

- `DATA` carries message body bytes.
- `HEADERS` and `CONTINUATION` carry compressed header-block fragments.
- `PRIORITY`, `RST_STREAM`, `SETTINGS`, `PUSH_PROMISE`, `PING`, `GOAWAY`, `WINDOW_UPDATE`, and `ALTSVC` represent control, flow-control, or extension behavior.

Not every frame belongs to one request/response. Control frames update connection/stream state; header and data frames contribute to HTTP messages.

### Payload codec boundary

Concrete frame bodies use `hotplace::io::payload` to describe binary fields and conditional groups. For example, DATA declares optional Pad Length, data, and padding; HEADERS declares optional padding/priority fields and the compressed header fragment.

```text
http2_frame subclass
  -> payload fields / conditional groups
  -> encoded or decoded frame body
  -> http2_frame header + body
  -> complete HTTP/2 frame bytes
```

The reusable `payload` codec belongs to `sdk/io/basic`. It encodes declared field layouts; it does not choose HTTP/2 state transitions or define HTTP request semantics.

### Shared HTTP objects

`http_uri`, `http_header`, `http_request`, and `http_response` are the shared HTTP model, not HTTP/2 frame classes. HTTP/2's HPACK-decoded header fields populate the request's method/scheme/authority/path and other header values; assembled DATA contributes the body. The completed request is then available to the HTTP server's callback/router layer. A response follows the reverse conceptual path: application response model → HTTP/2 response headers/body → HEADERS/DATA frames.

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

A socket read may contain part of a frame or multiple frames. Frame length, not read boundaries, determines frame parsing. A HEADERS block can span CONTINUATION frames, and a request can span multiple frames; completion depends on header-block and stream flags. One frame is not one request.

The router is not reached directly by the frame parser. The HTTP server's consume path must receive a completed HTTP request and dispatch it through the configured application callback; the application may call `http_router` or handle the request itself.

### Enabling HTTP/2

`http_server_builder`'s `enable_h2(true)` configures the HTTP server for HTTP/2, but the option alone is not a frame parser or a router invocation. The configured server must also use a compatible transport/protocol setup (normally HTTPS with ALPN negotiation for HTTP/2, or the applicable prior-knowledge path), register the HTTP/2 protocol/session path, and then process bytes through the flow above. TLS negotiates the application protocol; HTTP/2 session processing interprets frames after the transport/session path delivers them. A successful TLS handshake by itself does not mean an HTTP/2 request has been assembled.

### HPACK boundary

HTTP/2 frames determine the stream and boundaries of compressed header fragments. HPACK interprets the field representations and updates its compression context. The resulting fields populate the shared HTTP model; the HTTP router works with request semantics, not raw HPACK instructions.

## 4. Relationships

- `http2_frame.hpp/.cpp`, `http2_frame_builder.hpp/.cpp`, and `http2_frame_*.hpp/.cpp` — frame serialization and parsing.
- `http2_protocol.hpp/.cpp` — protocol recognition and frame framing.
- `http2_session.hpp/.cpp` — per-stream state and request assembly.
- `sdk/io/basic/payload.hpp/.cpp` — binary field-layout codec.
- [HTTP core model](../http-core-model.md), [HTTP protocol stack](../http-protocol-stack.md), and [HTTP server](../README.md).
- [HPACK](../hpack/README.md) and [compression](../compression/README.md).
- [Network session](../../server/network_session.md), [stream/protocol](../../server/network-stream-and-protocol.md), and [network server](../../server/README.md).
- `test/testcase/net/http/testcase_http2_frame.cpp` and `testvector_http2.cpp` — source-level frame/vector cases.

## 5. References

- [RFC 9113 — HTTP/2](https://www.rfc-editor.org/rfc/rfc9113)
