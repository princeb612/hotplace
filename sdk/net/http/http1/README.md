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
# HTTP/1.x protocol implementation

## 1. Role

`http1` implements the HTTP/1.x framing adapter used by the generic network protocol pipeline. It answers the transport-layer question “do the buffered bytes contain a complete HTTP/1.x message?” before the common `http_request` or `http_response` parser interprets the message.

It is not the common HTTP object model, the router, or the socket/session manager.

## 2. Data Model

```text
network_server / network_session
       │ buffered network_stream bytes
       ▼
network_protocol_group
       │ asks registered network_protocol objects to identify/frame input
       ▼
http_protocol : network_protocol
       ├─ is_kind_of(...)  -> identify HTTP/1.x bytes
       └─ read_stream(...) -> determine message boundary
       ▼
complete HTTP/1.x message bytes
       ├─ http_request::open(...)
       └─ http_response::open(...)
```

The abstraction is intentionally split: `network_protocol` provides the generic protocol/framing contract; `http_protocol` implements HTTP/1.x recognition and message-length logic; `http_request`/`http_response` parse the completed semantic message. The HTTP/2 sibling uses the same network-protocol boundary but recognizes a binary connection preface/frame sequence instead of HTTP/1.x text framing.

## 3. Behavior Model

HTTP/1.x runs over a TCP byte stream. One read may contain only part of the start line or headers, a header block without the full body, one complete message, or bytes from more than one persistent-connection message. The protocol layer therefore works against buffered bytes rather than treating each read as a complete request.

The current framing path recognizes the header terminator and, when `Content-Length` is present, waits for the declared body bytes before treating the message as complete. The protocol layer then returns the framed message to the common request/response parser. It should not be confused with application routing or with the body content-encoding mechanism.

The generic protocol abstraction is important to the architecture because it lets `network_stream` and `network_protocol_group` coordinate message framing without hard-coding HTTP parsing into the multiplexer callback. Protocol-specific behavior remains behind the `network_protocol` interface.

## 4. Relationships

- `http_protocol.hpp/.cpp` — HTTP/1.x implementation of the network protocol abstraction.
- `../../server/network_protocol.hpp/.cpp`, `network_stream.hpp/.cpp`, `network_session.hpp/.cpp` — generic protocol registration, buffered input, and session flow.
- `../http_request.hpp/.cpp`, `../http_response.hpp/.cpp` — parse/compose semantic messages after framing.
- [HTTP core model](../http-core-model.md)
- [HTTP protocol stack](../http-protocol-stack.md) — HTTP/1.x and HTTP/2 framing boundaries.
- [HTTP server/client flow](../http-server-client.md) — request callback and routing boundary.
- [HTTP/2 implementation](../http2/README.md) — sibling binary framing path.
- `../../../../test/testcase/net/http/testcase_http.cpp` — source-level HTTP parsing/framing tests.

## 5. References

- [RFC 9112 — HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112)
