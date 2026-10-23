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
# HTTP/1.x protocol implementation

## 1. Role

`http1` implements the HTTP/1.x framing adapter used by the generic network protocol pipeline. It answers the transport-layer question “do the buffered bytes contain a complete HTTP/1.x message?” before the common `http_request` or `http_response` parser interprets the message.

It is not the common HTTP object model, the router, or the socket/session manager.

## 2. Data Model

### Framing components

| Component | Responsibility / representation |
|---|---|
| `network_stream` | Buffered transport input; read boundaries are not HTTP message boundaries |
| `network_protocol_group` | Registry and selection boundary for protocol interpreters |
| `http_protocol` | HTTP/1.x recognition and framing-state implementation |
| `http_request` | Parsed request line, URI, headers, and body/content |
| `http_response` | Parsed/composed response status, headers, and body/content |

The generic `network_protocol` interface reports framing state and message size. `http_protocol` determines the current HTTP/1.x message boundary; the shared request/response classes represent semantic messages after framing. HTTP/2 uses a related protocol interface but has binary frame and stream state rather than HTTP/1.x textual framing.

## 3. Behavior Model

HTTP/1.x runs over a TCP byte stream. One read may contain only part of the start line or headers, a header block without the full body, one complete message, or bytes from more than one persistent-connection message. The protocol layer therefore works against buffered bytes rather than treating each read as a complete request.

The current framing path recognizes the header terminator and, when `Content-Length` is present, waits for the declared body bytes before treating the message as complete. In this path, absence of `Content-Length` means the current implementation completes at the header boundary; do not infer full support for chunked transfer coding or every RFC 9112 body-length rule from the generic framing adapter alone. The protocol layer then returns the framed message to the common request/response parser. It should not be confused with application routing or with the body content-encoding mechanism.

### Protocol pipeline boundary

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

This view emphasizes responsibility boundaries across the generic network pipeline. The detailed flow below describes how `http_protocol` finds the message boundary and handles incomplete or coalesced input; the request/response parsers interpret the complete framed bytes afterward.

### Step-by-step framing flow

```text
network_stream::do_writep()
  -> network_protocol_group identifies http_protocol
  -> http_protocol::read_stream(buffer, message_size, state, priority)
  -> locate CRLF-CRLF
  -> calculate required message length
       header only, or header + Content-Length body
  -> insufficient bytes: retain input for next producer pass
  -> complete: consume exactly message_size bytes
       ├─ trailing bytes remain for another persistent message
       └─ complete message enters target stream
  -> http_request::open() / http_response::open()
```

The `message_size` returned by framing is a byte count, not an HTTP semantic object. Parsing the request line, headers, URI, and body happens after this boundary. If several messages arrive in one read, the generic stream loop can process one complete message and retain or revisit the remaining bytes; if a message spans reads, the incomplete bytes remain queued.

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
