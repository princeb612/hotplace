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
# HTTP core model

## 1. Role

`sdk/net/http` provides the common HTTP message objects and application-facing server/client/router model. HTTP/1.x and HTTP/2 reuse `http_request`, `http_response`, `http_header`, and `http_uri`; their framing and compression mechanisms remain version-specific. HTTP/3 has its own frame and QPACK path above QUIC, and the current source should not be read as a complete HTTP/3 server implementation.

## 2. Data Model

### Request, response, headers, and URI

```text
http_request
  ├─ method
  ├─ http_uri
  │    ├─ original URI
  │    ├─ path
  │    └─ query string / query key-values
  ├─ http_header
  ├─ body/content
  └─ HTTP version / HTTP/2 stream id

http_response
  ├─ request context (when constructed from a request)
  ├─ http_header
  ├─ status / content type
  ├─ body/content
  └─ HTTP version / HTTP/2 stream id / compression context
```

These objects have related but distinct responsibilities:

- `http_request` represents an incoming request or a request being composed by a client. It exposes method, URI, headers, body/content, HTTP version, and HTTP/2 stream metadata.
- `http_response` represents response status, headers, and body. It can retain the originating request context used by the response path.
- `http_header` is the common header collection. A helper exposes structured authentication header parameters as `skey_value`; authentication providers interpret scheme-specific values.
- `http_uri` retains URI representation, path, and query string, with query parameters exposed as key/value data. It is not a substitute for the request method or headers.

HTTP/1.x framing, HTTP/2 per-stream assembly, and HTTP/3 stream/frame processing produce different inputs to this shared semantic model. The common request type does not make their wire formats interchangeable.

### Routing and authentication registrations

`http_router` stores URI-path and status-code handler registrations. A path registration may also retain an `http_authentication_provider`. Handler registration, provider registration, and the request/response objects are separate responsibilities; the router is not a protocol parser.

### Body encoding versus header compression

Response content encoding (for example, identity, deflate, or gzip) transforms the message body. HPACK and QPACK instead encode header fields for HTTP/2 and HTTP/3. These are separate mechanisms with different inputs and state.

### Response protocol and stream context

When an `http_response` is constructed from an `http_request`, it retains the context needed to answer it: request reference, HTTP version, HTTP/2 stream ID, and associated HPACK dynamic-table pointer.

## 3. Behavior Model

### Parsing and composing

The request/response objects are the shared semantic model; protocol-specific code decides how they become or are reconstructed from wire bytes. HTTP/1.x uses textual message framing over a TCP byte stream. HTTP/2 uses binary frames and stream identifiers, with HPACK field compression. HTTP/3 carries HTTP frames over QUIC streams and uses QPACK. A common `http_request` API does not make the wire formats interchangeable.

The HTTP/1.x framing layer must wait for sufficient bytes according to the framing information, rather than assuming that a socket read ends at the message boundary. The current framing implementation recognizes the header terminator and uses `Content-Length` to wait for the declared body bytes; do not infer broader transfer-coding/chunked-body behavior from this path without checking the parser implementation. HTTP/2 session processing must combine frames belonging to a stream before dispatching a completed request. The request parser and router should receive completed semantic messages, not raw multiplexer events.

The stages intentionally have different outputs: framing yields complete message bytes, protocol-specific parsing yields `http_request`/`http_response`, and routing maps request semantics to application behavior. Keeping these boundaries separate makes it possible to reason about transport fragmentation without mixing it with URI matching or authentication.

### Handler and response lifecycle

```text
completed HTTP request + session
             |
             v
application callback
             |
             +-- handle directly
             |
             +-- optionally call http_router::route()
                         |
                 optional authentication
                         |
                 URI/status handler lookup
                         |
                 handler / fallback response
                         |
                         v
                   http_response
                         |
               protocol-specific send path
```

`http_server::consume()` parses or assembles the request and delivers it to the callback registered with `set_handler()`. That callback may handle the request directly or call `http_router::route()`; the server does not automatically route every request. When invoked, the router selects an optional authentication provider and then a route handler. The handler populates the response, which is serialized for the active protocol and sent through the associated `network_session`. HTTP/2 additionally needs stream-aware response handling; a response is not merely an unqualified TCP write. The application callback and router are separate boundaries. The current `http_response::respond(network_session*)` implementation has HTTP/1.x and HTTP/2 branches, but no corresponding HTTP/3 response branch.

#### Router authentication and dispatch detail

```text
http_router::route(session, request, response)
                  │
                  ▼
      provider registered for request URI?
          ├─ yes -> resolver.resolve(...)
          │            │
          │            ▼
          │       provider::try_auth(...)
          │            ├─ parse scheme credentials
          │            ├─ resolver / credential verification
          │            └─ failure -> request_auth() challenge
          │                         and stop dispatch
          │
          └─ no provider / authentication succeeds
                       │
                       ▼
              URI handler lookup
              ├─ registered handler
              ├─ optional html_documents fallback
              └─ status handler / 404 fallback
                       │
                       ▼
                handler populates response
```

The router checks the registered authentication provider before selecting and invoking the URI handler. The provider/resolver path is scheme-specific; the exact credential verification may use an application callback or a built-in credential container. Authentication failure produces the provider's challenge response and prevents normal route dispatch. On success, the router selects the route handler or fallback path. This detail complements the lifecycle diagram above; the scheme-specific implementation is documented in [Authentication providers and credentials](auth/README.md).

## 5. Relationships

- `http_request.hpp/.cpp`, `http_response.hpp/.cpp`
- `http_header.hpp/.cpp`, `http_uri.hpp/.cpp`
- `http_router.hpp/.cpp`, `http_server.hpp/.cpp`, `http_server_builder.hpp/.cpp`, `http_client.hpp/.cpp`
- `http_resource.hpp` and [protocol lookup resources](resource/README.md) — status phrases and protocol metadata.
- `html_documents.hpp/.cpp` — optional file-backed fallback used by the router.
- [HTTP overview](README.md)
- [HTTP server/client and router flow](http-server-client.md)
- [HTTP protocol stack](http-protocol-stack.md)
- [Authentication providers and credentials](auth/README.md)
- [Header compression infrastructure](compression/README.md)
- [HTTP/1.x](http1/README.md), [HTTP/2](http2/README.md), [HTTP/3](http3/README.md)
- `test/testcase/net/http/testcase_http.cpp` — source-level request/response/router coverage.

## 6. References

- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110) — common request/response fields, status codes, and semantics.
- [RFC 3986 — Uniform Resource Identifier (URI): Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986) — URI structure and generic syntax.
- [RFC 9112 — HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112) and [RFC 9113 — HTTP/2](https://www.rfc-editor.org/rfc/rfc9113) — version-specific framing and protocol behavior.
