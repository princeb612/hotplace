## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
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
HTTP wire bytes / HTTP/2 stream frames
              │ protocol-specific parser
              ▼
         http_request
         ├─ method
         ├─ http_uri
         │    ├─ original URI
         │    ├─ path
         │    └─ query string / query key-values
         ├─ http_header
         ├─ body/content
         └─ HTTP version / HTTP/2 stream id

application handler
       │ fills status, headers and body
       ▼
   http_response
       ├─ http_header
       ├─ status / content type
       └─ composed response representation
              │
              ▼
      network_session send path
```

These objects have related but distinct responsibilities:

- `http_request` represents a parsed incoming request or a request being composed by a client. It exposes the method, URI, headers, body/content, HTTP version, and HTTP/2 stream metadata.
- `http_response` represents the response status, headers, and body. It can compose response output and `respond(network_session*)` is the network-session send boundary.
- `http_header` is the common header collection. Its conversion helper can parse structured authentication header parameters into `skey_value`; authentication providers then interpret scheme-specific values.
- `http_uri` parses and retains the URI representation, path, and query string, with query parameters exposed as key/value data. It is not a substitute for the request method or headers.

For HTTP/1.x, the protocol framing layer identifies a complete message before `http_request::open()` parses its request line, headers, and body. For HTTP/2, `http2_session` accumulates frames and per-stream header state; a request may not be available until the relevant HEADERS/CONTINUATION and END_HEADERS/END_STREAM conditions are met. Do not treat one HTTP/2 frame as one request.

### Routing and authentication

`http_router` maps URI paths and status codes to a registered function pointer or `std::function` handler. An optional `http_authentication_provider` can be registered alongside a path.

```text
network_session + completed HTTP request
                  │
                  ▼
        http_router::route()
                  │
                  ├─ path/status handler lookup
                  ├─ optional authentication provider
                  │      ├─ parse scheme credentials
                  │      ├─ provider try_auth()
                  │      ├─ resolver / credential verification
                  │      └─ request_auth() on challenge/failure path
                  └─ invoke registered request handler
                             │
                             ▼
                        http_response
```

The router dispatches a request; the handler supplies application behavior and response content. Authentication is distinct from authorization: a successful provider check does not by itself define which resources the application permits the principal to access.

### Body encoding versus header compression

Response content encoding (for example, identity, deflate, or gzip) transforms the message body. HPACK and QPACK instead encode header fields for HTTP/2 and HTTP/3. These are separate mechanisms with different inputs and state.

## 3. Behavior Model

### Parsing and composing

The request/response objects are the shared semantic model; protocol-specific code decides how they become or are reconstructed from wire bytes. HTTP/1.x uses textual message framing over a TCP byte stream. HTTP/2 uses binary frames and stream identifiers, with HPACK field compression. HTTP/3 carries HTTP frames over QUIC streams and uses QPACK. A common `http_request` API does not make the wire formats interchangeable.

The HTTP/1.x framing layer must wait for sufficient bytes according to the framing information, rather than assuming that a socket read ends at the message boundary. HTTP/2 session processing must combine frames belonging to a stream before dispatching a completed request. The request parser and router should receive completed semantic messages, not raw multiplexer events.

### Handler and response lifecycle

The server's consume path creates/parses an `http_request`, associates the router, and prepares an `http_response`. The router selects an optional authentication provider and then a route handler. The handler populates the response, which is serialized for the active protocol and sent through the associated `network_session`. HTTP/2 additionally needs stream-aware response handling; a response is not merely an unqualified TCP write.

## 4. Relationships

- `http_request.hpp/.cpp`, `http_response.hpp/.cpp`
- `http_header.hpp/.cpp`, `http_uri.hpp/.cpp`
- `http_router.hpp/.cpp`, `http_server.hpp/.cpp`, `http_server_builder.hpp/.cpp`, `http_client.hpp/.cpp`
- [HTTP overview](README.md)
- [HTTP server/client and router flow](http-server-client.md)
- [HTTP protocol stack](http-protocol-stack.md)
- [Authentication providers and credentials](auth/README.md)
- [Header compression infrastructure](compression/README.md)
- [HTTP/1.x](http1/README.md), [HTTP/2](http2/README.md), [HTTP/3](http3/README.md)
- `test/testcase/net/http/testcase_http.cpp` — source-level request/response/router coverage.

## 5. References

No external references are currently listed.
