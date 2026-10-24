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
# HTTP server and client flow

## 1. Role

This document traces the application-facing HTTP server/client integration: builder configuration, adapter and network-server startup, protocol registration, request delivery to the application callback, optional router dispatch, and the simple client request/response path. Generic socket/session orchestration remains in `sdk/net/server`; HTTP framing and semantic message objects remain in `sdk/net/http`.

## 2. Data Model

### Builder configuration state

`http_server_builder` is the configuration/factory boundary. An adapter is required; the builder does not silently choose OpenSSL or trial on the caller's behalf.

- **Backend:** `set(server_socket_adapter*)` selects `openssl_server_socket_adapter` or `trial_server_socket_adapter`.
- **Services and ports:** `enable_http`, `set_port_http`, `enable_https`, `set_port_https`.
- **Address families:** `enable_ipv4`, `enable_ipv6`.
- **HTTP protocol versions:** `enable_h1`, `enable_h2`, `enable_h3`.
- **TLS configuration:** `set_tls_certificate`, `set_tls_cipher_list`, `set_tls_verify_peer`.
- **Application integration:** `set_handler(handler, user_context)`.
- **Additional controls:** `allow_content_encoding` and `get_server_conf()` for concurrency/buffer settings.

The constructor defaults are source defaults, not an assertion that a server is enabled by default: IPv4/IPv6, HTTP, and HTTPS start disabled; ports default to 80/443; HTTP/1 is enabled; event concurrency is 1024; TLS-accept, network producer, and consumer concurrency each default to 2 in the builder configuration. Other protocol flags are not automatically enabled by those defaults.

### Server object composition

```text
http_server
  ├─ network_server
  ├─ server_conf
  ├─ selected server_socket_adapter
  ├─ IP ACL
  ├─ HTTP/1 and HTTP/2 protocol objects
  ├─ http_router
  └─ application consume callback

http_server_builder
  └─ configuration + selected adapter + handler/context
```

The builder owns configuration and construction responsibility; `http_server` coordinates the HTTP-facing server components. `network_server` owns transport events and session lifetime, while protocol objects frame input and the application callback decides whether to route requests.

### Client model

`http_client` currently supports a simple HTTP/1.x request/response path. It should not be treated as a shared client implementation for HTTP/1.x, HTTP/2, and HTTP/3 merely because the shared request/response classes are reusable.

## 3. Behavior Model

### Server construction and startup

```text
configure adapter + service/protocol/options + callback
                         |
                         v
                 http_server_builder::build()
                         |
                         +-- require adapter
                         +-- create http_server(adapter)
                         +-- copy server_conf
                         +-- start adapter TLS/QUIC resources when enabled
                         +-- startup_server(family, port, handler, context)
                                      |
                                      v
                                network_server::open()
                                      |
                                      +-- register accept-control callback
                                      +-- register http_protocol
                                      +-- register http2_protocol when enabled
```

The builder configures HTTP/HTTPS/HTTP3 service startup based on the selected flags and adapter. TLS certificate/key, cipher list, and peer-verification settings are passed to the secure adapter startup path. HTTP/3 selection requests the QUIC service path, but the current `http_server::startup_server()` still registers `http_protocol` and conditionally `http2_protocol`; it does not register an HTTP/3 `network_protocol`. `http_response::respond()` likewise has only HTTP/1.x and HTTP/2 branches. Thus `enable_h3` and QUIC socket setup must not be read as a complete HTTP/3 request/response service.

### Request delivery and handler callback

```text
network_server event/session processing
             | completed transport bytes
             v
      http_server::consume()
             |
             +-- HTTP/1.x: http_protocol recognition
             |              -> http_request::open()
             |
             +-- HTTP/2: network_session::get_http2_session()
                           -> http2_session::consume()
                           -> completed http_request (when ready)
             |
             v
application callback passed to set_handler()
             |
             +-- inspect event/session/request
             +-- optionally call http_router::route()
             |      +-- optional auth provider/resolver
             |      +-- URI/status handler lookup
             |      +-- registered callback
             +-- compose/send response through http_response
```

`http_server::consume()` invokes the callback registered by `set_handler`; it does not unconditionally call `http_router::route()` on the application's behalf. The application callback decides how to use the request and whether to route it. On HTTP/2, `http2_protocol` frames the initial connection preface together with the initial SETTINGS frame, then frames subsequent HTTP/2 frames individually; `http2_session::consume()` updates the stream-indexed request and accumulated flags. The request pointer remains null until the implementation has observed both `END_HEADERS` and `END_STREAM` for that stream (or the stream is reset, in which case no request is returned). Only a non-null request reaches the application callback.

The router supports both a plain function pointer (`http_request_handler_t`) and a `std::function` callback (`http_request_function_t`). A URI can be registered with an optional authentication provider. `route()` associates the router with request/response, resolves the provider if configured, invokes `request_auth()` when authentication fails, and otherwise selects the URI handler. If no URI handler exists, it may try `html_documents` and then the configured 404/status handler. The registered handler receives the session, request, response, and router; it supplies application response behavior. When a response is created from the request, the response inherits the HTTP version and HTTP/2 stream ID so the response composer can frame the answer in the originating stream context.

### Client request/response path

```text
URL
  -> split URL
  -> http_request::compose()
  -> client socket connect/send
  -> receive response bytes
  -> network_protocol_group + http_protocol
  -> http_response::open()
```

This is the current simple HTTP/1.x client path. It does not automatically negotiate or implement the separate HTTP/2 frame/session path.

### Concrete applet path: configure HTTP/2 and dispatch a request

`test/applet/httpserver2/run_server.cpp` shows how a real caller connects the builder, adapter, application callback, and router. The socket scheme is selected earlier from the applet options; the following excerpt keeps only the HTTP-facing setup and request dispatch:

```cpp
http_server_builder builder;
builder.set(adapter)
    .enable_http(false)
    .set_port_http(option.port)
    .enable_https(true)
    .set_port_https(option.port_tls)
    .set_tls_verify_peer(0)  // applet uses a self-signed certificate
    .enable_ipv4(true)
    .enable_ipv6(true)
    .enable_h2(true)
    .set_handler(consumer_routine)
    .set_tls_cipher_list(ciphersuites);

_http_server.make_share(builder.build());

// In consumer_routine, on mux_read when request is non-null:
http_response response(request);
_http_server->get_http_router().route(session, request, &response);
response.respond(session);
```

The applet then registers URI handlers such as `/api/html` and `/api/json`, and starts the server. This is a real integration path, not a standalone minimal program: `adapter`, `option`, `ciphersuites`, `consumer_routine`, and the shared `_http_server` are established by the surrounding applet. The callback explicitly invokes `route()`; this confirms that routing is application-controlled rather than an automatic consequence of `http_server::consume()`.

The `set_tls_verify_peer(0)` setting is for the applet's self-signed-certificate setup and is not a production verification recommendation. This example demonstrates HTTP/2 server configuration and request dispatch; it does not establish complete HTTP/3 server support.

### Network-server boundary

`http_server` uses `network_server` for listener setup, multiplexer registration, accept/TLS-accept work, session creation, producer/consumer buffering, and shutdown. For HTTPS, the chosen adapter creates/starts the secure server socket before the network server binds the listener. The network server's TLS-accept workers perform the secure accept/handshake stage before ordinary session event processing. For plain HTTP, the TCP server socket follows the direct accept path.

### Router callback and response

The router is an optional application-level dispatcher, not the protocol parser and not the network-server callback itself. If the application's consume callback invokes `http_router::route()`, the router can authenticate, resolve a URI handler, or produce a 404 response. The selected handler composes the `http_response`; the response is then serialized/sent through the associated session and active protocol path. The HTTP/2 path must preserve stream identity from frame/session assembly through response construction; a generic session send call does not, by itself, describe the complete HTTP/2 frame sequence.

### Real-code example: builder to runnable HTTP server

`test/applet/httpserver2/run_server.cpp` is the concrete builder path. It chooses an OpenSSL or trial socket adapter with `server_socket_builder`, configures the HTTP server (including HTTP/2), registers handlers, and starts the listener. Its `consumer_routine` then routes a completed request and responds on the associated session.

```text
server_socket_builder -> adapter
  -> http_server_builder / protocol options / handlers
  -> build and start listener
  -> network_server + network_session
  -> completed http_request -> http_router -> http_response
```

Use `test/applet/httpserver1/run_server.cpp` as the HTTP/1.1 comparison. The two applets show the practical reason for the builder layer: application routing remains familiar while transport backend and protocol configuration differ.

## 5. Relationships
- `http_server.hpp/.cpp`, `http_server_builder.hpp/.cpp`
- `http_client.hpp/.cpp`, `http_router.hpp/.cpp`
- `http_response.hpp/.cpp` — response composition and version-specific send path.
- `html_documents.hpp/.cpp` — optional static-document fallback after route lookup.
- [HTTP overview](README.md)
- [HTTP core model](http-core-model.md)
- [HTTP protocol stack](http-protocol-stack.md)
- [Network server model](../server/network-server-model.md)
- [Network session](../server/network_session.md)
- [Socket adapters](../basic/openssl/README.md) and [trial socket composition](../basic/trial/README.md)
- `test/testcase/net/http/testcase_http.cpp` — source-level request/response/router coverage.
- `test/applet/httpserver1/` and `test/applet/httpserver2/` — server applet source paths.

## 6. References
- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110) — request/response semantics and status codes.
- [RFC 9113 — HTTP/2](https://www.rfc-editor.org/rfc/rfc9113) — stream-aware request/response framing.
