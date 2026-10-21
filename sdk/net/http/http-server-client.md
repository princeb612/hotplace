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
# HTTP server and client flow

## 1. Role

This document traces the application-facing HTTP server/client integration: builder configuration, adapter and network-server startup, protocol registration, request delivery to the application callback, optional router dispatch, and the simple client request/response path. Generic socket/session orchestration remains in `sdk/net/server`; HTTP framing and semantic message objects remain in `sdk/net/http`.

## 2. Data Model

### Builder configuration and construction

`http_server_builder` is the configuration/factory boundary. An adapter is required; the builder does not silently choose OpenSSL or trial on the caller's behalf.

Relevant options exposed by the builder:

- Backend: `set(server_socket_adapter*)` — select `openssl_server_socket_adapter` or `trial_server_socket_adapter`.
- Services and ports: `enable_http`, `set_port_http`, `enable_https`, `set_port_https`.
- Address families: `enable_ipv4`, `enable_ipv6`.
- HTTP protocol versions: `enable_h1`, `enable_h2`, `enable_h3`.
- TLS configuration: `set_tls_certificate`, `set_tls_cipher_list`, `set_tls_verify_peer`.
- Application integration: `set_handler(handler, user_context)`.
- Additional controls: `allow_content_encoding` and `get_server_conf()` for concurrency/buffer settings.

The constructor defaults are source defaults, not an assertion that a server is enabled by default: IPv4/IPv6, HTTP, and HTTPS start disabled; ports default to 80/443; HTTP/1 is enabled; event concurrency is 1024; TLS-accept, network producer, and consumer concurrency each default to 2 in the builder configuration. Other protocol flags are not automatically enabled by those defaults.

```text
configure adapter + service/protocol/options + callback
                         │
                         ▼
                 http_server_builder::build()
                         │
                         ├─ require adapter
                         ├─ create http_server(adapter)
                         ├─ copy server_conf
                         ├─ start adapter TLS/QUIC resources when enabled
                         └─ startup_server(family, port, handler, context)
                                  │
                                  ▼
                            network_server::open()
                                  │
                                  ├─ register accept-control callback
                                  ├─ register http_protocol
                                  └─ register http2_protocol when enabled
```

The builder configures HTTP/HTTPS/HTTP3 service startup based on the selected flags and adapter. TLS certificate/key, cipher list, and peer-verification settings are passed to the secure adapter startup path. HTTP/3 selection requests the QUIC service path; the source's HTTP/3 server flow is incomplete and should not be described as a finished service just because `enable_h3` exists.

### Request delivery and handler callback

`http_server` owns a `network_server`, `server_conf`, the selected `server_socket_adapter`, an IP ACL, HTTP/1 and HTTP/2 protocol objects, a router, and the application consume callback.

```text
network_server event/session processing
             │ completed transport bytes
             ▼
      http_server::consume()
             │
             ├─ HTTP/1.x: http_protocol recognition
             │             -> http_request::open()
             │
             └─ HTTP/2: network_session::get_http2_session()
                          -> http2_session::consume()
                          -> completed http_request (when ready)
             │
             ▼
application callback passed to set_handler()
             │
             ├─ inspect event/session/request
             ├─ optionally call http_router::route()
             │      ├─ optional auth provider/resolver
             │      ├─ URI/status handler lookup
             │      └─ registered callback
             └─ compose/send response through http_response
```

Important boundary: `http_server::consume()` invokes the callback registered by `set_handler`; it does not unconditionally call `http_router::route()` on the application's behalf. The application callback decides how to use the request and whether to route it. The HTTP/2 request pointer can be null while the session is still accumulating frames or the relevant END_HEADERS/END_STREAM conditions have not yet completed.

The router supports both a plain function pointer (`http_request_handler_t`) and a `std::function` callback (`http_request_function_t`). A URI can be registered with an optional authentication provider. `route()` associates the router with request/response, resolves the provider if configured, invokes `request_auth()` when authentication fails, and otherwise selects the URI handler. If no URI handler exists, it may try `html_documents` and then the configured 404/status handler. The registered handler receives the session, request, response, and router; it supplies application response behavior.

### Client path

`http_client` currently follows a simple HTTP/1.x request/response path:

```text
URL -> split URL -> http_request::compose()
   -> client socket connect/send
   -> receive response bytes
   -> network_protocol_group + http_protocol
   -> http_response::open()
```

This simple flow does not automatically negotiate or implement the separate HTTP/2 frame/session path.

## 3. Behavior Model

### Network-server boundary

`http_server` uses `network_server` for listener setup, multiplexer registration, accept/TLS-accept work, session creation, producer/consumer buffering, and shutdown. It supplies the HTTP consume callback and registers `http_protocol` and, when configured, `http2_protocol`. The network server determines when bytes are ready and manages the session; the HTTP layer recognizes protocol messages and makes request objects available to application code.

For HTTPS, the chosen adapter creates/starts the secure server socket before the network server binds the listener. The network server's TLS-accept workers perform the secure accept/handshake stage before ordinary session event processing. For plain HTTP, the TCP server socket follows the direct accept path.

### Router callback and response

The router is an optional application-level dispatcher, not the protocol parser and not the network-server callback itself. If the application's consume callback invokes `http_router::route()`, the router can authenticate, resolve a URI handler, or produce a 404 response. The selected handler composes the `http_response`; the response is then serialized/sent through the associated session and active protocol path.

## 4. Relationships

- `http_server.hpp/.cpp`, `http_server_builder.hpp/.cpp`
- `http_client.hpp/.cpp`, `http_router.hpp/.cpp`
- [HTTP overview](README.md)
- [HTTP core model](http-core-model.md)
- [HTTP protocol stack](http-protocol-stack.md)
- [Network server model](../server/network-server-model.md)
- [Network session](../server/network_session.md)
- [Socket adapters](../basic/openssl/README.md) and [trial socket composition](../basic/trial/README.md)
- `test/testcase/net/http/testcase_http.cpp` — source-level request/response/router coverage.
- `test/applet/httpserver1/` and `test/applet/httpserver2/` — server applet source paths.

## 5. References

No external references are currently listed.
