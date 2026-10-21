## Publication

Edition 2 · Revision 1105  
Source basis: Revision 1105  
Documented with GPT-6  
Scope: source structure, implementation and applet usage

# HTTP/2 server applet

## 1. Role

`httpserver2` is a runnable HTTPS server configured for HTTP/2. It uses the higher-level `http_server` builder and selects either the OpenSSL-backed socket adapter or the trial adapter. It is intended for local browser/client integration and protocol tracing, not as a complete HTTP/2 conformance suite.

## 2. Model

The setup in `run_server.cpp` builds a socket adapter, then configures `http_server_builder` to disable the plain HTTP scheme, enable HTTPS, IPv4 and IPv6, enable HTTP/2, register `consumer_routine`, and set the TLS cipher list and certificate material.

On a read event, the callback obtains the parsed `http_request`, creates an `http_response`, calls the shared router's `route(session, request, &response)`, and sends the response through `response.respond(session)`. The source also defines small HTML and JSON handlers as examples.

## 3. Important behavior and lifetime

The adapter and HTTP server builder are separate setup stages. If adapter creation fails, the applet returns an internal error rather than starting the listener. The command-line options select ports, the trial adapter, key logging, cipher suite and certificate family; `sample.cpp` is the source of truth for the available options.

ALPN matters when verifying HTTP/2 over TLS. An HTTPS connection alone does not establish that HTTP/2 was negotiated; use an HTTP/2-capable client and inspect the negotiated protocol. The source's prior-knowledge command is a separate diagnostic mode, not the normal TLS-plus-ALPN path.

Key-log output contains traffic-secret material and must be handled as sensitive diagnostic data. Packet captures in `pcap/` help inspect selected cases but do not establish broad browser or protocol conformance.

## 4. Example from the applet instructions

The documented sequence is to start the server with either the default OpenSSL adapter or the trial adapter, then request the HTTPS endpoint with an HTTP/2-capable client. The curl example uses `--http2`; its `-k` option disables certificate verification and should be restricted to a local diagnostic environment.

This demonstrates an integration path through TLS negotiation, HTTP/2 selection, request routing and response composition. It is not a deterministic unit test and was not executed as part of this documentation update.

## 5. Relationships

- [HTTP implementation](../../../sdk/net/http/README.md) — request/response, routing and HTTP/2 handling.
- [TLS/DTLS/QUIC implementation](../../../sdk/net/tls/README.md) — secure transport and session state.
- [Network server](../../../sdk/net/server/README.md) — event processing and session management.
- [HTTP/1.1 server](../httpserver1/README.md) — comparison with the lower-level HTTP/1.1 applet.
- [Network client](../netclient/README.md) — client-side protocol selection.

## 6. References

- `run_server.cpp` — adapter setup, builder configuration, request callback and response routing.
- `sample.cpp`, `sample.hpp` — options, logging and applet lifecycle.
- `CMakeLists.txt` — build target and static-file staging.
- `index.html` and `pcap/` — static content and captured HTTP/2 examples.

## 7. Developer Notes

The original checklist records `network_server`, HTTP/2, OpenSSL, trial and ALPN integration as completed. Preserve this as historical maintainer context, not as a current compatibility claim for every browser, TLS backend or build. Re-run the exact client/server combination and record its source revision and tool versions before updating that status.
