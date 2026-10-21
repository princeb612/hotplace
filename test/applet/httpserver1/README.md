## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ Documentation scope: runnable server applet │
└──────────────────────────────────────────────┘
```

# HTTP/1.1 server applet

## 1. Role

`httpserver1` is a runnable HTTP/1.1 server built on hotplace's `network_server` and HTTP routing layer. It is the first HTTP example in the source's progression `tcpserver1 → tcpserver2 → tlsserver → httpserver1 → httpserver2`. It supports plain HTTP and HTTPS/TLS listener configuration, and can select either the OpenSSL-backed socket path or the trial adapter.

This is an integration applet for browser, curl and packet-capture inspection, not a complete HTTP conformance suite. The checked task list and commands below are historical maintainer notes; they are not a claim that every combination was rerun on the current source revision.

## 2. Model

### Request and response path

```text
network_server / socket event
          │
          ▼
consumer_routine(mux_connect / mux_read)
          │
          ├── retrieve network_session + parsed http_request
          │
          ▼
HTTP response handling
          │
          ├── TLS-enabled server socket → http_router.route(...)
          │
          └── plain HTTP path → local response handling
          │
          ▼
http_response → session output
```

The source defines simple HTML and JSON response handlers. In the TLS-enabled branch, the read callback delegates the request to the configured `http_router`; the plain HTTP branch has its own handling path. The applet therefore demonstrates integration between transport events, parsed requests and response composition rather than implementing all HTTP parsing inside the callback.

### Relevant options

- `-r` starts the server.
- `-h` selects the plain HTTP port (default 8080 in `sample.cpp`).
- `-s` selects the HTTPS port (default 9000).
- `-T` selects the trial adapter.
- `-k` enables TLS key logging.
- `-cert` selects a configured certificate family; `-cs` can select a cipher suite.
- `-e` enables Content-Encoding handling.

Use the command-line parser in `sample.cpp` as the source of truth for the current option set.

## 3. Important behavior and lifetime

The server uses the shared `http_server` instance configured by the applet setup. Incoming events are delivered to `consumer_routine`; a read event has access to the `network_session` and parsed `http_request`, and response objects are composed for that request. Router handlers are registered on the shared HTTP server rather than reconstructed as independent protocol stacks for every callback.

TLS availability depends on the selected socket implementation, certificate family, cipher configuration and allowed TLS versions. The checked historical matrix includes TLS 1.2 and TLS 1.3, OpenSSL and trial integration, browser/curl requests and several key-agreement groups. Some hybrid groups remain unchecked in that matrix; do not interpret neighboring checked rows as proof of support for those entries.

The `.run` marker is used by the applet's run/stop instructions. Key-log files contain sensitive traffic secrets and should be treated as diagnostic material, not committed as ordinary test data.

## 4. Example from the applet instructions

Start the server using the selected backend:

```sh
./test-httpserver1 -r -k --trace
# or the trial adapter
./test-httpserver1 -r -k --trace -T
```

Then issue a request using curl:

```sh
curl https://localhost:9000/ -v -s -k --http1.1
```

The `-k` curl option skips certificate verification and is suitable only for this local diagnostic setup. The request exercises the TLS handshake and HTTP/1.1 request/response path together. It does not by itself validate every HTTP method, malformed request, connection reuse case or response-framing edge case.

## 5. Relationships

- [HTTP implementation](../../../sdk/net/http/README.md) — HTTP request/response and routing implementation.
- [TLS/DTLS/QUIC implementation](../../../sdk/net/tls/README.md) — secure transport and session state.
- [Network-server layer](../../../sdk/net/server/README.md) — socket events and session integration.
- [Network client applet](../netclient/README.md) — runnable client-side protocol selection.
- `httpserver2/` — HTTP/2 applet and ALPN-focused comparison.

## 6. References

- `run_server.cpp` — event callback, routing and response handling.
- `sample.cpp`, `sample.hpp` — command-line setup and shared applet state.
- `CMakeLists.txt` — applet target and static-file staging.
- `index.html`, `signin.html`, `style.css` — static content.
- `pcap/` — captured HTTP/1.1 verification cases.

## 7. Developer Notes

### Historical integration checklist retained from the original README

The original checklist records successful local integration for the listed browser, curl and OpenSSL scenarios. It is retained as historical context, not as a current test report for Revision 1105. Unchecked hybrid groups remain explicitly unchecked.

- HTTP/1.1 with `network_server`, OpenSSL and trial paths.
- TLS 1.3 with Chrome/Edge, curl and OpenSSL client scenarios.
- TLS 1.2 curl scenario using `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.
- ML-DSA certificate experiment.

Before relying on a specific client, group, certificate or backend combination, rerun that exact scenario and record the source revision and tool versions.
