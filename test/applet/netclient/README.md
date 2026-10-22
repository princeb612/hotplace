## Publication

```text
hotplace source tree
Edition 1 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
Scope: runnable network client applet
```

# Network client applet

## 1. Role

`netclient` is a configurable client applet for exercising hotplace's TCP, UDP, TLS and DTLS socket paths against the matching server applets. It is an interactive integration tool rather than a self-contained unit test: results depend on a reachable server, selected protocol, backend, certificate configuration and command-line options.

The source maps the `-P` option to TCP, UDP, TLS, TLS 1.2-only, TLS 1.3-only, DTLS or QUIC modes. The currently documented server/client matrix below focuses on TCP/UDP/TLS/DTLS and HTTP integration; the presence of a `quic` option name alone should not be taken as proof of complete QUIC client coverage.

## 2. Model

### Option and implementation paths

- `-P tcp` / `-P udp` — select the plain transport path.
- `-P tls` — select TLS with the allowed TLS versions controlled by flags.
- `-P tls12` / `-P tls13` — select TLS and set the corresponding version allowance.
- `-P dtls` — select the DTLS path.
- `-T` — select the trial socket implementation for TCP/UDP and the trial TLS/DTLS path where applicable.
- `-a` / `-p` — target address and port; defaults in the command-line setup are `127.0.0.1:9000`.
- `-m` — override the message sent by the client; `-h` selects a basic HTTP/1.1 GET request.
- `-c`, `-b`, `-wto` — configure request count, receive buffer size and wait timeout.

The implementation separates transport-specific operations:

```text
command-line options
        │
        ▼
protocol selector (-P)
        │
        ├── TCP  ── connect / send / read / more
        ├── UDP  ── open / sendto / recvfrom
        ├── TLS  ── secure connect / send / read / more
        └── DTLS ── datagram-oriented secure path
        │
        ▼
log response, close socket, release client
```

For TCP/TLS, a response may span multiple reads: the client appends the first `read` result and continues with `more` while the status is `errorcode_t::more_data`. UDP uses one `recvfrom` operation per request iteration, consistent with datagram boundaries. These are different I/O models, not merely different protocol names.

## 3. Important behavior and lifetime

### Resource and response handling

Each client path creates the selected socket implementation, applies the configured wait timeout, opens or connects to the target, performs up to the configured request count, and closes/releases the client in its cleanup path. TLS uses an OpenSSL context and secure client socket; the trial selection is a separate implementation path. Successful connection and successful application exchange are distinct outcomes, so interpret the logged/testcase status together with the response output.

The applet prints received response data for interactive diagnosis. It is not a general HTTP conformance client and does not assert that every returned body matches a full HTTP specification. Use the dedicated HTTP testcase and server applets when validating protocol framing or browser interoperability.

### External dependencies

The applet expects a compatible peer to be running. The server side can be `tcpserver1`, `tcpserver2`, `udpserver1`, `udpserver2`, `tlsserver` or `dtlsserver`; HTTP scenarios use the corresponding HTTP server applet and client/browser configuration. TLS/DTLS results also depend on the selected certificate, protocol version and crypto backend. Do not treat a historical PASS table as evidence that the current working tree was rerun.

## 4. Example from the applet instructions

Start a matching server first, then run the client with the selected protocol. For example, for a TLS 1.3 client against a local TLS server:

```sh
./test-tlsserver.exe -r -k --trace -tls13 &
./test-netclient -P tls13 -k --trace
```

For the HTTP/1.1 request path, start `httpserver1` and use:

```sh
./test-netclient -P tls13 -h -k --trace
```

The exact executable suffix and command shell depend on the build environment. These commands document the intended integration sequence; they were not executed as part of this documentation update.

## 5. Relationships

- [Network SDK](../../../sdk/net/README.md) — socket, server, TLS/DTLS and HTTP layers.
- [Basic network sockets](../../../sdk/net/basic/README.md) — naive and trial socket implementations.
- [TLS/DTLS/QUIC](../../../sdk/net/tls/README.md) — secure transport and session behavior.
- [TCP server via multiplexer](../tcpserver1/README.md) and [TCP server via network_server](../tcpserver2/README.md).
- [UDP server via multiplexer](../udpserver1/README.md) and [UDP server via network_server](../udpserver2/README.md).
- [TLS server](../tlsserver/README.md), [DTLS server](../dtlsserver/README.md), [HTTP/1.1 server](../httpserver1/README.md), and [HTTP/2 server](../httpserver2/README.md).

## 6. References

- `sample.cpp` — command-line parsing, protocol selection and applet setup.
- `test_netclient.cpp` — transport-specific connect/send/read/receive paths.
- `sample.hpp` — option and shared applet declarations.
- `CMakeLists.txt` — target definition through `maketest`.

## 7. Developer Notes

### Historical integration matrix retained from the original README

The table below records the status labels in the prior maintainer notes. It is historical context, not a current verification result for Revision 1105; the source revision, compiler, backend version and peer configuration were not recorded with the table.

| Client implementation | MinGW | Linux | TLS 1.3 | TLS 1.2 |
|---|---|---|---|---|
| `naive_tcp_client_socket` | PASS | PASS | N/A | N/A |
| `naive_udp_client_socket` | PASS | PASS | N/A | N/A |
| `trial_tcp_client_socket` | PASS | PASS | N/A | N/A |
| `trial_udp_client_socket` | PASS | PASS | N/A | N/A |
| `openssl_tls_client_socket` | PASS | PASS | PASS | PASS |
| `openssl_dtls_client_socket` | PASS | PASS | N/A | PASS |
| `trial_tls_client_socket` | PASS | PASS | PASS | PASS |
| `trial_dtls_client_socket` | PASS | PASS | — | PASS |

Original scenario matrix:

| Scenario | Peer |
|---|---|
| TCP | `tcpserver1` or `tcpserver2` |
| UDP | `udpserver1` or `udpserver2` |
| TLS | `tlsserver` |
| DTLS | `dtlsserver` |
| HTTP/1.1 | `httpserver1` |
| HTTP/2 | `httpserver2` / browser |

The prior table is retained for maintainers; rerun the relevant applet/client pair before relying on any status for a new source revision.
