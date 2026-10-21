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

# TLS server applet

## 1. Role

`tlsserver` is a configurable TLS echo server used to exercise the hotplace network-server and secure-socket paths. It supports TLS 1.2 and TLS 1.3 selection, the OpenSSL-backed socket path and the trial adapter, and selectable certificate/key-agreement settings. It is an integration endpoint for clients such as `openssl s_client` and hotplace's `netclient`, not a complete TLS conformance test.

## 2. Model

### Event and data flow

```text
command-line configuration
          │
          ├── TLS version allowance
          ├── OpenSSL or trial adapter
          └── certificate / cipher configuration
          │
          ▼
network_server + TLS server_socket
          │
          ▼
consumer_routine
  connect → log event
  read    → log bytes → session.send(bytes)
  close   → log disconnect
```

The consumer callback is an echo path: on `mux_read`, it sends the received bytes back through the current `network_session`. The handshake, record protection and transport are supplied by the selected secure socket/session implementation rather than being implemented by the echo callback.

### Relevant options

- `-r` starts the server; `-p` selects its port (default 9000).
- `-tls12` and `-tls13` allow the corresponding protocol versions.
- `-T` selects the trial adapter.
- `-k` enables key logging for diagnostic analysis.
- `-cs` selects a cipher suite and `-group` selects a supported group where the implementation path permits it.
- `-cert` selects a certificate family such as RSA, ECDSA or ML-DSA.

The available combinations depend on the chosen backend, certificate material and build configuration.

## 3. Important behavior and lifetime

The server creates a `network_server`, configures a TLS server socket with the selected protocol flags, then enters the server event loop. The callback receives the `network_session` and byte buffer for the event; read data is echoed using `session->send`. A successful socket connection alone is not proof that a TLS handshake or application-data exchange completed, so inspect the client transcript and returned bytes when diagnosing a scenario.

The applet includes source-level examples for TLS 1.2/1.3 and hybrid post-quantum key agreement. These examples depend on the selected crypto backend and client tool version. A checklist entry or command in this document records an intended/previously exercised scenario; it does not establish that all options were rerun for the current revision.

Key-log output contains traffic-secret material. Use it only for controlled debugging and protect the resulting file.

## 4. Example from the applet instructions

Run a TLS 1.3 trial server:

```sh
./test-tlsserver.exe -r -k -T --trace -tls13
```

Then connect with OpenSSL using selected ML-KEM groups:

```sh
openssl s_client -connect localhost:9000 -state -msg -trace -debug \
  -keylogfile sslkeylog -tls1_3 -groups MLKEM512:MLKEM768:MLKEM1024
```

The server's callback echoes application data after the secure session is established. The OpenSSL transcript can be used to inspect negotiation and handshake progress; a successful connection for one group list does not prove every hybrid group or certificate combination works.

Stop the server using the applet's `.run` marker mechanism:

```sh
rm .run
```

Use the executable name produced by the active build on the target platform.

## 5. Relationships

- [TLS/DTLS/QUIC implementation](../../../sdk/net/tls/README.md) — protocol and session implementation.
- [Network server](../../../sdk/net/server/README.md) — event loop and session lifecycle.
- [Network client applet](../netclient/README.md) — matching client-side protocol options.
- [HTTP/1.1 server](../httpserver1/README.md) and [HTTP/2 server](../httpserver2/README.md) — application-protocol examples layered over secure transport.

## 6. References

- `run_server.cpp` — TLS socket setup, server event callback and echo path.
- `sample.cpp`, `sample.hpp` — options and shared applet initialization.
- `CMakeLists.txt` — applet build target.
- `pcap/` — captured TLS/HTTP verification cases.

## 7. Developer Notes

The original maintainer notes include TLS 1.3 ML-KEM, ECDHE-ML-KEM and ML-DSA draft-era experiments. Keep the exact draft labels and tool commands as historical records; do not silently reinterpret them as statements of final-standard conformance. Revalidate the scenario against the source revision and external client version before publishing a current compatibility claim.
