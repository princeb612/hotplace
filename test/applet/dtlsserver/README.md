# DTLS 1.2 server applet

This applet runs a DTLS 1.2 server over UDP and is used in the network/TLS test flow.

## Run and stop

- Start: `./test-tlsserver.exe -r -k --trace &`
- Stop the applet using the `.run` marker mechanism: `rm .run`

The executable name shown above follows the repository's test instructions; use the executable produced by the active build. The source entry points are `run_server.cpp`, `sample.cpp`, and `sample.hpp`; `CMakeLists.txt` defines the applet target.

## Related implementation

- [`sdk/net/tls`](../../../sdk/net/tls/README.md)

This is a test server for DTLS behavior, not a general-purpose production service.
