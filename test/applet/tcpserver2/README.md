# Network-server-integrated TCP server applet

`tcpserver2` demonstrates TCP handling through the higher-level `network_server` path rather than the direct multiplexer-oriented pattern in `tcpserver1`.

## Behavior and sources

- `run_server.cpp` defines an `ipaddr_acl` and checks the accepted peer address through `acl.determine()` in the accept handler.
- `sample.cpp` provides shared applet setup.
- `CMakeLists.txt` defines the build target.

This applet is useful for comparing the low-level event-loop example (`tcpserver1`) with a network-server integration and address-policy hook. It is not itself the TLS/HTTP applet; those follow later in the repository's example progression.
