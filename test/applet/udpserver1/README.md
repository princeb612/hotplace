# Multiplexer-integrated UDP server applet

`udpserver1` is the direct multiplexer-based UDP example. Its source comments specify IPv4-only support for this applet.

## Sources

- `run_server.cpp` implements the UDP event path and datagram handling.
- `sample.cpp` provides shared applet support.
- `CMakeLists.txt` defines the build target.

Compare with [`udpserver2`](../udpserver2/README.md), which uses `network_server` and documents IPv4 and IPv6 support. These applets demonstrate different integration layers, not different UDP protocol versions.
