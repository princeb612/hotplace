# Network-server-integrated UDP server applet

`udpserver2` demonstrates UDP datagram handling through `network_server`; the source comments specify IPv4 and IPv6 support.

## Sources

- `run_server.cpp` contains the network-server consumer/datagram path.
- `sample.cpp` provides shared applet support.
- `CMakeLists.txt` defines the build target.

Compare with [`udpserver1`](../udpserver1/README.md), which is the lower-level multiplexer example and is marked IPv4-only. This is an applet-level demonstration, not a claim that every backend/platform has identical behavior.
