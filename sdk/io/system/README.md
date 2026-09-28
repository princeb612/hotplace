### System I/O, multiplexing and platform integration

This directory contains system I/O facilities used by the SDK.

The main components include the multiplexer abstraction and controller, Linux epoll integration, Windows IOCP integration, netlink support, MLFQ scheduling support and Windows/PE-related system structures.

It forms the bridge between platform I/O mechanisms and higher-level network/session code.
