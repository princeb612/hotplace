### System I/O, multiplexing and platform integration

This directory contains system I/O facilities used by the SDK.

The main components include the multiplexer abstraction and controller, Linux epoll integration, Windows IOCP integration, netlink support, MLFQ scheduling support and Windows/PE-related system structures.

It forms the bridge between platform I/O mechanisms and higher-level network/session code.

## Module records

- [multiplexer](multiplexer.md) — event notification abstraction and epoll/IOCP backends
- [socket](socket.md) — low-level platform socket wrapper
- [mlfq](mlfq.md) — multi-level feedback queue scheduling structure
- [netlink](netlink.md) — Linux netlink integration
- [windows_registry](windows_registry.md) — Windows Registry access
- [winpe](winpe.md) — Windows PE structures and parsing support
- [platform](platform.md) — common boundary between SDK I/O and OS-specific support
