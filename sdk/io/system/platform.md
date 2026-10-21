## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — actual platform boundaries and semantics   │
└──────────────────────────────────────────────┘
```

# Platform-specific I/O support

## 1. Role

`sdk/io/system` collects operating-system facilities that higher-level I/O and network code use. The shared wrapper reduces platform branching, but it does not make the native resource lifecycle or notification model identical across systems.

## 2. Data Model

| Concern | Linux / POSIX path | Windows path | What remains different |
|---|---|---|---|
| Socket | POSIX socket APIs | Winsock; overlapped sockets can be created | Startup, error codes and socket handle conventions |
| Event notification | `epoll` | IOCP | Readiness versus completion; callback payload and registration semantics |
| Kernel process events | Netlink process connector | No equivalent in this module | Linux-only process-event stream |
| Registry | Not provided as a portable facility | Windows Registry wrapper | Windows key/value semantics and character-set selection |
| PE helpers | Compatibility PE declarations and checksum helper | Native `winnt.h` declarations and checksum helper | The PE format is shared, but native definitions and available APIs differ |

The multiplexer enum declares epoll, completion-port and kqueue types, but the current backend source files are Linux epoll and Windows IOCP. Do not infer a kqueue implementation from the enum.

## 3. Behavior Model

### What does the common layer actually unify?

The socket utilities centralize creation, connect, wait, nonblocking mode, address conversion and close operations. They do not hide every native error or initialization requirement. The multiplexer centralizes a callback entry point, but its payload differs by backend: epoll passes the multiplexer context and fd with a callback-control pointer; IOCP passes the context, transferred byte count, completion key and `OVERLAPPED*` with a null control pointer. See [multiplexer](multiplexer.md) for the full contract.

### Which component should a caller choose?

- Use [socket utilities](socket.md) for low-level socket operations. Use `sdk/net/basic/` for higher-level client/server and secure transport abstractions.
- Use [multiplexer](multiplexer.md) for event notification. Use [MLFQ](mlfq.md) when work items need priority ordering; these are separate mechanisms.
- Use [netlink](netlink.md) for Linux kernel process events, not as a portable socket or multiplexer backend.
- Use [Windows Registry](windows_registry.md) for Windows key/value operations.
- Use [PE helpers](winpe.md) for the exposed PE checksum utility. Use `sdk/crypto/authenticode/` for signature and Authenticode digest verification.

### Ownership and shutdown

Native sockets, multiplexer contexts, registry keys, and worker-thread contexts have separate lifecycles. A caller should stop callbacks/workers that reference a resource before closing it. A generic wrapper does not guarantee that a worker has joined or that queued work has been drained merely because a close function was called.

### Source-level evidence and limits

`test/testcase/io/system/testcase_mlfq.cpp` exercises concurrent producer/consumer use of the queue. `testcase_netlink.cpp` is guarded for Linux/glibc and exercises process events plus `/proc` lookups. These examples do not establish coverage of all socket or multiplexer branches, and this documentation update did not execute them.

## 4. Relationships

- [System integration overview](README.md) — component map.
- [Socket utilities](socket.md), [event multiplexer](multiplexer.md), [MLFQ](mlfq.md), [netlink](netlink.md), [Windows Registry](windows_registry.md), and [PE helpers](winpe.md) — component-level contracts.
- `sdk/net/basic/` and `sdk/net/server/` — higher-level consumers.
- `sdk/base/system/` — shared synchronization, thread and process utilities.

### Implementation source navigation

- `sdk/io/system/socket.hpp/.cpp`
- `sdk/io/system/multiplexer.hpp`, `multiplexer_controller.cpp`
- `sdk/io/system/linux/multiplexer_epoll.cpp`
- `sdk/io/system/windows/multiplexer_iocp.cpp`
- `sdk/io/system/mlfq.hpp`
- `sdk/io/system/linux/netlink.hpp/.cpp`
- `sdk/io/system/windows/windows_registry.hpp/.cpp`
- `sdk/io/system/winpe.hpp/.cpp`
- `test/testcase/io/system/testcase_mlfq.cpp`
- `test/testcase/io/system/testcase_netlink.cpp`

## 5. References

- Linux epoll API: https://man7.org/linux/man-pages/man2/epoll_create.2.html
- Microsoft Win32 socket, IOCP, Registry and PE/COFF API documentation.
