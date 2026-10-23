## Publication

```text
┌───────────────────────────────────────────────┐
│ hotplace source tree                          │
│ Edition 2 · Revision 1107                     │
│ Source basis: Revision 1107                   │
│ Documented with GPT-6                         │
│ — OS-facing APIs and implementation boundaries│
└───────────────────────────────────────────────┘
```

# System integration

## 1. Role

`sdk/io/system` contains low-level OS-facing APIs used by the I/O and network layers. Its components do not share one lifecycle or one event model: some wrap socket operations, one dispatches I/O notifications, one schedules queued work, and others integrate directly with Linux or Windows facilities.

## 2. Data Model

| Component | Main question it answers | Key implementation boundary |
|---|---|---|
| [Socket utilities](socket.md) | How are sockets created, connected, waited on, and closed across POSIX/Winsock? | `socket.hpp/.cpp`, `winsock.cpp` |
| [Event multiplexer](multiplexer.md) | What does a callback receive, and how do epoll and IOCP differ? | Linux epoll vs Windows IOCP |
| [MLFQ](mlfq.md) | Which queued work item is returned first, and who owns it? | Priority map, FIFO queues, binder and cancellation set |
| [Netlink](netlink.md) | How do Linux process events reach a consumer callback? | Process connector socket plus producer/consumer threads |
| [Windows Registry](windows_registry.md) | How are keys/values enumerated, read, written, and deleted? | Win32 Registry APIs and ANSI/Unicode overloads |
| [PE helpers](winpe.md) | What does the exposed PE checksum calculate, and what does it not verify? | PE checksum helper, distinct from Authenticode |

## 3. Behavior Model

### Similar-looking APIs that solve different problems

- **Socket readiness vs I/O completion:** epoll tells the caller that an operation can be attempted; IOCP tells the caller that a previously submitted overlapped operation completed. Their callback payloads are not interchangeable.
- **Event dispatch vs work scheduling:** the multiplexer observes OS I/O events. MLFQ chooses an item from application work queues by priority. A server can compose them, but neither replaces the other.
- **Generic socket wrapper vs kernel integration:** the socket wrapper creates and manages ordinary sockets; netlink subscribes to a Linux kernel process-event stream and uses its own producer/consumer pipeline.
- **PE checksum vs file authentication:** the PE checksum is a format-level checksum helper. Authenticode verification in `sdk/crypto/authenticode/` handles signature and digest rules.

### Resource and thread lifetime

A common wrapper does not automatically join worker threads or transfer ownership of native resources. Callers must coordinate callback completion before releasing socket/session contexts, wait for MLFQ consumers before freeing their work context, and close Registry handles explicitly. Platform-specific error and access rules still apply.

## 5. Relationships

- `sdk/net/basic/` — higher-level socket/client/server abstractions.
- `sdk/net/server/` — uses the multiplexer and may compose event dispatch with work scheduling.
- `sdk/base/system/` — synchronization, thread and process primitives.
- `sdk/crypto/authenticode/` — signature verification, distinct from the PE checksum utility.
- [Platform-specific I/O support](platform.md) — POSIX/Linux/Windows implementation boundaries.

### Source-level evidence

- `test/testcase/io/system/testcase_mlfq.cpp` — producer/consumer queue usage and priority selection.
- `test/testcase/io/system/testcase_netlink.cpp` — Linux/glibc-guarded process events and `/proc` lookups.

These are source-level examples, not a claim that the tests ran during this documentation update or that they cover every platform branch.

## 6. References

- [Linux man-pages: epoll_create(2)](https://man7.org/linux/man-pages/man2/epoll_create.2.html) — Linux event notification API.
- [Microsoft Learn: Windows Sockets](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page-2) — Winsock API.
- [Microsoft Learn: I/O completion ports](https://learn.microsoft.com/en-us/windows/win32/fileio/i-o-completion-ports) — IOCP model.
- [Microsoft Learn: Registry functions](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-functions) — Windows Registry API.
- [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) — PE image layout.
