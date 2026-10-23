## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — Linux process-event pipeline and limits    │
└──────────────────────────────────────────────┘
```

# Linux netlink process events

## 1. Role

The Linux-only `netlink` component subscribes to the kernel process connector and forwards selected process events to a caller callback. It is not a generic socket wrapper and is not a backend of the epoll/IOCP multiplexer.

## 2. Data Model

The runtime context owns:

- a `NETLINK_CONNECTOR` socket bound to `CN_IDX_PROC`;
- a producer thread that receives kernel messages;
- a queue of copied `PROC_EVENT` records protected by a lock;
- a consumer thread that removes queued events and calls the user handler;
- separate producer/consumer loop flags and a caller-provided cooldown delay for an empty queue.


## 3. Behavior Model

### Open and subscribe

Opening the socket binds to the process connector group and uses the process connector's multicast control message to enable notifications. This may require elevated privileges and can fail due to kernel/configuration restrictions. The public lifecycle is `netlink::open(handle, cooldown, consumer_handler, parameter)`, followed by `close(handle)`.


### Which events reach the callback?

The producer queues `PROC_EVENT_FORK`, `PROC_EVENT_EXEC`, `PROC_EVENT_EXIT`, `PROC_EVENT_UID`, and `PROC_EVENT_GID`. Other connector messages are ignored. The consumer invokes the callback with the event record and the user parameter; the callback must inspect `event.proc_ev.what` and the matching union member.

A process event is not a complete process record. The testcase uses `/proc/<pid>/exe` and `/proc/<pid>/cmdline` to look up executable path and command line after an exec event. Those follow-up reads can fail or race with process exit, and access to `/proc` is subject to OS permissions and process lifetime.

### Shutdown and resource lifetime

`close()` disables notification, closes the socket, signals and waits for the producer and consumer threads, clears queued records, and releases the context. Callers should stop relying on the callback context before closing it; the callback runs on the component's consumer thread. Do not free the user parameter while callbacks can still be executing.

### Source-level example and platform limits

`test/testcase/io/system/testcase_netlink.cpp` registers a handler, waits for SIGINT, then closes the component. The handler distinguishes fork, exec, exit, UID and GID changes; the testcase also queries `/proc` for executable and command-line details. It is compiled only for the Linux/glibc condition in the source. This is not portable coverage and was not executed as part of this documentation update.

## 5. Relationships

- [System integration overview](README.md) — platform boundary.
- [Socket utilities](socket.md) — generic socket helper layer; netlink uses its own kernel protocol socket path.
- [Event multiplexer](multiplexer.md) — readiness/completion dispatch, separate from the producer/consumer process-event queue.
- `test/testcase/io/system/testcase_netlink.cpp` — source-level usage.

### Implementation source navigation

- `sdk/io/system/linux/netlink.hpp`
- `sdk/io/system/linux/netlink.cpp`

## 6. References

- [Linux kernel documentation: Netlink](https://docs.kernel.org/userspace-api/netlink/intro.html) — Netlink userspace/kernel communication model.
- [Linux kernel UAPI: connector](https://github.com/torvalds/linux/blob/master/include/uapi/linux/connector.h) — connector identifiers and process-event definitions.
- [Linux man-pages: proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) — /proc filesystem interface.