## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — callback contract and epoll/IOCP behavior  │
└──────────────────────────────────────────────┘
```

# Event multiplexer

## 1. Role

The multiplexer adapts two different OS notification models to one callback signature:

- Linux `epoll` reports that a registered file descriptor is ready for an operation.
- Windows IOCP reports completion of an overlapped operation that was previously submitted.

This is a callback and event-dispatch boundary, not a cross-platform socket state machine. The caller still owns accept/receive/send operations, protocol state, and the lifetime of socket/session objects. The current implementation files are `linux/multiplexer_epoll.cpp` and `windows/multiplexer_iocp.cpp`. Although `multiplexer_type_t` declares `mux_type_kqueue`, that declaration alone does not mean a kqueue backend exists.

## 2. Data Model

### Event types

`multiplexer_event_type_t` defines the vocabulary shared with callback consumers:

| Value | API-level meaning |
|---:|---|
| `mux_tryconnect = 0` | Try SSL accept / connection-related follow-up |
| `mux_connect = 1` | Stream/listener connection event |
| `mux_read = 2` | Stream read readiness/completion |
| `mux_write = 3` | Stream send |
| `mux_disconnect = 4` | Stream closed / disconnect |
| `mux_dgram = 5` | Datagram read |

These names do not erase the difference between *readiness* and *completion*. A callback must interpret its event in the context of the backend and the operations the caller has posted. Backend-specific emission and mapping rules are described under Behavior Model.

### Callback signature and payload vectors

Both backends invoke the extended vector callback with the conceptual signature:

```cpp
return_t callback(
    uint32 type,
    uint32 count,
    void* data_vector[],
    CALLBACK_CONTROL* control,
    void* user_context);
```

The meaning of `data_vector` is backend-specific. Do not cast the same index to the same meaning without checking `count` and the selected backend.

#### IOCP — four entries

The callback payload contract is four entries; the behavior section compares how IOCP populates and dispatches them.

- `count == 4`.
- `data_vector[0]` is the multiplexer context, not the socket.
- `data_vector[1]` is the completed byte count, not a file descriptor.
- `data_vector[2]` is the completion key supplied when the socket was associated with the IOCP using `bind()`. It commonly carries the caller's socket/session context.
- `data_vector[3]` is the `OVERLAPPED*` identifying the completed operation.
- `control` is passed as `nullptr`; the epoll callback-control mechanism is not available on this path.

The application must retain the memory backing `OVERLAPPED` and any operation context until the completion has been consumed.

#### epoll — two entries

The callback payload contract is two populated entries; the behavior section compares how epoll populates and dispatches them.

- `count == 2`; only indexes 0 and 1 are populated for the callback contract.
- `data_vector[1]` is the file descriptor registered with epoll. The `data` argument passed to `bind()` is not stored by this implementation; `ev.data.fd` is used instead.
- `control` points to a local `CALLBACK_CONTROL` initialized to `CONTINUE_CONTROL`. The IOCP path passes no control pointer.
- The callback receives readiness, not a completed byte count or an `OVERLAPPED*`. The consumer normally performs the corresponding nonblocking socket operation.

The vector is stack-local to the dispatch iteration. A callback must copy any values it needs after returning; it must not retain the vector pointer itself.

## 3. Behavior Model

### epoll is level-triggered in this implementation

The registration uses:

```cpp
ev.events = EPOLLIN | EPOLLHUP | EPOLLRDHUP;
ev.data.fd = eventsource;
epoll_ctl(epoll_fd, EPOLL_CTL_ADD, eventsource, &ev);
```

There is no `EPOLLET` flag, so the registration uses level-triggered behavior. While the descriptor remains readable, epoll can report it again. The callback should therefore drain available input as appropriate for the socket/protocol and keep the descriptor's registration and close lifecycle consistent. This source does not establish an edge-triggered contract.

The loop waits in `epoll_wait(..., 100)`, a 100 ms timeout. `EINTR` causes another iteration; other wait errors leave the loop. For input events, the loop distinguishes a stream listener from a connected stream by checking `SO_ACCEPTCONN` on `listenfd`, and distinguishes datagrams using `typeof_socket()`. Disconnect callbacks are dispatched for HUP/RDHUP/ERR only in the `else if` branch after EPOLLIN.

### IOCP is completion-driven

`bind()` associates an event source with the completion port using `CreateIoCompletionPort`; unlike epoll, it requires a non-null completion key. The typical sequence is to open the multiplexer, start the event loop with the listening socket as context, accept a client socket, bind that client socket with its session/completion key, and submit an overlapped operation such as `WSARecv`. The event loop blocks in `GetQueuedCompletionStatus` with a 100 ms timeout and dispatches the returned byte count, completion key, and `OVERLAPPED*`.

The shown implementation classifies a completion with zero transferred bytes as `mux_disconnect`; otherwise it chooses `mux_dgram` or `mux_read` from the socket type of `listenfd`. This is the current code's classification rule, not a universal statement that every zero-byte operation means a remote close in every possible application. Consumers must account for the actual operation and socket semantics.

### epoll and IOCP comparison

| Concern | Linux epoll | Windows IOCP |
|---|---|---|
| Notification model | Readiness notification | Completion notification |
| Main wait call | `epoll_wait`, 100 ms timeout | `GetQueuedCompletionStatus`, 100 ms timeout |
| Registration | `epoll_ctl(EPOLL_CTL_ADD)` | `CreateIoCompletionPort` associates handle and completion key |
| `bind()` data argument | Ignored by current implementation; fd stored in `epoll_event.data.fd` | Required non-null completion key, returned as callback data[2] |
| Listening socket | Typically bound to epoll; passed as `listenfd` to classify readable listener events | Passed as `listenfd` for classification; the accepted client socket is associated with IOCP in the documented sequence |
| Callback count | 2 | 4 |
| Callback data[0] | Multiplexer context | Multiplexer context |
| Callback data[1] | Event-source file descriptor | Transferred byte count |
| Callback data[2] | Not part of the callback contract | Completion key / caller context |
| Callback data[3] | Not part of the callback contract | `OVERLAPPED*` |
| `CALLBACK_CONTROL*` | Pointer to local `CONTINUE_CONTROL` | `nullptr` |
| Read event meaning | Descriptor is readable; caller performs I/O | Submitted I/O completed; byte count and operation context are available |
| Write event | `mux_write` is reserved; not emitted here | `mux_write` is reserved; not emitted here |
| `post()` | No-op in current implementation | Calls `PostQueuedCompletionStatus` using vector indexes 1–3 |
| `unbind()` | Removes the fd with `EPOLL_CTL_DEL` | Currently returns success without detaching the handle |
| Stop behavior | Controller flag checked between waits, with up to the polling interval before observation | Controller flag checked between waits, with up to the polling interval before observation; a zero completion key also exits the loop |

The `post()` API is therefore not symmetric: the epoll implementation is a no-op, while IOCP can enqueue a completion packet. Similarly, `unbind()` has a real epoll deletion path but no corresponding IOCP operation in the current source. Callers must not assume these methods have equivalent backend effects.

### What state does the multiplexer maintain?

The shared `multiplexer_controller` stores a map from event-loop thread ID (`arch_t`) to a run flag (`uint32`) protected by a critical section:

- `event_loop_new()` inserts the current thread ID with value `1`; registering the same ID again returns `already_exist`.
- `event_loop_break(token)` sets one registered thread's flag to `0`; a null token sets all registered flags to `0`.
- `event_loop_break_concurrent(n)` marks up to `n` currently running entries as stopped.
- `event_loop_test_broken()` returns true when the flag is zero or the thread ID is no longer present.
- `event_loop_close()` erases the thread's entry.

This is stop bookkeeping for event-loop threads, not per-socket connection state. The multiplexer does not own the higher-level TLS/session state machine; event consumers and the network layer handle that state.

One source-level mismatch matters for shutdown: although the header documents a null token as “stop all,” the Linux `multiplexer_epoll::event_loop_break()` implementation rejects a null token with `invalid_parameter`. The IOCP wrapper passes a null token through to the controller, where it marks all registered loops as stopped. On epoll, use a specific thread token or `event_loop_break_concurrent()` rather than assuming the null-token form stops every loop.

### Resource and shutdown order

The event-loop API is cooperative. The controller's flag is checked during the loop, and both implementations use a 100 ms wait, so requesting a break is not the same as synchronously joining the event-loop thread. Coordinate worker shutdown before destroying a context or closing handles still used by callbacks. A typical sequence is to stop accepting new work, request loop termination, wait for the worker threads to leave the loop, then close the multiplexer and release registered sockets/session contexts.

The API comment examples show the intended server flow, but they are not evidence that every lifecycle race or backend-specific error path has a dedicated test.

## 4. Relationships
- `multiplexer_controller` manages event-loop thread stop flags; it does not manage per-connection protocol state.
- `sdk/net/server/` consumes the multiplexer as part of the server/session flow.
- `sdk/io/system/socket.hpp` supplies socket operations and socket-type detection used to classify events.

### Implementation source navigation

- `sdk/io/system/multiplexer.hpp`
- `sdk/io/system/multiplexer_controller.cpp`
- `sdk/io/system/linux/multiplexer_epoll.cpp`
- `sdk/io/system/windows/multiplexer_iocp.cpp`
- `sdk/net/server/network-server-model.md`

## 5. References
- [Linux man-pages: epoll_create(2)](https://man7.org/linux/man-pages/man2/epoll_create.2.html) and [epoll_wait(2)](https://man7.org/linux/man-pages/man2/epoll_wait.2.html) — Linux event notification APIs.
- [Microsoft Learn: CreateIoCompletionPort](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-createiocompletionport) and [GetQueuedCompletionStatus](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getqueuedcompletionstatus) — Windows I/O completion ports.
