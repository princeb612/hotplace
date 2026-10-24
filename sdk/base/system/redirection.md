## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Process standard-I/O redirection

## 1. Role

`redirection.hpp` defines the parent-side interface for communicating with a child process through redirected standard input and standard output. Platform-specific subclasses implement the underlying pipes or handles.

## 2. Data Model

`redirection_t` exposes three operations:

- `read_stdout(buffer, size)` — read child output into a caller-owned buffer.
- `write_stdin(data, size)` — write bytes to the child's standard input.
- `close()` — release redirection resources.

The Linux implementation uses pipe file descriptors and participates in `posix_spawn` file actions. The Windows implementation uses four pipe handles to distinguish parent-side and child-side stdin/stdout endpoints.

## 3. Behavior Model

**Initialization and spawn coordination**

The platform `redirection` class has an `initialize()` method that prepares the pipes or handles before launch. `event_spawned()` finalizes the post-spawn side of the setup, such as closing or marking handles that should no longer be used by the parent/child side.

**Reading and writing**

The caller supplies the memory buffer for `read_stdout()` and the byte range for `write_stdin()`. The interface does not provide a text encoding, message framing, or line protocol; callers must interpret the returned bytes themselves.

**Closing**

`close()` owns the platform resource cleanup. Because the child and parent use different ends of each pipe, the concrete implementation must close the correct handles at the correct lifecycle stage. Callers should not use the redirection object after its owner/process has closed it.

### Pipe/handle lifecycle

```text
initialize() ─► prepare pipe/handle pairs before process creation
      │
      ▼
spawn child ─► event_spawned() ─► close or mark ends unused by each side
      │
      ├─ parent writes bytes ─► child stdin
      └─ parent reads bytes  ◄─ child stdout
      │
      ▼
close() ─► release remaining platform handles
```

The API transfers bytes only; it does not add line boundaries, character encoding, or message framing. The parent must interpret the byte count returned by reads and must not keep using the redirection object after its owning process/lifecycle has closed it.

## 4. Relationships

- [Process execution](process.md) — creates the child and exposes its redirection object.
- `sdk/base/system/linux/redirection.hpp` — POSIX pipe/file-action implementation.
- `sdk/base/system/windows/redirection.hpp` — Windows pipe-handle implementation.
- `sdk/base/stream/` — in-memory stream and buffer operations; it does not itself redirect a process's standard handles.

## 5. References

No external references are listed.
