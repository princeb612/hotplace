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

# Process execution

## 1. Role

`process.hpp` defines a cross-platform child-process interface. Callers describe an executable, arguments, working directory, and optional standard-I/O redirection through `execparam`; the platform implementation performs process creation and lifecycle management.

## 2. Data Model

- `execparam` stores `executable`, an ordered vector of argument strings, `workdir`, and the `io_redirection` switch.
- `process_t` defines `spawn()`, `wait()`, `terminate()`, `isrunning()`, and `get_redirection()`.
- The Linux implementation tracks a PID, exit code, running state, and optional redirection object.
- The Windows implementation tracks `PROCESS_INFORMATION`, a process handle, and optional redirection object.

The public interface is shared, but the operating-system process handles and launch mechanics remain platform-specific.

## 3. Behavior Model

`execparam::add()` appends a string or formats an integer argument as decimal text. `clear()` clears the executable, argument list, and working directory, but does not reset `io_redirection`.

**`spawn(param)`**

Creates the child process from the supplied executable/arguments and working-directory configuration. If I/O redirection is enabled, the platform implementation prepares pipe/handle state and exposes it through `get_redirection()`.

**`wait()`**

Waits for process completion and returns the platform implementation's exit result. Callers should check the concrete implementation's behavior before interpreting negative or exceptional values as an application exit code.

**`terminate()`**

Requests termination of the child process using the platform API. It is separate from `wait()`; callers should not assume termination also performs all output draining or redirection cleanup.

**`isrunning()`**

Reports the implementation's current running-state view. Its result is tied to process lifecycle observations and can change asynchronously as the child exits.

**`get_redirection()`**

Returns the associated redirection interface when the launch path created one. The interface allows the parent to write to child stdin and read child stdout; the caller must respect the object's lifetime and close semantics.

### Child-process lifecycle

```text
configure executable / arguments / working directory
  └─ spawn(param)
       ├─ platform process creation
       └─ if requested: initialize redirection and expose interface

parent process
  ├─ write_stdin() / read_stdout() through redirection
  ├─ isrunning() ─► observe current lifecycle state
  ├─ wait() ──────► wait for completion and obtain exit result
  └─ terminate() ─► request termination (separate from wait/cleanup)
```

Process termination, output draining, and redirection cleanup are distinct concerns. The caller should follow the platform implementation's close/wait contract and should not assume `terminate()` by itself drains pending output or releases every associated resource.

## 5. Relationships

- [Standard-I/O redirection](redirection.md) — parent-side pipe/handle operations.
- `sdk/base/system/linux/process.hpp` — Linux implementation based on POSIX process creation.
- `sdk/base/system/windows/process.hpp` — Windows process and handle implementation.
- `sdk/base/system/dir.hpp` — independent filesystem helper; process working-directory configuration is not directory creation.
- Higher-level code should treat executable argument construction and child-process policy as application responsibilities.

## 6. References

No external references are listed.
