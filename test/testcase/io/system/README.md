## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — testcase behavior and verification          │
└──────────────────────────────────────────────┘
```

# System Testcases

## 1. Role

This directory contains system-oriented testcase sources for the multilevel feedback queue (`mlfq`) utility and Linux process-event notifications through netlink. These cases have different runtime characteristics: the queue case creates producer/consumer threads, while the netlink case is an interactive, platform-gated event monitor.

## 2. Test model

- `testcase_mlfq.cpp` — runs a producer and consumer against `t_mlfq`, records posted priorities, and prints a summary grouped by priority.
- `testcase_netlink.cpp` — on Linux builds satisfying its glibc preprocessor guard, subscribes to process events and waits for SIGINT before closing the netlink handle.
- `CMakeLists.txt` in the parent `test/testcase/io/` gathers `system/*.cpp` into the I/O testcase target; this directory's files are not necessarily separate CTest targets.

## 3. Example: producer/consumer queue exercise

`test_mlfq()` starts a scenario thread. The scenario creates one producer thread and one consumer thread, then waits for a completion semaphore. The producer posts 100 integer payloads at randomized priorities from 0 to 9; the consumer repeatedly calls `get`, logs and deletes retrieved values, and signals completion after 100 successful dequeues. The helper `confirm()` prints the producer-side observations grouped by priority.

This is a concurrent exercise of queue posting/retrieval and thread signaling, but the source does not assert a deterministic priority order or compare every consumed item against the producer map. The randomized scheduling and sleep intervals make it a stress/demo path rather than a deterministic scheduling conformance test.

## 4. Test and verification status

### 4.1 Source-level coverage

The MLFQ path exercises producer/consumer interaction and termination signaling, but does not assert fairness, strict ordering, or complete payload equality. The netlink path reports process fork/exec/UID/GID/exit events and queries process path/command line on selected events; it is Linux/glibc gated and waits indefinitely until interrupted. It is not suitable to assume as an unattended short-running test unless the harness or caller provides the expected signal.

### 4.2 Documentation and verification status

The latest available parent-group report is linked from [Test Report Snapshot](../../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest (conversation-supplied run context)**, with 596 pass, 0 expt, 0 fail, 0 skip and 0 triv for the entire `io` group. The report has no separate `io/system` row. In particular, this aggregate result must not be read as proof that the Linux-only netlink path ran on MinGW64. The report does not independently identify the tested source commit or exact build configuration. This documentation update did not rerun the tests.

## 5. Relationships

- `sdk/io/system/` — implementation-side OS facilities, including netlink.
- `sdk/base/` — synchronization, semaphore, thread and queue support used by the test.
- [I/O testcase group](../README.md) — target registration and aggregate report context.
- [Test Report Snapshot](../../test-report-status.md) — last known aggregate result and provenance limitations.

## 6. References

- `testcase_mlfq.cpp`
- `testcase_netlink.cpp`
- `../CMakeLists.txt`

## 7. Developer Notes

Keep the MLFQ queue exercise and netlink event monitor separate in report interpretation. The latter is OS/libc-gated and signal-terminated; an aggregate test report from a different platform cannot establish that it executed.
