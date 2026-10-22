## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
— source structure, testcase procedure & evidence
```

# System testcases

## 1. What

This directory contains two opt-in system exercises with distinct behavior: a multilevel feedback queue (MLFQ) producer/consumer scenario and a Linux process-event monitor based on netlink. Neither should be interpreted as an ordinary deterministic, always-on unit test.

## 2. How

### 2.1 Dispatch and platform guards

1. `sample.cpp` calls `testcase_mlfq()` only when `-mlfq` is supplied and calls `testcase_netlink()` only when `-netlink` is supplied. The source is collected into the shared `io` executable, not automatically into independent CTest targets. The netlink implementation is compiled under Linux/glibc preprocessor guards; on non-Linux builds, the testcase records `not_supported`.

### 2.2 producer/consumer queue exercise

1. **Setup.** `test_mlfq()` creates a scenario thread and waits for it to finish. The scenario constructs a `test_scenario`, creates one producer worker and one consumer worker through `signalwait_threads`, and blocks on a completion semaphore.

2. **Producer.** The producer loops up to 100 times. Unless its stop signal arrives, it chooses a priority in the range 0–9 using `rand()`, allocates an integer containing the loop index, posts it to `t_mlfq`, logs the priority/value pair, stores the pair in a global multimap, and waits briefly before the next iteration.

3. **Consumer.** The consumer repeatedly checks its stop signal, calls `get()` on the queue, logs and deletes each retrieved integer, increments a shared consumed count, and signals completion when the count reaches 100. It also waits between iterations to vary producer/consumer timing.

4. **Shutdown and output.** After completion, the scenario signals both worker threads and waits for them. `confirm()` prints the producer-side multimap grouped by priority.

5. **What this verifies:** it exercises queue post/get operations, allocated payload ownership in the normal consumption path, worker coordination, and completion signaling under randomized timing.

6. **What it does not verify:** there is no deterministic expected priority order, no equality check between each consumed value and the producer-side multimap, and no assertion for fairness/starvation or queue ordering guarantees. The helper's final `_test_case.test(ret, ...)` checks the scenario's return status, which is initialized to success; it is not a comprehensive queue-content assertion. The scenario can also wait indefinitely if the completion signal is never delivered, so it is unsuitable as an unattended short test without a timeout strategy.

### 2.3 Linux process-event monitor

1. **Entry and lifecycle.** `test_netlink()` opens a netlink process-event handle with `netlink_handler`, installs a SIGINT handler that signals a semaphore, blocks indefinitely on that semaphore, and closes the handle after interruption. The call is intentionally interactive: a caller must send SIGINT to finish it.

2. **Event observations.** The callback prints the initial multicast-listening event and process fork, exec, UID change, GID change, and exit events. For exec events it queries `/proc/<pid>/exe` for the executable path and `/proc/<pid>/cmdline` for the command line. The source also has a directory-query helper using the executable symlink. These observations are printed to stdout; they are not compared with a predetermined sequence of process events.

3. **What this verifies:** when built and run in a suitable Linux/glibc environment with the required privileges/support, it provides a manual exercise of subscription, callback dispatch, and selected `/proc` lookups.

4. **What it does not verify:** no deterministic event oracle, event-count assertion, or timeout is present. Event delivery depends on the host's processes and environment. The `query()` helper's command-line read path does not turn the displayed command line into an asserted expected value. A successful aggregate `io` report on MinGW64 cannot establish execution of this Linux-only branch.

## 3. Evidence

### Source-level coverage

**1. MLFQ producer/consumer (opt-in: `-mlfq`)**

```text
option -mlfq -> start producer/consumer workers
  -> enqueue / dequeue payloads
  -> coordinate stop/completion with signals
  -> check selected scenario status
  -> print priority summary
  -> no expected schedule or complete consumed-value comparison
```

**2. Netlink process monitor (opt-in: `-netlink`)**

```text
Linux/glibc guard + option -netlink
  -> open process-event monitor
  -> wait for SIGINT
  -> print observed fork/exec/identity/exit events
  -> no deterministic expected event-sequence comparison
```

The aggregate I/O report has no separate result for either optional function and cannot prove either option was supplied. To claim runtime evidence for netlink, retain the OS/kernel/libc, invocation, interruption method and output; for MLFQ, record the option and test log.



The shared [Test Report Snapshot](../../test-report-status.md) is an aggregate `io` report and does not give a separate result for either optional function. Its associated run context is Revision 1104 · MinGW64/GCC · CTest; that context cannot establish that the Linux-only netlink code executed. The report files do not independently identify the tested commit or full build configuration.

For evidence of a netlink run, retain a separate run record with Linux distribution/kernel, libc, invocation including `-netlink`, the interruption/termination method, and the observed output. For MLFQ, record whether `-mlfq` was supplied and retain the test log. This documentation update did not run either option.



## 4. Relationships

- `sdk/io/system/` — OS-specific implementation facilities.
- `sdk/base/` — thread, semaphore, and queue support used by MLFQ.
- [I/O testcase suite](../README.md) — option parsing and default dispatch.
- [`sample.cpp`](../sample.cpp) — `-mlfq` and `-netlink` switches.
- [`testcase_mlfq.cpp`](testcase_mlfq.cpp) — producer/consumer scenario.
- [`testcase_netlink.cpp`](testcase_netlink.cpp) — Linux process-event monitor.
- [Test Report Snapshot](../../test-report-status.md) — shared aggregate report and provenance limits.

## 5. References

No external reference is needed to describe the current testcase source behavior.

## 6. Developer Notes

Keep the MLFQ and netlink outcomes separate in any future evidence package. The first is a randomized producer/consumer exercise; the second is a signal-terminated, OS-gated event monitor. Neither's printed output should be described as a complete expected-result comparison.
