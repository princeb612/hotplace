## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Threading and synchronization

## 1. Role

### Introduction

`sdk/base/system` provides a small cross-platform abstraction over the thread and synchronization primitives used by hotplace.

## 2. Model

### Platform abstraction

The public interfaces select Linux or Windows implementations at compile time:

```text
thread_t
   ├─ Linux pthread implementation
   └─ Windows thread implementation

semaphore_t
   ├─ Linux implementation
   └─ Windows implementation

critical_section_t
   ├─ Linux implementation
   └─ Windows implementation
```

`thread_t` exposes `start()`, `join()`, `wait()` and `gettid()`.

`semaphore_t` exposes `signal()` and timed/untimed `wait()`.

`critical_section_t` exposes `enter()` and `leave()`, with `critical_section_guard` providing scoped release on destruction.

### Atomic operations

`atomic.hpp` supplies the small atomic increment/decrement operations required by the reference-counting classes. The implementation selects GCC built-ins or Windows `Interlocked*` operations rather than requiring a newer C++ standard library.

This is deliberately narrow: it is a compatibility utility for the project's C++11/older-platform target, not a general atomic programming framework.

## 3. Important behavior and lifetime

### Signal-and-wait thread group

`signalwait_threads` builds a higher-level pattern on top of the thread/semaphore abstractions.

```text
create() × N
     |
     v
 worker threads wait for signal
     |
     +---- signal callback
     |
     v
 join / signal_and_wait_all()
```

The object tracks a maximum concurrent-thread capacity, running threads, callbacks and thread IDs. `signal_and_wait_all()` is used to release waiting workers and wait until the group has terminated.

The corresponding test creates four workers, verifies the maximum-concurrency failure path, waits, and then terminates all workers.

### Tests

- `test/testcase/base/system/testcase_signalwait_threads.cpp`
- platform-specific thread/semaphore/critical-section implementations under `sdk/base/system/linux` and `sdk/base/system/windows`

The higher-level `signalwait_threads` behavior is the main project-specific part; the platform classes are primarily compatibility layers.

## 4. Example from the source tests

See the source-test references below; do not infer runtime execution from source presence alone.

## 5. Relationships

Related components and cross-module links are listed in References where available.

## 6. References

Implementation and test paths are retained in the sections above or the source tree.
