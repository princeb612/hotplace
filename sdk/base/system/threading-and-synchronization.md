## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Threading and synchronization

## 1. Role

### Introduction

`sdk/base/system` provides a small cross-platform abstraction over the thread and synchronization primitives used by hotplace.

## 2. Data Model

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

## 3. Behavior Model

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

The higher-level `signalwait_threads` behavior is the main project-specific part; the platform classes are primarily compatibility layers.

## 4. Relationships

- `sdk/base/system/atomic.hpp` — compiler-specific increment/decrement primitives used by reference-counting code.
- `sdk/base/system/shared_instance.hpp` — project-specific shared ownership and reference-count lifetime.
- `sdk/base/system/signalwait_threads.hpp/.cpp` — worker-group orchestration built on threads and semaphores.
- `sdk/base/system/linux/` and `sdk/base/system/windows/` — platform implementations selected by the public headers.
- `test/testcase/base/system/testcase_signalwait_threads.cpp` — source-level test for four-worker coordination, capacity failure, signaling, waiting, and termination.

## 5. References

No external references are listed.
