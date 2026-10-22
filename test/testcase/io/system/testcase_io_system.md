## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Documented with GPT-6                        │
│ Source basis: Revision 1105                  │
│ — testcase behavior and verification          │
└──────────────────────────────────────────────┘
```
# System I/O Testcases

## 1. Role

Documents the available system-I/O testcase sources under `test/testcase/io/system`.

## 2. Test model

1. `testcase_mlfq.cpp` covers the multi-level feedback queue implementation. `testcase_netlink.cpp` covers Linux netlink-related functionality; its applicability depends on platform and build guards in the source.

## 3. Example: system I/O testcase entry points

1. `test_mlfq()` creates a scenario thread, then producer/consumer workers; the producer posts 100 integers at randomized priorities, and the consumer dequeues and deletes values until it signals completion. The source logs a priority-grouped summary but does not assert a deterministic priority order or every payload. `test_netlink()` subscribes to Linux process events and waits for SIGINT; it is guarded by Linux/glibc conditions and is not a short, unattended default testcase.

## 4. Test and verification status

### 4.1 Source-level coverage

The presence of these test sources does not imply that netlink cases execute on Windows or that all MLFQ invariants are asserted. The exact runtime environment is not identified by the report archive.

### 4.2 Documentation and verification status

The latest available parent-group report is linked from [Test Report Snapshot](../../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest (conversation-supplied run context)**, with 596 pass, 0 expt, 0 fail, 0 skip and 0 triv for the entire `io` group. There is no separate `io/system` row, and the MinGW64 report does not establish that the Linux-only netlink branch ran. The report does not independently identify the tested source commit or exact build configuration. This documentation update did not rerun tests.

## 5. Relationships

- Implementation: `sdk/io/`
- Test registration: the adjacent `CMakeLists.txt` and shared testcase harness.

## 6. References

- `test/testcase/io/system/testcase_mlfq.cpp`
- `test/testcase/io/system/testcase_netlink.cpp`
