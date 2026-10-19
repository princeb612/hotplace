## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# System I/O Testcases

## 1. Role

Documents the available system-I/O testcase sources under `test/testcase/io/system`.

## 2. Test model

`testcase_mlfq.cpp` covers the multi-level feedback queue implementation. `testcase_netlink.cpp` covers Linux netlink-related functionality; its applicability depends on platform and build guards in the source.

## 3. Example: system I/O testcase entry points

Use `test_mlfq()` and `test_netlink()` as the source entry points; inspect their assertions and platform guards before interpreting a report as broad cross-platform evidence.

## 4. Test and verification status

### 4.1 Source-level coverage

The presence of these test sources does not imply that netlink cases execute on Windows or that all MLFQ invariants are asserted. The exact runtime environment is not identified by the report archive.

### 4.2 Documentation and verification status

The source assertions described here are source-level evidence, not a new runtime run. The supplied report archive does not record the exact OS/compiler configuration or source revision; it therefore cannot establish that these cases ran against Revision 1104.

## 5. Relationships

- Implementation: `sdk/io/`
- Test registration: the adjacent `CMakeLists.txt` and shared testcase harness.

## 6. References

- `test/testcase/io/system/testcase_mlfq.cpp`
- `test/testcase/io/system/testcase_netlink.cpp`
