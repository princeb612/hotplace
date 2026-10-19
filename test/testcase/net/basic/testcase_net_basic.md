## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Network Basic Testcases

## 1. Role

Documents source-level checks for the basic network layer, particularly IP address and CIDR-based ACL matching.

## 2. Test model

`testcase_acl.cpp` defines `testcase_acl()` and helper `test_acl(...)`. The helper records each ACL evaluation result against an expected boolean; the IPv6 branch explicitly reports either supported or not supported.

## 3. Example: ACL decision against expected result

The helper calls `_test_case.test(ret, ...)` with the ACL evaluation result and expected decision. This records an explicit expected outcome, while the IPv6-specific path includes a platform-support branch.

## 4. Test and verification status

### 4.1 Source-level coverage

The source checks multiple ACL inputs through a shared helper and records expected decisions. IPv6 support is conditional; an explicit not-supported result must not be described as successful IPv6 matching coverage.

### 4.2 Documentation and verification status

The supplied `net/report` records 268 pass and 1 expt, with no fail/skip/triv entries. The report does not identify OS/compiler configuration or source revision, and this documentation pass did not execute tests; therefore it cannot prove these sources ran against Revision 1104.

## 5. Relationships

- Implementation notes: `sdk/net/basic/ipaddr_acl.md`
- Test registration and shared helpers: `test/testcase/net/sample.hpp` and the parent testcase CMake configuration.

## 6. References

- `test/testcase/net/basic/testcase_acl.cpp`
