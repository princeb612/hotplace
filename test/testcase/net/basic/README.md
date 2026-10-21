## Publication

```text
hotplace source tree
Edition 2 · Revision 1105
Source basis: working source tree aligned to Revision 1105
Documented with GPT-6
Documentation scope: network testcase behavior and verification
```

# Network basic testcases

## 1. Role

This directory contains focused tests for foundational network helpers. The current source inventory includes `testcase_acl.cpp`, which checks IP address access-control decisions and address formatting/conversion. It is not a live socket integration suite.

## 2. Test model

The source builds an `ipaddr_acl`, adds individual addresses, CIDR-prefix rules and an inclusive address range, then evaluates the same addresses under whitelist and blacklist modes. IPv6 cases are guarded by `SUPPORT_IPV6`, so their execution depends on the build configuration.

### Coverage visible in source

- Exact IPv4 addresses such as `127.0.0.1` and `10.20.15.25`.
- A negative CIDR rule for `10.20.13.0/24`.
- IPv6 loopback and a `/64` prefix when IPv6 support is enabled.
- A true exact-address rule overlapping a false range rule, documenting that the range denial wins in the tested case.
- Whitelist and blacklist mode decisions.

## 3. Example: ACL decision

`test1()` creates rules, selects whitelist mode, and calls `do_determine` for both allowed and denied addresses. The helper calls `acl->determine(ip, check)`, compares the result with the expected boolean, and reports a testcase failure if they differ. The same rule set is then checked in blacklist mode. This verifies the rule-evaluation API and the selected examples; it does not test firewall enforcement at the operating-system level.

## 4. Test and verification status

### 4.1 Source-level coverage

The source covers rule insertion and decision outcomes for the listed addresses and modes. IPv6-specific assertions are conditional on `SUPPORT_IPV6`. Read `testcase_acl.cpp` for the additional address parsing/formatting checks and exact assertions.

### 4.2 Documentation and verification status

The latest available aggregate report for the parent `net` testcase group is recorded in [Test Report Snapshot](../../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest (conversation-supplied context)**, with 268 pass, 1 expt, 0 fail, 0 skip and 0 triv for the whole `net` group. The report does not provide a separate result count for `net/basic`, and its payload does not independently identify the tested source commit. Do not attribute the full parent-group count to this directory alone.

This documentation update did not execute the test. Preserve the last known report until a newer, revision-associated report is supplied.

## 5. Relationships

- [Network SDK](../../../../sdk/net/README.md) — implementation area containing network primitives.
- [IP address ACL implementation](../../../../sdk/net/basic/README.md) — address-policy component.
- [Parent network testcase report](../README.md) — aggregate `net` group result.

## 6. References

- `testcase_acl.cpp` — ACL rule setup, whitelist/blacklist assertions, and address helper cases.
- `test/testcase/net/sample.cpp` — parent testcase registration and harness.
- [Test Report Snapshot](../../test-report-status.md) — latest available aggregate runtime result and provenance limits.

## 7. Developer Notes

Keep source-level coverage and runtime report scope separate: the parent `net` row is not a per-directory report. When future reports expose finer-grained groups, update this section with that row rather than copying the aggregate count.
