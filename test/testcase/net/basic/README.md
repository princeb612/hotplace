## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
```

# Network Basic Testcases

## 1. What

`test/testcase/net/basic/` tests the network address access-control helper `ipaddr_acl`. The main source, `testcase_acl.cpp`, covers rule insertion, whitelist/blacklist decisions, IPv4 address conversion, CIDR masks, and conditional IPv6 handling. It does not open sockets or test operating-system firewall enforcement.

The directory has no YAML vector schema. The cases construct their rules and expected outcomes directly in C++.

## 2. How

### 2.1 ACL rule setup and decision checks

1. `test1()` creates an `ipaddr_acl` instance.
2. Add exact positive rules for `127.0.0.1` and `10.20.15.25`, a negative `10.20.13.0/24` prefix rule, and an exact positive rule for `10.20.1.125`.
3. Add a negative inclusive address range from `10.20.1.25` through `10.20.2.10`. This range overlaps the exact positive rule for `10.20.1.125`; the test expects that address to be denied.
4. Add an IPv6 loopback prefix and, when `SUPPORT_IPV6` is enabled, the optional `3ffe:ffff:0:f101::/64` rule.
5. Select whitelist mode and call `do_determine()` for the representative addresses. The helper calls `acl->determine(ip, check)`, compares the resulting boolean with the expected value, maps a mismatch to `internal_error`, and records the status through `_test_case.test`.
6. Switch to blacklist mode and repeat the selected decision checks. The assertions cover the listed cases, not every possible rule overlap or address.

### 2.2 IPv4 CIDR mask exploration

1. `test2()` converts `12.34.56.78` to the internal IPv4 integer representation.
2. Iterate prefix lengths from 0 through 32.
3. For each prefix, calculate and print the mask, masked address, and complementary range boundary.
4. Treat these rows as diagnostic output: the loop does not compare every printed mask against a fixed expected-value table.

### 2.3 IPv6 conversion and mask exploration

1. If `SUPPORT_IPV6` is enabled, `test3()` converts `3ffe:ffff:0:f101::1`.
2. Iterate prefix lengths from 0 through 128 and print the mask calculations.
3. The enabled path ends with `assert(true, "IPv6 supported")`; this marks that the support path ran and does not validate each printed mask.
4. If IPv6 support is disabled, the test records `not_supported` rather than exercising IPv6 conversion.

## 3. Evidence

### 3.1 Source-level coverage

#### ACL decision checks

```text
C++ rule setup
  -> set whitelist mode
  -> do_determine(address, expected)
  -> ipaddr_acl::determine(address, actual)
  -> compare actual boolean with expected
  -> mismatch becomes internal_error
  -> test_case records result
  -> repeat selected addresses in blacklist mode
```

**Assertion strength:** the selected ACL decisions are compared with explicit expected booleans. The test does not exhaustively cover all rule overlaps, every prefix length, or OS-level filtering.

#### IPv4/IPv6 conversion diagnostics

```text
address string
  -> convert_addr
  -> integer address
  -> iterate CIDR prefix lengths
  -> print mask / address & mask / range boundary
  -> no per-prefix expected-value comparison
```

**Assertion strength:** these loops expose conversion and mask results for inspection, but their printed output is not a per-row conformance assertion. The IPv6 path is compile-time conditional; the unsupported branch records `not_supported`.

### 3.2 Documentation and verification status

The latest available aggregate report for the parent `net` testcase group is linked from [Test Report Snapshot](../../test-report-status.md): **Revision 1104 · MinGW64/GCC · CTest**, with 268 pass, 1 expt, 0 fail, 0 skip and 0 triv for the whole group. It does not provide a separate `net/basic` count or independently identify the tested source commit. These totals must not be attributed to this directory alone.

This documentation update did not execute tests.

## 4. Relationships

- [Network SDK](../../../../sdk/net/README.md) — network primitives.
- [IP address ACL implementation](../../../../sdk/net/basic/README.md) — implementation counterpart.
- [Parent network testcases](../README.md) — shared dispatch and aggregate report context.

## 5. References

- `testcase_acl.cpp` — ACL setup, decision helper, IPv4/IPv6 conversion and mask output.
- `../sample.cpp` — parent test registration and runtime setup.
- [Test Report Snapshot](../../test-report-status.md) — report scope and provenance.
