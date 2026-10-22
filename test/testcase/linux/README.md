## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
— Linux-specific test behavior & evidence
```

# Linux-specific testcases

## 1. What

This directory contains the Linux-specific `test-linux` executable. Its current source exercises the `debug_trace()` diagnostic path; it is a narrow platform testcase, not a general suite for Linux system APIs.

## 2. How

### 2.1 Build and entry point

- `CMakeLists.txt` defines the `linux` module and passes it to the shared `maketest(...)` helper.
- `test/testcase/CMakeLists.txt` adds this directory only when `UNIX` is true.
- `sample.cpp` configures the testcase/logger harness, parses optional verbosity, logging, and debug flags, calls `test_trace()`, reports the accumulated testcase result, and returns that result from `main`.

### 2.2 Generate a trace

1. `test_trace()` creates an `ansi_string` to receive the trace text.
2. It calls `debug_trace(&stream)`.
3. The resulting text is written to the logger.
4. The return code from `debug_trace()` is passed to `_test_case.test(...)`.

## 3. Evidence

### 3.1 Source-level coverage

- **O** — the return code from `debug_trace()` is checked.
- **O** — generated trace text is emitted for inspection.
- **△** — the test does not compare the trace against expected frames or assert its exact contents.
- **—** — no Linux runtime report is asserted by this documentation update.

### 3.2 Runtime verification

A passing `test-linux` run demonstrates successful completion of the trace call in that build environment. It does not establish comprehensive coverage of epoll, netlink, multiplexer behavior, or all OS integration APIs. Associate runtime claims with the report for the matching source revision and Linux/compiler configuration; no test was rerun for this documentation change.

## 4. Relationships

- `sdk/io/system/` — OS-facing utilities, including multiplexer and netlink support.
- `test/testcase/io/system/` — tests for I/O-system-specific facilities.
- `test/testcase/CMakeLists.txt` — platform-gated testcase registration.
- `test/README.md` — environment-specific verification matrix.

## 5. References

- `sample.cpp`
- `CMakeLists.txt`
- [Test area overview](../../README.md)
