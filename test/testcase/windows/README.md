## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1106
Source basis: Revision 1105
Documented with GPT-6
— Windows-specific test behavior & evidence
```

# Windows-specific testcases

## 1. What

This directory contains the Windows-only `test-windows` testcase executable. It checks two narrow platform paths: process-module enumeration and debug-trace capture. These are platform integration checks, not portable SDK contracts or a comprehensive Windows API suite.

## 2. How

### 2.1 Build and entry point

- `CMakeLists.txt` defines the `windows` module and passes it to the shared `maketest(...)` helper.
- `test/testcase/CMakeLists.txt` adds this directory only when `WIN32` is true.
- `sample.cpp` configures the shared testcase/logger harness, parses optional logging and debug flags, calls both test functions, reports the accumulated testcase result, and returns that result from `main`.

### 2.2 Enumerate process modules

1. `test_enum_modules()` calls `enum_modules(GetCurrentProcess(), enum_modules_handler, nullptr)`.
2. For the `enum_toolhelp` callback type, `enum_modules_handler()` reads the `MODULEENTRY32` entry and logs `szExePath`.
3. The `enum_psapi` callback branch is currently only a commented outline; it does not assert module metadata.
4. The testcase records the return code from `enum_modules()`.

### 2.3 Capture a debug trace

1. `test_trace()` creates a `debug_trace` object and opens a trace context.
2. It captures a Windows `CONTEXT` structure with `dbg.capture(&rtlcontext)`.
3. It calls `dbg.trace(handle, &rtlcontext, &stream)`, then closes the context.
4. The trace text is logged and the return code from `trace()` is passed to the testcase assertion.

## 3. Evidence

### 3.1 Source-level coverage

- **O** — the return codes from module enumeration and trace generation are checked through `_test_case.test(...)`.
- **O** — Tool Help module paths and trace text are emitted for inspection.
- **△** — the test does not assert an expected module list, exact trace contents, or a particular stack frame.
- **△** — the PSAPI callback path is not implemented beyond commented placeholders.
- **—** — no Windows runtime report is asserted by this documentation update.

### 3.2 Runtime verification

A passing `test-windows` run demonstrates that these test functions completed with successful return codes in that environment. It does not establish coverage of Windows registry, sockets, ODBC, or every Windows-specific SDK path. Associate runtime claims with the relevant Windows/compiler report; no test was rerun for this documentation change.

## 4. Relationships

- `sdk/io/system/` — operating-system-facing facilities.
- `sdk/io/system/windows_registry.md` — Windows registry wrapper.
- `test/testcase/CMakeLists.txt` — platform-gated testcase registration.
- `test/README.md` — environment-specific verification matrix.

## 5. References

- `sample.cpp`
- `CMakeLists.txt`
