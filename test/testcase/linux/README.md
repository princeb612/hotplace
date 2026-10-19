# Linux-specific test cases

This directory contains Linux-specific diagnostics and their shared test harness.

## Current coverage

- [`sample.cpp`](sample.cpp) defines `test_trace()`, which calls `debug_trace()` and emits the resulting trace text.
- `CMakeLists.txt` defines how the sample is built.

This is a small platform-specific diagnostic test, not a general Linux system-test suite. Other Linux integrations, such as epoll and Netlink, are documented with their implementation modules under `sdk/io/system`.
