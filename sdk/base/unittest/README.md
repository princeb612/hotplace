# Unit Test Support

`unittest` provides the common test execution and logging infrastructure used by hotplace test programs.

The directory has two main responsibilities:

```text
unittest
├── testcase
│   └── test execution, assertions, result and timing
└── logger
    └── console/file logging, log levels and buffered output
```

## Components

### Test case

[`testcase.md`](testcase.md)

`test_case` groups individual checks, records their results, measures test time, produces reports, and returns the final process result.

It also supports expected failures, skipped/not-supported results, low-security cases, and temporarily excluding a code block from timing through `test_case_notimecheck`.

### Logger

[`logger.md`](logger.md)

`logger` provides the common output path used by tests and other hotplace components. It supports console and file output, log levels, formatted and stream-based messages, binary dumps, colors, flushing, and a consumer thread.

`logger_builder` is used to configure and construct the logger, including output destination, flush behavior, rotation settings, and time formatting.

## Relationship

The two components are deliberately connected:

```text
 test_case
     │
     └── logger
          ├── console / file
          ├── log level
          ├── dump / formatting
          └── flush / consumer
```

A test program can therefore use `test_case` for pass/fail semantics and `logger` for human-readable diagnostic output without implementing either mechanism itself.

## Tests

The direct tests are under:

`test/testcase/base/unittest/`

Important examples include:

- `testcase_unittest.cpp` — basic test-case flow, failure/trace paths, timing exclusion, and error reporting.
- `testcase_loglevel.cpp` — explicit and implicit log-level filtering.
- `testcase_consolecolor.cpp` — console color handling.

The tests are useful as executable examples of the intended test and logging interfaces.

## Related source

```text
sdk/base/unittest/
├── testcase.hpp / testcase.cpp
├── logger.hpp / logger.cpp
├── logger_builder.cpp
├── logger_write.cpp
├── logger_dump.cpp
├── console_color.hpp
└── types.hpp
```

The historical logger sketches in this directory are retained as design/history material; they are not treated as the current implementation specification.
