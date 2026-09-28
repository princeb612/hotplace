# Logger

`logger` is hotplace's common output facility for test and diagnostic messages.

It provides a single interface for console output, file output, formatted messages, stream-based messages, binary dumps, log-level filtering, colors, and buffered/asynchronous flushing.

## Construction

`logger_builder` configures the logger before construction.

The available configuration includes:

- stdout enable/disable
- file output
- consumer interval
- flush time
- flush size
- log rotation size
- maximum retained log files
- time format
- logfile name
- optional attachment to `test_case`

The default builder configuration enables stdout and uses a consumer interval of 100 ms, while file output and explicit flush thresholds are disabled until configured.

```text
logger_builder
      │
      ├── configuration
      │
      └── build()
            │
            ▼
          logger
            │
            └── consumer thread
```

## Output interfaces

The logger exposes several equivalent output forms:

```text
consoleln()
write()
writeln()
colorln()
dump()
hdump()
```

Messages can be supplied as:

- printf-style format strings
- `std::string`
- `basic_stream`
- `stream_t*`
- a callback that writes to `basic_stream`

This keeps callers independent of the final output destination.

`consoleln()` writes to the console path, while `write()` and `writeln()` use the configured general output path. `colorln()` adds explicit console color handling.

## Log levels

The logger maintains two levels:

- the configured log level
- the implicit level used when a message does not explicitly provide a level

A message is emitted when its effective level satisfies the configured threshold.

```text
message level >= configured log level
        │
        ├── true  → log
        └── false → suppress
```

The distinction between explicit and implicit levels allows callers to set a default verbosity while still selecting a level for individual messages.

`testcase_loglevel.cpp` systematically exercises the level combinations and records the expected filtering behavior.

## Buffered output and consumer

The logger maintains per-thread logger streams and uses a consumer thread for output processing.

```text
caller thread
     │
     ▼
 logger item / stream
     │
     ▼
 consumer thread
     │
     ├── stdout
     └── file
```

`flush()` can force pending output to be processed. Time-, size-, and interval-related settings control when buffered data is flushed during normal operation.

The implementation uses synchronization around the shared logger state and retains per-thread output context.

## File output and rotation

File logging can be enabled through `logger_builder::set_logfile()`.

The builder also exposes configuration for:

- flush time
- flush size
- rotation size
- maximum number of log files

These settings allow the same logger abstraction to be used for short-lived test programs as well as longer-running diagnostic output.

## Binary dumps

`dump()` and `hdump()` connect the logger with hotplace's binary-debugging facilities.

They accept raw memory as well as common hotplace types such as:

- `binary_t`
- `std::string`
- `basic_stream`

The optional header in `hdump()` is useful for identifying a packet, buffer, certificate, or cryptographic value in a larger diagnostic log.

This is complementary to `dump_memory`: the latter is the reusable formatting primitive, while `logger` provides the logging/output path.

## Console colors

`console_color.hpp` provides the console styling used by the logger.

`setcolor()` changes the current style, foreground color, and background color, while `colorln()` emits explicitly colored output.

The test suite contains a separate console-color testcase because color handling is a distinct terminal concern from ordinary logging.

## Test-case integration

A logger can attach to a `test_case` instance.

```text
 test_case ──────► logger
     │               │
     │               ├── diagnostic output
     │               ├── report output
     │               └── log filtering
     │
     └── pass/fail semantics
```

This separation is useful in hotplace tests: `test_case` decides whether a test passed, failed, or was intentionally skipped, while `logger` controls how diagnostic information is presented.

## Historical note

`logger.hpp` retains a history reaching back to the 2008 implementation. The current implementation was rebooted in the hotplace line in 2024.

The two `sketch_logger_2008_*.jpg` files in this directory are retained as historical design material. They document earlier ideas such as schedulable stream handling and conditional flush; they should not be read as a current implementation diagram.

## Tests

The main logging tests are:

- `test/testcase/base/unittest/testcase_loglevel.cpp`
- `test/testcase/base/unittest/testcase_consolecolor.cpp`
- `test/testcase/base/unittest/testcase_unittest.cpp`

Together they demonstrate log-level filtering, console color support, formatted output, and logger/test-case integration.

## Related source

- `sdk/base/unittest/logger.hpp`
- `sdk/base/unittest/logger.cpp`
- `sdk/base/unittest/logger_builder.cpp`
- `sdk/base/unittest/logger_write.cpp`
- `sdk/base/unittest/logger_dump.cpp`
- `sdk/base/unittest/console_color.hpp`
