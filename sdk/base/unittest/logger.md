## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Logger

## 1. Role

### Introduction

`logger` is hotplace's common output facility for test and diagnostic messages.

It provides a single interface for console output, file output, formatted messages, stream-based messages, binary dumps, log-level filtering, colors, and buffered/asynchronous flushing.

## 2. Data Model

### Construction

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

### Output interfaces

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

### Buffered output state

The logger maintains per-thread logger streams and uses a consumer thread for output processing. The implementation uses synchronization around the shared logger state and retains per-thread output context.

### File output and rotation

File logging can be enabled through `logger_builder::set_logfile()`.

The builder also exposes configuration for:

- flush time
- flush size
- rotation size
- maximum number of log files

These settings allow the same logger abstraction to be used for short-lived test programs as well as longer-running diagnostic output.

## 3. Behavior Model

### Buffered output lifecycle

`flush()` can force pending output to be processed. Time-, size-, and interval-related settings control when buffered data is flushed during normal operation.

```text
per-thread message context ─► buffered output ─► consumer / explicit flush
```

### Concrete setup example

The applet entry points repeat the same setup sequence after command-line parsing: configure a `logger_builder`, build a logger, and store it in a `t_shared_instance<logger>`. The following is a reduced example of the pattern used by `test/applet/tcpserver1/sample.cpp`; `option` represents the parsed applet options.

```cpp
// Global applet state:
// test_case _test_case;
// t_shared_instance<logger> _logger;

logger_builder builder;
builder.set(logger_t::logger_stdout, option.verbose);

if (option.log) {
    builder.set(logger_t::logger_flush_time, 1)
           .set(logger_t::logger_flush_size, 1024)
           .set_logfile("test.log")
           .attach(&_test_case);
}
if (option.time) {
    builder.set_timeformat("[Y-M-D h:m:s.f]");
}

_logger.make_share(builder.build());

// The same logger can receive ordinary messages and trace output.
_logger->writeln("application started");
// Optional: install a trace callback that forwards trace text to the logger.
if (option.debug) {
    auto lambda_tracedebug = [&](trace_category_t category, trace_event_t event, stream_t* s) {
        _logger->write(s);
    };
    set_trace_debug(lambda_tracedebug);
    set_trace_option(trace_bt | trace_except | trace_debug);
    set_trace_level(option.trace_level);
}

// After the applet's work is complete:
_logger->flush();
```

This sequence separates four responsibilities:

1. **Configure** output destinations and buffering policy with `logger_builder`.
2. **Construct and share** the logger with `make_share(builder.build())`, making it available to the applet's other routines through `_logger`.
3. **Connect optional producers** such as system trace callbacks to the logger; enabling the logger alone does not automatically enable trace capture.
4. **Flush at the lifecycle boundary** so buffered messages can be processed before the program exits.

File output and attachment to `test_case` are conditional in the applet example. The builder's default configuration can still provide console logging without those options. The exact logfile name and option names vary by applet; for example, `httpserver1` uses `server.log` rather than `test.log`.

### Practical usage patterns from test cases

The test cases use the logger in several complementary ways. These examples focus on message construction and handoff, rather than repeating the logger setup above.

#### 1. Write an already-built stream

When a component has already rendered its result into a `basic_stream`, pass that stream directly to the logger. The ASN.1 loader uses this pattern to display each generated module:

```cpp
auto modules = asn1_modules::get_instance();
for (const auto& name : result.module_names) {
    basic_stream bs;
    auto module = modules->get(name);
    module->represent(&bs);
    _logger->write(bs);
}
```

The component controls representation; the logger controls output routing. The caller does not need to copy the stream into a format string.

#### 2. Build one message from several typed values

A callback is useful when the output needs to be assembled from multiple values or formatting operations. The ASN.1 identifier test publishes notation and DER bytes, then logs both through a single callback:

```cpp
_logger->write([&](basic_stream& bs) -> void {
    valist va;
    va << bs_notation << bin_der;
    bs.vaprintln("notation {1:s}", va);
    bs.vaprintln("DER      {2:x}", va);  // base16 encoding
});
```

Here, `valist` holds the values used by the indexed formatter. The `{1:s}` and `{2:x}` specifiers choose how those values are rendered; the logger receives the completed message through the callback's `basic_stream`.

#### 3. Emit structured diagnostic fields directly

For diagnostics where each record has a known set of fields, a formatted logger call can be clearer than building a separate stream. The ASN.1 lexer reports token position, type, index, length, and source text this way:

```cpp
_logger->writeln("[%03zu] line %zi type %d(%s) index %d pos %zi len %zi (%.*s)",
                 cnt, desc->line, desc->type,
                 lexer.nameof_token(desc->type).c_str(),
                 desc->index, desc->pos, desc->size,
                 desc->size, desc->p);
```

The format string makes the diagnostic record's fields explicit. The length-limited `%.*s` prints the token's source slice using `desc->size`, rather than assuming it is null-terminated.

#### 4. Log binary results as both interpretation and bytes

For protocol and encoding tests, human-readable representation and raw bytes answer different questions. The DER test logs the notation/value and encoded bytes, then sends the encoded value to the logger's binary dump interface:

```cpp
_logger->write([&](basic_stream& bs) -> void {
    valist va;
    va << bs_type << bs_value << bin_encoded;
    bs.println("decode and encode");
    bs.vaprintln("> notation {1}", va);
    bs.vaprintln("> value    {2}", va);
    bs.vaprintln("> DER      {3:x}", va);
});
_logger->dump(bin_encoded);
```

Use the formatted message to explain what the bytes mean and `dump()` to inspect the byte-level result. These are complementary views of the same output, not substitutes for the test's assertions.

### Output routing

`consoleln()` writes to the console path, while `write()` and `writeln()` use the configured general output path. `colorln()` adds explicit console color handling.

### Log levels

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

### Binary dumps

`dump()` and `hdump()` connect the logger with hotplace's binary-debugging facilities.

They accept raw memory as well as common hotplace types such as:

- `binary_t`
- `std::string`
- `basic_stream`

The optional header in `hdump()` is useful for identifying a packet, buffer, certificate, or cryptographic value in a larger diagnostic log.

This is complementary to `dump_memory`: the latter is the reusable formatting primitive, while `logger` provides the logging/output path.

### Console colors

`console_color.hpp` provides the console styling used by the logger.

`setcolor()` changes the current style, foreground color, and background color, while `colorln()` emits explicitly colored output.

### Message-to-output lifecycle

```text
caller writes message
  └─ logger applies effective log level
       ├─ below threshold ─► suppress
       └─ accepted ─────────► format / optional dump
                                └─ enqueue or buffer output
                                     └─ consumer / flush
                                          ├─ console destination
                                          └─ file destination ─► rotation policy
```

Log-level filtering and output delivery are separate stages. A message that passes the threshold can still be waiting in a buffer until the consumer or an explicit flush processes it. File rotation and console color affect presentation/output handling, not test pass/fail accounting.

## 5. Relationships

- `test_case` can attach a logger for diagnostic output, but the test-case object owns the pass/fail/result accounting.
- [`test/testcase/asn.1/loader/testcase_loader.cpp`](../../../test/testcase/asn.1/loader/testcase_loader.cpp) — renders ASN.1 modules into `basic_stream` and passes the completed stream to `write()`.
- [`test/testcase/asn.1/testcase_basic1.cpp`](../../../test/testcase/asn.1/testcase_basic1.cpp) — builds one log message from ASN.1 notation and DER bytes using a callback and `valist`.
- [`test/testcase/asn.1/sample.cpp`](../../../test/testcase/asn.1/sample.cpp) — emits lexer token diagnostics with a formatted `writeln()` call.
- [`test/testcase/asn.1/testvector_der.cpp`](../../../test/testcase/asn.1/testvector_der.cpp) — logs decoded/encoded interpretations and dumps the resulting binary value.
- [`test/applet/tcpserver1/sample.cpp`](../../../test/applet/tcpserver1/sample.cpp) — representative logger builder setup, optional file output/time format, trace forwarding, and final flush. The same setup pattern recurs in other applet `sample.cpp` entry points, with applet-specific logfile names and optional producers.
- `test/testcase/base/unittest/testcase_loglevel.cpp`, `testcase_consolecolor.cpp`, and `testcase_unittest.cpp` — source-level coverage for log-level filtering, console colors, formatted output, and logger/test-case integration.
- `testcase_consolecolor.cpp` keeps terminal-color behavior distinct from ordinary logging.
- `basic_stream` and the project's formatting helpers provide message construction; logger routes and flushes the resulting output.
- `dump_memory` provides the common byte-to-hex/ASCII formatting primitive; logger dump APIs expose that capability through the configured output path.
- `console_color.hpp` handles terminal styling, which is independent of file output and log-level filtering.
- The consumer/buffering path means logger lifetime and shutdown/flush behavior matter when output must be complete before process exit. `logger.hpp/.cpp`, `logger_builder.cpp`, `logger_write.cpp`, and `logger_dump.cpp` implement the builder, write, and dump paths; `console_color.hpp` supplies terminal styling.

## 5. Development Notes (for maintainer review)

Pre-existing notes or development-oriented material retained for the maintainer to review and reorganize.


### Historical note

`logger.hpp` retains a history reaching back to the 2008 implementation. The current implementation was rebooted in the hotplace line in 2024.

The two `sketch_logger_2008_*.jpg` files in this directory are retained as historical design material. They document earlier ideas such as schedulable stream handling and conditional flush; they should not be read as a current implementation diagram.

## 6. References

No external references are listed.
