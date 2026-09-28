# Command Line

`cmdline` is a small template-based command-line parser. It connects recognized command-line tokens directly to an application-owned option object through callbacks.

The main types are `t_cmdline_t<T>` and `t_cmdarg_t<T>`.

```text
command-line tokens
        │
        ▼
   t_cmdline_t<T>
        │
        ├── registered t_cmdarg_t<T>
        │
        └── callback
                │
                ▼
        application option object
```

## Registration

Arguments are registered with `operator<<()`. A command argument can be marked as optional with `optional()` or used as a preceding/related argument through `preced()`.

The parser keeps mandatory arguments separately and rejects duplicate registrations.

## Parsing

The parser processes tokens in the registered command set and invokes the corresponding callback when a recognized argument is encountered.

The implementation checks for:

- missing mandatory arguments
- optional arguments
- arguments requiring a value
- unknown tokens
- duplicate registration
- valid combinations and ordering of arguments

`help()` reports the registered arguments and their required/processed state in registration order.

The implementation is intentionally small and is not a general command-line framework or a thread-safe parser.

## Tests

- `test/testcase/base/basic/testcase_cmdline.cpp`
- `test/testcase/base/basic/testvector_cmdline.cpp`
- `test/testcase/base/basic/testvector_cmdline.yml`

The test vectors provide cases for missing required arguments, optional options such as `-keygen`, missing values, unknown tokens, and valid argument combinations.

## Related source

- `sdk/base/basic/cmdline.hpp`
- `test/testcase/base/basic/testcase_cmdline.cpp`
- `test/testcase/base/basic/testvector_cmdline.cpp`
- `test/testcase/base/basic/testvector_cmdline.yml`
