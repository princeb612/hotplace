## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Command Line

## 1. Role

### Introduction

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

## 2. Model

### Registration

Arguments are registered with `operator<<()`. A command argument can be marked as optional with `optional()` or used as a preceding/related argument through `preced()`.

The parser keeps mandatory arguments separately and rejects duplicate registrations.

### Parsing

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

## 3. Important behavior and lifetime

### Required and optional arguments

The parser keeps mandatory arguments separately and rejects duplicate registrations. An argument can be optional, require a value, or participate in a precedence/relationship rule through `preced()`. `help()` reports registered arguments and their processing state in registration order.

The callback writes to the application-owned option object. The parser's own success does not validate application-specific combinations unless those combinations are encoded by the registered argument rules or checked by the callback/application.

### Input and error cases

The source test vectors cover missing mandatory arguments, optional flags such as `-keygen`, missing values, unknown tokens, and valid combinations. Preserve these cases when changing token matching or argument ordering. The implementation is a small parser, not a full shell parser: quoting, escaping, and shell tokenization are outside this interface when the program receives `argv`.

### Source tests

- `test/testcase/base/basic/testcase_cmdline.cpp`
- `test/testcase/base/basic/testvector_cmdline.cpp`
- `test/testcase/base/basic/testvector_cmdline.yml`

## 4. Example from the source tests

### Follow a registered option into application state

`test/testcase/base/basic/testcase_cmdline.cpp` defines an application option structure (`MYOPTION`) and registers options by chaining `t_cmdarg_t<MYOPTION>` values into `t_cmdline_t<MYOPTION>`. Each callback updates the option object; for example, the input option stores the supplied path in `infile`, while flag-style options update Boolean or verbosity fields.

```text
argv tokens
   │
   ▼
t_cmdline_t<MYOPTION>
   ├── registered token + argument rules
   └── callback(MYOPTION&, parameter)
              │
              ▼
       application option state
```

The paired `testvector_cmdline.cpp` / `.yml` files make it easier to inspect the intended accept/reject cases. When changing registration semantics, check both the parser implementation and the vectors, especially for required arguments, missing values, unknown options, and ordering constraints.

## 5. Relationships

- The callback target type `T` is application-defined; `cmdline` provides token recognition and parameter dispatch rather than defining the application's option structure.
- Test vectors are part of the behavior contract and should be reviewed with `testcase_cmdline.cpp` when parsing rules change.
- This parser is separate from any protocol-level command or configuration parser.

## 6. References

### Related source and vectors

- Implementation: `sdk/base/basic/cmdline.hpp`
- Test: `test/testcase/base/basic/testcase_cmdline.cpp`
- Vectors: `test/testcase/base/basic/testvector_cmdline.cpp`, `test/testcase/base/basic/testvector_cmdline.yml`

