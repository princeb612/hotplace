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

# Command Line

## 1. Role

### Introduction

`cmdline` is a small template-based command-line parser. It connects recognized command-line tokens directly to an application-owned option object through callbacks.

The main types are `t_cmdline_t<T>` and `t_cmdarg_t<T>`.

## 2. Data Model

### Registration and parser state

Each `t_cmdarg_t<T>` stores a token, description, callback `std::function<void(T&, const char*)>`, and flags. `optional()` and `preced()` set bits in those flags; they do not execute the callback.

The parser `t_cmdline_t<T>` maintains four distinct pieces of state:

- `_source`: the application option object returned by `value()`.
- `_args`: map from token to registered argument metadata/callback; this is the lookup structure used during parsing.
- `_list`: token order preserved for help output and registration-order behavior.
- `_mandatory`: the set of required tokens that still need to be satisfied by parsing.

The callback target type `T` is application-defined, so the parser does not define the fields or semantic validity of `_source`.

## 3. Behavior Model

### Parsing and dispatch flow

Registration moves each argument into `_args` and appends its token to `_list`; duplicate tokens throw `exception(errorcode_t::duplicate)`.

`parse(argc, argv)` examines the received argument tokens and looks them up in the registered map. For a recognized token, the parser applies its argument flags and precedence rules, obtains the next token when the callback expects a parameter, and invokes the callback with a reference to `_source`. Successful processing updates the parser's processed/mandatory state; after token processing, unsatisfied mandatory arguments produce an error. `help()` uses the preserved registration order to report the available options and their state.

The callback writes to the application-owned option object. In `testcase_cmdline.cpp`, for example, the input-option callback stores its supplied path in `MYOPTION::infile`, while flag-style callbacks update Boolean or verbosity fields. The parser's own success does not validate application-specific combinations unless those combinations are encoded by the registered argument rules or checked by the callback/application.

### Input and error cases

The implementation is a small parser, not a full shell parser: quoting, escaping, and shell tokenization are outside this interface when the program receives `argv`.

### Parsing flow

```text
register arguments with operator<<()
  └─ reject duplicate token; retain argument metadata and callback

parse(argv)
  ├─ find matching registered token
  ├─ check ordering / precedence rules
  ├─ if value required ─► consume next token or report missing value
  ├─ invoke callback ───► update application-owned option object
  └─ after input ───────► verify mandatory arguments were processed
                            └─ help() reports registration/processing state
```

The parser owns registration and dispatch state, not the application's option object. A successful callback only means that the registered handler ran; semantic validation of the resulting options remains the responsibility of the callback or application.

### Practical use: bind arguments to application state

The testcase defines an application-owned option type and registers callbacks that write directly into it. Required path arguments use `.preced()`; switches that may be omitted use `.optional()`.

```cpp
struct MYOPTION : public CMDLINEOPTION {
    std::string infile;
    std::string outfile;
    bool keygen;
    MYOPTION() : CMDLINEOPTION(), keygen(false) {}
};

t_cmdline_t<MYOPTION> cmdline;
cmdline << t_cmdarg_t<MYOPTION>("-in", "input",
    [](MYOPTION& o, const char* p) { o.infile = p; }).preced()
        << t_cmdarg_t<MYOPTION>("-out", "output",
    [](MYOPTION& o, const char* p) { o.outfile = p; }).preced()
        << t_cmdarg_t<MYOPTION>("-keygen", "keygen",
    [](MYOPTION& o, const char*) { o.keygen = true; }).optional();

return_t ret = cmdline.parse(argc, argv);
if (errorcode_t::success == ret) {
    const MYOPTION& option = cmdline.value();
    // Application logic consumes option.infile, option.outfile, option.keygen.
}
```

This is the parser's intended composition: token registration → callback dispatch → application option state → application logic. A successful parse only means the registered command-line rules were satisfied; it does not prove that the paths exist or that the requested operation is valid. The source testcase also checks missing required arguments and invalid combinations.

Source: [testcase_cmdline.cpp](../../../test/testcase/base/basic/testcase_cmdline.cpp).

## 4. Relationships

- The callback target type `T` is application-defined; `cmdline` provides token recognition and parameter dispatch rather than defining the application's option structure.
- The source test vectors cover missing mandatory arguments, optional flags such as `-keygen`, missing values, unknown tokens, and valid combinations; preserve these cases when changing token matching or argument ordering.
- Test vectors are part of the behavior contract and should be reviewed with `testcase_cmdline.cpp` when parsing rules change.
- The implementation is in `cmdline.hpp`; the associated vectors are `testvector_cmdline.cpp` and `testvector_cmdline.yml`, alongside `testcase_cmdline.cpp`. Parsing changes should be checked against both assertions and data-driven cases.
- This parser is separate from any protocol-level command or configuration parser.
