# Testcase

## Context

`testcase` is the repository's executable verification environment. It is not a
single test class and it is not a protocol-specific subsystem. It is the place
where reusable base facilities and higher-level protocol implementations are
exercised through concrete test functions, test vectors, command-line
conditions, result checking, and logging.

The important distinction is between **what is being tested**, **how the test is
executed**, **how the result is judged**, and **how execution is observed**.

```text
                         testcase
                            │
             ┌──────────────┼──────────────┐
             │              │              │
          cmdarg         test_case       logger
             │              │              │
      execution setup   verification    observation
             │              │              │
             │          result state       │
             │              │              │
             └──────────────┼──────────────┘
                            │
                     concrete tests
```

The three axes should not be read as one call hierarchy. `cmdarg` prepares the
execution conditions, `test_case` owns verification semantics, and `logger`
provides an observation/output path. They meet around concrete test execution
without becoming one subsystem.

This is a conceptual relationship, not a claim that these components form one
single class hierarchy.

## History

The testcase environment grew with hotplace as new study subjects were
implemented. The same execution and verification mechanisms are reused while
the actual test content moves from base algorithms and encodings to parsers,
ASN.1, crypto, TLS, QUIC, HTTP, and other protocol topics.

This makes testcase an important cross-topic boundary: the subject changes,
but the basic way a test is selected, executed, checked, and observed can stay
stable.

The development/study flow should therefore not be reconstructed from the
names of testcase directories. A testcase directory reflects the subject being
verified; the common execution model belongs to the shared test infrastructure.

## Conceptual

A useful way to understand the whole environment is to separate four roles.

```text
process / command line
        │
        ▼
      cmdarg
        │
        │ select / configure execution
        ▼
     testcase
        │
        │ run concrete test functions / vectors
        ├──────────────────────┐
        ▼                      ▼
    test_case                logger
        │                      │
 verification / result     observation / output
        │                      │
        ▼                      ▼
 result state             console / file / diagnostics
```

### cmdarg / cmdline — execution conditions

The command-line layer provides a typed option object and a collection of
`t_cmdarg_t<T>` definitions managed by `t_cmdline_t<T>`.

Conceptually:

```text
argv
 │
 ▼
t_cmdline_t<T>
 │
 ├── t_cmdarg_t<T>
 │     ├── token
 │     ├── description
 │     ├── optional / preceding-value flags
 │     └── binding callback
 │
 ▼
option object T
```

An argument can either act as a flag or consume the following argument as its
value. `optional()` and `preced()` describe command-line syntax; the callback
binds the parsed value into the option object.

The important boundary is that command-line parsing determines **execution
conditions**. It does not decide whether a test passed.

For example, the base testcase command-line test uses `-in` and `-out` as
arguments that consume a following value, while `-keygen` is an optional flag.
The test then verifies both successful and unsuccessful command-line cases.

### testcase — concrete execution

The testcase layer organizes actual test functions and groups them by subject.
Examples in the base test environment include command-line parsing, big-number
operations, pattern algorithms, streams, strings, encodings, and other base
facilities. Higher-level testcase trees similarly contain ASN.1, COSE, TLS,
QUIC, HTTP, and related tests.

A typical subject-specific path is:

```text
subject
  ↓
testcase_<subject>()
  ↓
individual test functions
  ↓
test vectors / direct assertions
```

The name `testcase` therefore describes **what is executed as a test suite or
scenario**, not the result object itself.

### test_case — verification and result boundary

`test_case` is the common verification object used by the testcase programs.
It provides operations such as `begin()`, `assert()`, `test()`, reporting, and
final result calculation.

The conceptual boundary is:

```text
test execution
      │
      ▼
test_case
      │
      ├── individual checks
      ├── pass / fail state
      ├── aggregated result
      ├── timing / statistics
      └── final process result
```

This is why `test_case` should not be treated as a synonym for `testcase`.
The former owns **verification state and result semantics**; the latter
organizes **concrete test execution**.

The final process status is derived from the collected test result, while the
individual protocol or algorithm being tested remains outside `test_case`.

### logger — observation and presentation

`logger` is a common output/observation mechanism rather than a test-result
owner. Test programs use it for textual output, formatted diagnostic data,
console output, dumps, and optional file logging.

A useful distinction is:

```text
test_case
   │
   └── decides / records verification result

logger
   │
   └── observes / presents execution and diagnostic information
```

The two components can be connected, but they have different responsibilities.
The logger can be used outside testcase verification, and test result semantics
do not depend on the logger being the source of truth.

## Structural

The common testcase infrastructure is provided from `sdk/base/unittest`, while
subject-specific tests live under `test/testcase`.

```text
sdk/base/unittest
   ├── test_case
   ├── logger
   └── common test execution support

        ▲
        │
        │ reused by
        │
 test/testcase
   ├── base
   ├── io
   ├── net
   ├── crypto / security topics
   └── protocol topics
```

The exact directory names of every test suite are implementation details. The
stable relationship is that subject-specific tests depend on common execution,
verification, and observation mechanisms.

### Test vectors

Not every testcase is written as a hand-coded assertion table. Many subjects
use external or structured test vectors so that the data being checked is
separated from the execution code.

The repository contains YAML schemas for several base and protocol subjects,
including command-line cases, big-number operations, capacity, floating point,
Aho-Corasick, KMP, parser cases, HPACK, and HTTP/2.

Conceptually:

```text
test vector
    │
    ▼
vector parser / loader
    │
    ▼
testcase execution
    │
    ▼
test_case
```

This separates **test data** from the **verification mechanism**. The same
pattern also allows RFC-derived vectors to remain recognizable as external
references rather than being hidden inside test implementation code.

## Flow

A normal testcase execution can be read as:

```text
process
  │
  ├── command-line arguments
  │        ↓
  │     cmdarg
  │        ↓
  │     option state
  │
  ▼
testcase entry
  │
  ├── begin test group
  ├── execute subject operation
  │
  ├───────────────┬────────────────┐
  ▼               ▼                ▼
test_case      error model       logger
  │               │                │
  │         result meaning       output
  │               │                │
  └──────► verification ◄──────────┘
              │
              ▼
         final result
```

A concrete command-line test follows the same pattern:

```text
argv
 ↓
t_cmdline_t
 ↓
option object
 ↓
command-line behavior
 ↓
test_case.assert()
 ↓
logger output
```

A parser or ASN.1 testcase adds the domain-specific operation without changing
the common verification boundary:

```text
ASN.1 notation
 ↓
parser / semantic construction
 ↓
runtime object
 ↓
test_case assertion
 ↓
logger observation
```

This is one reason the same testcase infrastructure can support otherwise very
different study topics.

## Study & Verification

The testcase infrastructure itself is verified by tests that exercise its
boundaries, while higher-level tests verify the subjects built on top of it.

For command-line processing, the test suite includes both positive and
negative cases, such as a missing mandatory argument versus a complete set of
arguments.

For semantic or protocol work, testcases can combine several forms of
verification:

```text
RFC / external vector
       │
       ▼
implementation
       │
       ├── direct assertion
       ├── round trip
       ├── expected notation
       └── captured / reproduced behavior
              │
              ▼
          test_case result
```

The common infrastructure therefore makes the result comparable across study
topics without forcing all topics to use the same kind of test data.

## Status

The testcase environment should be understood as a **cross-cutting
verification layer** of the repository.

- `cmdarg` / `cmdline` (`t_cmdarg_t`, `t_cmdline_t`) controls execution conditions and option binding.
- `testcase` organizes concrete test execution by subject.
- `test_case` owns assertion, result aggregation, reporting, and final status.
- `logger` provides observation and presentation and can be used beyond tests.
- Test vectors provide reusable, often externally derived test data.
- Subject-specific testcase directories remain responsible for the semantics of
  the thing being tested.

This separation lets the study documents describe a protocol or algorithm on
its own terms while the testcase documentation explains how that subject is
verified in the repository.

## Related topics

The meaning of `return_t` results and their categories belongs to the [Error Model](../error/README.md); this document only explains how those results participate in test verification.

- [SDK Base](../base/README.md)
- [Error Model](../error/README.md)
- [Build](../build/README.md)
- [Parser](../io/parser/README.md)
- [Payload](../io/payload/README.md)
- [ASN.1](../asn.1/README.md)
- [Network Server](../network_server/README.md)
