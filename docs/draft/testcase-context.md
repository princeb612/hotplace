# Testcase Context — Draft

## Why preserve this

`testcase` is easy to misunderstand as simply a directory containing many test functions. The more useful project-level view is that testcase is an execution environment where four common concerns meet:

```text
                         testcase
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
       cmdarg           test_case          logger
          │                 │                 │
 execution conditions   verification       observation
          │              / result             │
          └─────────────────┼─────────────────┘
                            │
                     concrete tests
```

The components are related, but they are not one class hierarchy and do not have identical responsibilities.

## Four axes

### `cmdarg` / command-line

Answers:

> Under what execution conditions should the test run?

Conceptually:

```text
argv
 ↓
t_cmdline_t<T>
 ↓
t_cmdarg_t<T>
 ↓
option state
```

Command-line parsing selects or configures execution. It does not decide whether a test passed.

### `testcase`

Answers:

> What concrete tests or test groups are executed?

```text
subject
  ↓
testcase_<subject>()
  ↓
test functions / vectors
```

The subject may be base, parser, ASN.1, crypto, TLS, QUIC, HTTP, or another study area. The common execution model remains stable while the subject changes.

### `test_case`

Answers:

> How is an individual verification recorded and how is the final test result derived?

```text
test execution
      ↓
test_case
      ├── begin
      ├── assert / test
      ├── pass / fail
      ├── aggregation
      ├── statistics / timing
      └── final result
```

`test_case` is therefore the verification/result boundary, not a synonym for `testcase`.

### `logger`

Answers:

> How is execution and diagnostic information observed or presented?

```text
test_case ── result semantics ──┐
                                ├── execution context
logger ── observation/output ───┘
```

`logger` is broader than testcase and can be used independently. It should not become the source of truth for pass/fail semantics.

## Combined execution flow

```text
process
  │
  ├── argv
  │    ↓
  │  cmdarg / cmdline
  │    ↓
  │  execution conditions
  │
  ▼
testcase entry
  │
  ├── begin group
  ├── execute subject operation
  ├── consume test vector / input
  └── verify
         │
         ▼
      test_case
         │
         ├── assert
         ├── aggregate result
         └── final status
         │
         └──────────────┐
                        ▼
                      logger
                        │
                        ▼
                 human-readable output
```

The final drawing is intentionally conceptual: actual call order can vary by testcase, and logger calls may occur before, during, or after assertions.

## Test vectors as a separate concern

Test vectors should not be forced into any of the four axes. They are test input/data:

```text
test vector
    ↓
execution
    ↓
test_case
```

This distinction is useful for RFC-derived vectors, YAML-based cases, and protocol captures because it separates **what data is being tested** from **how the test is executed and judged**.

## Relationship to `base` and `error`

`base` provides common verification support, but testcase owns the project-level execution context.

`error` owns the common error/result model. The testcase document should explain how verification consumes and reports results without duplicating the complete error model.

```text
base
 │
 ├── common mechanisms
 └── unittest support
        │
        ▼
     testcase
        │
        ├── cmdarg
        ├── test_case
        └── logger

error
 │
 └── error/result semantics
        │
        ▼
     test_case / reporting
```

## Candidate destinations

- Keep the four-axis model in `docs/testcase/README.md`.
- Keep detailed error/result semantics in `docs/error/README.md`.
- Keep only the existence of verification support in `docs/base/README.md`.
- Use a root README reading-path diagram only if it improves first-time navigation.

## Boundary with the error model

The testcase infrastructure should not be documented as if it owns all result semantics. The `error` model supplies the meaning of a `return_t` / `errorcode_t` result; `test_case` interprets that result in terms of test verification, aggregation, and reporting; `logger` and console facilities provide presentation.

```text
operation
    │
    ▼
return_t / errorcode_t
    │
    ▼
error_advisor / error_traits
    │
    ▼
error category / result meaning
    │
    ▼
test_case
    │
    ├── pass / fail / expected failure / skip ...
    ├── statistics
    └── final test result
    │
    └──────────────► logger / console
                         │
                         ▼
                    observation
```

This is an important boundary: the same error/result model is useful outside tests, while `test_case` adds test-specific semantics to it.

## Candidate destination

- `testcase/README.md`: common execution and verification model
- `error/README.md`: result/error meaning and category model
- `base/README.md`: only the fact that common verification infrastructure is part of the base foundation
