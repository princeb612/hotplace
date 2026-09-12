# Error Model — Error Code, Category, Testcase & Function Pipeline

**Edition 1 · Revision 1078**

## Context

The error model is shared infrastructure rather than a feature belonging to one protocol.

At its center is `return_t`, backed by `errorcode_t`. The same result value is then interpreted differently according to context:

```text
                       return_t / errorcode_t
                                │
              ┌─────────────────┼──────────────────┐
              │                 │                  │
              ▼                 ▼                  ▼
        error_advisor      error_traits       direct result
              │                 │
              ▼                 ▼
       error category      pipeline control
              │                 │
              ├───────┐       function_pipeline
              │       │
              ▼       ▼
          testcase   reporting
              │
              ▼
       console_color / logger
```

The important point is that **error code, category, control flow, and test reporting are one connected model**.

## History

The current error infrastructure predates the recent protocol work. The `CHANGELOG.md` provides a useful anchor at Revision 1023, where `error_traits` was explicitly improved. Revision 1024 then records the integration of `encoder_stream` / `decode_stream` with HTTP Huffman coding.

The current source also preserves an older unit-test lineage: `test_case` is documented as a prototype from codename.grape Revision 288, while the hotplace reboot begins at Revision 9. The present model therefore combines an established testcase/reporting mechanism with the later unified `return_t` / `error_traits` approach.

This document does not infer development order beyond the milestones recorded in `CHANGELOG.md`.

## Conceptual

### 1. Error code is a value, category is meaning

`errorcode_t` provides named result values. `return_t` provides the common result representation used throughout the SDK.

The numeric value alone is not sufficient for the higher-level infrastructure. `error_advisor::categoryof()` interprets the value as one of the project-level categories:

```text
success
expect_failure
severe
not_supported
low_security
trivial
warn
```

This allows one result value to participate in different policies without every caller having to duplicate numeric-range logic.

### 2. `error_advisor` supplies interpretation

`error_advisor` maintains two related views:

```text
return_t
   │
   ├── error code / name
   ├── error message
   └── category
          │
          ▼
   error_category_hint
```

`error_category_hint` binds a category to presentation and testcase semantics:

```cpp
struct error_category_hint {
    error_category_t category;
    console_color_t color;
    std::string testname;
    std::string longname;
};
```

For example, the current advisor maps success to `pass`, severe errors to `fail`, expected failures to `expt`, and non-supported conditions to `skip`.

Thus `hintof()` is more than a formatting helper: it is the bridge from an error result to the conventions used by the unit-test framework.

### 3. `error_traits` adapts foreign return conventions

The SDK does not require every lower-level API to return `return_t`.

`error_traits<T, category>` defines how a particular return type is interpreted. The current source includes:

```text
return_t
int + errno_category
int + osslerror_category
```

The traits provide operations such as:

```text
value_success()
value_exception()
value_invalid_parameter()
value_internal_error()
is_success()
is_not_fail()
to_return_t()
from_return_t()
compare()
```

This is especially important for `function_pipeline`, because the pipeline can execute functions returning different native conventions while retaining one control-flow model.

## Structural

### Error space and categorization

`errorcode_t` reserves project-specific and warning ranges:

```text
0xEF010000 ──────────────── 0xFF00FFFF
      hotplace severe errors

0xFF010000 ────────────────
      warnings / non-fatal conditions
```

`error_advisor::categoryof()` combines these ranges with selected special values and native OS ranges.

Conceptually:

```text
                         return_t.code
                              │
               ┌──────────────┼──────────────┐
               │              │              │
             zero        warning space    error space
               │              │              │
            success      special hints      severe
                              │
             ┌────────────────┼────────────────────┐
             ▼                ▼                    ▼
       not_supported   expect_failure       low_security
             │
             └────── trivial / warn
```

The category is therefore a policy-level interpretation of the result, not another independent error code namespace.

### `error_advisor`

The advisor builds:

```text
error_descriptions
      │
      ├── error code name
      └── human-readable message

error_category_map
      │
      └── error_category_hint
             ├── category
             ├── color
             ├── testname
             └── longname
```

The mappings are initialized once through the singleton and protected by the SDK's critical-section mechanism.

### `function_pipeline`

`function_pipeline<T, category>` consumes the same error semantics through `error_traits`.

Its internal state is essentially:

```text
last result
processed count
total count
discriminant
return_t conversion result
```

The discriminant determines whether another pipeline operation should execute.

```text
previous result
      │
      ▼
 error_traits<T, category>
      │
      ├── is_success
      └── is_not_fail
      │
      ▼
  discriminant
      │
      ├── continue
      └── stop
```

The pipeline therefore does not hard-code OpenSSL, errno, or hotplace error values. The category-specific behavior is supplied by `error_traits`.

### `test_case`

`test_case` is the reporting and aggregation boundary used by the unit tests.

It stores per-test results and aggregates counts for:

```text
success
fail
not supported
low security
trivial / warn
expect failure
```

The result path is:

```text
test/assert/ntest/ntest
          │
          ▼
       return_t
          │
          ▼
   error_advisor::hintof()
          │
     ┌────┼─────────────┐
     ▼    ▼             ▼
 category color       testname
     │    │             │
     └────┴──────┬──────┘
                 ▼
            test report
```

`assert(bool)` converts a failed boolean into `assert_failed`. `test(return_t)` accepts the SDK's common result directly. `ntest()` / `nassert()` express the negative-test expectation by converting an unexpected result into an `expect_failure` result when appropriate.

### Logger and console color

`logger` is deliberately secondary to the error model.

`test_case` can attach a `logger`, while `console_color` provides the actual terminal presentation. The category hint supplies the default color; the testcase/reporting layer may override presentation when the context requires it.

The useful separation is:

```text
error semantics
      │
      ▼
test_case decision / statistics
      │
      ▼
console presentation
      │
      └── logger (optional output path)
```

The logger does not decide whether a test passed. It helps deliver the resulting report.

## Flow

### Normal unit-test result

```text
test function
    │
    ▼
return_t result
    │
    ▼
test_case::test()
    │
    ▼
error_advisor::hintof()
    │
    ├── category
    ├── testname
    └── color
    │
    ▼
statistics + report line
    │
    ▼
logger / console
```

### Negative test

```text
operation returns error
        │
        ▼
      ntest()
        │
        ▼
expect_failure semantics
        │
        ▼
category = expect_failure
        │
        ▼
test is reported as expected
```

This distinction is important: an error result does not automatically mean a failed unit test. The testcase API can declare that the failure itself is the expected outcome.

### Function pipeline

A pipeline uses the same result semantics for execution control:

```text
run #1
  │
  ▼
result
  │
  ▼
discriminant
  │
  ├── success / allowed non-fail ──► run #2
  │
  └── failure ─────────────────────► skip normal run
                                      │
                                      ▼
                                walk_failed()
                                      │
                                      ▼
                                walk_always()
```

`walk_failed()` is therefore a control-flow operation driven by the error state, while `test_case` uses the same state to classify the final test result.

### Mixed return types

The current tests explicitly exercise the abstraction with OpenSSL-style and errno-style integer returns:

```text
int + osslerror_category
        │
        ▼
error_traits
        │
        ▼
function_pipeline
        │
        ▼
return_t

int + errno_category
        │
        ▼
error_traits
        │
        ▼
function_pipeline
```

This is one of the strongest reasons to keep `error_traits` in the same conceptual document as the error model.

## Study & Verification

The relationship is exercised by the project's unit-test infrastructure rather than by one isolated error testcase.

Representative verification includes:

- `test/testcase/base/basic/testcase_pipeline.cpp`
  - parameter validation
  - success/failure branching
  - `walk_failed()` and `walk_always()`
  - `goahead_if_not_fail()`
  - OpenSSL error category
  - Linux errno category
  - `result_to_return_t()`
- `sdk/base/unittest/testcase.hpp/.cpp`
  - result classification
  - statistics
  - report generation
  - expected-failure handling
- `sdk/base/system/error_advisor.cpp`
  - category-to-hint mapping
  - error-code/message lookup

The pipeline testcase demonstrates an especially useful property:

```text
one abstraction
     │
     ├── native int return
     ├── return_t return
     └── category-specific interpretation
             │
             ▼
        common pipeline
```

The broad `test/testcase` tree consequently benefits from the same result vocabulary instead of inventing independent pass/fail handling for each protocol test.

## Status

As of Revision 1078:

- `errorcode_t` and `return_t` provide the common result representation.
- `error_advisor` provides error-code/message lookup and category interpretation.
- `error_category_hint` connects categories to testcase names and console presentation.
- `error_traits` adapts `return_t`, errno-style integers, and OpenSSL-style integers.
- `function_pipeline` uses `error_traits` to control conditional execution and convert results.
- `test_case` uses the error category to classify and report unit-test results.
- `logger` can serve as the output path without owning test-result semantics.
- Pipeline behavior is directly exercised by unit tests, including foreign error conventions.

The resulting structure is best understood as a shared semantic layer:

```text
             ERROR MODEL
                  │
       ┌──────────┴──────────┐
       ▼                     ▼
 error_advisor          error_traits
       │                     │
       ▼                     ▼
 category / hint      function_pipeline
       │                     │
       ▼                     │
   test_case ◄───────────────┘
       │
       ▼
 console / logger
```

This shared model is what allows protocol and cryptographic testcases throughout `test/testcase` to use consistent success, failure, expected-failure, skip, warning, and presentation semantics.
