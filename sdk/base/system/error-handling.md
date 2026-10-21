## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# Error handling and error advice

## 1. Role

The system error layer gives meaning to hotplace's shared result model. Operations produce result values; the error layer provides a common representation, adapts external return conventions, classifies outcomes, and supplies symbolic names and messages for diagnostics.

The distinction between `errorcode_t` and `return_t` is foundational:

- `errorcode_t` is an `enum class` naming hotplace-defined outcomes and the platform-specific error values included by the build. It gives a readable name to a numeric code.
- `return_t` is a small wrapper around a `uint32 code`. It can be constructed from `errorcode_t` or integer/platform result values, and exposes `error_code()`, `error_message()`, and `category()`. It is the common return representation used by APIs and callbacks.

In short, `errorcode_t` names a code; `return_t` carries a code through an API and offers result-oriented helpers. They are intentionally interoperable, but they are not the same type.

The system layer has three cooperating responsibilities:

- `error_traits<T, category>` adapts conventions such as hotplace `return_t`, errno-style integers, and OpenSSL integer results.
- `error_advisor` looks up symbolic names and messages and classifies result codes.
- `error_category_hint` associates reporting categories with console colors and compact/long labels used by the unit-test reporter.

A code's message describes *which result occurred*; its category determines *how that result is grouped and displayed*.

## 2. Data Model

### Error values and descriptions

The shared `errorcode_t` enumeration contains success, platform-specific native error values where supported, hotplace-defined error ranges, and status/warning values. Hotplace-defined errors and warnings occupy reserved numeric ranges marked by `ERROR_CODE_BEGIN` and `WARN_CODE_BEGIN`. Numeric values are used by the common representation, so changing established values can affect callers and diagnostics.

`return_t` stores the numeric value in its `code` member. Its implicit conversion operators allow use as a `uint32` or `errorcode_t`, while its helper methods delegate symbolic-code lookup and category classification to the system error layer. For message retrieval, project-defined codes use the advisor's description table; native platform codes use the operating system's message mechanism where implemented.

The `error_descriptions` table associates selected values with an `error_description` containing the numeric error, symbolic code name, and human-readable message. The table is platform-dependent: the Linux build includes Linux errno and address-resolution entries, while common hotplace-defined entries are also present. Not every possible numeric value is guaranteed to have a registered symbolic description.

### Categories and presentation hints

A separate map associates `error_category_t` with an `error_category_hint`. Each hint contains:

| Field | Purpose |
|---|---|
| `category` | Category represented by this hint |
| `color` | Console color used when presenting the outcome |
| `testname` | Compact report label, such as `pass`, `expt`, `fail`, `skip`, or `triv` |
| `longname` | Longer category description, such as `success`, `expect failure`, or `severe` |

The description map and hint map are related but not interchangeable. One resolves a result code to a name/message; the other resolves a category to reporting metadata.

### Return-convention adapters

The `error_traits` specializations let generic code work with different result conventions while retaining a known success value, invalid-parameter value, exception value, and comparison behavior.

- `error_traits<return_t>` uses the hotplace result representation directly. Its success predicate also treats `expect_failure` as an accepted outcome for negative tests.
- `error_traits<int, errno_category>` follows errno's zero-is-success convention. When converted to `return_t`, a nonzero value is mapped to `internal_error`; the original errno number is not preserved as a one-to-one hotplace error by this conversion.
- `error_traits<int, osslerror_category>` follows OpenSSL's positive-is-success convention. A non-positive value converts to `error_openssl_inside`.

The category tag distinguishes conventions that otherwise share the same C++ type (`int`). These traits are adapters, not a universal registry of all external error codes.

## 3. Behavior Model

### Initialization and description lookup

`error_advisor::get_instance()` calls `build()` before returning the singleton. `build()` populates the description and category-hint maps only when they are empty, using a critical-section guard and a second emptiness check to protect initialization.

The lookup functions clear their output strings before searching by `return_t`. They return a Boolean indicating whether a description was found. The combined `error_message(error, code, message)` overload fills both the symbolic name and message when a match exists. Callers should check the Boolean result because an arbitrary numeric code may not be present in the table.

### Classification

`categoryof()` classifies the numeric value carried by `return_t`:

1. Zero is success.
2. Values in the warning range receive special treatment for `not_supported`, `expect_failure`, `low_security`, and `do_nothing`; other values in that range are warnings.
3. Values in hotplace's error-code range are severe.
4. Recognized Linux native error values are severe.
5. Values not matched earlier also fall through to severe.

This is a reporting classification, not a replacement for the original result code. An unsupported or warning result retains its original numeric value even though the reporter groups it under a category.

### From an operation result to a testcase report

The testcase layer records a result and asks the advisor for its category hint. The hint determines the reporting category, counter path, label, and color. The record still carries the original result so output can display its code and, when requested, its message.

```text
                         operation result
                                |
                                v
                     return_t { numeric code }
                         /              \
                        /                \
                       v                  v
          categoryof(return_t)     error description lookup
                       |                  |
                       v                  v
              error_category_t      symbolic code + message
                       |
                       v
                hintof(category)
                       |
                       v
              error_category_hint
                       |
                       v
          testcase counters, labels, and color
```

In `test_case::vtest()`, success increments the success count; expected failure has its own expected-outcome count; severe results count as failures; unsupported and low-security results use the skip-related reporting path; and trivial/warning outcomes use the non-failure reporting path. The report uses hint colors and compact labels, while failed-result output can request the error message.

The testcase entry styles differ in how the result is supplied. `assert()` converts a false condition into `assert_failed`; `test(return_t, ...)` accepts a result selected by the caller. In both cases, the advisor's category—not merely the truth value of a C++ expression—drives aggregate reporting.

### Error handling in a function pipeline

`function_pipeline<T, category>` composes operations that may return either the pipeline's configured result type `T` or hotplace's `return_t`. The pipeline uses `error_traits<T, category>` to determine success and whether later steps should run. This is where the generic adapter layer is operationally important: a pipeline can use `return_t` directly, or it can work with an external convention such as `int` plus `osslerror_category`.

By default, `run()` and `walk()` steps proceed only while the current result satisfies the pipeline's success predicate. `goahead_if_not_fail()` changes the continuation rule so non-severe outcomes can proceed. `run_failed()` / `walk_failed()` run on the failure path, while `walk_always()` provides an unconditional step for cleanup or finalization. Try/catch variants translate a caught exception into the trait's exception value; the non-catching variants throw hotplace's `exception`.

The pipeline keeps `result()` in its configured type `T`. `result_to_return_t()` converts that result to the common hotplace representation, while preserving a `return_t` result when a step supplied one. This is important when a pipeline mixes external API return values and hotplace operations: the pipeline controls sequencing, but the error conventions and conversion policy still come from `error_traits`.

```text
  function_pipeline<T, category>
              |
              v
       run / walk step
              |
              v
     step returns T or return_t
              |
              v
   error_traits<T, category>
   decides success / continuation
          /             \
         v               v
    continue          stop normal steps
         |               |
         v               v
    next step       failed/always step
          \             /
           v           v
           result() : T
                 |
                 v
       result_to_return_t()
                 |
                 v
            return_t
```

The pipeline does not make every operation's error values identical. For example, an errno-tagged pipeline converts a nonzero errno result to `internal_error` when producing `return_t`; callers that need the original native value must account for that conversion boundary.

## 4. Relationships

- **Shared result model — `sdk/base/error.hpp` and `sdk/base/error.cpp`:** define `errorcode_t`, the `return_t` wrapper, and result helpers. `return_t` delegates symbolic names and category information to the system error layer.
- **Adapter and advisor API — `sdk/base/system/error.hpp` and `sdk/base/system/error_advisor.cpp`:** define `error_traits`, category hints, and the advisor interface; the implementation builds lookup maps and performs lookups/classification.
- **Function sequencing — `sdk/base/basic/function_pipeline.hpp`:** uses `error_traits` to evaluate step results, decide whether subsequent operations run, and convert the final pipeline result to `return_t`. It consumes the error model rather than replacing it.
- **Test reporting — `sdk/base/unittest/testcase.cpp`:** asks for the result's category hint while recording a result, then uses category information for counters and presentation. The report path can also request the advisor's message for a failed result.
- **Error-flow macros — `sdk/base/syntax.hpp`:** provides `__try2` / `__finally2` / `__leave2` control-flow macros and allocation helpers that assign `errorcode_t` values such as `out_of_memory`; these macros supply results that can later be interpreted by the common error layer.
- **Trace diagnostics — `sdk/base/system/trace.cpp`:** uses the advisor to obtain an error-code name when emitting leave-trace diagnostics.
- **Source-level testcase coverage — `test/testcase/base/unittest/testcase_unittest.cpp`:** `test_error()` looks up the name and message for `invalid_parameter`; `test_testcase()` submits success, unsupported, and low-security results. Related tests exercise error-flow and trace paths. These describe test source, not a claim that tests were executed during this documentation update.

## 5. References

- [RFC 6749 — The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749): the shared error definitions include OAuth error names such as `invalid_request`, `access_denied`, `invalid_client`, and `invalid_grant`, with comments pointing to the relevant error-response sections. This RFC is relevant to those protocol-specific values; it does not define hotplace's general error-advisor, function-pipeline, or testcase-reporting model.
