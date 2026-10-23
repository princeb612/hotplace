# BASE-001 — function_pipeline discriminant selection

- **Status:** Resolved in current source; focused runtime verification not performed in this follow-up
- **Kind:** Source behavior follow-up
- **Area:** `sdk/base/basic/function_pipeline`
- **Original finding:** Revision 1107 review; checked master commit `98f4185e9631911683cbf214af1d9912e28bba42`
- **Current source basis:** Revision 1108 commit `4ff020d8f4db6be2639f8dd11ad39c4faa0904d8` (2026-10-23)
- **Related review record:** [Revision 1107 follow-up overview](../revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-001--function_pipeline)

## Background

During the Data Model / Behavior Model review of `sdk/base`, the `function_pipeline` continuation predicate selection was inconsistent: `goahead_if_success()` assigned `error_traits<T, category>::_discriminant`, although the policy API exposes `is_success` and `is_not_fail`. The constructor already selected `is_success`.

This is a source-level follow-up, not merely a documentation wording issue. The selected predicate controls continuation and result classification throughout the pipeline.

## Source context

- [Current `sdk/base/basic/function_pipeline.hpp` at Revision 1108](https://github.com/princeb612/hotplace/blob/4ff020d8f4db6be2639f8dd11ad39c4faa0904d8/sdk/base/basic/function_pipeline.hpp)
- [Current `sdk/base/system/error.hpp` at Revision 1108](https://github.com/princeb612/hotplace/blob/4ff020d8f4db6be2639f8dd11ad39c4faa0904d8/sdk/base/system/error.hpp)
- [Revision 1108 commit](https://github.com/princeb612/hotplace/commit/4ff020d8f4db6be2639f8dd11ad39c4faa0904d8)

## Current understanding

### Original finding

At the original checked snapshot (`98f4185e9631911683cbf214af1d9912e28bba42`), the relevant methods were:

```cpp
function_pipeline& goahead_if_success() {
    _discriminant = error_traits<T, category>::_discriminant;
    return *this;
}

function_pipeline& goahead_if_not_fail() {
    _discriminant = error_traits<T, category>::is_not_fail;
    return *this;
}
```

### Recheck against Revision 1108

The current source now contains:

```cpp
function_pipeline& goahead_if_success() {
    _discriminant = error_traits<T, category>::is_success;
    return *this;
}

function_pipeline& goahead_if_not_fail() {
    _discriminant = error_traits<T, category>::is_not_fail;
    return *this;
}
```

The latest source therefore has the expected predicate mapping. The diff between the original checked commit and Revision 1108 confirms that `sdk/base/basic/function_pipeline.hpp` changed by one line, replacing the inconsistent `_discriminant` member reference with `is_success`.

The relevant policy specializations in `sdk/base/system/error.hpp` expose `is_success(code)` and `is_not_fail(code)`. The pipeline stores the selected predicate as `bool (*)(T)`; `passed()`, `failed()`, runner continuation checks, and processed-count updates use that selected predicate.

### Existing testcase evidence

`test/testcase/base/basic/testcase_pipeline.cpp` already covers:
- ordinary success and failure routing, including `walk_failed()` and `walk_always()`;
- `goahead_if_not_fail()` continuing after the non-severe `errorcode_t::debug` result;
- OpenSSL-style `int` result classification and conversion;
- preservation of an explicit hotplace `return_t` result.

The existing testcase does not directly exercise an explicit call to `goahead_if_success()`. No new test was added and no test command was run as part of this follow-up session. The user's separate Revision 1108 build completion is not treated here as evidence of a particular test result.

## Behavior path

```text
function_pipeline<T, category>
          |
          | select continuation predicate
          v
  _discriminant : bool (*)(T)
          |
          +--> passed() / failed()
          |
          +--> runner() continuation check
          |        |
          |        +--> invoke step when expectation matches
          |        +--> skip step otherwise
          |
          +--> test_returncode()
                   |
                   +--> increment processed count when predicate returns true
```

The distinction between the two predicates matters for categories where “not a severe failure” is broader than “success”. They must not be assumed equivalent for every specialization.

## Disposition

**Resolved at source level in Revision 1108.** The previously inconsistent assignment is corrected in the current source. A dedicated `goahead_if_success()` assertion could be considered if future work makes it useful, but it is not required to keep this finding open, and no broad QA expansion is proposed.

## History

- **Revision 1107 review:** Recorded the inconsistent assignment and expected predicate mapping; further source verification was pending.
- **2026-10-23, Revision 1108 recheck:** Compared the original checked commit `98f4185e9631911683cbf214af1d9912e28bba42` with current commit `4ff020d8f4db6be2639f8dd11ad39c4faa0904d8`. Confirmed the one-line source correction and updated this record. No source or testcase changes were made in this follow-up workspace, and no test run is claimed.
