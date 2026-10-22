# BASE-001 — function_pipeline discriminant selection

- **Status:** Open — source recheck required
- **Kind:** Source behavior follow-up
- **Area:** `sdk/base/basic/function_pipeline`
- **Source basis:** The review notes were recorded against Revision 1107. The current `master` snapshot was checked on 2026-10-23 at commit `98f4185e9631911683cbf214af1d9912e28bba42`. Do not treat the branch name or revision label alone as proof of source identity.
- **Related review record:** [Revision 1107 follow-up overview](../revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-001--function_pipeline)

## Background

During the Data Model / Behavior Model review of `sdk/base`, the `function_pipeline` continuation predicate selection looked inconsistent: the success path used a member named `_discriminant` on `error_traits`, while the error-traits API exposed predicates named `is_success` and `is_not_fail`.

This is a source-level follow-up, not merely a documentation wording issue. The intended continuation rule should be selected explicitly by the corresponding `goahead_...` method.

## Source context

- [`sdk/base/basic/function_pipeline.hpp` on the checked master snapshot](https://github.com/princeb612/hotplace/blob/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/basic/function_pipeline.hpp)
- [`sdk/base/system/error.hpp` on the checked master snapshot](https://github.com/princeb612/hotplace/blob/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/system/error.hpp)

Relevant code in `function_pipeline.hpp`:

```cpp
function_pipeline()
    : _lastcode(error_traits<T, category>::value_success()),
      _processed_count(0), _total_count(0), _tracer(nullptr),
      _returncode(errorcode_t::success) {
    _discriminant = error_traits<T, category>::is_success;
}

function_pipeline& goahead_if_success() {
    _discriminant = error_traits<T, category>::_discriminant;
    return *this;
}

function_pipeline& goahead_if_not_fail() {
    _discriminant = error_traits<T, category>::is_not_fail;
    return *this;
}
```

The same class uses `_discriminant` as a function pointer of type `bool (*)(T)`; `passed()`, `failed()`, and the runner's continuation checks depend on that selected predicate. The `error_traits` predicates are therefore behavior selectors, not data fields.

The checked `sdk/base/system/error.hpp` defines `is_success(code)` and `is_not_fail(code)` on its `error_traits` specializations. The `function_pipeline.hpp` constructor already selects `is_success`, which makes the use of `error_traits<T, category>::_discriminant` in `goahead_if_success()` stand out as inconsistent.

## Current understanding

### Confirmed in the checked snapshot

1. The constructor initializes `_discriminant` to `error_traits<T, category>::is_success`.
2. `goahead_if_success()` assigns `error_traits<T, category>::_discriminant`.
3. `goahead_if_not_fail()` assigns `error_traits<T, category>::is_not_fail`.
4. The selected predicate controls `passed()`, `failed()`, processed-count updates, and whether subsequent pipeline steps run.
5. The source is still present in the checked `master` snapshot at the commit listed above. This does not establish whether another local or unpushed working tree has already changed it.

### Likely correction — confirm before editing

The expected assignment is:

- `goahead_if_success()` → `error_traits<T, category>::is_success`
- `goahead_if_not_fail()` → `error_traits<T, category>::is_not_fail`

This is a proposed correction based on the visible API and constructor, not a claim that the change has been made or tested.

## Behavior path

```text
function_pipeline<T, category>
          |
          | selects predicate
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

The distinction between the two predicates matters for error categories where “not a severe failure” is broader than “success”. Do not assume they are equivalent for every specialization; inspect the relevant specializations and intended API contract.

## Next steps

1. Before editing, fetch the current working source/branch and compare it with the checked master snapshot. The user may have made a source update since this note was prepared.
2. Inspect all relevant `error_traits<T, category>` specializations, especially those used by `function_pipeline`, and confirm the exact predicate signatures and semantics.
3. If the inconsistency remains, make the minimal source correction on a working branch only. Never modify `master`.
4. Check existing tests for `goahead_if_success()` and `goahead_if_not_fail()`. If behavior is not exercised, consider a focused test only if it is useful to this personal project; do not expand into a broad QA exercise.
5. Build/run the relevant existing test target and record the actual result. Do not mark resolved before source and verification results are known.

## History

- **Revision 1107 review:** Recorded the inconsistent assignment and the intended predicate mapping; further source verification was left pending.
- **2026-10-23:** Rechecked `function_pipeline.hpp` and `sdk/base/system/error.hpp` on master commit `98f4185e9631911683cbf214af1d9912e28bba42`. The inconsistent assignment is still visible in that snapshot. No source change or test run was performed as part of creating this note.
