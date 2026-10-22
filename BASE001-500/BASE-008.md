# BASE-008 — keyvalue removal and mapped-type contract

- **Status:** Open — possible source defect; confirm before changing
- **Area:** `sdk/base/nostd/keyvalue`
- **Historical basis:** Revision 1107 targeted source review. The concerns below must be rechecked against the current source before acting.
- **Source entry point:** [sdk/base/nostd on checked source snapshot](https://github.com/princeb612/hotplace/tree/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/nostd)

## Background

The prior source review raised two independent concerns in the key/value utility: case-insensitive removal may normalize a lookup key differently from the stored index, and `operator[]` may assume that a generic mapped type exposes `c_str()`. These are possible behavior/type-contract issues, not confirmed fixes.

## Observations from the historical review

1. `remove()` reportedly normalizes the input key but searches an index populated with original-case keys.
2. The returned iterator was reportedly dereferenced without first checking for `end()`.
3. `operator[]` reportedly assigns `iter->second.c_str()` to `TYPE`, which may only work for a narrower type set than the template suggests.

## Why it matters

- A case mismatch could make removal fail to find an existing key or produce invalid iterator access for a missing key.
- Dereferencing `end()` can cause undefined behavior.
- A mapped-type mismatch may cause compilation failures for supported-looking instantiations, or indicate that the template contract is narrower than its name suggests.

## Behavior path to verify

```text
remove(requested key)
       |
       v
normalize key?
       |
       v
lookup index
       |
       +--> found: erase intended entry
       |
       +--> not found: defined no-op/error?
```

## Questions to settle

1. Is the index itself normalized on insertion, or are original-case keys retained?
2. Is case-insensitive behavior a stated contract or only an implementation detail?
3. What is the documented behavior when removing an absent key?
4. Is iterator validity checked before dereference?
5. Which `TYPE` instantiations are intended for `operator[]`? Is the `.c_str()` assignment valid for all of them?
6. Are there existing tests for mixed-case insertion/removal and missing keys?

## Next steps

Re-open the current header and trace insertion, lookup, removal, and `operator[]` together. If the concern remains, discuss the smallest useful fix with the user before editing source. Add a focused test only if it helps demonstrate the intended API behavior. Do not silently treat this as a docs-only change.

## History

- **Revision 1107 review:** Recorded as a possible source concern requiring user notification before a docs-only disposition.
- **No source change or test run recorded.**
