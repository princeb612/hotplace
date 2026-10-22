# BASE-007 — datetime platform paths and normalization

- **Status:** Open — platform behavior needs source confirmation
- **Area:** `sdk/base/system/datetime`
- **Basis:** Revision 1107 review. No cross-platform test matrix was run during that documentation pass.
- **Source entry point:** [datetime_api.cpp](https://github.com/princeb612/hotplace/blob/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/system/datetime_api.cpp), [datetime.md](https://github.com/princeb612/hotplace/blob/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/system/datetime.md)

## Background

The datetime helper abstracts wall-clock and monotonic time across operating systems. Documentation discusses platform-specific clock selection, compatibility paths, and normalization of nanoseconds into seconds. The goal is to confirm that the descriptions match the actual compile-time branches and arithmetic.

## What is known

The implementation entry point is `datetime_api.cpp`. The earlier review highlighted realtime versus monotonic clocks, older Linux compatibility, Windows API selection, and nanosecond carry/borrow. These are verification topics, not proof that every platform path is correct or broken.

## Behavior path

```text
datetime request
      |
      v
platform / feature selection
      |
      +--> wall-clock source
      +--> monotonic source
      |
      v
native time fields
      |
      v
normalize seconds + nanoseconds
      |
      v
datetime result
```

## Questions

1. Which API is selected on each platform, and under which conditions?
2. What fallback is used when the preferred API is unavailable?
3. Does documentation state monotonic guarantees without overclaiming?
4. Are negative nanoseconds normalized with borrow and values at least one second with carry?
5. Are Windows and older-Linux paths guarded by appropriate feature checks?
6. Which existing tests cover normalization boundaries separately from API availability?

## Next steps

Trace each platform branch and normalization helper in current source. Compare documentation with what can be established statically; use existing supported environments only where execution checks add value. A single-host test does not verify all platforms.

## History

- **Revision 1107:** Clock selection and normalization were marked for follow-up.
- No source change or platform test run recorded.
