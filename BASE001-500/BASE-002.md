# BASE-002 — stream splitter ownership and lifetime

- **Status:** Open — source contract needs confirmation
- **Area:** `sdk/base/stream`
- **Historical basis:** Revision 1107 Data Model / Behavior Model review. The concern below is carried forward from that review; it is not a claim that every overload has been rechecked against the current source.
- **Source entry points:** [splitter.hpp](https://github.com/princeb612/hotplace/blob/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/stream/splitter.hpp), [split.hpp](https://github.com/princeb612/hotplace/blob/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/stream/split.hpp), [stream overview](https://github.com/princeb612/hotplace/blob/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/stream/README.md)

## Background

The stream overview distinguishes the ordinary `splitter` from the `splitter_noalloc` mode. The important question is not just how segments are emitted, but whether the splitter owns the input bytes or keeps references into caller-owned storage. That affects safe usage when input buffers are temporary, reused, or modified before `run()`.

## Current understanding

- `splitter` is documented as the general descriptor-aware segmentation helper.
- `splitter_noalloc` is represented by a flag in `split.hpp`; the review notes indicate that this mode may retain borrowed input rather than copying it.
- The exact ownership rule may depend on the overload used by `add()`, the flag, and when `run()` consumes the stored segments. Do not infer one rule for every overload without checking the implementation.

## Behavior path to verify

```text
caller buffer
    |
    +--> add(input, flags)
             |
             +--> owning path: copy/move bytes into splitter-owned storage
             |
             +--> no-allocation path: retain pointer/view to caller storage
                         |
                         v
                    run(callback)
                         |
                         +--> callback receives fragment + descriptor
```

## Questions to settle

1. Which constructors and `add()` overloads copy, move, or borrow the input?
2. Does `splitter_noalloc` require the caller's memory to remain valid and unchanged until `run()` finishes?
3. Are descriptors owned/copied, or can they also be borrowed?
4. What happens when fragments are added after a previous `run()`? Does `run()` consume, clear, or preserve queued state?
5. Are there tests that make the lifetime distinction explicit?

## Next steps

Read the current `splitter.hpp` and related types, trace `add()` to `run()`, then compare the contract with existing testcase usage. If the behavior is correct but easy to misuse, clarify the source-tree documentation. Change code only if a concrete lifetime or ownership defect is confirmed.

## History

- **Revision 1107 review:** Ownership distinction and lifetime were identified as worth verifying.
- **No fix or test run recorded.** Recheck current source before acting.
