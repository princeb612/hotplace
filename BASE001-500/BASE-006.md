# BASE-006 — nostd overview and reserve/commit contracts

- **Status:** Open — diagram and helper contracts need confirmation
- **Area:** `sdk/base/nostd`
- **Historical basis:** Revision 1107 review; not a full audit of the utilities in this directory.
- **Source entry points:** [encoder traits](https://github.com/princeb612/hotplace/blob/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/nostd/traits_encoder.hpp), [stream reserve/commit](https://github.com/princeb612/hotplace/blob/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/stream/stream.hpp), [basic_stream reserve/commit](https://github.com/princeb612/hotplace/blob/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/stream/basic_stream.hpp)

## Background

The `nostd` overview diagram is intended to help readers navigate independent utility families. It must not accidentally suggest that every box participates in one shared runtime pipeline. Two implementation contracts were also called out for verification: `encoder_stream_traits<T>`'s reserve/commit pair and custom-deleter ownership/release behavior.

## Current understanding

The encoding traits' reserve/commit pattern is described as:
1. determine required output capacity;
2. reserve destination space and obtain a writable pointer;
3. encode into the reserved region;
4. commit the number of bytes actually written, shrinking unused reserved tail space.

The review separately flagged custom-deleter ownership/release behavior as something to trace. No specific ownership defect is confirmed here.

## Behavior path to verify

```text
encoder estimates capacity
          |
          v
traits.reserve(destination, capacity)
          |
          +--> destination grows
          +--> writable region returned
          |
          v
encoder writes bytes
          |
          v
traits.commit(destination, reserved, written)
          |
          +--> unused tail removed
```

## Questions to settle

1. Which types specialize `encoder_stream_traits<T>`, and what is the common contract?
2. Does every reserve implementation return a pointer stable for the duration of the encode call?
3. Is commit called on both success and error paths? What happens if written > reserved?
4. Does commit only adjust logical size, or can it have other side effects?
5. For custom deleters, who owns the resource before and after wrapping, and what exactly does release() relinquish?
6. Does the overview diagram clearly label conceptual relationships versus actual call/data flow?

## Next steps

Check the traits specializations and the Base16/Base64 call sites, then trace representative owning-pointer/custom-deleter types. Make the diagram's arrows precise: use separate navigation/relationship edges where there is no runtime call. Change implementation only if a concrete contract violation is found.

## History

- **Revision 1107 review:** Overview diagram semantics, reserve/commit, and custom-deleter behavior were marked for verification.
- **No source change or test run recorded.**
