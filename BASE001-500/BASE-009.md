# BASE-009 — t_binaries produce and bin_wait_fin

- **Status:** Open — source and call-site investigation required
- **Area:** `sdk/base/nostd/binaries`
- **Historical basis:** Revision 1107 targeted source review; compile impact and runtime meaning remain unconfirmed.
- **Source entry point:** [binaries.hpp](https://github.com/princeb612/hotplace/blob/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/nostd/binaries.hpp)

## Background

The earlier review recorded two separate questions: whether `t_binaries::produce()` assigns values from `append()` overloads that return `void`, and what contract the `bin_wait_fin` state represents. They should be investigated separately; an apparently unused flag is not necessarily dead state until consumers and template instantiations are traced.

## Observations from the historical review

- `produce()` reportedly assigns `append(...)` results to `return_t`, while sequential append overloads reportedly return `void`.
- `bin_wait_fin` is reportedly stored/set by `reserve()`, but no consumer was found in the file inspected during that pass.

These statements are inherited observations and must be checked against the current source and all relevant overloads.

## Questions to settle

1. Which `append()` overloads are selected by each `produce()` instantiation, and what do they return?
2. Is the questionable assignment instantiated by current production call sites, or is it a dormant template path?
3. Does `produce()` aggregate multiple binary fragments, return a status, or expose a view?
4. What state transition sets and clears `bin_wait_fin`?
5. Are there consumers outside `binaries.hpp`, including macros, helpers, or template-dependent call paths?
6. What does “fin” mean in the API: complete binary object, flush boundary, or something else?

## Investigation path

```text
caller
  |
  v
reserve / append fragments
  |
  v
t_binaries state (including bin_wait_fin?)
  |
  v
produce()
  |
  +--> return status / assembled output
  +--> any completion-state consumer?
```

## Next steps

Inspect the full header, search all call sites and compile-relevant instantiations, then build the smallest existing target that exercises the relevant template path. Do not change return types or remove `bin_wait_fin` until the intended contract is clear.

## History

- **Revision 1107 review:** Recorded the append return-type concern and an unresolved consumer question for `bin_wait_fin`.
- **No source change or compile/test run recorded.**
