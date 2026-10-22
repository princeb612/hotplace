# BASE-010 — btree / avltree copy and assignment behavior

- **Status:** Open — possible source defects; confirm before editing
- **Area:** `sdk/base/nostd/containers`
- **Historical basis:** Revision 1107 targeted source review. Exact declarations and affected template instantiations need rechecking.
- **Source entry point:** [sdk/base/nostd on checked source snapshot](https://github.com/princeb612/hotplace/tree/98f4185e9631911683cbf214af1d9912e28bba42/sdk/base/nostd)

## Background

The previous review raised concerns about special-member behavior in `btree` and `avltree`: whether copy construction preserves the stored element count and whether assignment operators return the assigned object as their declared signature suggests. These concerns are separate from the correctness of the tree algorithms themselves.

## Observations from the historical review

- `btree` copy construction reportedly initializes `_size` from `other.size` rather than calling `other.size()`.
- `btree` copy/move assignment operators reportedly omit `return *this`.
- `avltree` copy construction reportedly does not copy `_size`.
- `avltree` copy/move assignment operators reportedly omit `return *this`.

Do not assume the exact line-level issue remains in the current source until rechecked.

## Why it matters

- An incorrect element count can make `size()` disagree with the actual tree contents and can affect later insert/erase logic if the count is operational state.
- An assignment operator returning a reference but falling off the end has undefined behavior when the returned reference is used.
- Chained assignment and assignment-expression tests can expose the latter contract.

## Questions to settle

1. What are the exact copy/move constructors and assignment signatures for both tree types?
2. Is `_size` derivable from the tree, or is it maintained as independent state?
3. Do copy operations preserve values, ordering, parent/child links, and count?
4. Do assignment operators return `*this` on all paths?
5. Are self-assignment and empty-tree copies handled?
6. What tests already cover copy/move, erase-after-copy, and chained assignment?

## Next steps

Recheck the current implementation and existing testcase coverage. If confirmed, prefer a minimal correction and a focused test of observable semantics (copied size and assignment result) rather than a broad container audit. Keep tree-invariant testing proportionate to the actual change.

## History

- **Revision 1107 review:** These special-member concerns were recorded for source confirmation.
- **No source change or test run recorded.**
