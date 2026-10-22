# Data / Behavior Follow-up — Revision 1107

## Scope and basis

This record captures findings from the 2026-10-23 Data Model / Behavior Model structural pass over the 77 existing Markdown documents under `sdk/base`, plus targeted source checks. It is not a line-by-line source audit and no build/test run was performed for this documentation-only pass.

The documentation pass moved internal indexes and testcase inventories out of model/behavior sections where appropriate; separated mutation behavior from state descriptions; removed repeated/orphaned material; and clarified several Data Model / Behavior Model boundaries. The findings below are the follow-ups worth preserving.

## BASE-001 — function_pipeline

- **Kind:** Source follow-up.
- **Observation:** The reviewed source assigned `error_traits<T, category>::_discriminant` in `goahead_if_success()`, while the error-traits API exposed `is_success` and `is_not_fail` predicates.
- **Current status:** Rechecked against master commit `98f4185e9631911683cbf214af1d9912e28bba42` on 2026-10-23; the inconsistent assignment is still visible there. No source change or test run was performed.
- **Detailed working record:** [BASE-001.md](../BASE001-500/BASE-001.md).
- **Expected correction to verify:** `goahead_if_success()` selects `is_success`; `goahead_if_not_fail()` selects `is_not_fail`. This remains a proposed correction until the relevant specializations and behavior are checked.

## BASE-002 — stream splitter lifetime

- **Kind:** Verify.
- **Observation:** The overview distinguishes `splitter`, which normally owns copied/moved input, from `splitter_noalloc`, which can retain borrowed input; exact lifetime depends on overloads/flags.
- **Next check:** Compare constructors, flags and `run()`; establish whether borrowed input must remain valid through execution and whether overloads change that rule.

## BASE-003 — graph visitor contracts

- **Kind:** Verify.
- **Observation:** Visitor result representation and callback behavior were separated in the docs.
- **Next check:** Verify callback arguments and semantics for adjacency, DFS, BFS and Dijkstra, plus raw-pointer ownership and source-graph lifetime against builder/search APIs.

## BASE-004 — encoder_stream finalization

- **Kind:** Verify.
- **Observation:** Docs describe persistent Base64 tail bytes and Huffman bit state across chunks, finalized through `str()` / `bin()`.
- **Next check:** Verify chunk processing and flush order, repeated finalization calls, pending Base64 bytes, Huffman padding and the stated `_maxsize` limitation.

## BASE-005 — Huffman decoding

- **Kind:** Verify.
- **Observation:** The generic learned Huffman table and fixed RFC 7541 HTTP/2 table are documented as separate paths; decode is described as trie-based and chunk-aware.
- **Next check:** Verify generic decode state and HTTP/2 wrapper padding against implementation and RFC 7541. Do not imply identical padding rules without evidence.

## BASE-006 — nostd overview diagram

- **Kind:** Verify.
- **Observation:** The diagram connects separate utility families and should remain illustrative, not imply one common runtime pipeline.
- **Next check:** Verify each edge against implementation/consumer, especially `encoder_stream_traits<T>` reserve/commit and custom-deleter ownership/release behavior.

## BASE-007 — datetime platform paths

- **Kind:** Verify.
- **Observation:** Docs describe platform-specific realtime/monotonic clocks, older Linux compatibility and nanosecond carry/borrow normalization.
- **Next check:** Verify platform branches, fallback conditions, Windows API selection and normalization against current source.

## BASE-008 — keyvalue

- **Kind:** Source follow-up; notify the user before treating it as documentation-only.
- **Observation in reviewed source:** Case-insensitive `remove()` normalizes a key but searches an index populated with original-case names; the returned iterator is dereferenced without checking `end()`. `operator[]` assigns `iter->second.c_str()` to `TYPE`, which may conflict with generic mapped-type support.
- **Next check:** Reconfirm against current source; decide separately whether a source fix/test is wanted. Useful focused cases: differently-cased removal, absent-key removal, and intended mapped-type contract.

## BASE-009 — binary produce and bin_wait_fin

- **Kind:** Source follow-up; verify compile impact before proposing a fix.
- **Observation in reviewed source:** `t_binaries::produce()` assigns `append(...)` results to `return_t` although the sequential `append()` overloads reportedly return `void`. `bin_wait_fin` is stored/set by `reserve()`, but no consumer was identified in the inspected file.
- **Next check:** Inspect call sites and instantiate affected overloads; establish what `bin_wait_fin` guarantees before documenting it as a complete-message signal.

## BASE-010 — btree and avltree special members

- **Kind:** Source follow-up.
- **Observation in reviewed source:** `btree` copy construction reportedly initializes `_size` with `other.size` rather than `other.size()`; its copy/move assignment operators omit `return *this`. `avltree` copy construction reportedly fails to copy `_size`; its copy/move assignments also omit `return *this`.
- **Next check:** Reconfirm current source and existing tests; decide whether focused copy/move tests and source fixes are warranted.

## BASE-011 — floating-point extreme exponent gap

- **Kind:** Source/behavior verification.
- **Observation in reviewed source:** `floating_point.cpp` uses `MAX_PRECISION = 1024` as a fallback for large exponent differences; the extreme-gap paths may not preserve general exact arithmetic.
- **Next check:** Verify mathematically and against boundary behavior for both signs of exponent difference and for both addition and subtraction. Keep documented limitations explicit unless corrected and retested.

## BASE-012 — source-basis metadata

- **Kind:** Documentation/source-basis verification.
- **Observation:** The following docs were observed with Revision 1105 source-basis labels while nearby docs used Revision 1107: `sdk/base/README.md`, `basic/crc.md`, `c++14.md`, `callback.md`, `charset.md`, `error.md`, `inline.md`, `nostd/README.md`, `nostd/memory.md`, `nostd/string_set.md`, `nostd/traits.md`, `stream.md`, `system/datetime.md`, `system/endian-and-wire-integers.md`, `system/error-handling.md`, `system/ieee754.md`, `system/threading-and-synchronization.md`, `trace.md`, `types.md`.
- **Next check:** Compare each with the source snapshot actually documented. Do not homogenize revision labels without that comparison.

## Documentation edits made during this pass

- Moved internal focused-document indexes into Relationships in `nostd/README.md` and `system/README.md`.
- Moved registration mutation details into Behavior Model in `basic/cmdline.md`; moved `execparam` mutation semantics into Behavior Model in `system/process.md`.
- Moved testcase inventories/results out of Behavior Model in `encoding/base16.md`, `basic/valist.md`, `basic/variant.md`, `basic/dump_memory.md`, `graph/graph.md`, `graph/gss.md`, `system/datetime.md`, `system/endian-and-wire-integers.md`, and `system/floating_point.md`.
- Separated CRC's cross-module relationship from Data Model in `basic/crc.md`; moved Base64 group processing and log-level conversion into Behavior Model in `encoding/base64.md` and `types.md`.
- Removed repeated/orphaned content in `basic/dump_memory.md`, `nostd/range.md`, `nostd/range_set.md`, `stream/README.md`, and `stream/basic_stream.md`; separated logger buffer state from flush behavior in `unittest/logger.md`.
- Removed redundant status/rationale subsections in `system/ieee754.md` and `system/floating_point.md`.

## Session boundary

These are follow-up notes, not claims that every item is a confirmed defect. Recheck the source before carrying an item forward or asking the user to change code.
