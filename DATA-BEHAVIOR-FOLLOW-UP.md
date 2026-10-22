# Data / Behavior Follow-up

This is the cumulative index for the isolated follow-up workspace. Read `FOLLOW-UP-POLICY.md` first at the start of a session.

The index is for navigation and current disposition; open the per-issue file for the full background before starting work. Revision records preserve the historical review context.

## Open items

| ID | Area | Current disposition | Detail record |
|---|---|---|---|
| BASE-001 | `sdk/base/basic/function_pipeline` | Recheck predicate selection against the current source; inconsistent assignment confirmed in checked master snapshot `98f4185e9631911683cbf214af1d9912e28bba42` | [BASE-001.md](BASE001-500/BASE-001.md) |
| BASE-002 | `sdk/base/stream` | Verify splitter ownership and borrowed-input lifetime | [Revision 1107 context](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-002--stream-splitter-lifetime) |
| BASE-003 | `sdk/base/graph` | Verify visitor signatures, callback semantics, pointer ownership and graph lifetime | [Revision 1107 context](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-003--graph-visitor-contracts) |
| BASE-004 | `sdk/base/encoding/encoder_stream` | Verify chunk state and finalization behavior | [Revision 1107 context](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-004--encoder_stream-finalization) |
| BASE-005 | `sdk/base/encoding/huffman_coding` | Verify generic and RFC 7541 decode/padding behavior separately | [Revision 1107 context](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-005--huffman-decoding) |
| BASE-006 | `sdk/base/nostd` | Verify overview diagram edges, encoder reserve/commit, and custom-deleter semantics | [Revision 1107 context](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-006--nostd-overview-diagram) |
| BASE-007 | `sdk/base/system/datetime` | Verify platform clock paths and time normalization | [Revision 1107 context](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-007--datetime-platform-paths) |
| BASE-008 | `sdk/base/nostd/keyvalue` | Reconfirm possible case-insensitive removal and mapped-type issues before deciding on a source change | [Revision 1107 context](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-008--keyvalue) |
| BASE-009 | `sdk/base/nostd/binary` | Verify `produce()` append return types and the role of `bin_wait_fin` | [Revision 1107 context](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-009--binary-produce-and-bin_wait_fin) |
| BASE-010 | `sdk/base/nostd/containers` | Reconfirm copy-size and assignment-return concerns in `btree` / `avltree` | [Revision 1107 context](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-010--btree-and-avltree-special-members) |
| BASE-011 | `sdk/base/system/floating_point` | Verify extreme exponent-gap arithmetic for both signs and add/subtract | [Revision 1107 context](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-011--floating-point-extreme-gap) |
| BASE-012 | `sdk/base` revision metadata | Compare Revision 1105 labels with the source snapshot before changing them | [Revision 1107 context](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-012--source-basis-metadata) |

## Maintenance

- Per-issue files are the work starting point. The revision overview is a historical source for items not yet expanded into a detail file.
- When an item is selected for work, expand its per-issue file before making source changes; don't make the user reconstruct missing context from prior chats.
- Re-check current source before carrying a finding into a newer revision.
- Remove resolved items from this open list only after verification; retain the history in the issue and revision records.
- This is a personal continuity aid, not a QA audit or product documentation.
