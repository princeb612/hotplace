# Data / Behavior Follow-up

This is the cumulative index for the isolated follow-up workspace. Read `FOLLOW-UP-POLICY.md` first at the start of each session.

The detailed observations for the first review pass are in [revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md).

## Open items

| ID | Area | Current disposition | Revision record |
|---|---|---|---|
| BASE-001 | `sdk/base/basic/function_pipeline` | Recheck after the intended source change; branch snapshot had the old discriminant assignment | [1107](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-001--function_pipeline) |
| BASE-002 | `sdk/base/stream` | Verify splitter ownership and borrowed-input lifetime | [1107](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-002--stream-splitter-lifetime) |
| BASE-003 | `sdk/base/graph` | Verify visitor signatures, algorithm callback semantics, pointer ownership and graph lifetime | [1107](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-003--graph-visitor-contracts) |
| BASE-004 | `sdk/base/encoding/encoder_stream` | Verify chunk state and finalization behavior | [1107](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-004--encoder_stream-finalization) |
| BASE-005 | `sdk/base/encoding/huffman_coding` | Verify generic and RFC 7541 decode/padding behavior separately | [1107](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-005--huffman-decoding) |
| BASE-006 | `sdk/base/nostd` | Verify illustrative diagram edges, encoder reserve/commit, and custom-deleter semantics | [1107](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-006--nostd-overview-diagram) |
| BASE-007 | `sdk/base/system/datetime` | Verify platform clock paths and time normalization | [1107](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-007--datetime-platform-paths) |
| BASE-008 | `sdk/base/nostd/keyvalue` | Source concern: case-insensitive remove lookup/end check and mapped-type contract | [1107](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-008--keyvalue) |
| BASE-009 | `sdk/base/nostd/binary` | Source concern: `produce()` return assignments and meaning/consumption of `bin_wait_fin` | [1107](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-009--binary-produce-and-bin_wait_fin) |
| BASE-010 | `sdk/base/nostd/containers` | Source concern: `t_btree` / `t_avltree` copy size and assignment return values | [1107](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-010--btree-and-avltree-special-members) |
| BASE-011 | `sdk/base/system/floating_point` | Verify extreme exponent-gap arithmetic for both signs and add/subtract | [1107](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-011--floating-point-extreme-gap) |
| BASE-012 | `sdk/base` revision metadata | Compare listed Revision 1105 labels with the source snapshot before changing them | [1107](revision-1107/DATA-BEHAVIOR-FOLLOW-UP.md#base-012--source-basis-metadata) |

## Maintenance

- Re-check against the actual source before carrying an item into a newer revision.
- Keep this table concise and current; details belong in the revision record.
- Remove resolved items from this open list after verification, retaining historical context in the revision record.
- This is a personal working aid, not a QA audit or project documentation.
