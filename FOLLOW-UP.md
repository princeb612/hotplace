# Data / Behavior Follow-up

This is the cumulative index for the isolated follow-up workspace. Read `FOLLOW-UP-POLICY.md` first at the start of a session.

The index is for navigation and current disposition. Open the linked per-issue file for the full background before starting work. Revision records preserve the historical review context.

## Open items

| ID | Area | Current disposition | Detail record |
|---|---|---|---|
| BASE-002 | `sdk/base/stream` | Verify splitter ownership and borrowed-input lifetime across overloads | [BASE-002.md](BASE001-500/BASE-002.md) |
| BASE-003 | `sdk/base/graph` | Verify callback semantics, traversal results, and source-graph lifetime | [BASE-003.md](BASE001-500/BASE-003.md) |
| BASE-004 | `sdk/base/encoding/encoder_stream` | Verify chunk state, finalization, repeated accessors, and output limits | [BASE-004.md](BASE001-500/BASE-004.md) |
| BASE-005 | `sdk/base/encoding/huffman_coding` | Verify generic versus RFC 7541 decoding and terminal padding | [BASE-005.md](BASE001-500/BASE-005.md) |
| BASE-006 | `sdk/base/nostd` | Verify reserve/commit contract, custom-deleter behavior, and diagram edges | [BASE-006.md](BASE001-500/BASE-006.md) |
| BASE-007 | `sdk/base/system/datetime` | Verify platform clock branches and nanosecond normalization | [BASE-007.md](BASE001-500/BASE-007.md) |
| BASE-008 | `sdk/base/nostd/keyvalue` | Reconfirm possible case-insensitive removal and mapped-type concerns | [BASE-008.md](BASE001-500/BASE-008.md) |
| BASE-009 | `sdk/base/nostd/binary` | Verify `produce()` append return types and `bin_wait_fin` state meaning | [BASE-009.md](BASE001-500/BASE-009.md) |
| BASE-010 | `sdk/base/nostd/containers` | Reconfirm copy-size and assignment-return concerns in `btree` / `avltree` | [BASE-010.md](BASE001-500/BASE-010.md) |
| BASE-011 | `sdk/base/system/floating_point` | Analyze large exponent-gap behavior for both signs and add/subtract | [BASE-011.md](BASE001-500/BASE-011.md) |
| BASE-012 | `sdk/base` revision metadata | Confirm source-basis meaning before changing Revision 1105 labels | [BASE-012.md](BASE001-500/BASE-012.md) |
| BASE-013 | `test/testcase/base/system`, `test/testcase/base/stream` | Focused assertion and stale-comment review | [BASE-013.md](BASE001-500/BASE-013.md) |
| IO-001 | `sdk/io/parser` | Reconcile old parser TODO/architecture notes with current LALR/GLR implementation | [IO-001.md](IO001-500/IO-001.md) |
| IO-002 | `sdk/io/asn.1/loader` | Recheck historical loader/PKIX/compiler roadmap against current source and test registration | [IO-002.md](IO001-500/IO-002.md) |
| IO-003 | `test/testcase/asn.1` | Strengthen selected DER round-trip and notation-reconstruction assertions | [IO-003.md](IO001-500/IO-003.md) |
| CRYPTO-001 | `sdk/crypto/jose` | Verify decrypt result contract, mixed-recipient acceptance, and output-buffer behavior | [CRYPTO-001.md](CRYPTO001-500/CRYPTO-001.md) |
| CRYPTO-002 | `sdk/crypto/jose` | Reconcile historical TODO/status matrix; do not treat it as current support status | [CRYPTO-002.md](CRYPTO001-500/CRYPTO-002.md) |
| CRYPTO-003 | `sdk/crypto/authenticode` | Decide digest error propagation contract and add focused failure-path evidence if needed | [CRYPTO-003.md](CRYPTO001-500/CRYPTO-003.md) |
| CRYPTO-004 | `sdk/crypto/authenticode` | Reconcile stale CRL source comment with current retrieval/checking implementation | [CRYPTO-004.md](CRYPTO001-500/CRYPTO-004.md) |
| NET-001 | `sdk/net/http/auth` | Trace RFC 9258 TODO to the owning TLS/PSK component; avoid attributing it to HTTP auth without evidence | [NET-001.md](NET001-500/NET-001.md) |

## Resolved items

| ID | Area | Disposition | Detail record |
|---|---|---|---|
| BASE-001 | `sdk/base/basic/function_pipeline` | Predicate selection corrected in Revision 1108; no new test or test run claimed in follow-up | [BASE-001.md](BASE001-500/BASE-001.md) |

## Maintenance

- Per-issue files are the starting point for work; the revision overview records the historical review context.
- Re-check current source before carrying a finding into a newer revision.
- Remove resolved items from this open list only after verification; retain history in issue and revision records.
- This is a personal continuity aid, not a QA audit or product documentation.
