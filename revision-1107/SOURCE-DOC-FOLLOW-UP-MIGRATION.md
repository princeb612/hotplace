# Source-document Follow-up Migration — Revision 1107

## Scope

This record captures the 2026-10-23 pass that moved explicit follow-up notes and historical unchecked lists out of normal source-tree documentation into the isolated `follow-up-workspace`. It is a documentation cleanup and issue-continuity record, not a claim that the source findings were fixed or runtime reproduced.

## Records added or expanded

- `BASE-008`, `BASE-009`, and `BASE-010` already tracked the `keyvalue`, `binary`, and tree special-member observations; their duplicated “Development Notes” blocks were removed from the normal source docs.
- `BASE-013` captures focused testcase assertions and two stream testcase comments that need a maintainer decision.
- `IO-001` captures old parser TODOs/architecture alternatives from `sdk/io/parser/parser.md`.
- `IO-002` captures the unchecked ASN.1 loader/PKIX/compiler roadmap from `sdk/io/asn.1/loader/loader-flow.md`.
- `IO-003` captures focused DER round-trip, notation-reconstruction, and selected re-decode testcase candidates from `test/testcase/asn.1/README.md`.
- `CRYPTO-001` captures JOSE decryption result/output and multi-recipient questions.
- `CRYPTO-002` captures the stale JOSE TODO/status checklist; it is not a current support matrix.
- `CRYPTO-003` captures Authenticode digest error propagation.
- `CRYPTO-004` captures the stale Authenticode CRL source-comment mismatch.
- `NET-001` captures the RFC 9258 external-PSK TODO scope question.

## Source-document changes

- Removed the BASE `containers`, `keyvalue`, and `binary` maintainer-review paragraphs after preserving their substantive observations in the existing/new BASE records.
- Removed the old parser TODO and recommended-architecture sections from `sdk/io/parser/parser.md`; retained the external references.
- Removed the unchecked loader TODO list from `sdk/io/asn.1/loader/loader-flow.md` and moved the compact Runtime/Compiler/Schema Loader/Repository checklist out of the ASN.1 testcase README into IO-002.
- Removed the ASN.1 testcase reinforcement candidate subsection from `test/testcase/asn.1/README.md`; retained its What/How/Evidence narrative and supplied-report context.
- Removed JOSE decryption discrepancy/test-gap prose from the normal JOSE README and the historical TODO checklist from `jose-overview.md`; renamed that file heading to the agreed `Developer Notes - ...` convention for its remaining historical material.
- Removed the RFC 9258 TODO mention from the HTTP authentication README.
- Removed Authenticode’s “revisit” wording while retaining the current source behavior statement about unchecked digest return status.
- Removed small maintainer-only comments from stream testcase docs after recording them in BASE-013.
- Removed a stale link in `test/testcase/base/README.md` to a reinforcement-candidates file that could not be found in the reviewed branch.

## Verification boundary

No source code changed. No build or tests were run. Findings remain open/recheck until the corresponding per-issue record is revisited against current source and useful verification.
