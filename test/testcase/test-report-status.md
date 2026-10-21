# Test Report Snapshot

## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1105
Documentation basis: report snapshot received 2026-10-17
Tested source revision: not identified by report files
Documented with GPT-6
Scope: report summary and provenance limits
```

## Scope and provenance

This document summarizes the per-directory `report` files supplied in `testcase-reports.zip`, generated after the user ran CTest. It records that report snapshot only; it is not a permanent claim about later runs.

- Report snapshot received: 2026-10-17; the separately uploaded archive `ttestcase-reports-revision1105-working.zip.zip` was received on 2026-10-18.
- Test command: the user reports that CTest was run before collecting the reports.
- **Last test run association:** the accompanying conversation identifies the report run as MinGW64/GCC for source revision 1104. Treat this as user-supplied run context, not as metadata independently encoded in each report.
- **Archive label:** `revision1105-working` identifies the working snapshot/package context; it must not be used by itself to claim the tests ran against revision 1105.
- The report files themselves do not embed a verifiable source commit/revision. Therefore the exact tested source revision remains **not independently identified by the report files**.
- OS/compiler/build details: MinGW64/GCC is the associated run context; exact GCC version, build flags, and CTest command line are **not recorded in the supplied reports**.
- Current documentation/source-tree bundle revision: 1105. This is distinct from the last test-run association above.
- The table below sums the `pass`, `expt`, `fail`, `skip`, and `triv` values from each report's `brief` section. These labels are preserved as emitted by the test harness; `expt` is not reinterpreted here.

## Per-directory report summary

| Test directory | pass | expt | fail | skip | triv | Note |
|---|---:|---:|---:|---:|---:|---|
| `asn.1` | 1,628 | 40 | 0 | 0 | 0 | Categorized entries present |
| `base` | 1,718 | 13 | 0 | 1 | 1 | `stream`: 27 pass; `bufferio`: 30 pass |
| `cbor` | 251 | 0 | 0 | 0 | 0 | Categorized entries present |
| `cose` | 2,013 | 0 | 0 | 2 | 0 | Categorized entries present |
| `crypto` | 4,214 | 281 | 0 | 90 | 0 | Categorized entries present |
| `encode` | 215 | 0 | 0 | 0 | 0 | Categorized entries present |
| `io` | 596 | 0 | 0 | 0 | 0 | Categorized entries present |
| `jose` | 295 | 0 | 0 | 0 | 2 | Categorized entries present |
| `net` | 268 | 1 | 0 | 0 | 0 | Categorized entries present |
| `odbc` | 0 | 0 | 0 | 0 | 0 | Report says `# pass 0`; no `brief` category rows |
| `quic` | 241 | 0 | 0 | 0 | 2 | Categorized entries present |
| `tls` | 17,664 | 1 | 0 | 0 | 0 | Categorized entries present |
| **Total of categorized entries** | **29,103** | **336** | **0** | **93** | **5** | **29,537 categorized entries** |

The totals are arithmetic sums of the report summaries, not counts of unique test functions. A report may contain multiple checks per test function. The `odbc` report has no categorized rows and is not included in the categorized-entry total.

## Interpretation

- The supplied reports contain **zero entries classified as `fail`** in their `brief` summaries.
- The reports also contain `expt`, `skip`, and `triv` entries. Their meanings should be interpreted according to the test harness rather than assumed from the labels alone.
- A zero `fail` count does not mean every check was a conventional pass; the other categories remain visible in the table.
- Report-level success does not by itself establish verification completeness. That remains a source-level assessment of what the tests actually assert.
- The reports establish the counts below, while the associated conversation supplies MinGW64/GCC and Revision 1104 as the last-run context. The report payload itself does not prove the tested commit or exact build configuration.
- Preserve this snapshot until a newer report set is supplied. Do not empty or replace these results merely because a newer documentation/source revision exists.
- For the next run, record the source revision/commit, environment and compiler version, build configuration, CTest command, date, and report archive name beside the new summary. Add a new dated snapshot rather than overwriting the prior record.

## Related testcase documentation

- [Stream testcases](base/stream/testcase_stream.md)
- [Buffer I/O testcases](base/stream/testcase_bufferio.md)

## Detailed testcase notes added in Edition.1

- Base stream: [`testcase_stream.md`](base/stream/testcase_stream.md) and [`testcase_bufferio.md`](base/stream/testcase_bufferio.md).
- Base string: [`testcase_string.md`](base/string/testcase_string.md), including assertion-strength analysis and the `string` report group result.

