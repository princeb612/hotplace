## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Base basic testcase analysis

## 1. Role

This document records what the base-basic tests exercise and what the supplied report establishes. It is not a replacement for the implementation documents under `sdk/base/basic/`.

### Test sources and purpose

| Source | Observed purpose |
|---|---|
| `testcase_builtinmemory.cpp` | Allocation/deallocation, reallocation, free-list integrity, STL compatibility, exhaustion, and allocation policy cases are represented in the report. |
| `testcase_cmdline.cpp`, `testvector_cmdline.*` | Positive and negative command-line parsing cases. |
| `testcase_dumpmemory.cpp` | String, `binary_t`, and blank-memory dump output cases. |
| `testcase_pipeline.cpp` | Pipeline execution, error propagation, and platform-specific errno paths. |
| `testcase_valist.cpp`, `testvector_valist.*` | Stored argument formatting and `va_list`-related behavior. |
| `testcase_variant.cpp` | Base16 and numeric/bignumber conversions, including formatted output. |

## 2. Test model

The directory covers small shared facilities: builtin memory allocation, command-line parsing, memory dumps, function pipelines, dynamic `va_list` formatting, and `variant` conversions. The testcase sources and vector files are the primary evidence for the cases listed here.

```text
implementation headers / sources
             │
             ▼
test/testcase/base/basic/*
             │
             ▼
expected values, return codes, and diagnostic output
             │
             ▼
base/report (aggregated execution record)
```

## 3. Example: representative testcase flow

This document does not duplicate a standalone program. The representative testcase functions and their assertion strength are described under Source-level coverage.

## 4. Test and verification status

### 4.1 Source-level coverage

#### Source-level verification notes

- The report lists `cmdline` with 12 successful cases, `valist` with 41, and `variant` with 7. These are report case counts, not counts of distinct C++ test functions.
- The report lists `pipeline` as `success 6` with `expt 2`; those categories are retained as reported and are not reinterpreted here.
- The dump-memory report contains cases named `string`, `binary_t`, and `dump blank`.
- Some tests use assertions whose condition is constant `true`; those assertions do not independently validate the logged output. Where that pattern occurs, runtime pass status should not be mistaken for full behavioral coverage.

### 4.2 Documentation and verification status

#### Documentation and verification status

| Axis | Status | Basis |
|---|---|---|
| Documentation completeness | Partial | Main testcase sources and report-visible cases are mapped; not every branch and platform-specific behavior is documented. |
| Verification completeness | Partial | Some cases compare expected values or return codes; diagnostic-only output and constant-true assertions provide weaker evidence. |
| Runtime execution | Report recorded | Supplied `test/testcase/base/report` contains results for this group; environment and source revision are not identified by the report itself. |

#### Source basis

Source and testcase structure reviewed against hotplace revision 1104. Runtime status is based on the supplied report archive; the report does not itself prove that the executable was built from revision 1104.

## 5. Relationships

- Implementation details: [`sdk/base/basic/README.md`](../../../../sdk/base/basic/README.md)
- Related test sources: this directory, especially the six testcase files listed above.
- Execution summary: [`test-report-status.md`](../../test-report-status.md)

## 6. References

Source paths and report provenance are recorded where available.
