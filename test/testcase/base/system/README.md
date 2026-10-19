## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# System and numeric utility testcases

## 1. Role

### Scope

This directory contains test sources and data for the `sdk/base/system` utilities. This page identifies the test files; [`testcase_system.md`](testcase_system.md) explains the covered behaviors and records the report evidence.

## 2. Test model

The testcase-to-module mapping is summarized by the retained source descriptions below.

## 3. Example: representative testcase flow

No standalone example was identified in the existing material; see source-level coverage for representative testcase functions.

## 4. Test and verification status

### 4.1 Source-level coverage

#### Test sources

- `testcase_bignumber.cpp` and `testvector_bignumber.cpp` — arbitrary-width integer behavior.
- `testcase_capacity.cpp` and `testvector_capacity.cpp` — byte-capacity and integer-width boundaries.
- `testcase_datetime.cpp` — time conversion and `timespec` arithmetic.
- `testcase_endian.cpp` — host/network byte-order conversion and endian detection.
- `testcase_floatingpoint.cpp` and `testvector_floatingpoint.cpp` — decimal/rational arithmetic cases.
- `testcase_ieee754.cpp` — IEEE-754 classification, conversions, and formatting.
- `testcase_shared.cpp` — reference count and object lifetime behavior.
- `testcase_signalwait_threads.cpp` — thread-group creation, capacity failure, and termination.

#### Test data

- `testvector_bignumber.yml`
- `testvector_capacity.yml`
- `testvector_floatingpoint.yml`

The exact assertions and supported branches remain defined by the source files. A report group marked `pass` does not imply every possible input or platform-specific path is covered.

### 4.2 Documentation and verification status

Documentation completeness, assertion strength, and recorded runtime execution are separate claims. State each only when supported by source or report evidence.

## 5. Relationships

Related implementation modules and testcase documents are listed in References where available.

## 6. References

Source paths and report provenance are recorded where available.
