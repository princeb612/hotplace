## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1106                    │
│ Source basis: Revision 1106                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# System testcase coverage and execution status

## 1. What is tested?
This note cross-checks the tests under `test/testcase/base/system/` against the low-level utilities in `sdk/base/system/`. It records (1) what the source visibly checks and (2) what the supplied base test report records. These are separate forms of evidence.

## 2. How is it tested?
1. The testcase-to-module mapping is summarized by the retained source descriptions below.

### Representative flow

2. `testcase_datetime.cpp` checks time conversions and comparisons, including normalized nanosecond results from `time_diff()` and `time_sum()`. `testcase_shared.cpp` checks reference-count transitions and destructor counts. These are distinct test flows: the first checks numeric/time results, while the second observes ownership behavior through object lifetime. The table below maps the remaining source files and notes where assertions are weaker.

## 3. What does the evidence establish?
### Source-level evidence
#### Test-to-module map
| Test source | Main behavior visible in source | Report group evidence |
|---|---|---:|
| `testcase_bignumber.cpp` + `testvector_bignumber.cpp` | Integer construction, arithmetic, bit operations, modular exponentiation and boundary cases; several categories are also reported separately. | See categories below |
| `testcase_capacity.cpp` + `testvector_capacity.cpp` | Signed/unsigned byte capacity and minimum width cases. | `byte capacity`: 21 pass |
| `testcase_datetime.cpp` | Time conversion and comparisons; `time_diff()` and `time_sum()` explicitly check normalized nanosecond results. | `datetime`: 10 pass |
| `testcase_endian.cpp` | Explicit expected-value checks for 16/32/64-bit conversion and optional 128-bit conversion; endian detection is asserted. | `endian`: 7 pass |
| `testcase_floatingpoint.cpp` + `testvector_floatingpoint.cpp` | Expected decimal/rational results and arithmetic cases, including conversion/error branches. | `floating point`: 92 pass |
| `testcase_ieee754.cpp` | Type classification, `frexp`, formatting, compact representation and conversion assertions for half/single/double formats. | `ieee754`: 184 pass |
| `testcase_shared.cpp` | Reference-count transitions and destructor-count checks. | `shared instance`: 8 pass |
| `testcase_signalwait_threads.cpp` | Thread creation, max-concurrency error, running count after wait/termination. Some assertions are unconditional `true` and therefore do not validate the preceding operation's result. | No distinct `signalwait_threads` group identified in the supplied report excerpt |

### Evidence status and limitations
#### Report-derived categories
1. The supplied `test/testcase/base/report` includes the following system-related groups. Counts below are copied from the report's category summary; they are result counts, not counts of unique test functions.

| Report group | pass | expt | fail | skip | triv |
|---|---:|---:|---:|---:|---:|
| `bignumber` | 294 | 0 | 0 | 0 | 0 |
| `bignumber string` | 10 | 0 | 0 | 0 | 0 |
| `bignumber arithmetic operations` | 81 | 0 | 0 | 0 | 0 |
| `bignumber intminmax` | 30 | 0 | 0 | 0 | 0 |
| `bignumber bitwise operations` | 21 | 0 | 0 | 0 | 0 |
| `bignumber negative` | 2 | 0 | 0 | 0 | 0 |
| `bignumber modpow` | 13 | 0 | 0 | 0 | 0 |
| `bit_length` | 14 | 0 | 0 | 0 | 0 |
| `byte capacity` | 21 | 0 | 0 | 0 | 0 |
| `unsigned_byte_capacity` | 60 | 0 | 0 | 0 | 0 |
| `signed_byte_capacity` | 40 | 0 | 0 | 0 | 0 |
| `datetime` | 10 | 0 | 0 | 0 | 0 |
| `endian` | 7 | 0 | 0 | 0 | 0 |
| `floating point` | 92 | 0 | 0 | 0 | 0 |
| `ieee754` | 184 | 0 | 0 | 0 | 0 |
| `shared instance` | 8 | 0 | 0 | 0 | 0 |

2. The report also contains other `base` groups that are outside this system-specific table. Do not treat the table above as the total for `/test/testcase/base`. The report itself does not identify the OS, compiler, build configuration, or source revision, so those details are not inferred here.

#### Documentation completeness

3. **Status: Partial.** The primary test files and their broad intent are mapped, and representative assertions have been cross-checked. This is not a line-by-line inventory of every assertion, vector, platform branch, or failure path.

#### Verification completeness

4. **Status: Partial.** Several categories contain explicit expected-value assertions. Coverage is not exhaustive: for example, `testcase_signalwait_threads.cpp` uses unconditional `assert(true, ...)` for the “threads created” and “msleep” messages, which cannot by itself establish that those operations succeeded. This is a source-review observation, not a claim that the test run failed.

#### Runtime execution

5. **Status: Reported pass for the listed report groups.** The supplied `test/testcase/base/report` records the counts shown above, with zero `fail` entries for these groups. This confirms the report's recorded results only; it does not prove complete behavior coverage or establish which source revision and runtime environment produced the report.

## Relationships
### Related implementation notes

- [`sdk/base/system/README.md`](../../../../sdk/base/system/README.md) — system module map.
- [`bignumber.md`](../../../../sdk/base/system/bignumber.md) — arbitrary-width integer implementation.
- [`datetime.md`](../../../../sdk/base/system/datetime.md) — time representation and arithmetic.
- [`endian-and-wire-integers.md`](../../../../sdk/base/system/endian-and-wire-integers.md) — endian and protocol-width integers.
- [`floating_point.md`](../../../../sdk/base/system/floating_point.md) and [`ieee754.md`](../../../../sdk/base/system/ieee754.md) — exact arithmetic vs binary floating-point support.
- [`shared_instance.md`](../../../../sdk/base/system/shared_instance.md) and [`threading-and-synchronization.md`](../../../../sdk/base/system/threading-and-synchronization.md) — ownership and thread coordination.

## References
6. Source paths and report provenance are recorded where available.
