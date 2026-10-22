## Publication

```text
hotplace source tree
Edition 2 · Revision 1106
Source basis: Revision 1106
Documented with GPT-6
— source structure, implementation & tests
```

# System and numeric utility testcases

## 1. What

This directory covers numeric and system-oriented facilities under [`sdk/base/system`](../../../../sdk/base/system/README.md): big-number arithmetic, integer bit/byte capacity, floating-point calculations, IEEE-754 representation and conversion, endian handling, date/time arithmetic, shared-instance ownership, and thread coordination.

The tests use different verification styles. Some compare exact numeric or byte-level results. Others inspect reference counts or destructor counters. Some paths mostly log output and use unconditional assertions. Platform/compiler guards and the optional `-thread` command-line option also affect which cases run.

## 2. How

### 2.1 Bit length, byte capacity, big-number arithmetic, and floating point

1. [`testcase_capacity.cpp`](testcase_capacity.cpp) checks `bit_length()` with explicit values across 16-, 32-, and 64-bit unsigned types. Examples include 0 → 0 bits, 1 → 1, 5 → 3, 255 → 8, 256 → 9, 1024 → 11, and `0x100000000` → 33. Unsigned `byte_capacity()` cases include `0x80` → 1 byte, `0x800` → 2, `0x80000` → 3, and `0x8000000` → 4. Signed cases check both sides of sign boundaries: 127 and -128 need 1 byte, 128 and -129 need 2, 32767 and -32768 need 2, and 32768 and -32769 need 3. Every listed table entry is compared with an expected integer.

2. [`testcase_bignumber.cpp`](testcase_bignumber.cpp) combines table-driven arithmetic with fixed boundary examples. The arithmetic table compares add, subtract, multiply, divide, modulo, left shift, and right shift against expected decimal strings; when `__SIZEOF_INT128__` is defined, corresponding native 128-bit results are also checked. Separate examples compare big-number operations with known large decimal results, check signed remainder cases (`-7 % 3` expects `-1`; `7 % -3` expects `1`), exercise signed/unsigned width boundaries, and compare bitwise AND/OR/XOR results with native integer operations for the selected inputs. The conditional native-128-bit checks are not available on every compiler, and these vectors do not establish arbitrary-precision coverage for every operand size.

3. [`testcase_floatingpoint.cpp`](testcase_floatingpoint.cpp) checks arithmetic using both `floating_point` values and decimal-string inputs. The string path formats the operands and result, compares the result string with the expected string, and records a failure when conversion/operation processing reports an error. The selected cases cover the table's operations and inputs; the group name alone does not establish exhaustive rounding-mode, precision-boundary, or exceptional-value coverage.

### 2.2 Endian conversion: compare byte-order values

1. In [`testcase_endian.cpp`](testcase_endian.cpp), `test_convert_endian()` checks 16-bit and 32-bit values by comparing `convert_endian()` with `htons()` and `htonl()`. The 64-bit cases use fixed hexadecimal pairs such as `0123456789ABCDEF` and `EFCDAB8967452301`, then assert that `hton64(input)` equals the expected reversed-byte value.

2. When `__SIZEOF_INT128__` is defined, the test repeats this pattern for 128-bit values. That path is compiler-gated and cannot be assumed to run everywhere. `test_is_endian()` also checks the detected endian macro path, but the source's supported macro definitions determine which branch is selected.

3. The dump of the source and expected values is diagnostic; the equality assertion is the actual expected-result check.

### 2.3 Date/time arithmetic: exact normalized timespec values

1. In [`testcase_datetime.cpp`](testcase_datetime.cpp), the `datetime` helper applies a `timespan_t(3, 30, 111)` to several constructions of a date/time value: a default `datetime`, a `timespec` round trip, a local-time structure round trip, a system-time conversion, and a timestamp-based construction. `do_apply_timespan()` adds then subtracts the same span and compares the restored value with the original using both equality and inequality operations.

2. The `timespec` test uses explicit nanosecond values. For `ts1 = 1.999999999` and `ts2 = 2.899999999`, `time_diff()` is expected to produce `0 seconds, 900000000 nanoseconds`. Summing four slices is expected to produce `7 seconds, 777777777 nanoseconds`. Those two exact comparisons provide stronger evidence than the printed timestamp samples.

### 2.4 IEEE-754 classification, decomposition, formatting, and shortest-width encoding

1. [`testcase_ieee754.cpp`](testcase_ieee754.cpp) contains five distinct checks; they should not be collapsed into a single floating-point test description.

1. **Classification:** separate tables for 16-bit half, 32-bit single, and 64-bit double representations compare `ieee754_typeof()` with the expected category. Each table includes positive zero, negative zero, `1.0`, positive infinity, negative infinity, and canonical, quiet, and signaling NaN encodings. For example, half `0x0000` and `0x8000` both classify as zero, while the library's infinity and NaN encodings must classify into their corresponding categories.
2. **Exponent decomposition:** for both `float` and `double`, the input table is `0, ±1, ±1.5, ±2, ±4,` and `±0.00006103515625`. The test compares sign, exponent, and mantissa from `ieee754_exp()` with the sign and `frexp()` result computed by the standard library. The comparison is exact for the selected values.
3. **Text formatting:** `basic_stream::printf()` formats zero, negative zero, positive/negative infinity, and three NaN encodings for both single and double precision. The result is compared with fixed strings, including `0.000000`, `-0.000000`, `inf`, `-inf`, and `nan`.
4. **Smallest representation:** `ieee754_as_small_as_possible()` is tested with values such as `0.0`, `±1.0`, `±1.5`, `±2.0`, `±4.0`, `0.00006103515625`, and `5.960464477539063e-8`. The test compares the selected 16-bit result with the expected half encoding. The logged text and binary dump are not the assertion oracle.
5. **Cross-width conversion:** a table supplies decimal text and expected half/single/double bit patterns for exact values, signed zero, infinities, NaN, overflow/loss examples, subnormal values, recurring fractions, and values such as `±4.1`. The code checks selected fp32-to-fp16, double-to-single, and shortest-representation outcomes. Round-trip assertions from half precision are performed only for rows marked `loss == false`; lossy rows deliberately do not assert a reversible half-to-single/double conversion.

2. The tables make important representation boundaries visible, but they are selected examples rather than exhaustive coverage of all NaN payloads, rounding modes, or every representable value.

### 2.5 Shared-instance ownership

1. [`testcase_shared.cpp`](testcase_shared.cpp) uses destructor counters and reference-count observations rather than relying only on logs.

- In `test_sharedinstance1()`, constructing `simple_instance1` starts at reference count 1. `addref()` is expected to return 2, the first `release()` returns 1, and the second returns 0 and deletes the instance. The test then checks that the destructor counter is 1.
- In `test_sharedinstance2()`, a `t_shared_instance` takes ownership of a newly allocated object. The test checks the reference count before and after move construction into `inst2`, then checks that leaving scope caused exactly one destructor call.

2. These assertions cover the selected retain/release and move/lifetime sequences, not every misuse or concurrent ownership scenario.

### 2.6 Thread coordination and execution guards

1. [`testcase_signalwait_threads.cpp`](testcase_signalwait_threads.cpp) configures a `signalwait_threads` object for four workers. Each worker enters `thread_routine()`, logs that it started, and blocks on a shared semaphore with an indefinite wait (`wait(-1)`). The configured signal callback calls `_mutex->signal()`.

2. The test then performs this sequence:

1. Calls `create()` four times to fill the configured concurrency limit. The following `assert(true, "threads created")` is unconditional: it does not verify the result of each creation.
2. Calls `create()` once more and explicitly checks that it returns `errorcode_t::max_reached`.
3. Sleeps for three seconds, then calls `join()` to let the configured signal/join behavior release the waiting workers.
4. Calls `signal_and_wait_all()` and checks that `threads.running()` is zero afterward.

3. The final running-count assertion and the fifth-create error assertion are the substantive result checks. The “threads created” and “msleep” assertions only mark that execution reached those points; the sleep itself is timing, not synchronization evidence. The test exercises one configured limit (four), one over-limit attempt, and the selected wait/signal/join path; it does not establish behavior for every concurrency limit or failure timing.

4. At the suite entry point, this testcase is invoked only when the `-thread` option is supplied. A source-level testcase therefore does not establish that a standard CTest run executed it. Likewise, `__SIZEOF_INT128__` controls the optional 128-bit endian path.

## 3. Evidence

### Source-level coverage

**1. Numeric helpers and endian conversion**

```text
numeric input -> bit length / byte capacity / big-number or FP helper
  -> compare expected number/status

source bytes -> endian conversion -> compare expected bytes/value
  -> selected widths only
```

**2. Date/time and IEEE-754**

```text
timespec operands -> arithmetic/normalization -> compare expected sec + nsec

FP value/bits -> classify / decompose / format / choose encoding width
  -> compare selected fields/text/bytes where asserted
  -> diagnostic prints alone are not verification
```

**3. Shared-instance and thread coordination**

```text
acquire/release shared instance -> observe selected state/lifetime checks
thread coordination -> signal/wait scenario -> check only explicit result
```

The aggregate report has no distinct `signalwait_threads` group; do not infer that this path ran from neighboring group results.



The supplied [Test Report Snapshot](../../test-report-status.md) records groups for big-number operations, bit length, byte capacity, datetime, endian, floating point, IEEE-754, and shared-instance behavior. The inspected report does not identify a distinct `signalwait_threads` group, so this README does not claim that its runtime path is represented by those results.

The report does not independently identify the tested source revision, OS, compiler, or complete build configuration. Group outcomes do not establish exhaustive branch or platform coverage.



## 4. Relationships

- [`sdk/base/system/README.md`](../../../../sdk/base/system/README.md) — system module map.
- [`bignumber.md`](../../../../sdk/base/system/bignumber.md), [`datetime.md`](../../../../sdk/base/system/datetime.md), [`endian-and-wire-integers.md`](../../../../sdk/base/system/endian-and-wire-integers.md), [`floating_point.md`](../../../../sdk/base/system/floating_point.md), and [`ieee754.md`](../../../../sdk/base/system/ieee754.md) — numeric and representation models.
- [`shared_instance.md`](../../../../sdk/base/system/shared_instance.md) and [`threading-and-synchronization.md`](../../../../sdk/base/system/threading-and-synchronization.md) — ownership and thread coordination.
- [`testcase_system.md`](testcase_system.md) — supplemental source-to-module notes.
- [Test Report Snapshot](../../test-report-status.md) — report provenance and interpretation limits.

## 5. References

No external reference is required to explain these testcase flows.
