## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# System-level utilities and numeric types

## 1. Role

` sdk/base/system ` provides low-level numeric, time, byte-order, synchronization, ownership, error-reporting, and tracing facilities used by higher SDK layers. It is not one single abstraction: the modules have separate responsibilities and should be read through their focused notes.

## 2. Model

The component model is described by the implementation and retained subsections below.

## 3. Important behavior and lifetime

### Module notes

- [Big number](bignumber.md) — arbitrary-width integer representation and operations.
- [Date and time](datetime.md) — `timespec`-centered time representation, conversions, and clocks.
- [Endian and wire integers](endian-and-wire-integers.md) — byte order and non-native wire widths such as 24- and 48-bit integers.
- [Error handling](error-handling.md) — adapters between hotplace return codes and external error conventions.
- [Floating point](floating_point.md) — exact decimal/rational arithmetic built on `bignumber`.
- [IEEE-754](ieee754.md) — floating-point classification, conversion, and formatting helpers.
- [Shared instances](shared_instance.md) — project-specific reference-counted ownership helpers.
- [Threading and synchronization](threading-and-synchronization.md) — platform thread, semaphore, critical-section, and signal/wait abstractions.
- [Trace](trace.md) — category-aware debug events and control-flow tracing.

### Tests

The corresponding source tests and vectors are under [`test/testcase/base/system/`](../../../test/testcase/base/system/README.md). The source-level coverage and report-derived execution summary are documented in [the system testcase note](../../../test/testcase/base/system/testcase_system.md). The broader base report is summarized separately at [`test-report-status.md`](../../../test/testcase/test-report-status.md).

## 4. Example from the source tests

See the source-test references below; do not infer runtime execution from source presence alone.

## 5. Relationships

```text
base/system
  ├─ bignumber ──> decimal_float / rational_float / floating_point
  ├─ endian + uint24_t/uint48_t ──> protocol wire fields
  ├─ thread / semaphore / critical section ──> signalwait_threads
  ├─ error_traits / error_advisor ──> return handling and diagnostics
  └─ trace / trace_advisor ──> debug event output
```

## 6. References

See the individual module notes for source paths and tests. Protocol-specific field usage should also be read in the corresponding TLS, DTLS, HTTP/2, ASN.1, or QUIC module documentation rather than duplicated here.
