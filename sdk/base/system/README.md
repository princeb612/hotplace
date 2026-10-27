## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1114                    │
│ Source basis: Revision 1114                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & behavior│
└──────────────────────────────────────────────┘
```

# System-level utilities and numeric types

## 1. Role

`sdk/base/system` provides low-level numeric, time, byte-order, synchronization, ownership, error-reporting, and tracing facilities used by higher SDK layers. It is not one unified runtime abstraction: the modules have separate responsibilities and distinct representation, lifetime, and platform constraints.

## 2. Data Model

### Component families

| Family | Components | Role |
|---|---|---|
| Numeric representation | `bignumber`, `floating_point`, `ieee754` | Arbitrary-width integers, decimal/rational arithmetic, and IEEE-754 conversion/classification |
| Wire representation | `endian-and-wire-integers` | Byte order and non-native wire widths such as 24- and 48-bit integers |
| Time | `datetime` | `timespec`-centered representation, conversions, and clock access |
| Ownership and synchronization | `shared_instance`, `threading-and-synchronization` | Project-specific reference-counted ownership helpers and platform synchronization |
| Diagnostics | `error-handling`, `trace` | Error-convention adaptation and category-aware debug/control-flow tracing |
| OS integration | `process`, `redirection`, `dir` | Child-process lifecycle, standard-I/O pipes/handles, and directory creation |

## 3. Behavior Model

### Source-flow overview

```text
numeric input ─► bignumber limbs ─► decimal/rational layer ─► floating_point
native float ─► IEEE-754 classify / convert / format helpers
host integer ─► endian conversion OR uint24_t / uint48_t ─► wire-width bytes

operation result ─► error_traits / error_advisor ─► return classification and description
trace event ─► trace category/configuration ─► registered handler ─► logger or caller
parent process ─► redirection setup ─► child process ─► read/write pipes ─► cleanup
thread group ─► create workers ─► signal/wait coordination ─► join / release
```

These paths share the `system` directory but not a common runtime object. Each has its own representation and cleanup contract: for example, wire-width conversion is not protocol framing, error classification is not diagnostic output, and process pipes have a different lifetime from thread synchronization primitives.

These modules do not share one lifecycle contract. Numeric representation and conversion rules are separate from OS-backed time/thread operations; shared-instance ownership should not be confused with ordinary raw-pointer lifetime; and trace output depends on the active category/configuration.

Wire-width helpers are particularly relevant at protocol boundaries, but protocol-specific field definitions and interpretation belong in TLS, DTLS, HTTP/2, ASN.1, or QUIC documentation rather than being duplicated here.

Platform-dependent facilities must be reviewed against their actual implementation branches and target environment. Process creation, standard-I/O redirection, synchronization, and time conversion can expose different native APIs and ownership constraints on Windows and POSIX systems.

The Windows type header, `sdk/base/system/windows/types.hpp`, also centralizes MSVC concurrency headers used by the synchronization/future-related code. Revision 1113 fixed an MSVC compile failure involving `pplcancellation_token.h` and `Concurrency::details::_RefCounter`. The relationship to the future/promise work introduced around Revision 1104 is a plausible lead, not a confirmed root-cause statement; the changelog records the fix without claiming more than the evidence establishes.

The numeric modules also have distinct purposes: `bignumber` supplies arbitrary-width integer operations, decimal/rational helpers build higher-level numeric representations, and IEEE-754 helpers concern binary floating-point formats. These should not be collapsed into a single generic “number” abstraction.

## 4. Relationships

### Focused module notes

- [Big number](bignumber.md) — arbitrary-width integer representation and operations
- [Date and time](datetime.md) — `timespec`-centered time representation, conversions, and clocks
- [Endian and wire integers](endian-and-wire-integers.md) — byte order and non-native wire widths such as 24- and 48-bit integers
- [Error handling](error-handling.md) — adapters between hotplace return codes and external error conventions
- [Floating point](floating_point.md) — exact decimal/rational arithmetic built on `bignumber`
- [IEEE-754](ieee754.md) — floating-point classification, conversion, and formatting helpers
- [Shared instances](shared_instance.md) — project-specific reference-counted ownership helpers
- [Threading and synchronization](threading-and-synchronization.md) — platform thread, semaphore, critical-section, and signal/wait abstractions
- [Trace](trace.md) — category-aware debug events and control-flow tracing
- [Process execution](process.md) — cross-platform child-process lifecycle.
- [Standard-I/O redirection](redirection.md) — parent/child pipe and handle operations.
- [Directory creation](dir.md) — single and prefix-based directory creation helpers.

```text
base/system
  ├─ bignumber ──> decimal_float / rational_float / floating_point
  ├─ endian + uint24_t/uint48_t ──> protocol wire fields
  ├─ thread / semaphore / critical section / atomic ──> signalwait_threads and shared ownership
  ├─ process ──> redirection pipes/handles and child lifecycle
  ├─ dir ──> directory creation helpers
  ├─ error_traits / error_advisor ──> return handling and diagnostics
  └─ trace / trace_advisor ──> debug event output
```

- [System testcase directory](../../../test/testcase/base/system/README.md) and [system testcase note](../../../test/testcase/base/system/testcase_system.md) own the source-level coverage descriptions for these modules. The shared [base testcase report snapshot](../../../test/testcase/test-report-status.md) should be interpreted only with its stated revision/environment limitations.

## 5. References

No external references are listed.
