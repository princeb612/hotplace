# hotplace — Repository Evidence Audit

## Purpose

This document connects the project review to actual repository evidence.

**Recommendation → Existing Evidence → Current Status → Missing Evidence →
Possible Direction**

The purpose is to avoid recommending work that already exists.

## 1. Current Verification Model

Known project structure:

- CMake / CTest is the primary testcase execution mechanism.
- MinGW64 / GCC is a ctest-based verification environment.
- CentOS 7 / GCC 4.8.5 is a ctest-based verification environment.
- Rocky Linux 8 is a ctest-based verification environment.
- `./test.sh` is an additional Valgrind verification path.
- Valgrind checks include memcheck, helgrind, and drd.
- The oldest previously identified test environment is FC4 x64 in a VM.

Therefore the review should not describe hotplace as simply "lacking
testing".

## 2. Audit Axes

### Verification

**Classification: Already Strong**

The project has project-level testcase/build infrastructure and extensive
protocol-oriented implementation records.

### Conformance

**Classification: Already Strong**

The public README documents many RFCs and implementation/application
statuses, including published cryptographic test-vector-related work.
citeturn0search0

### Wire / Packet Evidence

**Classification: Already Strong**

PCAP-oriented protocol testing is part of the project's existing verification
approach. The remaining task is to make its role more visible, not to
assume it is absent.

### Interoperability

**Classification: Needs Structure / Visibility**

A distinct public `interop` infrastructure was not identified. This does
not prove that external interoperability work is absent. Existing protocol,
PCAP, and external-library tests should be classified as independent
evidence where appropriate.

### Robustness / Fuzzing

**Classification: Potential Capability Gap**

No clearly separate public fuzz-target, corpus, or fuzzing workflow was
identified.

This is particularly relevant to parser/decoder-heavy areas such as ASN.1,
CBOR, TLS handshake, QUIC packet/frame, HTTP/2, and QPACK.

### Performance

**Classification: Potential Capability Gap, lower priority**

No clearly separate benchmark/regression layer was identified.

The objective should be repeatable observation rather than turning hotplace
into a performance-optimization project.

## 3. Evidence Principle

Do not turn every missing artifact into a requirement.

A capability may be:

- implemented and well verified
- implemented but poorly documented
- internally tested but lacking independent validation
- experimental by design
- genuinely missing

The audit exists to tell these cases apart.

## 4. Final Audit Position

Do not write:

> hotplace needs more testing.

Prefer:

> hotplace already has substantial testing and protocol-oriented
> verification; the next opportunity is to make verification evidence more
> explicit, identify independent interoperability evidence, and selectively
> add robustness and measurement capabilities where they naturally fit.

## 5. Scope Limitation

This audit uses the publicly visible GitHub repository as evidence as of
2026-10-03. It does not prove the absence of unpublished, local, or
working-tree experiments.
