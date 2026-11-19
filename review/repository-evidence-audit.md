# hotplace — Repository Evidence Audit

## Purpose

This document connects the project review to actual repository evidence.

## Review Attribution

Prepared with the assistance of ChatGPT (GPT-6) as an external reviewer of the hotplace project.

Review date: 2026-11-18

Source base : Revision 1132

**Recommendation → Existing Evidence → Current Status → Missing Evidence →
Possible Direction**

The purpose is to avoid recommending work that already exists.

## 1. Current Verification Model

Known project structure:

- CMake / CTest is the primary testcase execution mechanism.
- MinGW64 / GCC: CTest, with Application Verifier as an additional check.
- Ubuntu 20: CTest with Sanitizer.
- CentOS 7 / GCC 4.8.5: CTest; `test/testcase/test.sh` provides an additional Valgrind path.
- Rocky Linux 8: CTest; `test/testcase/test.sh` provides an additional Valgrind path.
- Windows / MSVC: CTest, with Application Verifier as an additional check.
- The Valgrind script selects `memcheck`, `helgrind`, and `drd`.
- FC4 x64 in a VM is retained as a historical environment previously identified for the project, but it is not independently evidenced by the current public source tree.

Therefore the review should not describe hotplace as simply "lacking
testing".

## 2. Audit Axes

### Verification

**Classification: Already Strong**

The project has project-level testcase/build infrastructure and extensive
protocol-oriented implementation records.

### Conformance

**Classification: Substantial Existing Evidence; not blanket conformance certification**

The root `README.md` maps RFC-oriented implementation/application areas.
Additional source evidence is distributed across `docs/pcapng/README.md`,
`docs/cose_jose/README.md`, `sdk/net/tls/README.md`, and the crypto/TLS
testcase documentation. These establish substantial vector and protocol
verification activity, not complete conformance for every listed RFC.

### Wire / Packet Evidence

**Classification: Substantial Existing Evidence, scenario-specific**

PCAP-oriented protocol testing and capture replay are part of the existing
verification approach. The evidence is scenario-specific; the remaining
task is to inventory which protocol, direction, version, and implementation
pairs each capture actually verifies.

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

This audit uses the publicly visible GitHub repository at Source base : Revision 1132 (reviewed 2026-11-18). It does not prove the absence of
unpublished, local, or working-tree experiments. The platform matrix is
cross-checked against `test/README.md`, `test/testcase/README.md`, and
`test/testcase/test.sh`; the FC4 x64 VM note remains historical rather than
independently reproducible repository evidence.
