# hotplace — Project Review

## Review Attribution

This review was prepared with the assistance of ChatGPT (GPT-5.6 Luna)
as an external reviewer of the hotplace project.

The observations and future-direction proposals in this document are
review findings, not project commitments. The project owner retains
final responsibility for deciding which recommendations to adopt.

Review date: 2026-10-03

## 1. Project Identity

hotplace is a personal C++ project for studying, implementing, testing,
and connecting low-level technologies encountered in systems, networking,
cryptography, data representation, and protocol engineering.

The project is therefore not intended to compete directly with a
specialized library such as a dedicated QUIC implementation, TLS library,
or ASN.1 compiler.

Its primary purpose is different:

> **Understand difficult systems technologies by implementing them,
> connecting them, testing them, and preserving the resulting knowledge
> in source code and documentation.**

Some characteristics that may appear unusual from a conventional
production-library perspective are deliberate project boundaries.

## 2. Strengths

### 2.1 Breadth with Internal Connections

hotplace covers a wide range of related technologies and studies their
relationships rather than treating them as isolated topics.

Examples include HTTP/2 and HPACK, QUIC and HTTP/3, TLS and handshake
extensions, ASN.1, type systems, constraints, encoding, parsing, runtime
objects, cryptographic and certificate-related components, and packet,
frame, stream, parser, and data-representation infrastructure.

### 2.2 Implementation-Oriented Learning

Difficult subjects are approached through implementation, experiments,
test cases, debugging, and source-level investigation.

The source tree itself is part of the learning record.

### 2.3 Low-Level Ownership

The project contains low-level implementations and utilities instead of
depending on a large collection of external libraries. This provides
direct visibility into binary representation, parsing, encoding/decoding,
protocol state, packet/frame processing, cryptographic integration, and
resource handling.

### 2.4 Long-Term Experimental Continuity

The project has accumulated knowledge over a long period. Source, tests,
documentation, and revision history provide continuity for revisiting
earlier subjects.

### 2.5 Cross-Domain Experimentation

The project connects subjects usually studied separately, which is useful
for understanding how protocol stacks depend on parsing, serialization,
cryptography, transport, and application layers together.

## 3. Limitations

### 3.1 Large Scope

Breadth naturally makes complete maturity difficult. Some components are
substantially developed while others remain experimental.

### 3.2 Uneven Maturity

Components differ in test coverage, interoperability evidence,
documentation, API stability, performance measurement, and maintenance.

### 3.3 Single-Developer Maintenance

The project depends heavily on the project owner's knowledge and continuity,
which naturally limits parallel development and review capacity.

### 3.4 Modern Ecosystem Compatibility

Maintaining a C++11 baseline limits direct adoption of some modern C++
libraries and techniques. This is a deliberate compatibility boundary.

### 3.5 External Validation

Internal tests provide important evidence, while interoperability and
independent validation provide a different kind of evidence.

## 4. Intentional Trade-offs

These should not automatically be treated as problems to fix.

- **C++11 as a compatibility boundary**
- **Minimal external dependencies**
- **Breadth over specialization**
- **Experimentation over productization**

Not every experiment needs to become a production-quality standalone
library.

## 5. Comparative Perspective

Specialized projects are useful references for engineering practices,
not competitors or templates that hotplace must reproduce.

Relevant comparison areas include QUIC transport, HTTP/2/HPACK,
HTTP/3/QPACK, TLS/crypto, ASN.1, testing, fuzzing, performance, API
stability, and documentation.

The purpose of comparison is to identify useful capabilities and engineering
patterns, not to rank projects.

## 6. Capability Gaps

A useful verification ladder is:

**Build Verification → Component Test → Protocol / Format Test Vector →
Wire / Packet Verification → Interoperability → Fuzz / Robustness**

Each level answers a different question. A component does not necessarily
need every level, but its available evidence should be understandable.

Potential gaps to examine include interoperability evidence, systematic
fuzzing/robustness, lightweight performance measurement, and clearer
component maturity boundaries.

## 7. Future Direction

### 7.1 Defend

Preserve C++11 compatibility, older-environment awareness, limited external
dependencies, implementation-oriented learning, low-level protocol study,
cross-domain experimentation, source as technical record, and documentation
connected to implementation history.

### 7.2 Strengthen

Strengthen testcase organization, protocol vectors, interoperability
evidence, parser/decoder robustness, documentation, reproducibility,
platform verification, API boundaries, regression testing, fuzzing, and
performance measurement where appropriate.

The goal is not to add all of these everywhere. The goal is to make
existing capabilities easier to verify and understand.

### 7.3 Explore

Natural exploration areas include broader HTTP/3 interoperability, deeper
QUIC recovery/congestion-control study, ASN.1 generation, post-quantum
cryptography, certificate/PKI processing, protocol conformance tooling,
packet diagnostics, additional compression formats, systematic fuzzing,
and repeatable benchmarks.

These are candidates, not commitments.

## 8. What Should Not Become a Goal

hotplace does not need to become a replacement for mature security
libraries, a complete production-grade QUIC stack, a project maximizing
modern C++, or a project maximizing supported protocols.

Experimental components should remain allowed.

## 9. Guiding Principles

- Understand Before Abstracting
- Implementation Is Part of Documentation
- Compatibility Is a Design Constraint
- Breadth Must Have Connections
- Tests Define Confidence
- Specialized Projects Are References, Not Competitors
- Preserve Freedom to Experiment
- Add Complexity Deliberately

## 10. Long-Term Direction

**Personal Research → Direct Implementation → Cross-Domain Connection →
Test / Verify / Interoperate → Document the Knowledge → Preserve and Refine the Work**

The goal is not to optimize hotplace into a different project.

> **Do not optimize hotplace into a different project.**
>
> **Strengthen what it already is, and selectively expand what naturally
> follows from it.**

## 11. Repository Evidence Review

The public repository provides an important correction to a simple
"testing gap" interpretation.

The README documents a broad set of implemented and applied RFCs across
TLS/DTLS/QUIC, CBOR/COSE/JOSE, HTTP/2/HTTP/3, ASN.1, and other protocol or
format work. It also records cryptographic work involving published RFC
test vectors and NIST CAVP-related validation. citeturn0search0

Therefore hotplace should **not** be described as lacking conformance or
component testing in general.

Current classification:

- **Already Strong:** build/test infrastructure, component tests,
  RFC/vector-oriented verification, wire/packet-oriented evidence.
- **Needs Structure / Visibility:** identifying interoperability evidence
  as an independent evidence layer.
- **Potential Capability Gap:** dedicated fuzzing/robustness infrastructure
  and a repeatable benchmark layer.

The public-repository search did not expose a clearly separate fuzz-target,
fuzz-corpus, or benchmark infrastructure. This is evidence about the
visible repository structure, not proof that no local or experimental work
exists.

The next step is therefore not to "add testing" in general, but to make
existing verification evidence more explicit and selectively add
independent robustness evidence.
