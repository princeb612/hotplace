# hotplace — Capability Gap Assessment

## Review Attribution

Prepared with the assistance of ChatGPT (GPT-5.6 Luna) as an external
reviewer of the hotplace project.

Review date: 2026-10-03

This document is an assessment framework, not a mandatory roadmap.

## 1. Verification Evidence

A useful verification ladder is:

**Build Verification → Component Test → Protocol / Format Test Vector →
Wire / Packet Verification → Interoperability → Fuzz / Robustness**

These layers answer different questions. Not every component needs every
layer; the important point is to make the available evidence explicit.

## 2. Interoperability

Potential targets include TLS with established TLS implementations,
HTTP/2 with an independent HTTP/2 implementation, QUIC/HTTP/3 with
established implementations, and ASN.1 with independent ASN.1 tooling.

The objective is not to replace internal tests but to add an independent
source of confidence.

At present, interoperability should be treated as **Needs Structure /
Visibility**, not as a confirmed missing capability.

## 3. Fuzzing

Fuzzing is particularly relevant to ASN.1, CBOR, TLS handshake, QUIC
packet/frame, HTTP/2, and HTTP/3/QPACK parsing and decoding.

A useful first step is to identify high-risk input boundaries and create
small, reproducible fuzz targets with seed inputs and regression cases.

The public repository search did not expose a distinct fuzz-target,
fuzz-corpus, or fuzzing workflow. Therefore fuzzing is the clearest
candidate for a genuinely new verification capability.

## 4. Performance Measurement

Performance remains secondary to correctness and understanding.

Useful measurements could include encoding/decoding throughput, parser
throughput, packet processing, cryptographic operation cost, and memory
behavior.

The objective should initially be observation and regression detection,
not aggressive optimization.

No clearly separate benchmark/regression layer was exposed in the public
repository search, so this remains a lower-priority capability candidate.

## 5. API and Component Maturity

A useful conceptual maturity model is:

**Experimental → Stable Internal Component → Documented Component → Public API**

Not every component needs to become a public API.

## 6. What Comparable Projects Teach

Specialized projects commonly separate unit tests, integration tests,
interoperability, fuzz targets, fuzz corpora, protocol vectors, security
processes, release discipline, and component boundaries.

These are references for practices that may strengthen hotplace, not
requirements to reproduce another project's structure.

## 7. Revised Priority

1. **Make the existing verification model explicit**
2. **Identify and document existing interoperability evidence**
3. **Consider targeted fuzzing for parser/decoder boundaries**
4. **Consider lightweight benchmarks where measurements add useful knowledge**

This is not a ranking of project features. It is a practical investigation
order.

## 8. Decision Rule

Before adding a capability, ask:

1. Does it strengthen an existing hotplace capability?
2. Does it provide useful evidence of correctness or robustness?
3. Does it preserve compatibility and dependency boundaries?
4. Does it create reusable technical knowledge?

If mostly no, it does not automatically belong on the roadmap.

## 9. Repository Evidence Review

The README's implementation/application matrix provides substantial
RFC-oriented evidence across many technologies, including cryptographic
test-vector-related work. citeturn0search0

Therefore:

- **Conformance:** Already Strong
- **Component Testing:** Already Strong
- **Wire / Packet Evidence:** Already Strong
- **Interoperability:** Needs Structure / Visibility
- **Fuzzing:** Potential Capability Gap
- **Benchmarking:** Potential Capability Gap, lower priority

The distinction is important: hotplace already has substantial testing and
verification activity. The opportunity is to make its evidence model more
explicit and add independent robustness capabilities selectively.
