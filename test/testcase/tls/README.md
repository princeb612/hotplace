## Publication

```text
hotplace source-tree documentation
Edition 2 · Revision 1105
Source basis: Revision 1105
Documented with GPT-6
Documentation scope: TLS/DTLS test inventory and verification boundaries
```

# TLS and DTLS testcase suite

## 1. Role

This directory contains TLS/DTLS testcase sources, packet-capture references, test-vector schemas, and handshake construction notes. It covers protocol message construction and selected TLS 1.2/1.3 and DTLS behavior; the directory is not by itself a claim of complete protocol conformance.

## 2. Test model

| Area | Source material |
|---|---|
| TLS handshake/protection | RFC 8448 trace testcases, TLS 1.2 AEAD, premaster-secret and handshake construction tests |
| TLS 1.2 | [TLS 1.2 tests](tls12/README.md) |
| TLS 1.3 | [TLS 1.3 tests](tls13/README.md) |
| DTLS 1.2 | [DTLS 1.2 tests](dtls12/README.md) |
| HTTP integration | [TLS/HTTP tests](http/README.md) |
| Linux-specific paths | [Linux tests](linux/README.md) |
| Captured traffic and vectors | [Packet captures](packet-capture.md), [test-vector schema](testvector-schema.md) |

The surrounding testcase CMake configuration builds the TLS group as part of the automated testcase tree. QUIC tests are maintained under the sibling `test/testcase/quic/` directory rather than being implied by the TLS directory name.

## 3. Example: RFC 8448 handshake trace

`testcase_rfc8448_2.cpp`, `testcase_rfc8448_5.cpp`, and related trace testcases provide source examples for TLS 1.3 handshake messages and protection transitions. The useful distinction is between the captured/example message sequence, the implementation operation under test, and the assertions that compare expected bytes or state. Read the specific testcase before asserting which handshake branch or extension is covered.

## 4. Test and verification status

### 4.1 Source-level coverage

The directory includes TLS 1.2/1.3 and DTLS-focused sources, but the existence of a trace or packet capture does not prove that every version, extension, error path, or transport behavior is tested. The dedicated QUIC packet/frame test inventory is separate.

### 4.2 Documentation and verification status

This README indexes source and study material. It does not claim that tests were executed during this documentation pass. Use a report that identifies the source revision and environment before asserting runtime success.

## 5. Relationships

- `sdk/net/tls/` — TLS/DTLS/QUIC implementation.
- `sdk/net/basic/openssl/` — OpenSSL-backed secure socket adapters.
- `sdk/crypto/` — cryptographic primitives and keys.
- `test/testcase/quic/` — QUIC-specific test material.
- `test/testcase/net/http/` — HTTP integration and framing tests.

## 6. References

- [Test checklist](test.md)
- [Packet captures](packet-capture.md)
- [Cipher suites](cipher-suites.md)
- [Test-vector YAML schema](testvector-schema.md)
- [TLS handshake construction](test-construct-tls-routine.md)
- [TLS 1.3 flow](tls13-flow.md)
- `testcase_tls12_aead.cpp`, `testcase_rfc8448_*.cpp`, `testcase_understand_tls12.cpp`

## Latest recorded runtime report

The latest shared report snapshot is indexed in [Test Report Snapshot](../test-report-status.md). It records 17,664 pass, 1 expt, 0 fail, 0 skip and 0 triv entries for the `tls` group. The associated run context supplied in the conversation is Revision 1104 on MinGW64/GCC with CTest; the report payload does not independently identify the tested source commit or exact build configuration. Preserve this snapshot until newer reports are supplied; this group result should not be generalized to QUIC, which has its own report row and testcase directory.
