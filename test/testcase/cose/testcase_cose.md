## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1106                    │
│ Documented with GPT-6                         │
│ Source basis: Revision 1106                   │
│ — COSE testcase source map                    │
└──────────────────────────────────────────────┘
```

# COSE testcase source map

## 1. What

This file is a navigation map from the COSE testcase entry point to the source-level case families. The directory [README](README.md) is the primary procedure document: it contains the per-case flows, assertions and known limits. This map keeps the source-to-purpose relationship visible without duplicating every procedure.

## 2. How

1. Start from `sample.cpp` and follow the dispatcher in execution order:

```text
sample.cpp
  ├─ testcase_resources()
  │    └─ testcase_resource.cpp
  │         algorithm metadata → expected key-size assertions
  ├─ testcase_rfc8152()
  │    └─ testcase_rfc8152.cpp
  │         .cbor fixtures → CBOR round-trip
  │         RFC B / C.1–C.7 message construction
  │         tagged Sign / Encrypt / MAC → verify/decrypt status
  │         COSE_Key import and key selection
  ├─ testcase_testvector_cose_examples()
  │    └─ testvector_cose_examples.cpp + testvector_cose_examples.yml
  │         YAML keys/shared parameters/CBOR → cose.process status
  │         optional -v parse/compose byte equality
  ├─ testcase_cose()
  │    └─ testcase_cose.cpp
  │         generated key inventory
  │         sign/verify × algorithm list
  │         encrypt/decrypt × content/key-management matrix
  │         MAC/verify × algorithm matrix
  ├─ testcase_rfc8392()
  │    └─ testcase_rfc8392.cpp
  │         fixed CWT hex inputs → verify/decrypt/process status
  └─ testcase_akp() + testcase_testvector_akp()
       └─ testcase_akp.cpp + testvector_akp.cpp + JSON vectors
            OpenSSL >= 3.5 → ML-DSA sign/verify
            import COSE key → compare raw public key → verify Sign1
```

2. The important execution switches are `-b` (skip the RFC 8152 basic fixture round-trip) and `-g` (skip generated-key COSE matrices). `-v` is also coverage-affecting: RFC 8152 fixture byte comparisons and YAML parse/compose equality are inside verbose-only branches. See the main README for exact case flows and assertion limits.

## 3. Evidence

### Source-level coverage map

| Case family | Primary source | Inputs | What the source actually checks |
|---|---|---|---|
| RFC 8152 basic CBOR | `testcase_rfc8152.cpp` | Paired `.cbor` fixtures | Parsed/published bytes equal original fixture |
| RFC 8152 message examples | `testcase_rfc8152.cpp` | Source-built CBOR trees and paired RFC fixtures | Cryptographic return status always; source-vs-fixture and several parse/publish comparisons only with `-v` |
| COSE_Key import / selection | `testcase_rfc8152.cpp` | Public/private COSE_Key CBOR | Selected key/kid assertions and sign/verify operation status |
| COSE Examples | `testvector_cose_examples.cpp` | `testvector_cose_examples.yml`, mapped key sets and CBOR hex | `cose.process` return status; parse/compose equality only with `-v`; `skip` entries are not executed |
| Generated algorithm matrices | `testcase_cose.cpp` | Generated keys, fixed payload `hello world` and algorithm arrays | Sign/encrypt/MAC and corresponding process/decrypt/verify return statuses; no plaintext equality or verification-result boolean assertion |
| Resource metadata | `testcase_resource.cpp` | Fixed algorithm/key-size table | `hint->enc.ksize` equals expected key length |
| CWT | `testcase_rfc8392.cpp` | Embedded RFC 8392 CBOR hex | Verify/decrypt/process return statuses; no independent claim/payload equality |
| AKP / ML-DSA | `testcase_akp.cpp`, `testvector_akp.cpp` | Generated keys and three JSON vectors | Sign/verify status and exact raw public-key equality; OpenSSL 3.5+ required |

The main README documents the concrete call and comparison sequence for each family. In particular, successful cryptographic API status is not automatically evidence of expected plaintext equality or a true verification-result boolean.

### Documentation and verification status

The shared [Test Report Snapshot](../test-report-status.md) records the supplied COSE run as **Revision 1104 · MinGW64/GCC · CTest**: **2,013 pass, 0 expt, 0 fail, 2 skip, 0 triv**. The source/documentation basis here is Revision 1106; the report does not independently identify the tested source commit or exact build configuration. No tests were rerun during this documentation update.

## 4. Relationships

- [COSE testcase procedures and detailed flows](README.md)
- `sdk/crypto/cose/` — COSE processing implementation.
- `sdk/io/cbor/` — CBOR parsing, object representation and serialization.
- `sdk/crypto/basic/` — cryptographic keys and primitives.

## 5. References

- RFC 8152 / RFC 9052 — COSE structures and processing.
- RFC 8392 — CBOR Web Token.
- RFC 8778 — HSS/LMS with COSE.
- RFC 9338 — COSE Countersignatures.
- [COSE working-group Examples](https://github.com/cose-wg/Examples).
