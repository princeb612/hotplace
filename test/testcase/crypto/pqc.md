## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Pqc

## 1. Role

This document records testcase organization, test-vector schema, or reference material for the crypto test area. Its presence does not by itself establish runtime verification.

## 2. Test model

#### PQC

1. [Post-Quantum Cryptography](https://seed.kisa.or.kr/kisa/ngc/pqc.do)
NIST 2022
|                    |               |                                                            |
| --                 | --            | --                                                         |
| Crystals-Kyber     | Lattice-based | ML-KEM (Module Lattice-Based Key Encapsulation Mechanism)  |
| Crystals-Dilithium | Lattice-based | DL-DSA (Dilithium Digital Signature Algorithm)             |
| FALCON             | Lattice-based | FN-DSA (Falcon Digital Signature Algorithm)                |
| SPHINCS+           | Hash-based    | SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) |

## 3. Example: Source inventory and test-vector use

1. The retained material is a schema/reference or directory-level record. Consult the listed testcase source files to determine which functions consume these inputs and what assertions they make.

## 4. Test and verification status

### 4.1 Source-level coverage

No claim of algorithmic coverage is inferred from this reference document alone. Coverage must be established from the consuming C++ testcase functions and their expected-result checks.

### 4.2 Documentation and verification status

The supplied `test/testcase/crypto/report` records 4,214 pass, 281 expt, 0 fail, 90 skip, and 0 triv entries. The report does not identify the OS, compiler/build configuration, or source revision, and this documentation pass did not execute the tests.

## 5. Relationships

- Crypto implementation: `sdk/crypto/README.md`
- Test sources and vector consumers are located in the corresponding sibling testcase directories.
- Related testcase source: `test/testcase/crypto/sample.cpp`



## 6. References

No external references are currently listed.
