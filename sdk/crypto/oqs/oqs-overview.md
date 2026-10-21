## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Post-quantum cryptography overview

## 1. Role

This overview records post-quantum algorithm families and terminology relevant to hotplace. It is a background reference, not a definitive inventory of algorithms enabled by the current build.

## 2. Data Model
The source overview discusses lattice-based KEM/signature families and hash-based signatures. Algorithm names and standardization labels evolve; distinguish the historical names in a study table from the provider algorithm names actually discovered at runtime.

The current integration boundary is the OpenSSL 3 `oqsprovider` adapter described in [the provider overview](README.md).

## 3. Behavior Model
Provider availability, OpenSSL version, OID registration, and hotplace's common key/operation support are separate constraints. A family name appearing in a background table does not prove that the corresponding implementation is available or tested in a particular environment.

## 4. Relationships

### Implementation and test sources

- Source overview content retained below for maintainer review.
- OpenSSL 3 provider API

### Source-test evidence

The direct integration tests enumerate algorithms from the loaded provider and gate full tests on OID registration. See [OQS test coverage](oqs-tests.md).

- [OQS provider adapter](oqs-provider-adapter.md)
- `../basic/` — common cryptographic operations
- `../../../test/testcase/crypto/pqc/` — PQC tests

- NIST post-quantum cryptography standardization resources

## Development Notes (for maintainer review)

The following legacy overview material is retained as supplied. Review algorithm names, standardization status, and external links before treating this table as current.

#### PQC

[Post-Quantum Cryptography](https://seed.kisa.or.kr/kisa/ngc/pqc.do)
NIST 2022
|                    |               |                                                            |
| --                 | --            | --                                                         |
| Crystals-Kyber     | Lattice-based | ML-KEM (Module Lattice-Based Key Encapsulation Mechanism)  |
| Crystals-Dilithium | Lattice-based | DL-DSA (Dilithium Digital Signature Algorithm)             |
| FALCON             | Lattice-based | FN-DSA (Falcon Digital Signature Algorithm)                |
| SPHINCS+           | Hash-based    | SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) |

- oqs-provider
  - KEM
    - p256_mlkem512
    - x25519_mlkem512
  - DSA
    - p256_mldsa44
    - rsa3072_mldsa44
    - p384_mldsa65
    - p521_mldsa87
    - falcon512
    - p256_falcon512
    - rsa3072_falcon512
    - falconpadded512
    - p256_falconpadded512
    - rsa3072_falconpadded512
    - falcon1024
    - p521_falcon1024
    - falconpadded1024
    - p521_falconpadded1024
    - sphincssha2128fsimple
    - p256_sphincssha2128fsimple
    - rsa3072_sphincssha2128fsimple
    - sphincssha2128ssimple
    - p256_sphincssha2128ssimple
    - rsa3072_sphincssha2128ssimple
    - sphincssha2192fsimple
    - p384_sphincssha2192fsimple
    - sphincsshake128fsimple
    - p256_sphincsshake128fsimple
    - rsa3072_sphincsshake128fsimple
    - mayo1
    - p256_mayo1
    - mayo2
    - p256_mayo2
    - mayo3
    - p384_mayo3
    - mayo5
    - p521_mayo5
    - CROSSrsdp128balanced
    - OV_Is_pkc
    - p256_OV_Is_pkc
    - OV_Ip_pkc
    - p256_OV_Ip_pkc
    - OV_Is_pkc_skc
    - p256_OV_Is_pkc_skc
    - OV_Ip_pkc_skc
    - p256_OV_Ip_pkc_skc
    - snova2454
    - p256_snova2454
    - snova2454esk
    - p256_snova2454esk
    - snova37172
    - p256_snova37172
    - snova2455
    - p384_snova2455
    - snova2965
    - p521_snova2965
