#### PQC

[Post-Quantum Cryptography](https://seed.kisa.or.kr/kisa/ngc/pqc.do)
NIST 2022
|                    |               |                                                            |
| --                 | --            | --                                                         |
| Crystals-Kyber     | Lattice-based | ML-KEM (Module Lattice-Based Key Encapsulation Mechanism)  |
| Crystals-Dilithium | Lattice-based | DL-DSA (Dilithium Digital Signature Algorithm)             |
| FALCON             | Lattice-based | FN-DSA (Falcon Digital Signature Algorithm)                |
| SPHINCS+           | Hash-based    | SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) |

### oqs-provider

* [oqs-provider](https://github.com/open-quantum-safe/oqs-provider/)
- [ ] study
  - [x] encode/decode
    - [x] DER, PEM
    - [x] public, private, encrypted private
  - [x] KEM
    - [x] build OQS_KEM_ENCODERS
    - [x] encapsulate/decapsulate
  - [x] DSA
    - [x] sign/verify
  - [ ] test vector
    - [ ] [ML-DSA-keyGen-FIPS204](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-keyGen-FIPS204)
    - [ ] [ML-DSA-sigGen-FIPS204](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigGen-FIPS204)
    - [ ] [ML-DSA-sigVer-FIPS204](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigVer-FIPS204)
    - [ ] [ML-KEM-keyGen-FIPS203](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203)
    - [ ] [ML-KEM-encapDecap-FIPS203](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203)
