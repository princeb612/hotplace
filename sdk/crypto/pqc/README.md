
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
