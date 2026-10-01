# OQS Tests

The OQS tests are integration tests around the provider boundary rather than algorithm-reference test vectors.

## Encode / decode

`testcase_oqs_encode.cpp` enumerates KEM and signature algorithms and exercises:

- private PEM
- encrypted private PEM
- public PEM
- private DER
- encrypted private DER
- public DER

The test uses `pqc_oqs::keygen()`, `encode()`, and `decode()` and can optionally dump generated key material.

## KEM

`testcase_oqs_kem.cpp` exercises the complete key-encapsulation flow:

1. generate a key pair
2. encode public/private keys
3. decode the public key
4. encapsulate with the public key
5. decapsulate with the private key
6. compare both shared secrets

This verifies that the provider-backed key representation and KEM operation can cross the public-key distribution boundary.

## Signature

`testcase_oqs_dsa.cpp` exercises:

1. key generation
2. public/private key serialization
3. public-key decode
4. signing with the private key
5. verification with the public key

## Current test boundary

The existing tests are not yet a NIST/ACVP known-answer test suite. The retained `oqs-provider.md` records the planned ML-DSA and ML-KEM ACVP test-vector work separately.
