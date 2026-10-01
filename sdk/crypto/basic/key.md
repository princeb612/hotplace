# Key Objects, Generation and Key Exchange

The `key/` directory is the largest part of `crypto/basic`.  It combines the key object representation with key import/export, generation and key-exchange helpers because these operations share the same OpenSSL `EVP_PKEY` boundary.

## Key object

`crypto_key` represents a key together with its algorithm/type information and encoded key material.  The implementation supports extraction/search and multiple encodings, including PEM/DER and raw forms where the OpenSSL backend permits them.

`crypto_keychain` stores key components and descriptions used to build or inspect a key.  Algorithm-specific source files cover RSA, DSA, DH, EC, OKP and octet keys, including compressed/uncompressed EC forms and OpenSSL 3 handling.

## Key generation

`crypto_keygen` and its algorithm-specific implementations generate keys for the supported key families.  The generated key eventually enters the same `crypto_key` / `EVP_PKEY` representation used by signing, encryption and exchange.

## Key exchange

`crypto_keyexchange` provides the common exchange operation.  The key directory contains implementations and helpers for DH/EC-oriented exchange and related protocol use, while higher-level protocols decide how the resulting secret participates in their own key schedule.

## Important boundary

```text
encoded/raw key material
        ↓
crypto_key / crypto_keychain
        ↓
        EVP_PKEY
   ↙       ↓       ↘
 sign    encrypt   key exchange
```

Algorithm identifiers and aliases are resolved through `crypto/advisor`; this directory should be understood as the key material/object/operation layer rather than an algorithm registry.

## Tests

`test/testcase/crypto/key/` covers key objects, curves, DER, DH, EC, HPKE, RSA/DSA, FFDHE, ML-KEM, generation, key exchange and RFC/test-vector cases.
