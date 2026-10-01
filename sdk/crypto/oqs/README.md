# OQS / Post-Quantum Cryptography

`sdk/crypto/oqs` is hotplace's adapter for the OpenSSL 3 `oqsprovider` provider. It does not implement the post-quantum algorithms itself; it discovers provider algorithms and exposes common KEM/signature operations through `pqc_oqs`.

## Implementation

- `oqs/oqs.hpp`, `oqs.cpp` — provider context, algorithm discovery, key generation, key serialization, KEM, and signature operations.
- `oqs/types.hpp` — OQS provider context and discovered algorithm state.
- `oqs_alg_oid_registered` — marks provider algorithms for which hotplace can resolve an OID through OpenSSL's NID mapping.

## Main flow

```text
OpenSSL 3 OSSL_LIB_CTX
    ↓
load default provider + oqsprovider
    ↓
query KEM / SIGNATURE operations
    ↓
pqc_oqs
    ├── keygen / encode / decode
    ├── encapsule / decapsule
    └── sign / verify
    ↓
crypto/basic / OpenSSL EVP_PKEY
```

## Related documentation

- `oqs-provider.md` — existing study/test notes for the external provider and remaining test-vector work.
- `../basic/` — OpenSSL PQC and common key/crypto abstractions used by the adapter.
- `../advisor/` — algorithm/OID metadata used to identify supported algorithms.

## Tests

- `test/testcase/crypto/pqc/oqs/testcase_oqs_encode.cpp`
- `test/testcase/crypto/pqc/oqs/testcase_oqs_kem.cpp`
- `test/testcase/crypto/pqc/oqs/testcase_oqs_dsa.cpp`

The test suite requires the external `oqsprovider` module to be installed where OpenSSL can load it. The tests enumerate provider algorithms and exercise only entries marked as OID-registered.
