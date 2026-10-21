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
# OpenSSL Backend, PRNG and PQC

## 1. Role

Three smaller areas complete the `crypto/basic` implementation layer: OpenSSL SDK support, random generation and post-quantum cryptography.

## 2. Data Model
### OpenSSL SDK support

`sdk/` contains the hotplace-side OpenSSL support layer.  It includes SDK initialization/debug support and OpenSSL tuning/helpers used by the primitive implementations.

The important architectural point is that most crypto classes do not expose OpenSSL setup details directly.  Backend-specific code stays close to the operation it implements, while common types and builders remain in the hotplace namespace.

### PRNG

`prng/openssl_prng.cpp` provides the random-number generation path through OpenSSL.  The public wrapper is intentionally small; consumers should use the hotplace crypto abstraction rather than depending directly on backend calls.

The corresponding testcase is `test/testcase/crypto/prng/testcase_random.cpp`.

### PQC

`pqc/openssl_pqc.cpp` is the OpenSSL-facing post-quantum cryptography integration.  Current tests cover PQC key/signature operations and hybrid KEM behavior, with OQS-provider material retained under `test/testcase/crypto/`.

PQC support should be understood as backend integration rather than a separate protocol implementation.  Higher-level TLS/COSE/other modules decide where these algorithms are used.

## 3. Behavior Model
The backend layer is where hotplace's generic crypto interfaces meet OpenSSL-specific initialization, EVP operations, PRNG behavior and provider integration. Availability of an algorithm depends on the linked OpenSSL version/provider configuration; the presence of a wrapper or an algorithm name in a reference table is not sufficient evidence that the backend can instantiate it.

## 4. Relationships

### Source-test evidence

`test/testcase/crypto/prng/testcase_random.cpp` is the direct random-generation source path. PQC behavior is exercised by the key/signature tests under `test/testcase/crypto/key/`, `test/testcase/crypto/sign/`, and `test/testcase/crypto/pqc/` where present. These cover specific backend configurations and are not proof of universal provider availability.

- `sdk/crypto/basic/` — common crypto operation and key interfaces
- `sdk/crypto/oqs/` — OpenSSL 3 OQS provider adapter
- `sdk/crypto/advisor/` — algorithm and backend metadata
- `sdk/net/tls/` and `sdk/crypto/cose/` / `jose/` — higher-level consumers that choose when algorithms are used

- `sdk/crypto/basic/sdk.cpp` and OpenSSL support sources under `sdk/crypto/basic/sdk/`
- `sdk/crypto/basic/prng/openssl_prng.cpp`
- `sdk/crypto/basic/pqc/openssl_pqc.cpp`
- `test/testcase/crypto/prng/testcase_random.cpp`
- `sdk/crypto/oqs/` and `test/testcase/crypto/pqc/`
