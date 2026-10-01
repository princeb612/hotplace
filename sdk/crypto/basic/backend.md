# OpenSSL Backend, PRNG and PQC

Three smaller areas complete the `crypto/basic` implementation layer: OpenSSL SDK support, random generation and post-quantum cryptography.

## OpenSSL SDK support

`sdk/` contains the hotplace-side OpenSSL support layer.  It includes SDK initialization/debug support and OpenSSL tuning/helpers used by the primitive implementations.

The important architectural point is that most crypto classes do not expose OpenSSL setup details directly.  Backend-specific code stays close to the operation it implements, while common types and builders remain in the hotplace namespace.

## PRNG

`prng/openssl_prng.cpp` provides the random-number generation path through OpenSSL.  The public wrapper is intentionally small; consumers should use the hotplace crypto abstraction rather than depending directly on backend calls.

The corresponding testcase is `test/testcase/crypto/prng/testcase_random.cpp`.

## PQC

`pqc/openssl_pqc.cpp` is the OpenSSL-facing post-quantum cryptography integration.  Current tests cover PQC key/signature operations and hybrid KEM behavior, with OQS-provider material retained under `test/testcase/crypto/`.

PQC support should be understood as backend integration rather than a separate protocol implementation.  Higher-level TLS/COSE/other modules decide where these algorithms are used.
