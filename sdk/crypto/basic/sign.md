# Digital Signatures

`sdk/crypto/basic/sign` provides the common signing/verifying abstraction and concrete algorithm implementations.

## Common interface

`crypto_sign_builder` selects a signature category and digest.  It can also accept TLS signature schemes and JOSE identifiers, allowing higher-level protocol code to select a primitive without directly constructing an OpenSSL operation.

`crypto_sign` exposes `sign()` and `verify()` over either a byte stream or `binary_t`.  RSA-PSS salt length is retained as primitive configuration.

## Implementation families

The current source includes:

- RSA PKCS#1 v1.5
- RSA-PSS
- DSA
- ECDSA
- EdDSA
- HMAC signing
- ML-DSA
- SLH-DSA

The digest-sign path is represented separately for algorithms such as EdDSA and the newer signature families where the backend operation is not simply the traditional explicit digest-then-sign flow.

## Identifier boundary

The builder accepts TLS and JOSE-facing identifiers, but it is still a primitive layer.  Protocol semantics remain outside `crypto/basic`; `crypto/advisor` supplies common algorithm/identifier metadata.

## Tests

`test/testcase/crypto/sign/` covers generic signing, ECDSA, HMAC, ML-DSA, RSA signatures, SLH-DSA, X.509-related signing and DSA/ECDSA/RSA test vectors.
