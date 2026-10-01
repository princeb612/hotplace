# Key Derivation Functions

`sdk/crypto/basic/kdf` provides key-derivation primitives through the OpenSSL backend.

Implemented paths include:

- AES-based KDF
- PBKDF2
- scrypt
- Argon
- TLS-related derivation

The generic KDF interface hides the backend-specific EVP setup while keeping the inputs and derived output in hotplace `binary_t`-based types.

## Boundary

KDF is a primitive layer, not a protocol implementation.  For example, TLS-specific derivation is represented here as a cryptographic operation while the TLS key schedule and handshake state remain in `sdk/net/tls`.

## Tests

`test/testcase/crypto/kdf/` contains HKDF tests and RFC 6070, RFC 7914 and RFC 9106 coverage, plus RFC 4615 and RFC 5869 test vectors.
