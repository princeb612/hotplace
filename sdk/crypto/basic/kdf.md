## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Key Derivation Functions

## 1. Role

`sdk/crypto/basic/kdf` provides key-derivation primitives through the OpenSSL backend.

Implemented paths include:

- AES-based KDF
- PBKDF2
- scrypt
- Argon
- TLS-related derivation

The generic KDF interface hides the backend-specific EVP setup while keeping the inputs and derived output in hotplace `binary_t`-based types.

## 2. Model

The model, structure, or retained explanatory material is described where the existing source-tree notes provide evidence.

## 3. Important behavior and lifetime

Implementation behavior is documented only to the extent supported by the retained notes and source references.

## 4. Example from the source tests

### Tests

`test/testcase/crypto/kdf/` contains HKDF tests and RFC 6070, RFC 7914 and RFC 9106 coverage, plus RFC 4615 and RFC 5869 test vectors.

## 5. Relationships

### Boundary

KDF is a primitive layer, not a protocol implementation.  For example, TLS-specific derivation is represented here as a cryptographic operation while the TLS key schedule and handshake state remain in `sdk/net/tls`.

## 6. References

Relevant source paths, sibling documentation, and standards references are retained here where available.
