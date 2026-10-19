## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# COSE cryptographic processing

## 1. Role

Describes COSE cryptographic processing paths and the structures passed to the crypto layer.

## 2. Model

`cbor_object_signing_encryption` is the main processing engine connecting the COSE message tree to `sdk/crypto/basic`.

### Operations

The public processing surface covers:

- encrypt / decrypt
- sign / verify
- MAC creation / verification
- multi-layer key distribution

The implementation has send and receive modes. Receive processing reverses the relevant operations and validates the cryptographic result.

### Context construction

COSE cryptography does not operate directly on the original CBOR message. The implementation composes the structures required by the COSE algorithms, including:

- encryption AAD / Enc_structure
- signature / Sig_structure
- MAC structure
- KDF context for key agreement/distribution

The source exposes these as dedicated `compose_*_context` paths. This is an important boundary between COSE encoding and the primitive crypto API.

### Key distribution

The implementation supports direct key use and layered key-distribution algorithms such as AES-KW, HKDF-based methods and ECDH variants. Recipient layers carry the algorithm/key-distribution metadata needed to derive or unwrap the content encryption key.

The processing flow is therefore roughly:

```text
COSE layer
  ↓
preprocess
  ├── inspect protected/unprotected algorithms
  ├── establish random/nonce material when needed
  ├── process recipient/key distribution
  └── compose cryptographic context
  ↓
crypto/basic
  ↓
write/read ciphertext, tag or signature
```

### Primitive boundary

COSE owns the message semantics and context construction. `crypto/basic` owns the underlying digest, MAC, encryption, signature, key and KDF operations. `advisor` supplies identifier/resource metadata where needed.

## 3. Important behavior and lifetime

COSE processing depends on message family, protected/unprotected headers, key and algorithm availability, and the underlying cryptographic implementation.

## 4. Example from the source tests

### Tests

The implementation is exercised by `testcase_cose.cpp`, RFC 8152 vectors, COSE example vectors, and algorithm/key tests in the COSE testcase directory.

## 5. Relationships

- `sdk/io/cbor/` provides CBOR parsing, encoding, and object representation.
- `sdk/crypto/basic/` provides cryptographic primitives used by COSE.

## 6. References

- Source: this module and its related testcase directory (Revision 1104).
