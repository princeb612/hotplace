# COSE cryptographic processing

`cbor_object_signing_encryption` is the main processing engine connecting the COSE message tree to `sdk/crypto/basic`.

## Operations

The public processing surface covers:

- encrypt / decrypt
- sign / verify
- MAC creation / verification
- multi-layer key distribution

The implementation has send and receive modes. Receive processing reverses the relevant operations and validates the cryptographic result.

## Context construction

COSE cryptography does not operate directly on the original CBOR message. The implementation composes the structures required by the COSE algorithms, including:

- encryption AAD / Enc_structure
- signature / Sig_structure
- MAC structure
- KDF context for key agreement/distribution

The source exposes these as dedicated `compose_*_context` paths. This is an important boundary between COSE encoding and the primitive crypto API.

## Key distribution

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

## Primitive boundary

COSE owns the message semantics and context construction. `crypto/basic` owns the underlying digest, MAC, encryption, signature, key and KDF operations. `advisor` supplies identifier/resource metadata where needed.

## Tests

The implementation is exercised by `testcase_cose.cpp`, RFC 8152 vectors, COSE example vectors, and algorithm/key tests in the COSE testcase directory.
