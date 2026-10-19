## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# Digest and Transcript Hash

## 1. Role

`sdk/crypto/basic/digest` contains message-digest primitives and the transcript-hash abstraction used by protocol code.

## 2. Model

### Digest layer

`crypto_hash` is the common hash interface.  The builder selects a hash algorithm and the OpenSSL implementation performs the actual digest operation.

The implementation keeps algorithm selection separate from the operation itself:

```text
crypto/advisor
    → hash algorithm metadata
crypto_hash_builder
    → crypto_hash
    → OpenSSL digest
```

### Transcript hash

`transcript_hash` keeps an accumulated hash state for protocol handshakes.  It is not a new hash algorithm; it is a stateful protocol-facing wrapper around the digest primitive.

This distinction is important for TLS, where handshake messages are fed into a transcript and the resulting digest is later consumed by key schedule or authentication logic.

## 3. Important behavior and lifetime

Implementation behavior is documented only to the extent supported by the retained notes and source references.

## 4. Example from the source tests

### Tests

`test/testcase/crypto/hash/` covers OpenSSL hashing, RFC 4226/4231/4493/6238 cases and transcript-hash behavior.

## 5. Relationships

Related implementation modules and protocol boundaries are recorded here where identified.

## 6. References

Relevant source paths, sibling documentation, and standards references are retained here where available.
