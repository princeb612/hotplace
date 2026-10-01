# Digest and Transcript Hash

`sdk/crypto/basic/digest` contains message-digest primitives and the transcript-hash abstraction used by protocol code.

## Digest layer

`crypto_hash` is the common hash interface.  The builder selects a hash algorithm and the OpenSSL implementation performs the actual digest operation.

The implementation keeps algorithm selection separate from the operation itself:

```text
crypto/advisor
    → hash algorithm metadata
crypto_hash_builder
    → crypto_hash
    → OpenSSL digest
```

## Transcript hash

`transcript_hash` keeps an accumulated hash state for protocol handshakes.  It is not a new hash algorithm; it is a stateful protocol-facing wrapper around the digest primitive.

This distinction is important for TLS, where handshake messages are fed into a transcript and the resulting digest is later consumed by key schedule or authentication logic.

## Tests

`test/testcase/crypto/hash/` covers OpenSSL hashing, RFC 4226/4231/4493/6238 cases and transcript-hash behavior.
