## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1105                    │
│ Source basis: Revision 1105                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Digest and Transcript Hash

## 1. Role

This directory provides message-digest operations and a stateful transcript-hash abstraction. A one-shot digest answers “hash these bytes”; a transcript hash maintains the digest of an ordered sequence of protocol messages and exposes results at checkpoints.

## 2. Data Model

| Type | Responsibility |
|---|---|
| `openssl_hash` | Backend API over an opaque `hash_context_t`. Opens a digest/HMAC/CMAC context, accepts incremental updates, finalizes or duplicates state, and closes the handle. |
| `crypto_hash` | Algorithm-bound digest facade; `digest(input, result)` calls the backend for the selected `hash_algorithm_t`. |
| `crypto_hash_builder` | Selects a digest by enum or name and creates a `crypto_hash`; it centralizes selection but does not perform the digest itself. |
| `transcript_hash` | Stateful wrapper around a hash context, supporting `update`, `digest`, `reset`, and `dup`. |
| `transcript_hash_builder` | Selects the hash algorithm for a transcript-hash instance. |

```text
one-shot digest:
crypto_hash_builder → crypto_hash → openssl_hash → EVP_MD

incremental protocol transcript:
transcript_hash_builder → transcript_hash
                              ├─ update(message 1)
                              ├─ update(message 2)
                              └─ digest(checkpoint) / dup() / reset()
                                         ↓
                                    openssl_hash
```

## 3. Behavior Model

### Digest versus transcript hash

A digest is computed over a byte sequence. A transcript object retains incremental state across calls, so message order and the exact set of messages included in a checkpoint matter. In the `transcript_hash` API, `digest(message, result)` adds the supplied message to the current state and returns the resulting digest; it is not simply an independent one-shot hash of that message.

`dup()` clones backend state so a caller can preserve a checkpoint while exploring a later branch. `reset()` reinitializes state for the selected algorithm. Callers must follow the open/update/finalize/close contract of the backend context on all paths.

### Relationship to TLS

TLS handshake processing hashes handshake messages in protocol-defined order. In TLS 1.3, transcript checkpoints feed the key schedule and authentication calculations, including Finished verification and CertificateVerify inputs. This module supplies the stateful hashing mechanism; `sdk/net/tls/` decides which messages enter the transcript and when each checkpoint is required.

### Backend availability

The advisor's algorithm metadata does not guarantee that the active OpenSSL build/provider offers a particular digest. Keep the selected algorithm, context lifecycle and backend availability separate in diagnostics.

## 4. Relationships

- `../../advisor/README.md` maps digest names/aliases and resolves backend methods.
- `../mac/README.md` documents keyed HMAC/CMAC contracts that share hash-context machinery.
- `../kdf/README.md` uses digest/HMAC algorithms for key derivation.
- `sdk/net/tls/` owns handshake message ordering and transcript checkpoints.
- `../digest-and-mac.md` preserves the combined source-maintained digest/HMAC/CMAC inventory.

### Implementation entry points

- `crypto_hash.cpp`, `crypto_hash_builder.cpp`
- `openssl_hash.cpp`, `openssl_digest.cpp`
- `transcript_hash.cpp`, `transcript_hash_builder.cpp`
- `test/testcase/crypto/hash/testcase_openssl_hash.cpp`
- `test/testcase/crypto/hash/testcase_transcript_hash.cpp`

### Source-test evidence

- `testcase_openssl_hash.cpp` checks digest operations against known results.
- `testcase_transcript_hash.cpp` hashes `client hello` followed by `server hello` in one incremental context, then repeats the sequence while capturing intermediate hashes. It compares the final incremental result with the result produced through `transcript_hash_builder`, demonstrating agreement for the same accumulated transcript.
- The hash testcase directory also contains HMAC/CMAC RFC groups; those are related backend coverage, not all direct tests of `crypto_hash`.

## 5. References

- RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3.
- RFC 2104 — HMAC: Keyed-Hashing for Message Authentication (related keyed-hash backend, not the unkeyed digest contract).
