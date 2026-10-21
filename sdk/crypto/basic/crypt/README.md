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

# Crypt and AEAD

## 1. Role

This directory implements symmetric encryption, authenticated encryption (AEAD), and a separate public-key encryption facade. The common operation interfaces/builders sit above OpenSSL-backed cipher implementations.

The key distinction is that symmetric ciphering, AEAD, and public-key encryption are separate contracts even where they share backend infrastructure.

## 2. Data Model

| Type | Role | Configuration |
|---|---|---|
| `openssl_crypt` | Low-level symmetric cipher backend. Opens a `crypt_context_t` for an algorithm/mode and key/IV, then encrypts/decrypts through that handle. It also exposes AAD/tag overloads for AEAD modes. | Explicit algorithm + mode, or an advisor-resolvable name; caller manages `open` / operation / `close`. |
| `cipher_encrypt` | Symmetric wrapper around `openssl_crypt`; performs encrypt/decrypt calls over `binary_t`. | Constructed with `crypt_algorithm_t` and `crypt_mode_t`; no builder is needed for this wrapper. |
| `crypto_aead` | Common authenticated-encryption interface accepting key, nonce/IV, plaintext/ciphertext, AAD and authentication tag. | `crypto_aead_builder` selects a `crypto_scheme_t`, such as AES-GCM. |
| `crypto_encrypt` | Public-key encryption/decryption with an `EVP_PKEY`; not the symmetric cipher API. | `crypto_encrypt_builder` selects `crypt_enc_t`, including RSA PKCS#1 v1.5 and RSA-OAEP variants. |

Typical AEAD path:

```text
crypto_aead_builder.set_scheme(scheme)
       └─ build() → crypto_aead
                      └─ advisor maps scheme → algorithm + mode
                             └─ openssl_crypt → OpenSSL EVP
```

For direct low-level use, `openssl_crypt::open()` creates the context and `close()` releases it. The `cipher_encrypt` convenience wrapper owns that sequence internally. Public-key encryption follows the separate path `crypto_encrypt_builder` → `crypto_encrypt` → RSA EVP operation.

### Builder purpose

Builders resolve a library/protocol identifier into an operation object and hide concrete implementation selection. They do not generate keys, guarantee provider availability, choose a safe nonce for every use case, or define a security policy. The caller still supplies the key and required per-message parameters.

## 3. Behavior Model

### Symmetric cipher versus AEAD

A conventional cipher call returns ciphertext but does not necessarily authenticate it. AEAD additionally authenticates the ciphertext and caller-supplied additional authenticated data (AAD), returning a tag. Decryption must provide matching AAD and tag; plaintext is accepted only if authentication succeeds.

### ChaCha20 counter and nonce handling

The helper `openssl_chacha20_iv()` prepends a 32-bit counter in little-endian byte order to supplied nonce bytes. In the RFC 7539 test vectors, the supplied nonce field is 8 bytes, so counter + nonce produces the 12-byte nonce expected by the IETF ChaCha20-Poly1305 path. The helper caps its nonce input at 12 bytes; passing a full 12-byte value therefore produces a 16-byte result. Callers must follow the input convention of the specific call site.

This helper represents the counter-plus-nonce layout used by the original ChaCha20 interface/test-vector convention. It must not be confused with the ChaCha20-Poly1305 AEAD API, which passes its nonce to the selected EVP cipher and configures AEAD nonce length separately. IV/nonce layouts are algorithm- and API-specific; they are not interchangeable byte strings.

### Key and nonce responsibilities

The caller supplies key and IV/nonce values. In particular, a nonce must not be reused with the same key where the selected AEAD algorithm forbids reuse. Selecting an algorithm with a builder is not a nonce-generation policy.

### `openssl_crypt` cooltime: optional pacing for large buffers

The `cooltime` setting is a throttling workaround, not a faster encryption path. With the default value of zero, `encrypt_internal()` and `decrypt_internal()` pass the whole input to one `EVP_CipherUpdate()` call. When a nonzero cooltime is configured, the implementation processes input in cipher-block-sized updates and sleeps for the configured interval after the accumulated processed output exceeds `unitsize`. This can reduce sustained CPU pressure at the cost of throughput and added wall-clock time.

```text
ossl_set_cooltime(ms) ────────┐
ossl_set_unitsize(bytes) ─────┼── global tuning settings
                              │
openssl_crypt::encrypt_internal()
openssl_crypt::decrypt_internal()
                              │
                              ▼
                     cooltime = ossl_get_cooltime()
                              │
                 mode is CCM or key-wrap?
                       ┌──────┴──────┐
                      yes            no
                       │              │
                cooltime = 0     cooltime > 0?
                                      │
                           ┌──────────┴──────────┐
                          no                     yes
                           │                      │
                one EVP_CipherUpdate()     advisor block size
                for the input              + block-sized updates
                                                  │
                                      accumulate processed bytes
                                                  │
                                  size_process > unitsize?
                                        ┌─────────┴────────┐
                                       no                 yes
                                        │                  │
                                   continue            msleep(cooltime)
                                                           │
                                                    reset size_process
                                        │
                                        ▼
                           EVP_CipherFinal() / result
```

#### Current settings and behavior

| Item | Current source behavior |
|---|---|
| `ossl_cooltime` | Global setting; default `0` ms, so pacing is off by default. |
| `ossl_cooltime_max` | Default `1000` ms. `ossl_set_cooltime(ms)` accepts only `ms < max`, so the current maximum value itself is rejected. |
| `ossl_cooltime_unitsize` | Global threshold; default `4096` bytes. A nonzero requested size is rounded up to a multiple of 8. |
| Sleep trigger | The code sleeps when accumulated processed output is **greater than** `unitsize`, then resets the accumulator. It is not a precise rate limiter and does not promise a fixed CPU percentage. |
| Cipher update size | Each paced update uses the block size from `crypto_advisor`; the OpenSSL block-size API is deliberately avoided here because source comments note incorrect results for some stream-like modes such as CFB/OFB. |
| Modes excluded from pacing | CCM and key-wrap (`wrap`) force local `cooltime` to zero, even when the global setting is nonzero. |
| Settings scope | The settings are static globals shared by callers, not per-`openssl_crypt` context settings. |

#### Source flow and limitations

1. `ossl_set_cooltime()` and `ossl_set_unitsize()` configure global tuning values in `sdk/openssl_tune.cpp`.
2. Encryption and decryption each read the current cooltime when the internal operation reaches the data-processing stage.
3. If pacing is enabled for the selected mode, the code walks the input by the advisor-reported cipher block size, calls `EVP_CipherUpdate()` repeatedly, and sleeps after the processed-byte accumulator crosses the configured threshold.
4. Finalization still runs through `EVP_CipherFinal()`; AEAD tag handling remains in the surrounding operation flow. Pacing changes the update schedule, not the cipher or its security properties.

This is a best-effort pacing mechanism. The threshold is checked after each block-sized update, so a sleep may occur after the processed amount has crossed the threshold. It does not cap CPU utilization directly, guarantee fairness to other threads, or make encryption intrinsically faster. In the paced loops, the return value from each `EVP_CipherUpdate()` is not checked in the same way as the single-call fast path; this is a concrete point to revisit if the implementation is refactored.

#### Existing source-test path

`test/testcase/crypto/crypt/testcase_openssl_crypt.cpp` runs the routine first with `cooltime = 10` ms and `unitsize = 4096`, then with `cooltime = 0` for the speed path. The test reports these as a large-stream/performance condition and a speed condition; it uses a short fixed string and a matrix of algorithms/modes, so it is **not evidence of CPU-load reduction on a genuinely large file**.

One detail worth preserving: the second call passes `unitsize = 0`, but `ossl_set_unitsize(0)` returns `invalid_parameter`. Because the test does not check that setter's return value, the prior 4096-byte threshold remains in place. That does not affect the second run's pacing decision because cooltime is set to zero.

#### Review points for a future change

- Measure CPU utilization and throughput on genuinely large buffers/files; the current test mainly verifies encrypt/decrypt round trips over short input.
- Decide whether the threshold should be checked with `>=` rather than `>`, and document the actual maximum interval semantics.
- Check and propagate errors from every chunk-level `EVP_CipherUpdate()` call.
- Decide whether tuning should remain global or become per-context/per-operation, and define synchronization expectations if settings may change concurrently with encryption.
- Verify that chunking remains correct for every supported cipher mode, especially AEAD modes and block/padding boundaries.
- Consider a more explicit pacing policy if the goal is to control CPU pressure rather than merely insert sleeps at byte thresholds.

### Algorithm inventory caveat

The source-maintained cipher/mode inventory in [Cipher](../cipher.md) records combinations represented by the source. It does not guarantee that every algorithm/mode is enabled by every OpenSSL build or provider.

## 4. Relationships

- `crypto_advisor` maps `crypto_scheme_t` and names to cipher metadata and OpenSSL methods; metadata does not guarantee provider availability.
- `../digest/README.md` and `../mac/README.md` document related digest/MAC primitives.
- TLS, JOSE and COSE build protocol-specific inputs and headers above these primitives; this layer does not construct TLS records or JOSE/COSE messages.
- `../key/README.md` documents key objects and key material.

### Implementation entry points

- `openssl_crypt.cpp`, `openssl_crypt_evp.cpp`, `openssl_crypt_cipher.cpp` — backend/context operations.
- `cipher_encrypt.cpp` — symmetric algorithm/mode wrapper.
- `crypto_aead.cpp`, `crypto_aead_builder.cpp` — AEAD facade and scheme selection.
- `crypto_encrypt.cpp`, `crypto_encrypt_builder.cpp` — public-key encryption facade and selection.
- `openssl_chacha20.cpp` — counter/nonce layout helper.
- `test/testcase/crypto/crypt/` — operation tests and known-answer vectors.

### Source-test evidence

- `testcase_crypto_encrypt.cpp` and `testcase_cipher_encrypt.cpp` exercise public-key encryption and the symmetric wrapper respectively.
- `testcase_crypto_aead.cpp` and `testcase_aead_ccm.cpp` exercise AEAD behavior.
- CAVP block-cipher vectors, RFC 3394 key-wrap vectors, RFC 7539 ChaCha20/Poly1305 vectors, and CBC-HMAC TLS/JOSE vectors cover specific algorithm contracts. Vector presence should not be read as support for every algorithm/mode in every build.

## 5. References

- RFC 8017 — PKCS #1: RSA Cryptography Specifications Version 2.2.
- RFC 3394 — Advanced Encryption Standard (AES) Key Wrap Algorithm.
- RFC 5649 — AES Key Wrap with Padding.
- RFC 5116 — An Interface and Algorithms for Authenticated Encryption.
- RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols (supersedes RFC 7539).
