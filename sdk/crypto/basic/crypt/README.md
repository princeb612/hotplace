## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source basis: Revision 1107                  │
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

The low-level context is the backend state associated with a selected cipher and its key/IV configuration. The higher-level wrappers keep that context lifecycle behind a simpler operation contract; public-key encryption instead carries an `EVP_PKEY` and uses a distinct EVP public-key operation.

### Builder purpose

Builders resolve a library/protocol identifier into an operation object and hide concrete implementation selection. They do not generate keys, guarantee provider availability, choose a safe nonce for every use case, or define a security policy. The caller still supplies the key and required per-message parameters.

## 3. Behavior Model

### Symmetric cipher lifecycle

```text
algorithm + mode + key + IV
             |
             v
    openssl_crypt::open()
             |
             v
       crypt_context_t
             |
       encrypt / decrypt
             |
             v
    EVP_CipherUpdate / Final
             |
             v
       output bytes
             |
             v
    openssl_crypt::close()
```

`cipher_encrypt` owns this open → operation → close sequence internally. With the low-level `openssl_crypt` interface, the caller controls the context lifecycle and must close it on all paths. The context is backend state, not the ciphertext or key material itself.

### AEAD path: scheme selection, authenticated inputs and result

```text
crypto_aead_builder.set_scheme(scheme)
             |
             v
           build()
             |
             v
         crypto_aead
             |
             v
 advisor: scheme → algorithm + mode
             |
             v
 openssl_crypt / OpenSSL EVP
             |
    +--------+---------+
    |                  |
 encrypt            decrypt
 key, nonce,        key, nonce,
 plaintext, AAD     ciphertext, AAD, tag
    |                  |
    v                  v
 ciphertext + tag   authentication check
                       |
                 plaintext only on success
```

The scheme selects the operation family; the caller supplies per-message key/nonce and, for AEAD, AAD. During decryption the supplied tag is checked against the selected ciphertext and AAD. The authentication result is part of the operation contract: successful byte processing alone is not enough to treat unauthenticated plaintext as valid.

### Public-key encryption path

```text
crypt_enc_t
    |
    v
crypto_encrypt_builder
    |
    v
crypto_encrypt + EVP_PKEY
    |
    v
RSA EVP encrypt / decrypt operation
    |
    v
output bytes or operation failure
```

This path is separate from symmetric encryption: the key is an `EVP_PKEY`, and the builder selects a public-key encryption scheme such as RSA PKCS#1 v1.5 or RSA-OAEP. A symmetric mode/IV configuration is not a substitute for the public-key scheme and its parameters.

### Operation result and per-message data

Across the paths, the important data differs by operation: symmetric encryption transforms input bytes under a cipher context; AEAD additionally binds AAD and an authentication tag; public-key encryption dispatches using an `EVP_PKEY` and an encryption scheme. Callers must check the operation status before consuming output, and must supply the exact parameter layout expected by the chosen backend.

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

The implementation questions identified above are tracked in [`follow-up-workspace/README.md`](../../../../follow-up-workspace/README.md) under **CRYPTO-01**; this document retains the current implementation behavior and limitations.

### Algorithm inventory caveat

The source-maintained cipher/mode inventory in [Cipher](../cipher.md) records combinations represented by the source. It does not guarantee that every algorithm/mode is enabled by every OpenSSL build or provider.

### Practical use: build a cipher, round-trip bytes, then release it

The symmetric wrapper testcase selects an algorithm/mode through a builder, encrypts a byte range, and only attempts decryption after encryption succeeds:

```cpp
cipher_encrypt_builder builder;
auto cipher = builder.set(crypt_algorithm_t::aes128, crypt_mode_t::cbc).build();
if (cipher) {
    binary_t ciphertext;
    return_t ret = cipher->encrypt(key, iv, input, input_size, ciphertext);
    if (errorcode_t::success == ret) {
        binary_t plaintext;
        ret = cipher->decrypt(key, iv, ciphertext, plaintext);
        // Compare plaintext with the original input in the caller.
    }
    cipher->release();
}
```

The builder chooses the operation implementation; the caller supplies the key, IV, and input bytes. The round trip demonstrates API composition, not a recommendation to reuse a fixed IV or key in an application. Real applications must follow the selected mode's key/IV requirements and manage key material and nonce/IV uniqueness appropriately.

For AEAD, the analogous testcase uses `crypto_aead_builder::set_scheme()` and carries AAD and the authentication tag as separate inputs/outputs. See [testcase_cipher_encrypt.cpp](../../../../test/testcase/crypto/crypt/testcase_cipher_encrypt.cpp) and [testcase_crypto_aead.cpp](../../../../test/testcase/crypto/crypt/testcase_crypto_aead.cpp).

### Concrete caller path: AEAD round trip

The common AEAD testcase builds a scheme-specific object, supplies the per-message key, nonce/IV, plaintext and AAD, and carries the returned tag into decryption. The shortened form below follows `test/testcase/crypto/crypt/testcase_crypto_aead.cpp`:

```cpp
#include <hotplace/sdk/crypto/basic/crypto_aead.hpp>

crypto_aead_builder builder;
auto aead = builder.set_scheme(crypto_scheme_t::aes_128_gcm).build();
if (aead) {
    binary_t ciphertext, plaintext, tag;
    return_t ret = aead->encrypt(key, iv,
        reinterpret_cast<const byte_t*>(input.data()), input.size(),
        ciphertext, aad, tag);
    if (errorcode_t::success == ret) {
        ret = aead->decrypt(key, iv, ciphertext, plaintext, aad, tag);
    }
    aead->release();
}
```

The important contract is that the tag is a separate output of encryption and an input to decryption, while AAD is supplied to both operations but is not encrypted into the ciphertext. The test exercises round trips for several AES-GCM/CCM scheme identifiers; it does not establish interoperability with another implementation or define a production nonce-generation strategy. The test's fixed key and IV are fixtures and must not be copied into application code.

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
