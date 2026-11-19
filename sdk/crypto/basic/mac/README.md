## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 2 · Revision 1107                    │
│ Source base : Revision 1132                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Message Authentication and One-Time Passwords

## 1. Role

This directory groups keyed authentication operations and two application-level OTP constructions. The key distinction is between producing/verifying a message authenticator and producing/verifying a short numeric code from a counter or time step.

## 2. Data Model

| Type | Responsibility |
|---|---|
| `openssl_mac` | Stateless helper API for one-shot HMAC, CMAC and CBC-MAC-style operations. Its HMAC path opens an `openssl_hash` context, performs the operation, and closes it; its CMAC path delegates to the CMAC-KDF helper. |
| `crypto_hmac` | Algorithm- and key-bound HMAC object. It supports one-shot `mac()` and incremental `init` / `update` / `finalize` usage. |
| `crypto_hmac_builder` | Selects the hash algorithm and key, then builds the `crypto_hmac` object. |
| `crypto_cbc_hmac` | Combined CBC encryption plus HMAC construction used for specific compatibility/protocol suites; it is not another name for standalone HMAC. |
| `hmac_otp` | HOTP configuration and counter-based code operation: shared secret/HMAC choice, counter and requested decimal digit count. |
| `time_otp` | TOTP configuration: time-step interval and digit policy; derives a counter from time and delegates code generation/verification to HOTP. |

## 3. Behavior Model

### HMAC lifecycle

```text
hash algorithm + secret key
            |
            v
 crypto_hmac_builder
            |
            v
       crypto_hmac
        /       \
       /         \
mac(message)   init → update(chunk)* → finalize
       \         /
        \       /
         openssl_hash / OpenSSL HMAC
```

The builder binds the selected hash and secret key to the higher-level object. A one-shot `mac()` call consumes a complete message; the incremental path retains keyed hash state across `update()` calls until finalization. `openssl_mac` is a separate one-shot helper, while `openssl_hash` is the context-level interface used for stateful backend work.

**Current `crypto_hmac` status limitation:** its constructor ignores the return values from `openssl_hash::open()` and `init()`; `mac()` returns its initialized success value without propagating `init/update/finalize` failures; and the fluent `init/update/finalize` methods also discard backend statuses. `digest(md)` calls `openssl_hash::update(handle, nullptr, 0, md)`, whose current null-input path returns success without writing a digest (the same underlying issue documented for `transcript_hash`). A non-null builder result therefore does not prove a valid backend context, and the no-message `digest()` method should not be relied on until fixed.

### Concrete caller paths: primitive, facade, and JOSE

`test/testcase/crypto/sign/testcase_hmac.cpp` deliberately exercises three layers with the same message and key material:

```text
message bytes
   ├─ openssl_hash(hash context, SHA-256) ──> unkeyed digest
   ├─ openssl_hash(hash context + key) ─────> HMAC bytes
   ├─ openssl_sign::sign_hmac / verify_hmac
   │                                         └─> status
   └─ json_object_signing_encryption
         sign(jws_t::hs256) / verify()
                     └─> JOSE signature object/string + status
```

The testcase compares the `openssl_hash` SHA-256 result with `EVP_Digest` output, which checks agreement between two unkeyed digest paths. For HMAC, it opens `openssl_hash` with the key and SHA-256 and checks the operation status; the shown code logs the resulting bytes but does not compare them against an expected HMAC vector. The `openssl_sign` path then signs and verifies the same message using `sign_hmac()` and `verify_hmac()`. Finally, the JOSE path uses `jws_t::hs256`, verifies the produced JOSE signature, and closes its context.

These are related but different API contracts: raw HMAC bytes are not a JOSE signature representation, and a successful sign/verify round trip is not a substitute for a known-answer vector. The RFC 4231 testcase supplies the independent known-answer HMAC checks.

### HOTP and TOTP data flow

```text
HOTP:
secret key + counter
        |
        v
       HMAC
        |
        v
 dynamic truncation → numeric value → decimal digits

TOTP:
supplied time + configured time-step interval
        |
        v
   time-step counter
        |
        v
       HOTP
        |
        v
     decimal code
```

HOTP's counter and digit count are operation inputs. TOTP first maps the supplied time to a time-step counter and then uses the HOTP mechanism. Verification additionally depends on the caller's accepted counter/time window and replay policy; those policies are not encoded by the primitive itself. In the current implementation, the HOTP context has `_window` / `_window_size` fields and a lock, but the operations do not use them: there is no built-in look-ahead window and automatic counter access is not synchronized. The automatic counter is `uint32`, so it does not cover the full 64-bit RFC 4226 counter range; callers needing a wider counter must use the binary-counter overload. `digit_length == 0` selects 6 digits and values above 9 are capped at 9. TOTP `interval == 0` is converted to a 1-second interval, not the commonly used 30-second interval.

There are also status-propagation defects: `hmac_otp::get(handle, code)` ignores the result of the counter-specific `get()` and returns success after incrementing the counter; `time_otp::get()` ignores the underlying HOTP result and returns success; and `time_otp::verify()` returns success when its internal `get()` fails. These methods should not be described as reliably propagating backend failures.

### HMAC and CBC-HMAC are different contracts

HMAC authenticates a message with a secret key and hash function. CBC-HMAC combines encryption and authentication with a specified byte layout and ordering; the order is protocol-specific. The [CBC-HMAC developer note](cbc-hmac-survey.md) distinguishes TLS MAC-then-encrypt (MtE), TLS encrypt-then-MAC (EtM), and JOSE's AES-CBC-HMAC construction. In the current API, the combined-tag `encrypt/decrypt` overloads handle the TLS flags and reject `jose_encrypt_then_mac`; JOSE uses the separate-tag overloads, which require that flag and are called by the JOSE JWE path and its vector tests.

The separate-tag JOSE `encrypt()` path currently does not assign/check the return value from `crypt.encrypt()`, then computes the tag and returns the earlier status. The JOSE decrypt path verifies the tag before decrypting, but compares tags with ordinary container equality (`tag != mac`), not a constant-time comparison. The TLS decrypt paths use the same ordinary tag comparison. The CBC-HMAC implementation also uses the `crypto_hmac` fluent API described above, which does not propagate backend errors.

### Why OTP is separate

- HOTP applies HMAC to a counter and dynamically truncates the result to a configured digit length.
- TOTP computes a time-step counter from the supplied time and interval, then uses HOTP's counter-based mechanism.
- Verification needs counter/time policy in addition to cryptographic comparison. Replay prevention, rate limiting, and the server-side accepted-window policy remain application responsibilities.

### Supported algorithms and caveat

HMAC's digest choice is resolved through common hash metadata/backend operations. CMAC and CBC-HMAC have distinct construction requirements. An algorithm appearing in advisor metadata does not guarantee that the active OpenSSL/provider build offers it.

## 4. Relationships
- `../digest/README.md` explains the shared hash backend and the difference between an unkeyed digest and keyed HMAC.
- `../sign/README.md` exposes HMAC through a common sign/verify facade for consumers that share interfaces.
- `../crypt/README.md` documents cipher/AEAD constructions with their own authentication-tag contracts.
- `sdk/net/tls/` owns TLS record processing and MtE/EtM semantics; this module supplies primitive/construction operations.
- `sdk/crypto/jose/` uses CBC-HMAC content-encryption algorithms specified by JOSE.

### Implementation entry points

- `sdk/crypto/basic/mac/crypto_hmac.cpp`, `crypto_hmac_builder.cpp`, `openssl_mac.cpp`
- `sdk/crypto/basic/mac/crypto_cbc_hmac.cpp`, `hmac_otp.cpp`, `time_otp.cpp`
- `test/testcase/crypto/hash/` (HMAC/CMAC/HOTP/TOTP vectors), `test/testcase/crypto/crypt/` (TLS/JOSE CBC-HMAC vectors), and `test/testcase/crypto/sign/` (HMAC signing/JOSE integration)

### Source-test evidence

- `test/testcase/crypto/hash/testcase_rfc4231.cpp` covers HMAC-SHA known-answer vectors; `testcase_rfc4493.cpp` covers AES-CMAC known-answer vectors through the `openssl_hash` CMAC context path.
- `test/testcase/crypto/hash/testcase_rfc4226.cpp` and `testcase_rfc6238.cpp` compare generated HOTP/TOTP codes with RFC vectors. They do not exercise the `verify()` methods, and their per-code `get()` return values are not checked explicitly.
- `test/testcase/crypto/crypt/testvector_cbc_hmac_tls.cpp` covers TLS MtE/EtM; `testvector_cbc_hmac_jose.cpp` covers the separate-tag JOSE path and checks intermediate/final vector values plus encrypt/decrypt results.
- `test/testcase/crypto/sign/testcase_hmac.cpp` exercises the `openssl_hash`, `openssl_sign`, and JOSE HS256 integration paths; it does not directly exercise the `crypto_hmac` facade.
- These are source-level coverage references; they do not claim the tests were executed in the current environment.

## 5. References
- RFC 2104 — HMAC: Keyed-Hashing for Message Authentication.
- RFC 4226 — HOTP: An HMAC-Based One-Time Password Algorithm.
- RFC 4231 — Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512.
- RFC 4493 — The AES-CMAC Algorithm.
- RFC 6238 — TOTP: Time-Based One-Time Password Algorithm.
- RFC 7366 — Encrypt-then-MAC for TLS and DTLS.
- RFC 7516 — JSON Web Encryption (JWE).
- RFC 7518 — JSON Web Algorithms (JWA).
