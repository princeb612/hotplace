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
| `hmac_otp` | HOTP: computes a truncated numeric code from an HMAC and counter. |
| `time_otp` | TOTP: derives a counter from time steps and delegates code generation/verification to HOTP. |

### Builder and backend path

```text
crypto_hmac_builder.set(hash).set(key).build()
                    ↓
                crypto_hmac
           ├─ mac(message)
           └─ init → update* → finalize
                    ↓
               openssl_hash / OpenSSL HMAC

hmac_otp (HOTP) ── uses HMAC over counter bytes
time_otp (TOTP) ── maps time to counter ──► HOTP
```

The builder records algorithm and key for the higher-level object. The backend owns OpenSSL HMAC context and update/finalize operations. Use `crypto_hmac` for a reusable keyed object and incremental updates; use `openssl_mac` for one-shot helper calls where input/output are already available. `openssl_mac` is not itself the lower-level stateful-context API—the context-level interface is `openssl_hash`.

## 3. Behavior Model

### HMAC and CBC-HMAC are different contracts

HMAC authenticates a message with a secret key and hash function. CBC-HMAC combines encryption and authentication with a specified byte layout and ordering; the order is protocol-specific. The [CBC-HMAC developer note](cbc-hmac-survey.md) distinguishes TLS MAC-then-encrypt (MtE), TLS encrypt-then-MAC (EtM), and JOSE's AES-CBC-HMAC construction. Treat it as comparative implementation study material, not a generic construction recipe.

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

- `crypto_hmac.cpp`, `crypto_hmac_builder.cpp`, `openssl_mac.cpp`
- `crypto_cbc_hmac.cpp`, `hmac_otp.cpp`, `time_otp.cpp`
- `test/testcase/crypto/hash/`, `test/testcase/crypto/sign/`

### Source-test evidence

- `testcase_rfc4231.cpp` covers HMAC-SHA vectors.
- `testcase_rfc4493.cpp` covers AES-CMAC vectors.
- `testcase_rfc4226.cpp` covers HOTP, and `testcase_rfc6238.cpp` covers TOTP.
- `testcase_hmac.cpp` exercises the signing/MAC integration path.
- These are source-level coverage references; they do not claim the tests were executed in the current environment.

## 5. References

- RFC 2104 — HMAC: Keyed-Hashing for Message Authentication.
- RFC 4226 — HOTP: An HMAC-Based One-Time Password Algorithm.
- RFC 4231 — Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512.
- RFC 4493 — The AES-CMAC Algorithm.
- RFC 6238 — TOTP: Time-Based One-Time Password Algorithm.
