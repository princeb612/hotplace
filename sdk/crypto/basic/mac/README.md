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

HOTP's counter and digit count are operation inputs. TOTP first maps the supplied time to a time-step counter and then uses the HOTP mechanism. Verification additionally depends on the caller's accepted counter/time window and replay policy; those policies are not encoded by the primitive itself.

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
