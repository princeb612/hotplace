## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1107                    │
│ Source basis: Revision 1107                  │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# OpenSSL Backend, PRNG and PQC

## 1. Role

Three smaller areas complete the `crypto/basic` implementation layer: OpenSSL SDK support, random generation and post-quantum cryptography.

## 2. Data Model

These directories do not define one shared object. They cover three backend concerns with separate state and output shapes.

### OpenSSL SDK support

`sdk/openssl_sdk.cpp` owns process-level OpenSSL startup/cleanup and the compatibility path for thread setup on OpenSSL versions older than 1.1. The relevant state is a pair of reference counts protected by critical sections: one for global startup/cleanup and one for legacy thread setup/cleanup. These counts coordinate repeated calls; they are not per-cipher or per-key state.

The layer also provides BIO-to-`stream_t` copying and shared initialization/debug helpers used by concrete primitive implementations. Most operation classes keep these backend details behind their own interfaces.

### PRNG

`openssl_prng` is a stateless static-function facade. It exposes several result shapes:

| API family | Input | Output representation |
|---|---|---|
| `rand32()`, `rand64()` | Fixed integer width | Integer populated from random bytes |
| `random(buf, size)` | Caller-owned byte buffer and size | Bytes written into the supplied buffer |
| `random(binary_t&, size)` | Requested byte count | Resized `binary_t` containing random bytes |
| `random(uint32&, mask)` | Integer plus bit mask | Random integer with masked bits |
| `rand(size, encoding, usetime)` | Requested size, text encoding, optional time prefix | Encoded random bytes, optionally preceded by encoded timestamp bytes |
| `nonce(size, encoding)`, `token(size, encoding)` | Requested size and text encoding | Encoded string generated through `rand(..., false)` |

The `rand()` path enforces a minimum random-buffer size of eight bytes. When `usetime` is true, the encoded timestamp is prepended to the encoded random bytes; the timestamp is additional structure, not itself random entropy. `nonce()` and `token()` currently use the same generation path and do not add distinct token/nonce semantics.

### PQC

`openssl_pqc` groups OpenSSL-facing post-quantum key encoding, decoding, KEM and signature operations. Its main data shapes are:

| Data | Meaning |
|---|---|
| `EVP_PKEY` | Algorithm-specific key object supplied to or returned from the backend |
| `key_encoding_t` | Selects PEM, DER or raw key representation, including public/private and encrypted-private forms where supported |
| `keycapsule` | KEM encapsulation output sent to the private-key holder; not the shared secret |
| `sharedsecret` | Derived secret output from encapsulation or decapsulation |
| `signature` | Signature bytes produced by signing or consumed by verification |
| `OSSL_LIB_CTX*` | OpenSSL library-context parameter used by the key encode/decode and signature paths |

The documented ML-KEM parameter table records algorithm-specific public-key and capsule sizes. Hybrid ECDHE-ML-KEM shares combine component data according to the selected TLS group metadata; their ordering is not a universal property of the PQC backend. The higher-level key-exchange layer owns that combined wire layout.

## 3. Behavior Model

### 3.1 OpenSSL startup and cleanup

```text
openssl_startup()
       |
       v
 acquire startup lock
       |
       v
 refcount == 0 ? ── yes ──> initialize OpenSSL for version
       |                         |
       no                        v
       |                  legacy thread setup if required
       +-------------------------+
                 |
             refcount++

openssl_cleanup()
       |
       v
 legacy thread cleanup if required
       |
       v
 acquire startup lock → decrement positive refcount
       |
       v
 refcount reaches zero? ── yes ──> version-specific cleanup
```

For OpenSSL 1.1 and later, the startup path uses the version's initialization APIs and the legacy manual thread callbacks are compiled out. Older versions use explicit initialization and reference-counted thread-lock setup/cleanup. The counters coordinate this module's startup calls; they do not represent ownership of individual EVP objects.

### 3.2 Random-byte and encoded-string paths

```text
random(buf, size) ───────────────> RAND_bytes → caller buffer
random(binary_t, size) ──────────> resize → RAND_bytes → binary_t
rand32 / rand64 ─────────────────> RAND_bytes → integer
random(value, mask) ─────────────> RAND_bytes → apply mask
rand(size, encoding, usetime)
       ├─ enforce minimum random-buffer size of 8 bytes
       ├─ if usetime: encode timestamp prefix
       ├─ generate random byte buffer
       └─ encode bytes as base16 / base64 / base64url
nonce() / token() ───────────────> rand(size, encoding, false)
```

The byte-buffer APIs and encoded-string APIs return different representations of random data. Callers should choose the representation required by the protocol and should not mistake an optional timestamp prefix for additional random bytes. The wrapper does not assign protocol-specific nonce uniqueness, token expiry, or storage policy.

#### Concrete caller path from `testcase_random.cpp`

```cpp
openssl_prng random;

int32 value = random.rand32();
std::string nonce = random.nonce(16, encoding_t::encoding_base16);
std::string token = random.token(16, encoding_t::encoding_base64url);

// Separate API path: include an encoded timestamp prefix.
std::string timestamped = random.rand(16, encoding_t::encoding_base16, true);
```

The testcase repeats the integer, nonce and token calls 30 times and optionally logs the latest value. It does not check uniqueness, length/alphabet for every result, entropy, or distribution. The timestamped path is not equivalent to a nonce/token of the same random-byte length: `usetime=true` prepends encoded timestamp bytes before the random buffer. Treat these calls as examples of the API shape, not as proof of a token format or a protocol's nonce policy.

### 3.3 PQC key encoding and operation flow

Key serialization routes by the requested encoding: PEM/DER formats use the keychain's format decoder/encoder, while raw public/private forms use the named-algorithm raw path. The algorithm name is needed for raw decoding because the byte string alone does not identify the key type.

```text
encode / decode
    └─ key_encoding_t
         ├─ PEM / DER ──> crypto_keychain format path
         └─ raw key ────> named-algorithm raw path

KEM:
public EVP_PKEY ── encapsulate ──> capsule + shared secret
private EVP_PKEY + capsule ──────> decapsulate ──> shared secret

signature:
private EVP_PKEY + message ──> DigestSign path ──> signature bytes
public EVP_PKEY + message + signature ──> DigestVerify path ──> status
```

The encapsulation output has two separate values: the capsule is transmitted to the private-key holder, while the shared secret is consumed by the protocol's key schedule. Decapsulation uses the corresponding private key and capsule to derive the matching secret. The signature path streams message bytes through DigestSign/DigestVerify operations. These backend methods implement cryptographic operations, not the higher-level TLS handshake, COSE message construction or hybrid-share framing.

Availability remains conditional on the linked OpenSSL version, provider configuration, key type and operation. A wrapper or an algorithm name in a reference table does not by itself guarantee that the backend can instantiate the operation.

#### Concrete ML-KEM caller path from `testcase_pqc_kem.cpp`

The common OpenSSL PQC testcase runs only when the compile-time OpenSSL version is at least 3.5. For each of ML-KEM-512, ML-KEM-768 and ML-KEM-1024, it follows this sequence:

```text
crypto_keychain::pkey_keygen_byname(algorithm)
  -> private key object
  -> DER public-key encode/decode
  -> raw public-key encode/decode (algorithm name required)
  -> assert EVP_PKEY_eq(DER public key, raw public key)
  -> openssl_pqc::encapsule(public key)
       -> capsule + Bob shared secret
  -> openssl_pqc::decapsule(private key, capsule)
       -> Alice shared secret
  -> assert Alice shared secret == Bob shared secret
  -> free EVP_PKEY objects
```

The testcase checks the reconstructed public-key objects and the final shared-secret equality. It logs capsule/secret bytes for inspection, but those logs are not fixed expected values. This is a KEM operation demonstration, not a complete TLS 1.3 handshake or key schedule; TLS still defines the key-share framing and how the shared secret is consumed. On older OpenSSL builds, the testcase reports `not_supported` rather than exercising these operations.

## 4. Relationships
### 4.1 Source-test evidence

`test/testcase/crypto/prng/testcase_random.cpp` is the direct random-generation source path. PQC behavior is exercised by the key/signature tests under `test/testcase/crypto/key/`, `test/testcase/crypto/sign/`, and `test/testcase/crypto/pqc/` where present. These cover specific backend configurations and are not proof of universal provider availability.

- `sdk/crypto/basic/` — common crypto operation and key interfaces
- `sdk/crypto/oqs/` — OpenSSL 3 OQS provider adapter
- `sdk/crypto/advisor/` — algorithm and backend metadata
- `sdk/net/tls/` and `sdk/crypto/cose/` / `jose/` — higher-level consumers that choose when algorithms are used

- `sdk/crypto/basic/sdk/openssl_sdk.cpp` and OpenSSL support headers/sources under `sdk/crypto/basic/sdk/`
- `sdk/crypto/basic/prng/openssl_prng.cpp`
- `sdk/crypto/basic/pqc/openssl_pqc.cpp`
- `test/testcase/crypto/prng/testcase_random.cpp`
- `sdk/crypto/oqs/` and `test/testcase/crypto/pqc/`


## 5. References
- [OpenSSL RAND_bytes](https://docs.openssl.org/3.0/man3/RAND_bytes/) — random-byte generation API used by `openssl_prng`.
- [OpenSSL provider](https://docs.openssl.org/3.0/man7/provider/) — provider model used by OpenSSL 3 PQC integration.
