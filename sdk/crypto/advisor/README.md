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

# Crypto Advisor

## 1. Role

`sdk/crypto/advisor` is hotplace's cryptographic metadata and lookup layer. It resolves names, enums, backend identifiers, protocol identifiers, and parameter descriptions into the hints consumed by cryptographic and protocol code.

It does **not** implement encryption, hashing, signatures, or key exchange. Those operations belong to the relevant primitive and key implementations, including [`../basic/`](../basic/README.md).

## 2. Data Model
The main public interface is `crypto_advisor`, exposed by [`crypto_advisor.hpp`](crypto_advisor.hpp). The README describes the directory role, entry points, hint families, cross-domain relationships, and common lookup paths.

```text
crypto/protocol caller
        │ query by name, enum, NID, EVP object, or scheme
        ▼
crypto_advisor
        ├── domain lookup maps
        ├── feature index
        └── resource tables (hint_* / evp_* metadata)
        │
        ▼
OpenSSL identifiers and TLS / JOSE / COSE identifiers
```

The `resource_*.cpp` files hold static metadata for ciphers, digests, curves, keys, signatures, signature schemes, TLS groups, COSE, and JOSE/JWA/JWE. `crypto_advisor_*.cpp` implements domain-specific query and conversion methods. Treat a returned hint as descriptive metadata, not as proof that the active OpenSSL/provider build can execute every advertised operation.


### Hint domains and what they describe

The advisor is a collection of **domain-specific hint records**, not one universal algorithm object. Each record answers a different caller question: what algorithm or parameter is this, how is it named in another ecosystem, what key type or operation family does it imply, and which OpenSSL/TLS/JOSE/COSE identifier maps to it?

| Hint type | Information carried | Typical caller question |
|---|---|---|
| `hint_blockcipher_t` | Cipher family, key/IV/block sizes and key-wrap block size | What are the nominal dimensions of this primitive family? |
| `hint_cipher_t` | Hotplace scheme, algorithm/mode, OpenSSL fetch name, AEAD nonce/tag sizes | Which concrete mode implements this scheme, and what parameters does it use? |
| `hint_digest_t` | Hash enum, backend fetch name, digest size and alternate/protocol names | Which digest is this alias, and what output length/name is expected? |
| `hint_curve_t` | OpenSSL NID/ID, key type/use, TLS group, COSE curve, OID, aliases, curve category and size/support flags | How does this curve map across the naming and protocol domains? |
| `hint_cose_group_t` | COSE operation group, crypto category and behavior flags | What operation family and processing flags does this COSE group represent? |
| `hint_cose_algorithm_t` | COSE algorithm ID/name, key type/group, key/curve mapping, digest/key sizes, encryption nonce/tag sizes | What does this COSE algorithm require for processing? |
| `hint_jose_encryption_t` | JOSE name and `htype` discriminator, family/group, key constraints, cipher/mode/key-size/hash metadata | Is this a JWA key-management algorithm or JWE content encryption, and what does it map to? |
| `hint_kty_name_t` | Hotplace key type and JOSE/JWK key-type name | Which external key-type name represents this key? |
| `hint_signature_t` | Signature enum, JWS name/group, signature category, COSE mapping, key type, digest and NIDs | How is this signature represented across hotplace, JWS, COSE and OpenSSL? |
| `hint_sigscheme_t` | TLS signature-scheme ID/name/version, category, signature family, key type, NID, digest and size metadata | Which signing family, key and digest does this TLS code select? |
| `hint_group_t` | TLS group ID/name, key-exchange family, security/support/PQC/hybrid flags and component key descriptions | Is this a classical or hybrid key exchange, and what components are involved? |

These records are related but **not interchangeable**. `hint_blockcipher_t` describes a primitive family; `hint_cipher_t` describes a concrete mode such as AES-GCM and can carry nonce/tag sizes. `hint_curve_t` has direct COSE-curve and TLS-group fields where mapped; JOSE/JWK curve names are related through key conversion and are not a direct field on that struct. The `hint_jose_encryption_t` record uses its discriminator to distinguish JWA key-management data from JWE content-encryption data.

### Cross-domain mapping

This is a conceptual relationship map of fields and lookup methods, not a database schema or a guarantee that every possible cross-product exists.

```text
crypt_algorithm_t ──► hint_blockcipher_t
        │                    │ key / IV / block dimensions
        ▼                    ▼
crypto_scheme_t ───────► hint_cipher_t ───────► OpenSSL EVP_CIPHER name
                              │
hash_algorithm_t ──────► hint_digest_t ───────► OpenSSL EVP_MD name

curve alias / OpenSSL NID ─► hint_curve_t
                                ├── key type + usage, OID + aliases
                                ├── COSE curve and TLS group (when mapped)
                                └── JOSE/JWK crv naming through key conversion

signature_t ────────────► hint_signature_t
                                ├── JWS name / group, COSE algorithm
                                └── key type / digest / NIDs
tls_sigscheme_t ────────► hint_sigscheme_t ───► signing family / key / digest

JWA alg name / jwa_t ──► hint_jose_encryption_t [key management]
JWE enc name / jwe_t ──► hint_jose_encryption_t [content encryption]
                                └── key type / cipher / mode / KDF hash

COSE alg ID / name ────► hint_cose_algorithm_t ─► hint_cose_group_t
TLS group ID / name ───► hint_group_t ──────────► classical/hybrid components
```

### Choosing a lookup path

| Caller question | Lookup entry point |
|---|---|
| Cipher-family key, IV, block or key-wrap dimensions | `hintof_blockcipher(...)` |
| Concrete algorithm/mode and OpenSSL fetch mapping | `hintof_cipher(...)`, then `find_evp_cipher(...)` |
| Digest aliases, output length and EVP mapping | `hintof_digest(...)`, `nameof_md(...)`, `find_evp_md(...)` |
| Curve alias, OID, COSE curve, TLS group or key type | `hintof_curve_name(...)`, `hintof_curve_nid(...)` |
| JWA key-management algorithm | `hintof_jose_algorithm(...)` |
| JWE content-encryption algorithm | `hintof_jose_encryption(...)` |
| JWS signature name and family | `hintof_jose_signature(...)` |
| COSE algorithm and operation group | `hintof_cose_algorithm(...)` |
| TLS signature scheme or supported group | `hintof_sigscheme(...)`, `hintof_tls_group(...)` |
| Enumerate resource entries/features | Relevant `for_each_*` or `query_feature()` method |

A `hint_*` pointer may be null when there is no matching entry. Even when metadata exists, backend resolution may fail because of the active OpenSSL version, provider configuration, or build options. Callers must check both lookup results and backend objects before using them.

## 3. Behavior Model
- `crypto_advisor::get_instance()` returns the class's static instance and calls `load()` before returning it.
- `load()` uses `_flag` and a critical-section guard to initialize the lookup state once. The current implementation builds maps and feature indexes from the resource tables.
- Backend availability is not identical to metadata presence. For example, a resource entry may describe an algorithm even when the current OpenSSL build cannot resolve its EVP implementation.
- OpenSSL 3 and earlier OpenSSL versions use different cipher/digest lookup paths in the implementation. Callers must handle unavailable backend methods rather than assuming every resource entry maps to a usable EVP object.
- Curve aliases may resolve to the same curve metadata; the returned hint includes multiple naming domains and identifiers where available.

The advisor reports mappings and availability; it does not itself guarantee that a particular algorithm is appropriate for a security policy.

## 4. Relationships
- [`../basic/`](../basic/README.md) — primitive implementations and core crypto types.
- [`../cose/`](../cose/README.md) — COSE structures and algorithm identifiers.
- [`../jose/`](../jose/README.md) — JOSE/JWA/JWE/JWS integration.
- [`../../net/tls/`](../../net/tls/README.md) — TLS use of signature schemes, groups, ciphers, and digests.
- [`../../../test/testcase/crypto/advisor/`](../../../test/testcase/crypto/advisor/README.md) — source tests for advisor mappings.

### Test evidence

[`testcase_advisor.cpp`](../../../test/testcase/crypto/advisor/testcase_advisor.cpp) exercises feature enumeration, curve alias resolution, and consistency of cipher resource entries. The curve test checks that `P-256`, `prime256v1`, and `secp256r1` resolve to the same OpenSSL NID in the tested build.

A representative query pattern is:

```cpp
crypto_advisor* advisor = crypto_advisor::get_instance();
const hint_curve_t* curve = advisor->hintof_curve_name("P-256");
```

The result should be checked before dereferencing in production code; the snippet illustrates the API shape, not a complete error-handling example.
