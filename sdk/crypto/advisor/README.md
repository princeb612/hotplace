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

# Crypto Advisor

## 1. Role

`sdk/crypto/advisor` is hotplace's cryptographic metadata and lookup layer. It resolves names, enums, backend identifiers, protocol identifiers, and parameter descriptions into the hints consumed by cryptographic and protocol code.

It does **not** implement encryption, hashing, signatures, or key exchange. Those operations belong to the relevant primitive and key implementations, including [`../basic/`](../basic/README.md).

## 2. Data Model
The main public interface is `crypto_advisor`, exposed by [`crypto_advisor.hpp`](crypto_advisor.hpp). The README describes the directory role, entry points, hint families, cross-domain relationships, and common lookup paths.

The data is organized into three layers rather than one universal algorithm object:

```text
static resource tables
  hint_* records / evp_* method descriptions
            │ pointers to stable metadata
            ▼
crypto_advisor runtime indexes
  name / enum / scheme / NID / EVP-object maps
  feature-name -> feature-bit mask
  feature-name -> minimum OpenSSL version
            │ lookup result
            ▼
caller-facing metadata and optional backend object
  const hint_* / const EVP_CIPHER* / const EVP_MD*
```

The `resource_*.cpp` files hold static metadata for ciphers, digests, curves, keys, signatures, signature schemes, TLS groups, COSE, and JOSE/JWA/JWE. `crypto_advisor_*.cpp` implements domain-specific query and conversion methods. The runtime maps index the static records; they do not turn every protocol identifier into a single shared algorithm type. Treat a returned hint as descriptive metadata, not as proof that the active OpenSSL/provider build can execute every advertised operation.


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

### Runtime indexes and intermediate data

The important runtime data is the index state built from static resource records:

| Data | Key / contents | Role and lifetime |
|---|---|---|
| `_blockcipher_map` | `crypt_algorithm_t → hint_blockcipher_t*` | Finds primitive-family dimensions such as key, IV and block size. |
| `_cipher_byname_map`, `_cipher_scheme_map` | Name or scheme → `hint_cipher_t*` | Descriptive lookup; can contain a record even when no EVP method was resolved. |
| `_cipher_fetch_map` | Scheme → `cipher_fetch_block_t` | Couples an available `EVP_CIPHER*` with the corresponding `hint_cipher_t*`. |
| `_evp_cipher_map` | `EVP_CIPHER* → hint_cipher_t*` | Converts an already-held backend method back to its advisor metadata. |
| `_md_byname_map`, `_md_fetch_map` | Digest name or enum → metadata / `md_fetch_block_t` | Separates aliases and digest metadata from an available `EVP_MD*`. |
| Curve/signature/JOSE/COSE/TLS maps | Domain-specific enum, name, NID or scheme → hint pointer | Supports only the explicit cross-domain links present in each resource record. |
| `_features`, `_versions` | Feature name → bit mask / minimum OpenSSL version | Stores feature categories and version gates for `query_feature()`. |
| `_cookie_secret` | Caller key → cached `binary_t` | Holds generated cookie secrets for reuse by that key. |

The `cipher_fetch_block_t` and `md_fetch_block_t` records are intermediate join points: each keeps the backend method alongside the static hint that explains it. This is why a successful metadata lookup and a successful backend lookup are separate facts. The hint records themselves are static resource data; the maps store pointers to them rather than owning copies of every record. On OpenSSL 3+, the advisor owns and frees the fetched EVP cipher/digest handles retained in the fetch maps; on older versions the implementation uses OpenSSL's borrowed method pointers.

The `key_encoding_params_t` output of `get_encoding_params()` is different: it is assembled for a caller from the requested encoding enum and is not another persistent index. Similarly, the feature list is not a separate catalogue of executable primitives; it combines backend availability, protocol metadata registration, and selected version requirements.

## 3. Behavior Model

The implementation has two distinct jobs: build a set of query indexes once, then answer lookups against those indexes. Most lookups are read-only; initialization also probes the active OpenSSL build and creates a small amount of owned backend state.

### 3.1 Initialize the shared advisor

```text
crypto_advisor::get_instance()
          │
          ▼
      _instance.load()
          │
          ├── _flag != 0 ───────────────► already initialized
          │
          └── _flag == 0
                 │
                 ▼
           critical_section_guard
                 │ recheck _flag
                 ▼
                build()
                 │
                 ├── index static resource tables
                 ├── resolve available EVP methods
                 ├── register feature/version metadata
                 └── populate cross-domain maps
                 │
                 ▼
             _flag = 1
                 │
                 ▼
          return &_instance
```

The double check around `_flag` prevents two callers from building the maps concurrently. `get_instance()` returns the same static object; callers do not own or delete it. The initialization routine reports success through its current interface, but the caller should not interpret that as proof that every individual OpenSSL method was found: unavailable methods are represented as missing backend entries and feature flags.

### 3.2 Build metadata indexes and backend indexes

`build()` walks the static resource arrays and creates several parallel indexes. They serve different purposes and are deliberately not collapsed into one table.

**Cipher path**

1. Each `hint_blockcipher_t` resource is indexed by algorithm.
2. Each `evp_cipher_methods` entry is queried by its OpenSSL fetch name. On OpenSSL 3 or later, `EVP_CIPHER_fetch()` attempts to obtain a provider-backed method; on earlier versions, `EVP_get_cipherbyname()` is used.
3. If a backend cipher is obtained, `_cipher_fetch_map` stores a `cipher_fetch_block_t` containing both the EVP object and its hint pointer, and `_evp_cipher_map` indexes the EVP object back to metadata.
4. Independently, `_cipher_byname_map` and `_cipher_scheme_map` index the descriptive hint records. A cipher feature bit is added only when the corresponding EVP method is available.
5. For OpenSSL versions before 3.0, the dedicated AES-wrap resource entries provide a compatibility path for wrap methods not returned by the ordinary name lookup.

```text
evp_cipher_methods + hint_blockcipher_t resources
          │
          ├── descriptive index: name / scheme -> hint_cipher_t
          │
          └── backend resolution by fetch name
                    │
                    ├── success -> scheme -> {EVP_CIPHER*, hint}
                    │              EVP_CIPHER* -> hint
                    │              feature bit set
                    │
                    └── unavailable -> no backend entry / no cipher feature
```

**Digest path**

The digest loop follows the same distinction. It tries `EVP_MD_fetch()` on OpenSSL 3 or `EVP_get_digestbyname()` on earlier versions. The name index includes the canonical fetch name and available alternate/RFC names, while the backend map is populated only when the digest method resolves. Feature bits for the digest and its alternate name are added only for an available method. After the cipher/digest probes, `ERR_clear_error()` clears OpenSSL errors left by expected unsupported-method probes.

**Protocol and key metadata paths**

The JWA, JWE, JWS, COSE, signature-scheme, curve, key-type and TLS-group loops index their corresponding static hint records by the identifiers used by callers. A signature record can contribute multiple indexes: Hotplace signature enum, JWS name/type, OpenSSL NID(s), and COSE algorithm mapping. A curve record contributes name aliases, OpenSSL ID/NID, optional COSE curve and TLS group links. TLS group names are normalized to lowercase before insertion into the name index. These indexes preserve the relationships explicitly represented by the resource record; they do not imply that every combination across standards exists.

Curve metadata is indexed even if the active backend cannot construct the curve/key type. During feature registration, the implementation probes EC curves with `EC_KEY_new_by_curve_name()` and OKP types with `EVP_PKEY_CTX_new_id()`. Successful probes mark the relevant curve aliases as supported features; failed probes clear the expected OpenSSL error and leave the descriptive mapping available without asserting runtime support.

### 3.3 Resolve a caller query

A lookup typically starts with the identifier available to the caller and uses the matching index. For example, a cipher caller can begin with a name, a Hotplace algorithm/mode pair, a scheme, or an existing `EVP_CIPHER*`. The return value depends on which layer is requested:

```text
 "AES-128-GCM"  / algorithm+mode / scheme / EVP_CIPHER*
                         │
                         ▼
             matching advisor lookup map
                         │
             ┌───────────┴──────────────────────────┐
             ▼                                      ▼
       hint_* metadata             EVP backend method
       descriptive mapping         executable method handle
             │                                      │
             └──── caller checks both as needed ────┘
```

For cipher and digest methods, `hintof_*` and `find_evp_*` are not interchangeable. A metadata lookup can succeed because a resource record exists while backend lookup returns null because the method is unavailable in the current OpenSSL build/provider configuration. Likewise, name lookup may return null when the name is absent from the resource index. Callers must check nullable pointer results before dereferencing or invoking a backend method.

### 3.4 Query feature availability

`query_feature(feature, spec)` first looks up the exact feature string in `_features`.

1. If no entry exists, it returns zero.
2. If the stored flags include `advisor_feature_version`, the method looks up the required version in `_versions` and compares it with `OpenSSL_version_num()`.
3. Otherwise, if the caller supplied a nonzero `spec`, the method returns the matching bitwise intersection of the stored flags and `spec`.
4. With `spec == 0`, it returns the stored flags.

The feature index therefore combines distinct kinds of information: backend-probed availability for selected cipher/digest/curve features, protocol metadata registration for JWA/JWE/JWS/COSE/TLS-group names, and explicit minimum-version requirements for selected algorithms such as scrypt, Argon2, and ML-KEM. A feature query is a report from this index, not a cryptographic known-answer test and not a complete policy decision.

The `for_each_*` methods expose different views: some enumerate static hint records; others call back with feature names and the result of `query_feature()`. The distinction matters when interpreting an inventory: a resource record can be listed even when its current feature bit is zero.

### 3.5 Stateful helper paths and cleanup

The advisor also provides two small services outside the main lookup indexes:

- `get_cookie_secret(key, secret_size, secret)` checks the `_cookie_secret` cache by key. If present, it returns the previously cached bytes; otherwise it asks `openssl_prng` to generate the requested number of bytes and caches them under that key. On a later call for the same key, the cached secret is returned and the new requested size is not used to regenerate it.
- `get_encoding_params(encoding, params)` maps a supported key-encoding enum to OpenSSL 3 encoder parameters (selection, format, structure, and password-use flag). Unsupported enum/version combinations return `not_supported`; `nameof_encoding()` separately returns a human-readable label.

On destruction, `cleanup()` frees the `EVP_CIPHER*` and `EVP_MD*` objects retained by the fetch maps on OpenSSL 3 or later, then clears those maps. Earlier OpenSSL paths use borrowed method pointers and do not run those OpenSSL 3 free loops.

The advisor reports mappings and backend availability; it does not itself implement the selected cipher, digest, signature, key exchange, or encoding operation, and it does not decide whether an algorithm is suitable for a security policy.

### 3.5 Lookup entry points by caller question

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

### 3.3 Concrete caller path: enumerate advertised JWS features

The advisor testcase iterates signature metadata and checks whether each JWS name has the corresponding feature registered:

```cpp
#include <hotplace/sdk/crypto/advisor/crypto_advisor.hpp>

crypto_advisor* advisor = crypto_advisor::get_instance();
advisor->for_each_jws([&](const hint_signature_t* item) {
    bool available = advisor->query_feature(item->jws_name, advisor_feature_jws);
    // Use the result as a capability hint for this runtime build.
});
```

This is a metadata/capability query, not a signature operation. A registered JWS mapping does not by itself prove that a given key type, key size, provider, or protocol policy will permit the operation. The testcase also enumerates cipher, digest, COSE, and curve features; it is useful for understanding the advisor as a runtime index rather than as a cryptographic primitive.

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
