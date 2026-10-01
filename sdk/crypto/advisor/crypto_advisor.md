# Crypto Advisor

`sdk/crypto/advisor` is the lookup and mapping layer that connects cryptographic names, identifiers, parameters, and OpenSSL representations to hotplace's crypto abstractions.

It is not another primitive implementation. The implementation tables describe algorithms and parameters, while `crypto_advisor` provides the query interface used by crypto and protocol code.

## Main role

The advisor bridges several naming domains:

```text
hotplace enum / scheme
        ↕
crypto_advisor
        ↕
resource tables
        ↕
OpenSSL NID / EVP / names
        ↕
TLS / JOSE / COSE identifiers
```

Representative queries include:

- cipher and mode → cipher hint / EVP cipher
- digest algorithm → digest hint / EVP MD
- curve name/NID → curve hint, key type, TLS group
- key/signature identifiers → corresponding metadata
- JOSE/COSE algorithm names → implementation metadata
- TLS signature scheme / group information → crypto metadata
- OpenSSL `EVP_PKEY` / NID → hotplace hint information

## Resource tables

The `resource_*.cpp` files are generated/static lookup data rather than independent crypto implementations. They cover areas such as:

- cipher algorithms
- digests
- curves
- keys
- signatures and signature schemes
- COSE
- JOSE/JWA/JWE
- TLS parameters

Keeping this data in the advisor separates identifier/parameter knowledge from the primitive implementations in `sdk/crypto/basic`.

## Feature flags

`advisor_feature_t` records where an algorithm/parameter is used or supported. The current flags include cipher, digest, wrapping, JWA, JWE, JWS, COSE, curve, version-specific, signature-scheme, and TLS-group features.

`query_feature()` and the `for_each_*()` family allow callers and tests to inspect the supported resource set without duplicating the tables.

## Relationship to OpenSSL

The advisor is also an adaptation boundary between hotplace identifiers and OpenSSL identifiers. Examples include:

- `find_evp_cipher()`
- `find_evp_md()`
- curve NID lookup
- `hintof_pkey()` / `hintof_ossl_nid()`

The implementation therefore contains OpenSSL-specific knowledge, but the purpose of the directory is still metadata/lookup rather than cryptographic computation.

## Verification

`test/testcase/crypto/advisor/testcase_advisor.cpp` checks three important properties:

1. advertised cipher/digest/JOSE/COSE/curve features can be queried;
2. curve aliases such as `P-256`, `prime256v1`, and `secp256r1` resolve to the same curve metadata;
3. cipher resource entries remain internally consistent with their algorithm/mode and fetch-name mappings.

The testcase is especially useful as a record of the invariant expected from the resource tables: modifying a resource entry must not silently break the mapping between its public name, scheme, algorithm/mode, and backend representation.

## Related areas

- `../basic/` — cryptographic primitive implementations
- `../cose/` — COSE structures and algorithms
- `../jose/` — JOSE structures and algorithms
- `../../net/tls/` — TLS use of signature schemes, groups, ciphers, and digests
- `../../../test/testcase/crypto/advisor/` — advisor verification
