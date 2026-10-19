## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# Crypto Advisor

## 1. Role

`sdk/crypto/advisor` is hotplace's cryptographic metadata and lookup layer. It resolves names, enums, backend identifiers, protocol identifiers, and parameter descriptions into the hints consumed by cryptographic and protocol code.

It does **not** implement encryption, hashing, signatures, or key exchange. Those operations belong to the relevant primitive and key implementations, including [`../basic/`](../basic/README.md).

## 2. Model

The main public interface is `crypto_advisor`, exposed by [`crypto_advisor.hpp`](crypto_advisor.hpp). Its lookup methods consult resource tables declared in the `hint_*` and related types. The tables are grouped by domain rather than represented as one universal algorithm record.

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

The `resource_*.cpp` files hold static metadata for ciphers, digests, curves, keys, signatures, signature schemes, TLS parameters, COSE, and JOSE/JWA/JWE. `crypto_advisor_*.cpp` implements domain-specific query and conversion methods.

## 3. Important behavior and lifetime

- `crypto_advisor::get_instance()` returns the class's static instance and calls `load()` before returning it.
- `load()` uses `_flag` and a critical-section guard to initialize the lookup state once. The current implementation builds maps and feature indexes from the resource tables.
- Backend availability is not identical to metadata presence. For example, a resource entry may describe an algorithm even when the current OpenSSL build cannot resolve its EVP implementation.
- OpenSSL 3 and earlier OpenSSL versions use different cipher/digest lookup paths in the implementation. Callers must handle unavailable backend methods rather than assuming every resource entry maps to a usable EVP object.
- Curve aliases may resolve to the same curve metadata; the returned hint includes multiple naming domains and identifiers where available.

The advisor reports mappings and availability; it does not itself guarantee that a particular algorithm is appropriate for a security policy.

## 4. Example from the source tests

[`testcase_advisor.cpp`](../../../test/testcase/crypto/advisor/testcase_advisor.cpp) exercises feature enumeration, curve alias resolution, and consistency of cipher resource entries. The curve test checks that `P-256`, `prime256v1`, and `secp256r1` resolve to the same OpenSSL NID in the tested build.

A representative query pattern is:

```cpp
crypto_advisor* advisor = crypto_advisor::get_instance();
const hint_curve_t* curve = advisor->hintof_curve_name("P-256");
```

The result should be checked before dereferencing in production code; the snippet illustrates the API shape, not a complete error-handling example.

## 5. Relationships

- [`../basic/`](../basic/README.md) — primitive implementations and core crypto types.
- [`../cose/`](../cose/README.md) — COSE structures and algorithm identifiers.
- [`../jose/`](../jose/README.md) — JOSE/JWA/JWE/JWS integration.
- [`../../net/tls/`](../../net/tls/README.md) — TLS use of signature schemes, groups, ciphers, and digests.
- [`../../../test/testcase/crypto/advisor/`](../../../test/testcase/crypto/advisor/README.md) — source tests for advisor mappings.

## 6. References

- [`crypto_advisor.hpp`](crypto_advisor.hpp) — public query interface and feature flags.
- [`crypto_advisor.cpp`](crypto_advisor.cpp) — singleton initialization and resource-map construction.
- [`crypto_advisor.md`](crypto_advisor.md) — detailed lookup domains and resource-table behavior.
