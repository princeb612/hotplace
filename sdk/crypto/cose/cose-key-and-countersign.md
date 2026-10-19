## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# COSE keys and countersignatures

## 1. Role

Describes COSE key-related structures and countersignature handling.

## 2. Model

### COSE keys

`cose_key` represents COSE key metadata and is connected to the project's `crypto_key` abstraction. `cbor_web_key` integrates the COSE/CBOR representation with the crypto keychain.

The repository's COSE test vectors cover EC, OKP, RSA and additional algorithm-specific key material. AKP testcases also exercise newer public-key material, including ML-DSA vectors.

The important distinction is:

```text
COSE key representation
        ↓
  cbor_web_key / cose_key
        ↓
    crypto_key
        ↓
  crypto/basic backend
```

COSE does not replace the crypto key implementation; it supplies the representation and protocol metadata needed to use a key in a COSE message.

### Countersignatures

`cose_countersign` and `cose_countersigns` extend the recipient/layer model for countersignature data. They are represented as nested COSE structures rather than as an unrelated post-processing flag.

This is particularly relevant to RFC 9338 test coverage, where countersignatures are part of the COSE message model itself.

## 3. Important behavior and lifetime

COSE processing depends on message family, protected/unprotected headers, key and algorithm availability, and the underlying cryptographic implementation.

## 4. Example from the source tests

### Test material

The testcase directory contains RFC 8152, RFC 8778, RFC 9338 and COSE example vectors, plus AKP and CWT-related tests. The binary CBOR and diagnostic files should be treated as protocol test fixtures, not merely sample documentation.

## 5. Relationships

- `sdk/io/cbor/` provides CBOR parsing, encoding, and object representation.
- `sdk/crypto/basic/` provides cryptographic primitives used by COSE.

## 6. References

- Source: this module and its related testcase directory (Revision 1104).
