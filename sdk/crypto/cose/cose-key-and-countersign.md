# COSE keys and countersignatures

## COSE keys

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

## Countersignatures

`cose_countersign` and `cose_countersigns` extend the recipient/layer model for countersignature data. They are represented as nested COSE structures rather than as an unrelated post-processing flag.

This is particularly relevant to RFC 9338 test coverage, where countersignatures are part of the COSE message model itself.

## Test material

The testcase directory contains RFC 8152, RFC 8778, RFC 9338 and COSE example vectors, plus AKP and CWT-related tests. The binary CBOR and diagnostic files should be treated as protocol test fixtures, not merely sample documentation.
