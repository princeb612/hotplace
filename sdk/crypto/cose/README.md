# COSE

`sdk/crypto/cose` implements CBOR Object Signing and Encryption (COSE) on top of the project's CBOR and crypto layers.

The directory is not a general CBOR implementation. It models COSE message structure, protected/unprotected headers, payloads, recipients, signatures, countersignatures, keys, and the cryptographic processing needed to compose/process those messages.

## Implementation map

- `cose_data` — COSE data/header/value representation and algorithm/key identifiers.
- `cose_composer` and related classes — message/layer construction: protected, unprotected, payload, signature/tag, recipients and unsent fields.
- `cbor_object_signing_encryption` — high-level send/receive processing for encrypt, decrypt, sign, verify and MAC operations, including key distribution and context construction.
- `cbor_object_signing` / `cbor_object_encryption` — focused signing/MAC and encryption entry points.
- `cbor_web_key` — CBOR Web Key integration with the crypto keychain.
- countersignature classes — RFC 9338-style countersignature representation.

## Message model

The implementation follows the COSE tagged message families:

```text
Encrypt / Encrypt0
    protected + unprotected + ciphertext + recipients

Mac / Mac0
    protected + unprotected + payload + tag + recipients

Sign / Sign1
    protected + unprotected + payload + signatures
```

A `cose_composer` exposes these logical fields through a `cose_layer`; nested recipients/signatures are represented as additional layers rather than being flattened into one byte buffer.

## Processing flow

```text
COSE message / CBOR
        ↓
    cose_composer
        ↓
  cose_layer tree
        ↓
preprocess / context construction
        ├── Enc_structure / AAD
        ├── Sig_structure
        ├── MAC structure
        └── key-distribution / KDF context
        ↓
crypto/basic
        ↓
CBOR serialization
```

`cbor_object_signing_encryption` has separate send/receive modes and dispatches encryption, signature and MAC processing through the layer tree.

## Related areas

- `sdk/io/cbor/` — CBOR object model and encoding used by COSE.
- `sdk/crypto/basic/` — cryptographic primitives, keys, MAC, signatures and KDF.
- `sdk/crypto/advisor/` — algorithm/resource metadata used to map identifiers.
- `sdk/crypto/jose/` — related JSON-based JOSE processing.
- `sdk/net/http/` — protocol users of COSE-related structures where applicable.

## Tests and references

- `test/testcase/cose/testcase_cose.cpp`
- `test/testcase/cose/testcase_rfc8152.cpp`
- `test/testcase/cose/testcase_rfc8392.cpp`
- `test/testcase/cose/testvector_cose_examples.cpp`
- `test/testcase/cose/testcase_akp.cpp`
- RFC 8152 / RFC 9052 family: COSE message definitions
- RFC 8392: CBOR Web Token
- RFC 8778: HSS/LMS with COSE
- RFC 9338: COSE Countersignatures

The repository also keeps CBOR/diagnostic test vectors and the COSE examples YAML data under `test/testcase/cose/`.
