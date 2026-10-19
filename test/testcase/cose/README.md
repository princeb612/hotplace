## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```

# COSE testcase assets

## 1. Role

Identifies COSE RFC/example vectors and documents the YAML schema for keys and message cases.

## 2. Test model

The directory contains RFC and COSE working-group examples plus a YAML schema for keys, CBOR message bytes, and cryptographic inputs.

### Existing vector schema and notes

### COSE

* test vector
  * RFC 8152 CBOR Object Signing and Encryption (COSE)
  * RFC 8778 Use of the HSS/LMS Hash-Based Signature Algorithm with CBOR Object Signing and Encryption (COSE)
  * RFC 9338 CBOR Object Signing and Encryption (COSE): Countersignatures
  * RFC 8392 CBOR Web Token (CWT)
  * https://github.com/cose-wg/Examples

### YAML schema

* COSE YAML schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: COSE EXAMPLES       # [mandatory] "COSE EXAMPLES"
    keys:
      - item: string            # [mandatory] kid
        keyuse: string          # "enc"|"sig"
        keyalg: string          #
        keyset: string          # [mandatory]
        encoding: string        # [mandatory] "base64url"|"base64"|"base16"
        kty: ec                 # [mandatory] "ec"
        crv: string             # [mandatory] "P-256"|"P-384"|"P-521"|...
        x: encoding             # [mandatory] x
        y: encoding             # [mandatory] y
        d: encoding             # d
      - item: string            # [mandatory] kid
        keyuse: string          # "enc"|"sig"
        keyalg: string          #
        keyset: string          # [mandatory]
        encoding: string        # [mandatory] "base64url"|"base64"|"base16"
        kty: okp                # [mandatory] "okp"
        crv: string             # [mandatory] "Ed25519"|"Ed448"
        x: encoding             # [mandatory] x
        d: encoding             # private
      - item: string            # [mandatory] kid
        keyuse: string          # "enc"|"sig"
        keyalg: string          #
        keyset: string          # [mandatory]
        encoding: string        # [mandatory] "base64url"|"base64"|"base16"
        kty: rsa                # [mandatory] "rsa"
        n: encoding             # [mandatory] n
        e: encoding             # [mandatory] e
        d: encoding             # d
    items:
      - item: string            # [mandatory] filename, description
        keyset: string          # [mandatory] foreign key (keyset) references KEYS (keyset)
        cbor: hexstring         # [mandatory]
        shared:                 # unsent, shared
          external: hexstring
          iv: hexstring
          apu_id: hexstring
          apu_nonce: hexstring
          apu_other: hexstring
          apv_id: hexstring
          apv_nonce: hexstring
          apv_other: hexstring
          pub_other: hexstring
          priv: hexstring
        enc:
          aad:
          cek:
          tomac:
        skip: bit               # do not test
        untagged: bit
        debug: bit              # breakpoint
````

## 3. Example: RFC COSE vectors

A COSE vector can reference a key set, message CBOR, shared inputs, crypto inputs, and flags such as skip or untagged.

## 4. Test and verification status

### 4.1 Source-level coverage

`testcase_rfc8152.cpp` checks CBOR parse/compose results against RFC assets; `testcase_cose.cpp` exercises sign/verify, encrypt/decrypt and MAC/verify; resource and AKP tests cover their named paths.

### 4.2 Documentation and verification status

The supplied report is identified as **MinGW64, source revision 1104**: **2013 pass, 0 expt, 0 fail, 2 skip, 0 triv**. The documentation task did not rerun the tests.

## 5. Relationships

- `sdk/crypto/cose/` contains COSE processing.
- `sdk/io/cbor/` provides CBOR parsing and encoding.
- `sdk/crypto/basic/` supplies cryptographic primitives.

## 6. References

- RFC 8152 / RFC 9052; RFC 8392; RFC 8778; RFC 9338.
- `test/testcase/cose/` sources and vector assets (Revision 1104).
