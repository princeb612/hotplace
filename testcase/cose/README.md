#### COSE

* test vector
  * RFC 8152 CBOR Object Signing and Encryption (COSE)
  * RFC 8778 Use of the HSS/LMS Hash-Based Signature Algorithm with CBOR Object Signing and Encryption (COSE)
  * RFC 9338 CBOR Object Signing and Encryption (COSE): Countersignatures
  * RFC 8392 CBOR Web Token (CWT)
  * https://github.com/cose-wg/Examples

#### YAML schema

* COSE YAML schema

````
testvector:
  - example:
    schema: COSE EXAMPLES       # [mandatory] "COSE EXAMPLES"
    items:
      - item: string            # [mandatory] filename, description
        keyset: string          # [mandatory] name of pre-defined keyset
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
