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
