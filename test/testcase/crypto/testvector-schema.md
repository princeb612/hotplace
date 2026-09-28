#### YAML schema

* CBC-HMAC JOSE schema

````
testvector:
  - example: string         # [mandatory] testcase
    schema: CBC-HMAC JOSE   # [mandatory] "CBC-HMAC JOSE"
    items:
      - item: string
        encalg: string      # [mandatory] algorithm
        macalg: string      # [mandatory] algorithm
        k: hexstring        # [mandatory] mackey || enckey
        p: hexstring        # [mandatory] PT
        iv: hexstring       # [mandatory] IV
        a: hexstring        # [mandatory] AAD
        q: hexstring        # [mandatory] Q = CBC-ENC(ENC_KEY, P || PS)
        s: hexstring        # [mandatory] S = IV || Q
        t: hexstring        # [mandatory] T = MAC(MAC_KEY, A || S || AL)
        c: hexstring        # [mandatory] CT = S || T
````

* CBC-HMAC JOSE TLS schema

````
testvector:
  - example: string         # [mandatory] testcase
    schema: CBC-HMAC TLS    # [mandatory] "CBC-HMAC TLS"
    items:
      - item: string        #
        flag: string        # [mandatory] "mac_then_encrypt"|"encrypt_then_mac"
        enckey: hexstring   # [mandatory] key
        iv: hexstring       # [mandatory] IV
        macalg: string      # [mandatory] algorithm
        mackey: hexstring   # [mandatory] MAC key
        aad: hexstring      # [mandatory] AAD
        pt: hexstring       # [mandatory] plaintext
        ct: hexstring       # [mandatory] ciphertext
````

* NIST CAVP block-ciphers TLS schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: BLOCK CIPHERS       # [mandatory] "BLOCK CIPHERS"
    items:
      - item: string            #
        alg: string             # [mandatory] algorithm
        key: hexstring          # [mandatory] key
        iv: hexstring           # [mandatory] IV
        pt: hexstring           # [mandatory] plaintext
        ct: hexstring           # [mandatory] ciphertext
````

* RFC 3394 schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: RFC 3394            # [mandatory] "RFC 3394"
    items:
      - item: string            #
        alg: string             # [mandatory] "aes-128-wrap"|"aes-192-wrap"|"aes-256-wrap"
        kek: hexstring          # [mandatory] key encryption key
        key: hexstring          # [mandatory] key
        keydata: hexstring      # [mandatory] key data
````

* RFC 4615 schema
  * RFC 4615 The Advanced Encryption Standard-Cipher-based Message Authentication Code-Pseudo-Random Function-128 (AES-CMAC-PRF-128) Algorithm for the Internet Key Exchange Protocol (IKE)

````
testvector:
  - example: string             # [mandatory] testcase
    schema: RFC 4615            # [mandatory] "RFC 4615"
    items:
      - item: string            # [mandatory] 
        salt: hexstring         # [mandatory] key
        ikm: hexstring          # [mandatory] message
        prk: hexstring          # [mandatory] RFC 4493 AES-CMAC, RFC 4615 PRF output
````

* CKDF schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: CKDF                # [mandatory] CKDF
    items:
      - item: string            # [mandatory] 
        salt: hexstring         # [mandatory] key
        ikm: hexstring          # [mandatory] message
        prk: hexstring          # [mandatory] RFC 4493 AES-CMAC, RFC 4615 PRF output
        len: int                # [mandatory]
        info: hexstring         # [mandatory]
        okm: hexstring          # [mandatory]
````

* RFC 5869 schema
  * RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF)

````
testvector:
  - example: string             # [mandatory] testcase
    schema: RFC 5869            # [mandatory] "RFC 5869"
    items:
      - item: string            # [mandatory] 
        alg: string             # [mandatory]
        dlen: int               # [mandatory]
        ikm: hexstring          # [mandatory]
        salt: hexstring         # [mandatory]
        info: hexstring         # [mandatory]
        prk: hexstring          # [mandatory]
        okm: hexstring          # [mandatory]
````

* RFC 7439 schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: RFC 7539            # [mandatory] "RFC 7539"
    items:
      - item: string            # [mandatory] 
        alg: string             # [mandatory] "chacha20"|"chacha20-poly1305"
        key: hexstring          # [mandatory] key
        counter: int            # [mandatory] counter
        iv: hexstring           # [mandatory] IV
        aad: hexstring          # mandatory if chacha20-poly1305
        tag: hexstring          # mandatory if chacha20-poly1305
        pt: string              # [mandatory] plaintext
        ct: hexstring           # [mandatory] ciphertext
````

* RFC 7919 schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: RFC 7919            # [mandatory] "RFC 7919"
    items:
      - item: string            #
        group: string           # [mandatory]
        p: hexstring            # [mandatory] p
        q: hexstring            # [mandatory] q
        g: hexstring            # [mandatory] g
````

* NIST CAVP ECDSA schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: ECDSA TESTVECTOR    # [mandatory] "ECDSA TESTVECTOR"
    encoding: "base16"|"plain"  # [mandatory] m encoding
    items:
      - item: string            #
        curve: string           # [mandatory]
        m: hexstring            # [mandatory] message (see encoding)
        d: hexstring            # [mandatory] private
        x: hexstring            # [mandatory] public
        y: hexstring            # [mandatory] public
        k: hexstring            # [mandatory]
        r: hexstring            # [mandatory] R
        s: hexstring            # [mandatory] S
````

* NIST CAVP DSA schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: DSA PARAMETER       # [mandatory] "DSA PARAMETER"
    items:
      - item: string            # [mandatory] primary key
        p: hexstring            # [mandatory] prime
        q: hexstring            # [mandatory] subprime
        g: hexstring            # [mandatory] generator
  - example: string             # [mandatory] testcase
    schema: DSA TESTVECTOR      # [mandatory] "DSA TESTVECTOR"
    items:
      - item: string            #
        param: string           # [mandatory] foreign key (param) references DSA PARAMETER (item)
        alg: string             # [mandatory]
        m: hexstring            # [mandatory]
        x: hexstring            # [mandatory] private
        y: hexstring            # [mandatory] public
        k: hexstring            # [mandatory]
        r: hexstring            # [mandatory] R
        s: hexstring            # [mandatory] S
````

* NIST CAVP RSA schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: RSA KEY             # [mandatory] "RSA KEY"
    items:
      - item: string            # [mandatory] primary key
        n: hexstring            # [mandatory] modulus
        e: hexstring            # [mandatory] public exponent
        d: hexstring            # [mandatory] private exponent
  - example: string             # [mandatory] testcase
    schema: RSA PKCS 1.5        # [mandatory] "RSA PKCS 1.5"
    items:
      - item: string            #
        key: string             # [mandatory] foreign key (key) references RSA KEY (item)
        alg: string             # [mandatory] algorithm
        m: hexstring            # [mandatory] message
        s: hexstring            # [mandatory] signature
  - example: string             # [mandatory] testcase
    schema: RSA PSS             # [mandatory] "RSA PSS"
    items:
      - item: string            #
        key: string             # [mandatory] foreign key (key) references RSA KEY (item)
        alg: string             # [mandatory] algorithm
        m: hexstring            # [mandatory] message
        s: hexstring            # [mandatory] signature
        salt: hexstring         # [mandatory] salt
````

* CLIENT SHARE schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: CLIENT SHARE        # [mandatory] "CLIENT SHARE"
    items:
    - item: string              # [mandatory]
      group: string             # [mandatory]
      share: hexstring          # [mandatory]
````

* KEY GEN schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: KEY GEN             # [mandatory] "KEY GEN"
    items:
    - item: string              # [mandatory]
      kty: string               # [mandatory] rsaEncryption, RSASSA-PSS, X25519, Ed25519, P-256, P-384, P-521, DSA, ffdhe2048, ...
      kid: string               # [mandatory]
      param:                    #
        x: encoded              # DH, DSA, EC, OKP
        y: encoded              # DH, DSA, EC
        d: encoded              # EC, OKP, RSA
        n: encoded              # RSA
        e: encoded              # RSA
        p: encoded              # DH, DSA
        q: encoded              # DH, DSA
        g: encoded              # DH, DSA
        uncompressed: encoded   # EC
        ybit: bool              # EC
````

