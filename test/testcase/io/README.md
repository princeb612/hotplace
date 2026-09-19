#### CBOR

* test vector
  * QUIC: A UDP-Based Multiplexed and Secure Transport
    * A.1.  Sample Variable-Length Integer Decoding

#### YAML schema

* PARSER YAML schema

````
testvector:
  - example: string             # [mandatory] testcase
    schema: PARSER              # [mandatory] "PARSER"
    items:
      - item: string            # [mandatory]
        asn1: |
          statements            # [mandatory] ASN.1 notation
        expect:
          imports_clause: array # [[begin1, end1],[begin2, end2]]
          exports_clause: array # [[begin1, end1],[begin2, end2]]
          header_clause: array  # [[begin1, end1],[begin2, end2]]
````
