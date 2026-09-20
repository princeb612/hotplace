#### CBOR

* test vector
  * QUIC: A UDP-Based Multiplexed and Secure Transport
    * A.1.  Sample Variable-Length Integer Decoding

#### YAML schema

* PARSER YAML schema

````
testvector:
  - example: string                 # [mandatory] testcase
    schema: PARSER                  # [mandatory] "PARSER"
    items:
      - item: string                # [mandatory]
        asn1: |
          statements                # [mandatory] ASN.1 notation
        expect:                     # [mandatory]
          imports_clause: array     # [mandatory] ex. [[begin1, end1],[begin2, end2]]
          exports_clause: array     # [mandatory] ex. [[begin1, end1],[begin2, end2]]
          header_clause: array      # [mandatory] ex. [[begin1, end1],[begin2, end2]]
          level_unmatched: array    # [mandatory] ex. [[begin1, end1],[begin2, end2]]
          level_matched: array      # [mandatory] ex. [[begin1, end1],[begin2, end2]]
          edge_unmatched: array     # [mandatory] ex. [[begin1, end1],[begin2, end2]]
          edge_matched: array       # [mandatory] ex. [[begin1, end1],[begin2, end2]]
````
