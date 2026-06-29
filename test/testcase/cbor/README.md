#### CBOR

* test vector
  * RFC 7049 Concise Binary Object Representation (CBOR)
    * Appendix A.  Examples
    * Appendix B.  Jump Table
  * RFC 8949 Concise Binary Object Representation (CBOR)
    * Appendix A.  Examples of Encoded CBOR Data Items
    * Appendix B.  Jump Table for Initial Byte

#### YAML schema

* CBOR YAML schema

````
testvector:
  - example: string          # [mandatory] testcase
    schema: RFC 7049         # [mandatory] "RFC 7049"
    items:
      - item: string         # [mandatory] diagnostic, description
        cbor: hexstring      # [mandatory]
        # [mandatory] diagnostic expression
        diag: |
          string
        loss: boolean        # dataloss encoding e.g. float(5.960464477539063e-8) FP32 5.96046448e-08 BINARY32 33800000
````
