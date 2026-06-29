#### HPACK

* test vector
  * RFC 7541 HPACK: Header Compression for HTTP/2
  * QPACK: Field Compression for HTTP/3

#### YAML schema

* HPACK schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: HPACK                           # [mandatory] "HPACK"
    items:
      - item: string                        # [mandatory]
        hpack: hexstring                    # [mandatory]
        keyvalue:                           #
          key: value                        #
````

* HTTP/2 schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: HTTP/2                          # [mandatory] "HTTP/2"
    items:
      - item: string                        # [mandatory]
        frame: hexstring                    # [mandatory] HTTP/2 frame
````
