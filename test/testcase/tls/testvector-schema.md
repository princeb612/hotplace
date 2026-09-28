#### YAML schema

* PCAP schema

````
testvector:
  - example: string                         # [mandatory] testcase
    schema: PCAP SIMPLE                     # [mandatory] "PCAP SIMPLE" (not 5 tuple format)
    protocol: "TLS"|"DTLS"                  # [mandatory]
    secrets:                                # pre master secrets
      - item: string                        #
    items:                                  # TLS Record
      - item: string                        #
        dir: "from_client"|"from_server"    # [mandatory]
        record: hexstring                   # [mandatory]
````

