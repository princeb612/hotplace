## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# References

## 1. Role

This document identifies the module or protocol area represented by this file.

## 2. Model

* [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000) [summary](rfc9000.md)
* [RFC 9001](https://datatracker.ietf.org/doc/html/rfc9001) [summary](rfc9001.md)
* [RFC 9369](https://datatracker.ietf.org/doc/html/rfc9369) [summary](rfc9369.md)

#### RFC 9000

```
   Client                                                  Server

   Initial[0]: CRYPTO[CH] ->

                                    Initial[0]: CRYPTO[SH] ACK[0]
                          Handshake[0]: CRYPTO[EE, CERT, CV, FIN]
                                    <- 1-RTT[0]: STREAM[1, "..."]

   Initial[1]: ACK[0]
   Handshake[0]: CRYPTO[FIN], ACK[0]
   1-RTT[0]: STREAM[0, "..."], ACK[0] ->

                                             Handshake[1]: ACK[0]
            <- 1-RTT[1]: HANDSHAKE_DONE, STREAM[3, "..."], ACK[0]

                     Figure 5: Example 1-RTT Handshake
```

```
   Client                                                  Server

   Initial[0]: CRYPTO[CH]
   0-RTT[0]: STREAM[0, "..."] ->

                                    Initial[0]: CRYPTO[SH] ACK[0]
                                     Handshake[0] CRYPTO[EE, FIN]
                             <- 1-RTT[0]: STREAM[1, "..."] ACK[0]

   Initial[1]: ACK[0]
   Handshake[0]: CRYPTO[FIN], ACK[0]
   1-RTT[1]: STREAM[0, "..."] ACK[0] ->

                                             Handshake[1]: ACK[0]
            <- 1-RTT[1]: HANDSHAKE_DONE, STREAM[3, "..."], ACK[1]

                     Figure 6: Example 0-RTT Handshake
```

```
   Client                                                  Server

   Initial: DCID=S1, SCID=C1 ->
                                     <- Initial: DCID=C1, SCID=S3
                                ...
   1-RTT: DCID=S3 ->
                                                <- 1-RTT: DCID=C1

               Figure 7: Use of Connection IDs in a Handshake
```

```
   Client                                                  Server

   Initial: DCID=S1, SCID=C1 ->
                                       <- Retry: DCID=C1, SCID=S2
   Initial: DCID=S2, SCID=C1 ->
                                     <- Initial: DCID=C1, SCID=S3
                                ...
   1-RTT: DCID=S3 ->
                                                <- 1-RTT: DCID=C1

         Figure 8: Use of Connection IDs in a Handshake with Retry
```

#### RFC 9001

```
   +------------+                               +------------+
   |            |<---- Handshake Messages ----->|            |
   |            |<- Validate 0-RTT Parameters ->|            |
   |            |<--------- 0-RTT Keys ---------|            |
   |    QUIC    |<------- Handshake Keys -------|    TLS     |
   |            |<--------- 1-RTT Keys ---------|            |
   |            |<------- Handshake Done -------|            |
   +------------+                               +------------+
    |         ^
    | Protect | Protected
    v         | Packet
   +------------+
   |   QUIC     |
   |  Packet    |
   | Protection |
   +------------+

                    Figure 4: QUIC and TLS Interactions
```

```
   Client                                                    Server
   ======                                                    ======

   Get Handshake
                        Initial ------------->
   Install tx 0-RTT keys
                        0-RTT - - - - - - - ->

                                                 Handshake Received
                                                      Get Handshake
                        <------------- Initial
                                              Install rx 0-RTT keys
                                             Install Handshake keys
                                                      Get Handshake
                        <----------- Handshake
                                              Install tx 1-RTT keys
                        <- - - - - - - - 1-RTT

   Handshake Received (Initial)
   Install Handshake keys
   Handshake Received (Handshake)
   Get Handshake
                        Handshake ----------->
   Handshake Complete
   Install 1-RTT keys
                        1-RTT - - - - - - - ->

                                                 Handshake Received
                                                 Handshake Complete
                                                Handshake Confirmed
                                              Install rx 1-RTT keys
                        <--------------- 1-RTT
                              (HANDSHAKE_DONE)
   Handshake Confirmed

             Figure 5: Interaction Summary between QUIC and TLS
```

#### implementation areas

* [frame](frame/README.md)
* [packet](packet/README.md)
* [TLS integration](../README.md)

#### related areas

* `sdk/net/http/http3/` - HTTP/3 above QUIC
* `sdk/net/tls/` - TLS 1.3 handshake and key schedule used by QUIC
* `sdk/crypto/` - packet protection cryptography

## 3. Important behavior and lifetime

Implementation details and behavior are described where the existing source-tree notes provide evidence.

## 4. Example from the source tests

See the referenced testcase sources for concrete examples. Where no direct test is identified, this is not evidence of runtime verification.

## 5. Relationships

Related implementation areas and protocol boundaries are recorded here where identified.

## 6. References

Source references and related documents are retained here where available.
