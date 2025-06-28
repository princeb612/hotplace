#### memo

* QUIC initial packet number
  * https://quic.xargs.org
    * client 0
    * server 0
  * RFC 9001, RFC 9369
    * client 0
    * server 1

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
