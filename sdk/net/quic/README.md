#### RC 9001

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