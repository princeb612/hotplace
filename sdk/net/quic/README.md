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
