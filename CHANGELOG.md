# history

* Revision 652
  * [study] QUIC (RFC 9001)
  * [study] TLS (RFC 8446, 8448)

* Revision 647
  * [tested] QUIC (RFC 9001)
    * A.4.  Retry
  * [study] TLS (RFC 8446)

* Revision 646
  * [tested] QUIC (RFC 9001)
    * A.2.  Client Initial
    * A.3.  Server Initial

* Revision 644
  * [added] log level

* Revision 634, 635
  * [tested] HPACK/QPACK

* Revision 629, 630
  * [study] HTTP/2 Server Push

* Revision 627, 628
  * [study] ALTSVC HTTP/2 Frame

* Revision 626
  * [tested] QPACK (RFC 9204)

* Revision 625
  * [tested] RFC 9204 Appendix B.
  * [changed] QPACK RIC

* Revision 624
  * [changed] QPACK duplicate

* Revision 623
  * [tested] HPACK eviction

* Revision 622
  * [changed] HPACK/QPACK eviction

* Revision 621
  * [fixed] HPACK (changed parameter type to encode index over 255)

* Revision 620
  * [changed] faster match/select (hpack_dynamic_table)

* Revision 617
  * [feature] DTLS on network_server (epoll/IOCP)
  * [tested] DTLS server (epoll)

* Revision 615
  * [changed] TLS non-blocking io

* Revision 614
  * [tested] DTLS server (IOCP)

* Revision 613
  * [added] TCP/TLS/UDP/DTLS client (see test/netclient)

* Revision 607
  * [fixed] sprintf

* Revision 601
  * [feature] UDP on network_server (epoll/IOCP)
  * [tested] test/udpserver2 (udp server on network_server, epoll/iocp)

* Revision 600
  * [changed] udp server on network_server, epoll

* Revision 598
  * [changed] udp server on network_server, iocp

* Revision 584
  * [fixed] authenticode_verifier::verify
    * std::equal (a.begin(), a.end(), empty.begin()) stack overflow
  * [fixed] lower case digest algorithm

* Revision 578
  * [feature] Aho Corasick Algorithm + wildcard (single, any)
  * [tested] Aho Corasick Algorithm + wildcard (any)

* Revision 573
  * [tested] Aho Corasick Algorithm + wildcard (single)

* Revision 553
  * [feature] Ukkonen algorithm

* Revision 551
  * [feature] suffix tree

* Revision 550
  * [feature] trie

* Revision 548
  * [feature] Aho Corasick algorithm

* Revision 541
  * [feature] shortest path (djkstra)

* Revision 536
  * [feature] parser
  * [feature] Knuth-Morris-Pratt Algorithm

* Revision 524
  * [feature] logger

* Revision 523
  * [feature] HTTP/2 (RFC 7541, RFC 9113)

* Revision 506
  * [feature] HPACK (RFC 7541)

* Revision 504
  * [feature] huffman_coding

* Revision 486
  * [feature] OAuth 2.0 (RFC 6749)

* Revision 472
  * [added] RS1

* Revision 455
  * [feature] HTTP Digest Access Authentication (RFC 7616, userhash)

* Revision 454
  * [feature] HTTP Authentication: Basic and Digest Access Authentication (RFC 2617)

* Revision 442
  * [feature] COSE (RFC 8152, RFC 8230, RFC 8392, RFC 8812, RFC 9052, RFC 9053, RFC 9338)
  * [tested] COSE (valgrind)

* Revision 411
  * [changed] COSE (RFC 8152 Appendix B. Two Layers of Recipient Information)

* Revision 392
  * [fixed] mingw terminal delay fixed

* Revision 305
  * [added] elliptic curves B-163, K-163, P-192

* Revision 211
  * [added] COSE (RFC 8152 examples .cbor, .diag)

* Revision 108
  * [feature] Authenticode (verification only)

* Revision 107
  * [feature] CBOR (RFC 7049, RFC 8949)

* Revision 106
  * [feature] ODBC

* Revision 38
  * [feature] HOTP(RFC 4226), TOTP(RFC 6238)
