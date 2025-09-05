# history

* topic
  * [study] QUIC (RFC 9001, 9369)
  * [study] TLS (RFC 4346, 5246, 8446, 8448)
  * [study] HTTP/2 (RFC 7541, 7540, 9113)
  * [study] CBOR/COSE (RFC 7049, 8949, 8152)

* understanding
  * Revision 805-
    * server - DTLS
    * QUIC, HTTP/3
  * Revision 777-804
    * server - TLS, HTTP/1.1, HTTP/2
  * Revision 682-776
    * client - TLS, DTLS
  * Revision 673-680 (Tag 0.97, Revision.684)
    * RFC 8448 Example Handshake Traces for TLS 1.3
  * Revision 650-672
    * https://tls13.xargs.org/
    * https://tls12.xargs.org/
    * https://dtls.xargs.org/
  * Revision 501-523 (Tag 0.56, Revision.528)
    * server - HTTP/2 (libssl)
  * Revision 221-442
    * COSE
  * Revision 144-220
    * CBOR

* details
  * Revision 868
  * Revision 839
    * [tested] DTLS records
  * Revision 836
    * [tested] DTLS 1.2 server (linux)
  * Revision 835
    * [tested] DTLS 1.2 server (mingw64)
  * Revision 834
    * [tested] MSYS2 update issue [gcc 15 __glibcxx_requires_subscript assertion](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=111250)
  * Revision 833
    * [tested] shared build
    * [tested] gcc < 4.9
  * Revision 831
    * [tested] valgrind
  * Revision 826
    * [tested] DTLS 1.2 AES-GCM, chacha20-poly1305
  * Revision 825
    * [tested] TLS 1.2 chacha20-poly1305
  * Revision 824
    * [fixed] QPACK
  * Revision 823
    * [tested] RFC 9204
  * Revision 804
    * [tested] HTTP/2 feat. curl (MINGW64, linux environment)
  * Revision 803
    * [tested] HTTP/1.1 feat. curl
  * Revision 799
    * [tested] http_server HTTP/1.1 (linux environment)
  * Revision 795
    * [tested] http_server HTTP/2 (MINGW64 environment)
  * Revision 794
    * [tested] http_server HTTP/1.1 (MINGW64 environment)
  * Revision 789
    * [fixed] key_share
  * Revision 788
    * [tested] TLS 1.2 ciphersuites (GCM)
  * Revision 785
  * Revision 784
    * [tested] CCM_8
      * no test vector (s_server/s_client)
  * Revision 783
    * [fixed] AEAD_AES_128_CCM, AEAD_AES_256_CCM
  * Revision 781
    * [tested] DTLS fragmentation
  * Revision 779
    * [fixed] server_key_exchange, ECDSA DER format
    * [tested] extended_master_secret
    * [tested] TLS 1.2 ciphersuites (CBC)
  * Revision 778
    * [tested] server certificates
  * Revision 777
    * [tested] server socket, netserver integration
  * Revision 770
    * [tested] valgrind
    * [applied] openssl-3.5.0 (LTS)
  * Revision 766
    * [tested] DTLS over UDP, client
  * Revision 764
    * [fixed] DTLS reconstruction data (record epoch and sequence), handshake message sequence
  * Revision 762
    * [tested] DTLS reconstruction data (record epoch and sequence), handshake message sequence
  * Revision 760
    * [tested] TLS 1.2 finished
  * Revision 752
    * [tested] encrypt_then_mac
  * Revision 740
    * [fixed] TLS 1.2
  * Revision 731
    * [tested] valgrind (tcpserver1, tcpserver2, tlsserver, udpserver1, udpserver2, dtlsserver)
  * Revision 729
    * simple client (TLS over TCP)
      * test/netclient <-> test/tlsserver
  * Revision 716
    * [tested] RFC 9369 QUIC Version 2
  * Revision 715
    * [tested] valgrind
  * Revision 714
    * [tested] https://quic.xargs.org/
  * Revision 702
    * [tested] DSA
  * Revision 684 (Tag 0.97)
  * Revision 679
    * [tested] RFC 8448 6.  Client Authentication
    * [tested] RFC 8448 7.  Compatibility Mode
  * Revision 677
    * [tested] RFC 8448 5.  HelloRetryRequest
  * Revision 675
    * [tested] RFC 8448 4.  Resumed 0-RTT Handshake
  * Revision 671
    * [tested] https://dtls.xargs.org/
  * Revision 669
    * [study] SSLKEYLOGFILE
  * Revision 667
    * [tested] https://tls12.xargs.org/
  * Revision 663
    * [tested] RFC 8448 3.  Simple 1-RTT Handshake
  * Revision 660
    * [tested] https://tls13.xargs.org/
  * Revision 658
    * [tested] TLS 1.3 certificate_verify, finished
  * Revision 657
    * [added] ffdhe2048 ffdhe3072 ffdhe4096 ffdhe6144 ffdhe8192
  * Revision 656
    * [tested] RSA_PSS key
  * Revision 654
    * [tested] stream autoindent
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
  * Revision 528 (Tag 0.56)
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
