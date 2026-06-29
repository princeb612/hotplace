#### client

````
openssl s_client -connect localhost:9000 -state -debug -trace -keylogfile sslkeylog -tls1_2 -ciphersuites TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
Connecting to ::1
CONNECTED(000001E0)
SSL_connect:before SSL initialization
Sent TLS Record
Header:
  Version = TLS 1.0 (0x301)
  Content Type = Handshake (22)
  Length = 194
    ClientHello, Length=190
      client_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0x8D4E72AC
        random_bytes (len=28): F55111544EADC50E5E9E0C3015648025881194328BCE1573DEC89ED6
      session_id (len=0):
      cipher_suites (len=56)
        {0xC0, 0x2B} TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        {0xC0, 0x2C} TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        {0xC0, 0x30} TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        {0x00, 0x9F} TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        {0xCC, 0xA9} TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        {0xCC, 0xA8} TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        {0xCC, 0xAA} TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        {0xC0, 0x2B} TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        {0xC0, 0x2F} TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        {0x00, 0x9E} TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        {0xC0, 0x24} TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
        {0xC0, 0x28} TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        {0x00, 0x6B} TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
        {0xC0, 0x23} TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        {0xC0, 0x27} TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        {0x00, 0x67} TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        {0xC0, 0x0A} TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        {0xC0, 0x14} TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        {0x00, 0x39} TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        {0xC0, 0x09} TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        {0xC0, 0x13} TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        {0x00, 0x33} TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        {0x00, 0x9D} TLS_RSA_WITH_AES_256_GCM_SHA384
        {0x00, 0x9C} TLS_RSA_WITH_AES_128_GCM_SHA256
        {0x00, 0x3D} TLS_RSA_WITH_AES_256_CBC_SHA256
        {0x00, 0x3C} TLS_RSA_WITH_AES_128_CBC_SHA256
        {0x00, 0x35} TLS_RSA_WITH_AES_256_CBC_SHA
        {0x00, 0x2F} TLS_RSA_WITH_AES_128_CBC_SHA
      compression_methods (len=1)
        No Compression (0x00)
      extensions, length = 93
        extension_type=renegotiate(65281), length=1
            <EMPTY>
        extension_type=ec_point_formats(11), length=4
          uncompressed (0)
          ansiX962_compressed_prime (1)
          ansiX962_compressed_char2 (2)
        extension_type=supported_groups(10), length=12
          ecdh_x25519 (29)
          secp256r1 (P-256) (23)
          ecdh_x448 (30)
          secp521r1 (P-521) (25)
          secp384r1 (P-384) (24)
        extension_type=session_ticket(35), length=0
        extension_type=encrypt_then_mac(22), length=0
        extension_type=extended_master_secret(23), length=0
        extension_type=signature_algorithms(13), length=48
          ecdsa_secp256r1_sha256 (0x0403)
          ecdsa_secp384r1_sha384 (0x0503)
          ecdsa_secp521r1_sha512 (0x0603)
          ed25519 (0x0807)
          ed448 (0x0808)
          ecdsa_brainpoolP256r1_sha256 (0x081a)
          ecdsa_brainpoolP384r1_sha384 (0x081b)
          ecdsa_brainpoolP512r1_sha512 (0x081c)
          rsa_pss_pss_sha256 (0x0809)
          rsa_pss_pss_sha384 (0x080a)
          rsa_pss_pss_sha512 (0x080b)
          rsa_pss_rsae_sha256 (0x0804)
          rsa_pss_rsae_sha384 (0x0805)
          rsa_pss_rsae_sha512 (0x0806)
          rsa_pkcs1_sha256 (0x0401)
          rsa_pkcs1_sha384 (0x0501)
          rsa_pkcs1_sha512 (0x0601)
          ecdsa_sha224 (0x0303)
          rsa_pkcs1_sha224 (0x0301)
          dsa_sha224 (0x0302)
          dsa_sha256 (0x0402)
          dsa_sha384 (0x0502)
          dsa_sha512 (0x0602)

write to 0x21333770400 [0x21333bd4350] (199 bytes => 199 (0xC7))
0000 - 16 03 01 00 c2 01 00 00-be 03 03 8d 4e 72 ac f5   ............Nr..
0010 - 51 11 54 4e ad c5 0e 5e-9e 0c 30 15 64 80 25 88   Q.TN...^..0.d.%.
0020 - 11 94 32 8b ce 15 73 de-c8 9e d6 00 00 38 c0 2b   ..2...s......8.+
0030 - c0 2c c0 30 00 9f cc a9-cc a8 cc aa c0 2b c0 2f   .,.0.........+./
0040 - 00 9e c0 24 c0 28 00 6b-c0 23 c0 27 00 67 c0 0a   ...$.(.k.#.'.g..
0050 - c0 14 00 39 c0 09 c0 13-00 33 00 9d 00 9c 00 3d   ...9.....3.....=
0060 - 00 3c 00 35 00 2f 01 00-00 5d ff 01 00 01 00 00   .<.5./...]......
0070 - 0b 00 04 03 00 01 02 00-0a 00 0c 00 0a 00 1d 00   ................
0080 - 17 00 1e 00 19 00 18 00-23 00 00 00 16 00 00 00   ........#.......
0090 - 17 00 00 00 0d 00 30 00-2e 04 03 05 03 06 03 08   ......0.........
00a0 - 07 08 08 08 1a 08 1b 08-1c 08 09 08 0a 08 0b 08   ................
00b0 - 04 08 05 08 06 04 01 05-01 06 01 03 03 03 01 03   ................
00c0 - 02 04 02 05 02 06 02                              .......
SSL_connect:SSLv3/TLS write client hello
read from 0x21333770400 [0x21333bd9423] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 41                                    ....A
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 65
read from 0x21333770400 [0x21333bd9428] (65 bytes => 65 (0x41))
0000 - 02 00 00 3d 03 03 07 4a-0c b6 fe 8a 12 a0 47 0f   ...=...J......G.
0010 - c3 29 88 f9 8e ef ee 81-e3 d6 a6 09 9d df 44 4f   .)............DO
0020 - 57 4e 47 52 44 01 00 c0-2b 00 00 15 ff 01 00 01   WNGRD...+.......
0030 - 00 00 0b 00 04 03 00 01-02 00 23 00 00 00 17 00   ..........#.....
0040 - 00                                                .
SSL_connect:SSLv3/TLS write client hello
    ServerHello, Length=61
      server_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0x074A0CB6
        random_bytes (len=28): FE8A12A0470FC32988F98EEFEE81E3D6A6099DDF444F574E47524401
      session_id (len=0):
      cipher_suite {0xC0, 0x2B} TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
      compression_method: No Compression (0x00)
      extensions, length = 21
        extension_type=renegotiate(65281), length=1
            <EMPTY>
        extension_type=ec_point_formats(11), length=4
          uncompressed (0)
          ansiX962_compressed_prime (1)
          ansiX962_compressed_char2 (2)
        extension_type=session_ticket(35), length=0
        extension_type=extended_master_secret(23), length=0

Can't use SSL_get_servername
read from 0x21333770400 [0x21333bd9423] (5 bytes => 5 (0x5))
0000 - 16 03 03 02 16                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 534
read from 0x21333770400 [0x21333bd9428] (534 bytes => 534 (0x216))
0000 - 0b 00 02 12 00 02 0f 00-02 0c 30 82 02 08 30 82   ..........0...0.
0010 - 01 ad a0 03 02 01 02 02-14 41 4d f6 cb ca 7e 42   .........AM...~B
0020 - 21 ee 06 a6 88 02 79 a4-e0 c0 48 88 92 30 0a 06   !.....y...H..0..
0030 - 08 2a 86 48 ce 3d 04 03-02 30 59 31 0b 30 09 06   .*.H.=...0Y1.0..
0040 - 03 55 04 06 13 02 4b 52-31 0b 30 09 06 03 55 04   .U....KR1.0...U.
0050 - 08 0c 02 47 47 31 0b 30-09 06 03 55 04 07 0c 02   ...GG1.0...U....
0060 - 59 49 31 0d 30 0b 06 03-55 04 0a 0c 04 54 65 73   YI1.0...U....Tes
0070 - 74 31 0d 30 0b 06 03 55-04 0b 0c 04 54 65 73 74   t1.0...U....Test
0080 - 31 12 30 10 06 03 55 04-03 0c 09 54 65 73 74 20   1.0...U....Test
0090 - 52 6f 6f 74 30 1e 17 0d-32 35 30 32 30 39 31 34   Root0...25020914
00a0 - 34 39 35 37 5a 17 0d 32-36 30 32 30 39 31 34 34   4957Z..260209144
00b0 - 39 35 37 5a 30 59 31 0b-30 09 06 03 55 04 06 13   957Z0Y1.0...U...
00c0 - 02 4b 52 31 0b 30 09 06-03 55 04 08 0c 02 47 47   .KR1.0...U....GG
00d0 - 31 0b 30 09 06 03 55 04-07 0c 02 59 49 31 0d 30   1.0...U....YI1.0
00e0 - 0b 06 03 55 04 0a 0c 04-54 65 73 74 31 0d 30 0b   ...U....Test1.0.
00f0 - 06 03 55 04 0b 0c 04 54-65 73 74 31 12 30 10 06   ..U....Test1.0..
0100 - 03 55 04 03 0c 09 54 65-73 74 20 52 6f 6f 74 30   .U....Test Root0
0110 - 59 30 13 06 07 2a 86 48-ce 3d 02 01 06 08 2a 86   Y0...*.H.=....*.
0120 - 48 ce 3d 03 01 07 03 42-00 04 56 af c0 cb 7b 57   H.=....B..V...{W
0130 - 8e 97 f3 4a 06 2d a5 91-ca 5f ac 2a 6a 24 f2 f1   ...J.-..._.*j$..
0140 - 16 c2 b7 91 28 2c 3e da-87 cc c1 40 14 33 f1 c5   ....(,>....@.3..
0150 - 1a 79 cc 31 01 4a c7 f2-62 3f 28 79 00 4c e1 6c   .y.1.J..b?(y.L.l
0160 - a3 cc 90 23 a8 96 c1 73-3f 04 a3 53 30 51 30 1d   ...#...s?..S0Q0.
0170 - 06 03 55 1d 0e 04 16 04-14 03 e0 ab e4 28 de e7   ..U..........(..
0180 - 2f 73 e9 e1 5f 5e 47 0d-b6 5f e8 24 ff 30 1f 06   /s.._^G.._.$.0..
0190 - 03 55 1d 23 04 18 30 16-80 14 03 e0 ab e4 28 de   .U.#..0.......(.
01a0 - e7 2f 73 e9 e1 5f 5e 47-0d b6 5f e8 24 ff 30 0f   ./s.._^G.._.$.0.
01b0 - 06 03 55 1d 13 01 01 ff-04 05 30 03 01 01 ff 30   ..U.......0....0
01c0 - 0a 06 08 2a 86 48 ce 3d-04 03 02 03 49 00 30 46   ...*.H.=....I.0F
01d0 - 02 21 00 93 6c 1f 79 f6-7b 8e 21 b8 ff 00 91 9b   .!..l.y.{.!.....
01e0 - 01 c9 0d 66 46 a2 72 44-c2 a4 8d fe 4e 12 41 d8   ...fF.rD....N.A.
01f0 - 7a 07 94 02 21 00 fb bc-a9 86 0e eb c5 a6 74 38   z...!.........t8
0200 - 5f 05 54 2a fb d2 57 7b-76 88 d7 fc d6 e4 e2 3b   _.T*..W{v......;
0210 - 55 05 df 38 d6 8e                                 U..8..
SSL_connect:SSLv3/TLS read server hello
    Certificate, Length=530
      certificate_list, length=527
        ASN.1Cert, length=524
------details-----
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            41:4d:f6:cb:ca:7e:42:21:ee:06:a6:88:02:79:a4:e0:c0:48:88:92
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C = KR, ST = GG, L = YI, O = Test, OU = Test, CN = Test Root
        Validity
            Not Before: Feb  9 14:49:57 2025 GMT
            Not After : Feb  9 14:49:57 2026 GMT
        Subject: C = KR, ST = GG, L = YI, O = Test, OU = Test, CN = Test Root
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:56:af:c0:cb:7b:57:8e:97:f3:4a:06:2d:a5:91:
                    ca:5f:ac:2a:6a:24:f2:f1:16:c2:b7:91:28:2c:3e:
                    da:87:cc:c1:40:14:33:f1:c5:1a:79:cc:31:01:4a:
                    c7:f2:62:3f:28:79:00:4c:e1:6c:a3:cc:90:23:a8:
                    96:c1:73:3f:04
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                03:E0:AB:E4:28:DE:E7:2F:73:E9:E1:5F:5E:47:0D:B6:5F:E8:24:FF
            X509v3 Authority Key Identifier:
                03:E0:AB:E4:28:DE:E7:2F:73:E9:E1:5F:5E:47:0D:B6:5F:E8:24:FF
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:93:6c:1f:79:f6:7b:8e:21:b8:ff:00:91:9b:
        01:c9:0d:66:46:a2:72:44:c2:a4:8d:fe:4e:12:41:d8:7a:07:
        94:02:21:00:fb:bc:a9:86:0e:eb:c5:a6:74:38:5f:05:54:2a:
        fb:d2:57:7b:76:88:d7:fc:d6:e4:e2:3b:55:05:df:38:d6:8e
-----BEGIN CERTIFICATE-----
MIICCDCCAa2gAwIBAgIUQU32y8p+QiHuBqaIAnmk4MBIiJIwCgYIKoZIzj0EAwIw
WTELMAkGA1UEBhMCS1IxCzAJBgNVBAgMAkdHMQswCQYDVQQHDAJZSTENMAsGA1UE
CgwEVGVzdDENMAsGA1UECwwEVGVzdDESMBAGA1UEAwwJVGVzdCBSb290MB4XDTI1
MDIwOTE0NDk1N1oXDTI2MDIwOTE0NDk1N1owWTELMAkGA1UEBhMCS1IxCzAJBgNV
BAgMAkdHMQswCQYDVQQHDAJZSTENMAsGA1UECgwEVGVzdDENMAsGA1UECwwEVGVz
dDESMBAGA1UEAwwJVGVzdCBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
Vq/Ay3tXjpfzSgYtpZHKX6wqaiTy8RbCt5EoLD7ah8zBQBQz8cUaecwxAUrH8mI/
KHkATOFso8yQI6iWwXM/BKNTMFEwHQYDVR0OBBYEFAPgq+Qo3ucvc+nhX15HDbZf
6CT/MB8GA1UdIwQYMBaAFAPgq+Qo3ucvc+nhX15HDbZf6CT/MA8GA1UdEwEB/wQF
MAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAJNsH3n2e44huP8AkZsByQ1mRqJyRMKk
jf5OEkHYegeUAiEA+7yphg7rxaZ0OF8FVCr70ld7dojX/Nbk4jtVBd841o4=
-----END CERTIFICATE-----
------------------

depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
verify error:num=18:self-signed certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
verify return:1
read from 0x21333770400 [0x21333bd9423] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 73                                    ....s
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 115
read from 0x21333770400 [0x21333bd9428] (115 bytes => 115 (0x73))
0000 - 0c 00 00 6f 03 00 1d 20-80 aa 59 31 f2 23 0c 66   ...o... ..Y1.#.f
0010 - 29 5e eb 05 1a e9 47 aa-e7 a0 1b 9e e1 12 44 65   )^....G.......De
0020 - f5 4c 21 f9 77 88 ec 00-04 03 00 47 30 45 02 20   .L!.w......G0E.
0030 - 29 9d 6b 03 af 88 8f 01-a9 cc 50 c9 3f 92 87 de   ).k.......P.?...
0040 - 28 98 97 c8 a8 e1 94 91-a0 02 67 33 ba e5 64 60   (.........g3..d`
0050 - 02 21 00 d3 2c e3 0b c0-87 60 73 ad 75 70 30 ff   .!..,....`s.up0.
0060 - 59 47 83 ca 91 c1 26 f1-b8 e0 54 40 f1 a0 c3 9a   YG....&...T@....
0070 - 81 fa 6d                                          ..m
SSL_connect:SSLv3/TLS read server certificate
    ServerKeyExchange, Length=111
      KeyExchangeAlgorithm=ECDHE
        named_curve: ecdh_x25519 (29)
        point (len=32): 80AA5931F2230C66295EEB051AE947AAE7A01B9EE1124465F54C21F97788EC00
      Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
      Signature (len=71): 30450220299D6B03AF888F01A9CC50C93F9287DE289897C8A8E19491A0026733BAE56460022100D32CE30BC0876073AD757030FF594783CA91C126F1B8E05440F1A0C39A81FA6D

read from 0x21333770400 [0x21333bd9423] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 04                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 4
read from 0x21333770400 [0x21333bd9428] (4 bytes => 4 (0x4))
0000 - 0e 00 00 00                                       ....
SSL_connect:SSLv3/TLS read server key exchange
    ServerHelloDone, Length=0

SSL_connect:SSLv3/TLS read server done
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 37
    ClientKeyExchange, Length=33
      KeyExchangeAlgorithm=ECDHE
        ecdh_Yc (len=32): FF5F0A763670E25DB7CA205E7655ABAD0976836CC05C0D5E78C1FC37A2A05139

SSL_connect:SSLv3/TLS write client key exchange
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ChangeCipherSpec (20)
  Length = 1
    change_cipher_spec (1)

SSL_connect:SSLv3/TLS write change cipher spec
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 40
    Finished, Length=12
      verify_data (len=12): FF7486F7D9A31384A38CF562

write to 0x21333770400 [0x21333bd4350] (93 bytes => 93 (0x5D))
0000 - 16 03 03 00 25 10 00 00-21 20 ff 5f 0a 76 36 70   ....%...! ._.v6p
0010 - e2 5d b7 ca 20 5e 76 55-ab ad 09 76 83 6c c0 5c   .].. ^vU...v.l.\
0020 - 0d 5e 78 c1 fc 37 a2 a0-51 39 14 03 03 00 01 01   .^x..7..Q9......
0030 - 16 03 03 00 28 f1 b1 d2-e2 78 b9 f2 34 5d d1 73   ....(....x..4].s
0040 - bb f2 f3 7c ef 1f 1e 54-c5 af bb 79 b6 b0 e2 f8   ...|...T...y....
0050 - 03 e9 98 40 94 3c 28 51-8b 1d b1 8f a8            ...@.<(Q.....
SSL_connect:SSLv3/TLS write finished
read from 0x21333770400 [0x21333bd9423] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 ba                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 186
read from 0x21333770400 [0x21333bd9428] (186 bytes => 186 (0xBA))
0000 - 04 00 00 b6 00 00 1c 20-00 b0 60 a0 3d 87 d7 e1   ....... ..`.=...
0010 - a2 7f b2 4b 57 b5 01 cc-06 ac 77 7b eb 16 e1 8c   ...KW.....w{....
0020 - 1f 76 34 b1 c1 f7 93 1d-e6 3f e6 02 e4 e4 1d 5e   .v4......?.....^
0030 - a7 34 4c 1c 1b f9 14 28-57 90 de ec 13 3b 1b 6b   .4L....(W....;.k
0040 - 5e bb 34 69 2c a7 bc 3f-c3 a9 8f 1b b9 fe 28 87   ^.4i,..?......(.
0050 - 22 8f 15 ff 30 20 df 6a-9d 42 44 70 85 21 b9 a6   "...0 .j.BDp.!..
0060 - f8 e8 39 3e e6 0f 4e 82-ee da 9d 6e 7f dd 53 f2   ..9>..N....n..S.
0070 - fa f3 e3 34 63 da 7d 44-37 0d ba fe 1a 4c c1 ec   ...4c.}D7....L..
0080 - a0 34 15 29 c4 7d 02 44-f1 0c 4d fb ee 28 f7 a2   .4.).}.D..M..(..
0090 - 08 6f 87 d5 be 1e 7d 0f-f3 da 0a 30 8a 8c db b1   .o....}....0....
00a0 - 17 57 c6 f8 e7 03 56 ed-92 3b 63 1f e5 de 87 e7   .W....V..;c.....
00b0 - 64 4d 7a c8 48 e3 3d e4-9b 25                     dMz.H.=..%
SSL_connect:SSLv3/TLS write finished
    NewSessionTicket, Length=182
        ticket_lifetime_hint=7200
        ticket (len=176): 60A03D87D7E1A27FB24B57B501CC06AC777BEB16E18C1F7634B1C1F7931DE63FE602E4E41D5EA7344C1C1BF914285790DEEC133B1B6B5EBB34692CA7BC3FC3A98F1BB9FE2887228F15FF3020DF6A9D4244708521B9A6F8E8393EE60F4E82EEDA9D6E7FDD53F2FAF3E33463DA7D44370DBAFE1A4CC1ECA0341529C47D0244F10C4DFBEE28F7A2086F87D5BE1E7D0FF3DA0A308A8CDBB11757C6F8E70356ED923B631FE5DE87E7644D7AC848E33DE49B25

read from 0x21333770400 [0x21333bd9423] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ChangeCipherSpec (20)
  Length = 1
read from 0x21333770400 [0x21333bd9428] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_connect:SSLv3/TLS read server session ticket
read from 0x21333770400 [0x21333bd5363] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 28                                    ....(
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 40
read from 0x21333770400 [0x21333bd5368] (40 bytes => 40 (0x28))
0000 - a8 89 ac 79 78 9b 9a 83-83 ec 32 32 c3 1d c8 95   ...yx.....22....
0010 - a8 43 3d 71 4c 5e 4e f4-d2 2e b2 05 30 90 e9 fe   .C=qL^N.....0...
0020 - ba 3f a0 1d 39 cc 41 dc-                          .?..9.A.
SSL_connect:SSLv3/TLS read change cipher spec
    Finished, Length=12
      verify_data (len=12): 305971C8F38E0968280F935D

SSL_connect:SSLv3/TLS read finished
---
Certificate chain
 0 s:C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
   i:C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
   a:PKEY: id-ecPublicKey, 256 (bit); sigalg: ecdsa-with-SHA256
   v:NotBefore: Feb  9 14:49:57 2025 GMT; NotAfter: Feb  9 14:49:57 2026 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIICCDCCAa2gAwIBAgIUQU32y8p+QiHuBqaIAnmk4MBIiJIwCgYIKoZIzj0EAwIw
WTELMAkGA1UEBhMCS1IxCzAJBgNVBAgMAkdHMQswCQYDVQQHDAJZSTENMAsGA1UE
CgwEVGVzdDENMAsGA1UECwwEVGVzdDESMBAGA1UEAwwJVGVzdCBSb290MB4XDTI1
MDIwOTE0NDk1N1oXDTI2MDIwOTE0NDk1N1owWTELMAkGA1UEBhMCS1IxCzAJBgNV
BAgMAkdHMQswCQYDVQQHDAJZSTENMAsGA1UECgwEVGVzdDENMAsGA1UECwwEVGVz
dDESMBAGA1UEAwwJVGVzdCBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
Vq/Ay3tXjpfzSgYtpZHKX6wqaiTy8RbCt5EoLD7ah8zBQBQz8cUaecwxAUrH8mI/
KHkATOFso8yQI6iWwXM/BKNTMFEwHQYDVR0OBBYEFAPgq+Qo3ucvc+nhX15HDbZf
6CT/MB8GA1UdIwQYMBaAFAPgq+Qo3ucvc+nhX15HDbZf6CT/MA8GA1UdEwEB/wQF
MAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAJNsH3n2e44huP8AkZsByQ1mRqJyRMKk
jf5OEkHYegeUAiEA+7yphg7rxaZ0OF8FVCr70ld7dojX/Nbk4jtVBd841o4=
-----END CERTIFICATE-----
subject=C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
issuer=C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: ECDSA
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 980 bytes and written 292 bytes
Verification error: self-signed certificate
---
New, TLSv1.2, Cipher is ECDHE-ECDSA-AES128-GCM-SHA256
Protocol: TLSv1.2
Server public key is 256 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-ECDSA-AES128-GCM-SHA256
    Session-ID: 573475834ABC111B32770E039D5A19228B447C562722B52C4B34BB7710BDACFC
    Session-ID-ctx:
    Master-Key: 20C27D23FD3F64170B2B63917CCFE7251B792EA9492FA52B59C6ADCCC71095102E72AD1B08880A78F3F8316C1234A89B
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 60 a0 3d 87 d7 e1 a2 7f-b2 4b 57 b5 01 cc 06 ac   `.=......KW.....
    0010 - 77 7b eb 16 e1 8c 1f 76-34 b1 c1 f7 93 1d e6 3f   w{.....v4......?
    0020 - e6 02 e4 e4 1d 5e a7 34-4c 1c 1b f9 14 28 57 90   .....^.4L....(W.
    0030 - de ec 13 3b 1b 6b 5e bb-34 69 2c a7 bc 3f c3 a9   ...;.k^.4i,..?..
    0040 - 8f 1b b9 fe 28 87 22 8f-15 ff 30 20 df 6a 9d 42   ....(."...0 .j.B
    0050 - 44 70 85 21 b9 a6 f8 e8-39 3e e6 0f 4e 82 ee da   Dp.!....9>..N...
    0060 - 9d 6e 7f dd 53 f2 fa f3-e3 34 63 da 7d 44 37 0d   .n..S....4c.}D7.
    0070 - ba fe 1a 4c c1 ec a0 34-15 29 c4 7d 02 44 f1 0c   ...L...4.).}.D..
    0080 - 4d fb ee 28 f7 a2 08 6f-87 d5 be 1e 7d 0f f3 da   M..(...o....}...
    0090 - 0a 30 8a 8c db b1 17 57-c6 f8 e7 03 56 ed 92 3b   .0.....W....V..;
    00a0 - 63 1f e5 de 87 e7 64 4d-7a c8 48 e3 3d e4 9b 25   c.....dMz.H.=..%

    Start Time: 1747977329
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: yes
---
test
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 30
write to 0x21333770400 [0x21333bf9b03] (35 bytes => 35 (0x23))
0000 - 17 03 03 00 1e f1 b1 d2-e2 78 b9 f2 35 09 38 1f   .........x..5.8.
0010 - 19 29 04 b3 fe 1a 05 2a-2e ce d8 05 84 04 10 e3   .).....*........
0020 - b9 75 44                                          .uD
Q
DONE
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Alert (21)
  Length = 26
write to 0x21333770400 [0x21333bf9b03] (31 bytes => 31 (0x1F))
0000 - 15 03 03 00 1a f1 b1 d2-e2 78 b9 f2 36 cf b1 9b   .........x..6...
0010 - ea 4b f4 47 e8 c7 cc 93-fd 64 d5 dd 2d 63 cc      .K.G.....d..-c.
    Level=warning(1), description=close notify(0)

SSL3 alert write:warning:close notify
read from 0x21333770400 [0x213336b7fc0] (16384 bytes => 31 (0x1F))
0000 - 15 03 03 00 1a a8 89 ac-79 78 9b 9a 84 71 05 60   ........yx...q.`
0010 - 9e 34 20 56 86 ca a8 df-f0 d2 6b 74 40 3a 07      .4 V......kt@:.
read from 0x21333770400 [0x213336b7fc0] (16384 bytes => 0)
````

[TOC](README.md)
