#### client

````
$ openssl s_client -connect localhost:9000 -state -debug -trace -keylogfile sslkeylog -tls1_2 -ciphersuites TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
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
        gmt_unix_time=0x19587698
        random_bytes (len=28): 676B7FE86D78564051C0C44D0D8123939567DAFBC01BBF8F78B323C0
      session_id (len=0):
      cipher_suites (len=56)
        {0xCC, 0xA9} TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
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

write to 0x292ea303550 [0x292ea713280] (199 bytes => 199 (0xC7))
0000 - 16 03 01 00 c2 01 00 00-be 03 03 19 58 76 98 67   ............Xv.g
0010 - 6b 7f e8 6d 78 56 40 51-c0 c4 4d 0d 81 23 93 95   k..mxV@Q..M..#..
0020 - 67 da fb c0 1b bf 8f 78-b3 23 c0 00 00 38 cc a9   g......x.#...8..
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
read from 0x292ea303550 [0x292ea718353] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 41                                    ....A
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 65
read from 0x292ea303550 [0x292ea718358] (65 bytes => 65 (0x41))
0000 - 02 00 00 3d 03 03 55 fb-6e 5d be 1f 6e c9 7a 7e   ...=..U.n]..n.z~
0010 - 30 a6 d2 28 ab c6 70 79-3a d3 f6 e5 bb a6 44 4f   0..(..py:.....DO
0020 - 57 4e 47 52 44 01 00 cc-a9 00 00 15 ff 01 00 01   WNGRD...........
0030 - 00 00 0b 00 04 03 00 01-02 00 23 00 00 00 17 00   ..........#.....
0040 - 00                                                .
SSL_connect:SSLv3/TLS write client hello
    ServerHello, Length=61
      server_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0x55FB6E5D
        random_bytes (len=28): BE1F6EC97A7E30A6D228ABC670793AD3F6E5BBA6444F574E47524401
      session_id (len=0):
      cipher_suite {0xCC, 0xA9} TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
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
read from 0x292ea303550 [0x292ea718353] (5 bytes => 5 (0x5))
0000 - 16 03 03 02 16                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 534
read from 0x292ea303550 [0x292ea718358] (534 bytes => 534 (0x216))
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
read from 0x292ea303550 [0x292ea718353] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 73                                    ....s
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 115
read from 0x292ea303550 [0x292ea718358] (115 bytes => 115 (0x73))
0000 - 0c 00 00 6f 03 00 1d 20-29 16 0d e3 5b 2e de ae   ...o... )...[...
0010 - a7 9a 72 0f 5e 74 fc 60-5e ce a7 df dc 82 83 79   ..r.^t.`^......y
0020 - b3 9b 1a da b9 dc 8f 75-04 03 00 47 30 45 02 20   .......u...G0E.
0030 - 22 c8 c3 7e e3 ce e2 56-14 96 78 53 45 b1 57 5a   "..~...V..xSE.WZ
0040 - 94 ba 48 4c fd fa a3 b6-de bf d4 04 6e 52 6d 50   ..HL........nRmP
0050 - 02 21 00 9e 97 b0 aa 31-9d 5b 3a 0c d9 b6 f8 88   .!.....1.[:.....
0060 - 76 43 73 b5 7b 8d 8c 67-5e 31 76 08 71 90 c9 95   vCs.{..g^1v.q...
0070 - 52 1a 8f                                          R..
SSL_connect:SSLv3/TLS read server certificate
    ServerKeyExchange, Length=111
      KeyExchangeAlgorithm=ECDHE
        named_curve: ecdh_x25519 (29)
        point (len=32): 29160DE35B2EDEAEA79A720F5E74FC605ECEA7DFDC828379B39B1ADAB9DC8F75
      Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
      Signature (len=71): 3045022022C8C37EE3CEE2561496785345B1575A94BA484CFDFAA3B6DEBFD4046E526D500221009E97B0AA319D5B3A0CD9B6F888764373B57B8D8C675E3176087190C995521A8F

read from 0x292ea303550 [0x292ea718353] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 04                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 4
read from 0x292ea303550 [0x292ea718358] (4 bytes => 4 (0x4))
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
        ecdh_Yc (len=32): BF37A93EA7D9C5DE95F2C378A0E19AE5B750F42E01086F94E5341BD10A823365

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
  Length = 32
    Finished, Length=12
      verify_data (len=12): 06D57E2441096BD4DD68343F

write to 0x292ea303550 [0x292ea713280] (85 bytes => 85 (0x55))
0000 - 16 03 03 00 25 10 00 00-21 20 bf 37 a9 3e a7 d9   ....%...! .7.>..
0010 - c5 de 95 f2 c3 78 a0 e1-9a e5 b7 50 f4 2e 01 08   .....x.....P....
0020 - 6f 94 e5 34 1b d1 0a 82-33 65 14 03 03 00 01 01   o..4....3e......
0030 - 16 03 03 00 20 be f5 78-ab c8 59 33 50 3c cf 80   .... ..x..Y3P<..
0040 - 07 91 fe 3c 78 e2 af 2c-60 e7 f4 4b c7 ea 33 21   ...<x..,`..K..3!
0050 - c5 9d f9 02 36                                    ....6
SSL_connect:SSLv3/TLS write finished
read from 0x292ea303550 [0x292ea718353] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 ba                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 186
read from 0x292ea303550 [0x292ea718358] (186 bytes => 186 (0xBA))
0000 - 04 00 00 b6 00 00 1c 20-00 b0 45 da bd 56 b9 c1   ....... ..E..V..
0010 - 0c 6d c1 e2 5a 87 8c ad-ae 6d 0a 2e 89 89 d1 7e   .m..Z....m.....~
0020 - d8 ce ed b4 ae 88 e4 35-62 34 bf ea 39 2c bd 82   .......5b4..9,..
0030 - 80 0a 19 3a 3f 58 db f8-16 06 2e 7d 6d c3 a1 b8   ...:?X.....}m...
0040 - 43 c7 ca 44 01 0f f3 60-1b 69 d2 fb b8 e5 1f 8e   C..D...`.i......
0050 - 8c 7d b9 39 b4 5b 9a eb-14 68 78 50 c8 ea 8e d4   .}.9.[...hxP....
0060 - 5b 38 2c 5b d7 46 ae 53-6c 5a 73 b9 4d 15 24 70   [8,[.F.SlZs.M.$p
0070 - a2 e5 fb db 48 4e 3a dc-0d bf 84 f8 67 32 66 6b   ....HN:.....g2fk
0080 - ba 42 99 6a 22 1b 74 ed-0d 95 d8 b6 ac af 8d a1   .B.j".t.........
0090 - 32 8e 39 46 21 2e 3b ec-09 bc 1b 8a 7b 10 ea 71   2.9F!.;.....{..q
00a0 - 9e ac a9 20 27 78 9b 93-99 78 fb a5 7d 9a 03 39   ... 'x...x..}..9
00b0 - 37 67 cd 26 a5 8d 17 c9-37 07                     7g.&....7.
SSL_connect:SSLv3/TLS write finished
    NewSessionTicket, Length=182
        ticket_lifetime_hint=7200
        ticket (len=176): 45DABD56B9C10C6DC1E25A878CADAE6D0A2E8989D17ED8CEEDB4AE88E4356234BFEA392CBD82800A193A3F58DBF816062E7D6DC3A1B843C7CA44010FF3601B69D2FBB8E51F8E8C7DB939B45B9AEB14687850C8EA8ED45B382C5BD746AE536C5A73B94D152470A2E5FBDB484E3ADC0DBF84F86732666BBA42996A221B74ED0D95D8B6ACAF8DA1328E3946212E3BEC09BC1B8A7B10EA719EACA92027789B939978FBA57D9A03393767CD26A58D17C93707

read from 0x292ea303550 [0x292ea718353] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ChangeCipherSpec (20)
  Length = 1
read from 0x292ea303550 [0x292ea718358] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_connect:SSLv3/TLS read server session ticket
read from 0x292ea303550 [0x292ea718353] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 20                                    ....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 32
read from 0x292ea303550 [0x292ea718358] (32 bytes => 32 (0x20))
0000 - fc 96 42 59 c2 1b ce 2a-85 75 b5 a8 ce a0 c5 71   ..BY...*.u.....q
0010 - ec 99 dd 73 47 b4 15 2a-1c 2e f7 c3 7d 34 5e 64   ...sG..*....}4^d
SSL_connect:SSLv3/TLS read change cipher spec
    Finished, Length=12
      verify_data (len=12): 1416A0981F02D6CD6B0B84B1

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
SSL handshake has read 972 bytes and written 284 bytes
Verification error: self-signed certificate
---
New, TLSv1.2, Cipher is ECDHE-ECDSA-CHACHA20-POLY1305
Protocol: TLSv1.2
Server public key is 256 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-ECDSA-CHACHA20-POLY1305
    Session-ID: C044C116BC02E83C6DBCCC445BA8FD64CEE2F484A72595544F3B6EB1A7D7ED70
    Session-ID-ctx:
    Master-Key: 6525943D87978A14A4553A956B6F71501D0CBFD97AA856CE69B9ACA4A7B5C1209D663B389778393170E9E4C068E51843
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 45 da bd 56 b9 c1 0c 6d-c1 e2 5a 87 8c ad ae 6d   E..V...m..Z....m
    0010 - 0a 2e 89 89 d1 7e d8 ce-ed b4 ae 88 e4 35 62 34   .....~.......5b4
    0020 - bf ea 39 2c bd 82 80 0a-19 3a 3f 58 db f8 16 06   ..9,.....:?X....
    0030 - 2e 7d 6d c3 a1 b8 43 c7-ca 44 01 0f f3 60 1b 69   .}m...C..D...`.i
    0040 - d2 fb b8 e5 1f 8e 8c 7d-b9 39 b4 5b 9a eb 14 68   .......}.9.[...h
    0050 - 78 50 c8 ea 8e d4 5b 38-2c 5b d7 46 ae 53 6c 5a   xP....[8,[.F.SlZ
    0060 - 73 b9 4d 15 24 70 a2 e5-fb db 48 4e 3a dc 0d bf   s.M.$p....HN:...
    0070 - 84 f8 67 32 66 6b ba 42-99 6a 22 1b 74 ed 0d 95   ..g2fk.B.j".t...
    0080 - d8 b6 ac af 8d a1 32 8e-39 46 21 2e 3b ec 09 bc   ......2.9F!.;...
    0090 - 1b 8a 7b 10 ea 71 9e ac-a9 20 27 78 9b 93 99 78   ..{..q... 'x...x
    00a0 - fb a5 7d 9a 03 39 37 67-cd 26 a5 8d 17 c9 37 07   ..}..97g.&....7.

    Start Time: 1749007918
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: yes
---
test
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 22
write to 0x292ea303550 [0x292ea714293] (27 bytes => 27 (0x1B))
0000 - 17 03 03 00 16 ef 2f cc-c0 67 46 6d 26 cd 29 b4   ....../..gFm&.).
0010 - 97 58 92 b8 44 3c 4c d3-e3 58 44                  .X..D<L..XD
Q
DONE
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Alert (21)
  Length = 18
write to 0x292ea303550 [0x292ea714293] (23 bytes => 23 (0x17))
0000 - 15 03 03 00 12 fd 7c 83-2c fd ef 75 ff f5 3d 95   ......|.,..u..=.
0010 - 17 a8 3b dc 38 72 81                              ..;.8r.
    Level=warning(1), description=close notify(0)

SSL3 alert write:warning:close notify
read from 0x292ea303550 [0x292ea247fe0] (16384 bytes => 23 (0x17))
0000 - 15 03 03 00 12 14 d9 a3-06 be 23 39 a4 40 fa a8   ..........#9.@..
0010 - 5a 20 a8 83 78 bc 01                              Z ..x..
read from 0x292ea303550 [0x292ea247fe0] (16384 bytes => 0)
````

[TOC](README.md)
