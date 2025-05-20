#### client


````
$ openssl s_client -connect localhost:9000 -state -debug -trace -keylogfile sslkeylog -tls1_2
Connecting to ::1
CONNECTED(000001DC)
SSL_connect:before SSL initialization
Sent TLS Record
Header:
  Version = TLS 1.0 (0x301)
  Content Type = Handshake (22)
  Length = 192
    ClientHello, Length=188
      client_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0x96C6C35F
        random_bytes (len=28): F6E90ACA1305DD42EA2FBE50FCDABB5600CFE24697B2F01FBF236253
      session_id (len=0):
      cipher_suites (len=54)
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

write to 0x232a2af5720 [0x232a2b0e210] (197 bytes => 197 (0xC5))
0000 - 16 03 01 00 c0 01 00 00-bc 03 03 96 c6 c3 5f f6   .............._.
0010 - e9 0a ca 13 05 dd 42 ea-2f be 50 fc da bb 56 00   ......B./.P...V.
0020 - cf e2 46 97 b2 f0 1f bf-23 62 53 00 00 36 c0 2c   ..F.....#bS..6.,
0030 - c0 30 00 9f cc a9 cc a8-cc aa c0 2b c0 2f 00 9e   .0.........+./..
0040 - c0 24 c0 28 00 6b c0 23-c0 27 00 67 c0 0a c0 14   .$.(.k.#.'.g....
0050 - 00 39 c0 09 c0 13 00 33-00 9d 00 9c 00 3d 00 3c   .9.....3.....=.<
0060 - 00 35 00 2f 01 00 00 5d-ff 01 00 01 00 00 0b 00   .5./...]........
0070 - 04 03 00 01 02 00 0a 00-0c 00 0a 00 1d 00 17 00   ................
0080 - 1e 00 19 00 18 00 23 00-00 00 16 00 00 00 17 00   ......#.........
0090 - 00 00 0d 00 30 00 2e 04-03 05 03 06 03 08 07 08   ....0...........
00a0 - 08 08 1a 08 1b 08 1c 08-09 08 0a 08 0b 08 04 08   ................
00b0 - 05 08 06 04 01 05 01 06-01 03 03 03 01 03 02 04   ................
00c0 - 02 05 02 06 02                                    .....
SSL_connect:SSLv3/TLS write client hello
read from 0x232a2af5720 [0x232a2b132e3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 41                                    ....A
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 65
read from 0x232a2af5720 [0x232a2b132e8] (65 bytes => 65 (0x41))
0000 - 02 00 00 3d 03 03 3b 6a-ca b1 3f 5a 35 32 2b f2   ...=..;j..?Z52+.
0010 - df 69 77 0a 24 8c ff 91-44 cd 35 5b b5 b4 44 4f   .iw.$...D.5[..DO
0020 - 57 4e 47 52 44 01 00 c0-2c 00 00 15 ff 01 00 01   WNGRD...,.......
0030 - 00 00 0b 00 04 03 00 01-02 00 23 00 00 00 17 00   ..........#.....
0040 - 00                                                .
SSL_connect:SSLv3/TLS write client hello
    ServerHello, Length=61
      server_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0x3B6ACAB1
        random_bytes (len=28): 3F5A35322BF2DF69770A248CFF9144CD355BB5B4444F574E47524401
      session_id (len=0):
      cipher_suite {0xC0, 0x2C} TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
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
read from 0x232a2af5720 [0x232a2b132e3] (5 bytes => 5 (0x5))
0000 - 16 03 03 02 16                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 534
read from 0x232a2af5720 [0x232a2b132e8] (534 bytes => 534 (0x216))
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
read from 0x232a2af5720 [0x232a2b132e3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 72                                    ....r
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 114
read from 0x232a2af5720 [0x232a2b132e8] (114 bytes => 114 (0x72))
0000 - 0c 00 00 6e 03 00 1d 20-f0 d2 20 2c c0 73 90 62   ...n... .. ,.s.b
0010 - d8 d7 aa d7 c4 24 81 11-22 6e 49 a1 40 8d 59 40   .....$.."nI.@.Y@
0020 - a0 48 53 b1 8b a6 3d 36-04 03 00 46 30 44 02 20   .HS...=6...F0D.
0030 - 29 02 00 65 0b c7 2a 8e-d8 d3 06 7e e4 09 b2 20   )..e..*....~...
0040 - 75 d5 e1 b5 75 4a 28 8e-71 75 a5 b3 01 5e ee 46   u...uJ(.qu...^.F
0050 - 02 20 49 c2 b4 e0 a0 3b-c1 aa d0 61 33 03 7c 2a   . I....;...a3.|*
0060 - c2 f3 9f 27 40 48 d7 dd-f3 53 a9 f1 af 5f 91 f9   ...'@H...S..._..
0070 - 6b ff                                             k.
SSL_connect:SSLv3/TLS read server certificate
    ServerKeyExchange, Length=110
      KeyExchangeAlgorithm=ECDHE
        named_curve: ecdh_x25519 (29)
        point (len=32): F0D2202CC0739062D8D7AAD7C4248111226E49A1408D5940A04853B18BA63D36
      Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
      Signature (len=70): 30440220290200650BC72A8ED8D3067EE409B22075D5E1B5754A288E7175A5B3015EEE46022049C2B4E0A03BC1AAD06133037C2AC2F39F274048D7DDF353A9F1AF5F91F96BFF

read from 0x232a2af5720 [0x232a2b132e3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 04                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 4
read from 0x232a2af5720 [0x232a2b132e8] (4 bytes => 4 (0x4))
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
        ecdh_Yc (len=32): B85712CB0422C3B05BA1EB457826C3BF8FAB6A8D7BC72F2ADFF35F2BF9EDFA75

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
      verify_data (len=12): 5036C5210E64EB0127D607FE

write to 0x232a2af5720 [0x232a2b0e210] (93 bytes => 93 (0x5D))
0000 - 16 03 03 00 25 10 00 00-21 20 b8 57 12 cb 04 22   ....%...! .W..."
0010 - c3 b0 5b a1 eb 45 78 26-c3 bf 8f ab 6a 8d 7b c7   ..[..Ex&....j.{.
0020 - 2f 2a df f3 5f 2b f9 ed-fa 75 14 03 03 00 01 01   /*.._+...u......
0030 - 16 03 03 00 28 a5 15 62-a0 74 39 c5 81 80 f6 06   ....(..b.t9.....
0040 - 53 cb b6 31 4c a7 ee 98-c1 87 bd 2e f5 6b 61 51   S..1L........kaQ
0050 - 1b 08 0e 0d e1 ee 07 68-c1 64 8e c6 f0            .......h.d...
SSL_connect:SSLv3/TLS write finished
read from 0x232a2af5720 [0x232a2b132e3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 ba                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 186
read from 0x232a2af5720 [0x232a2b132e8] (186 bytes => 186 (0xBA))
0000 - 04 00 00 b6 00 00 1c 20-00 b0 b8 17 08 f8 39 11   ....... ......9.
0010 - 12 e7 c9 63 e3 af fb b4-79 2f 15 78 8b 2e 82 e9   ...c....y/.x....
0020 - 18 fe 3c 4a 25 3a 25 99-0f d2 c0 7d 12 82 df 11   ..<J%:%....}....
0030 - 2e 39 2a d8 a9 01 1c 71-d3 1c 8e 2a 66 c4 1a 58   .9*....q...*f..X
0040 - 78 65 ef ac fe 95 3e 6d-c8 04 f0 3a 7d 0e 27 85   xe....>m...:}.'.
0050 - 41 c3 7a 5e c8 9b d3 4b-d3 9d 14 ba 79 91 14 6e   A.z^...K....y..n
0060 - dd 20 1a a8 b2 59 11 4a-56 11 fa 4b 79 3f 51 1d   . ...Y.JV..Ky?Q.
0070 - e0 f9 73 42 33 8a 26 46-8a a0 60 af 3a 2b b2 41   ..sB3.&F..`.:+.A
0080 - 7c 94 b2 50 3e 31 d1 b0-74 30 a2 d9 e9 f2 aa 00   |..P>1..t0......
0090 - 5a b7 c4 2a 8d 8b 60 a7-f1 eb a5 d0 d6 53 44 d1   Z..*..`......SD.
00a0 - 90 12 90 7d 19 a5 77 00-d6 bb d4 d2 f1 9b c5 77   ...}..w........w
00b0 - 87 d7 3b 4d dc 80 be b5-2b 8a                     ..;M....+.
SSL_connect:SSLv3/TLS write finished
    NewSessionTicket, Length=182
        ticket_lifetime_hint=7200
        ticket (len=176): B81708F8391112E7C963E3AFFBB4792F15788B2E82E918FE3C4A253A25990FD2C07D1282DF112E392AD8A9011C71D31C8E2A66C41A587865EFACFE953E6DC804F03A7D0E278541C37A5EC89BD34BD39D14BA7991146EDD201AA8B259114A5611FA4B793F511DE0F97342338A26468AA060AF3A2BB2417C94B2503E31D1B07430A2D9E9F2AA005AB7C42A8D8B60A7F1EBA5D0D65344D19012907D19A57700D6BBD4D2F19BC57787D73B4DDC80BEB52B8A

read from 0x232a2af5720 [0x232a2b132e3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ChangeCipherSpec (20)
  Length = 1
read from 0x232a2af5720 [0x232a2b132e8] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_connect:SSLv3/TLS read server session ticket
read from 0x232a2af5720 [0x232a2b0f223] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 28                                    ....(
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 40
read from 0x232a2af5720 [0x232a2b0f228] (40 bytes => 40 (0x28))
0000 - d1 d5 10 d4 68 62 b9 26-55 17 2b 36 c5 8c ef e2   ....hb.&U.+6....
0010 - 45 9a a1 39 79 40 43 fb-67 42 be db a6 f5 a2 1e   E..9y@C.gB......
0020 - 38 69 d6 96 6b 1a d6 e7-                          8i..k...
SSL_connect:SSLv3/TLS read change cipher spec
    Finished, Length=12
      verify_data (len=12): 9FE920579B9B2910C7983412

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
SSL handshake has read 979 bytes and written 290 bytes
Verification error: self-signed certificate
---
New, TLSv1.2, Cipher is ECDHE-ECDSA-AES256-GCM-SHA384
Protocol: TLSv1.2
Server public key is 256 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-ECDSA-AES256-GCM-SHA384
    Session-ID: 8558B130B23ECDBCE6C662B735EABA1AC115902E6367BA15A4C36FCAE33AEEC1
    Session-ID-ctx:
    Master-Key: 53AC051A523D484A8C552868E7FB7CE0A3494534B110C2D9567AEEC1071AF15B21DA3E3B123BC909A95B456BFDD3D67D
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - b8 17 08 f8 39 11 12 e7-c9 63 e3 af fb b4 79 2f   ....9....c....y/
    0010 - 15 78 8b 2e 82 e9 18 fe-3c 4a 25 3a 25 99 0f d2   .x......<J%:%...
    0020 - c0 7d 12 82 df 11 2e 39-2a d8 a9 01 1c 71 d3 1c   .}.....9*....q..
    0030 - 8e 2a 66 c4 1a 58 78 65-ef ac fe 95 3e 6d c8 04   .*f..Xxe....>m..
    0040 - f0 3a 7d 0e 27 85 41 c3-7a 5e c8 9b d3 4b d3 9d   .:}.'.A.z^...K..
    0050 - 14 ba 79 91 14 6e dd 20-1a a8 b2 59 11 4a 56 11   ..y..n. ...Y.JV.
    0060 - fa 4b 79 3f 51 1d e0 f9-73 42 33 8a 26 46 8a a0   .Ky?Q...sB3.&F..
    0070 - 60 af 3a 2b b2 41 7c 94-b2 50 3e 31 d1 b0 74 30   `.:+.A|..P>1..t0
    0080 - a2 d9 e9 f2 aa 00 5a b7-c4 2a 8d 8b 60 a7 f1 eb   ......Z..*..`...
    0090 - a5 d0 d6 53 44 d1 90 12-90 7d 19 a5 77 00 d6 bb   ...SD....}..w...
    00a0 - d4 d2 f1 9b c5 77 87 d7-3b 4d dc 80 be b5 2b 8a   .....w..;M....+.

    Start Time: 1747628311
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
write to 0x232a2af5720 [0x232a2b3c633] (35 bytes => 35 (0x23))
0000 - 17 03 03 00 1e a5 15 62-a0 74 39 c5 82 14 24 2e   .......b.t9...$.
0010 - c5 55 13 30 20 a5 7c c0-52 8f 85 f0 07 79 5e fa   .U.0 .|.R....y^.
0020 - 28 71 f3                                          (q.
Q
DONE
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Alert (21)
  Length = 26
write to 0x232a2af5720 [0x232a2b3c633] (31 bytes => 31 (0x1F))
0000 - 15 03 03 00 1a a5 15 62-a0 74 39 c5 83 e4 39 b3   .......b.t9...9.
0010 - ad 24 ae 47 24 ce 96 10-3b ba 3b e6 aa c7 9e      .$.G$...;.;....
    Level=warning(1), description=close notify(0)

SSL3 alert write:warning:close notify
read from 0x232a2af5720 [0x232a2a97160] (16384 bytes => 31 (0x1F))
0000 - 15 03 03 00 1a d1 d5 10-d4 68 62 b9 27 38 f7 9a   .........hb.'8..
0010 - 01 db 8c 1f 50 6e 81 34-ca fe 1e c9 b6 85 91      ....Pn.4.......
read from 0x232a2af5720 [0x232a2a97160] (16384 bytes => 0)
````

[TOC](README.md)
