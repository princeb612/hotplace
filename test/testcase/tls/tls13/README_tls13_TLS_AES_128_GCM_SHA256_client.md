#### client

````
openssl s_client -connect localhost:9000 -state -debug -trace -keylogfile sslkeylog -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256
Connecting to ::1
CONNECTED(000001E4)
SSL_connect:before SSL initialization
Sent TLS Record
Header:
  Version = TLS 1.0 (0x301)
  Content Type = Handshake (22)
  Length = 227
    ClientHello, Length=223
      client_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0x809E8158
        random_bytes (len=28): CE5615096911896042AFA66B1BDF63678C35ACE06618E5DA520C2DED
      session_id (len=32): F79F1A7A3FAD6E2780284F412CDF9929F02D868ED40A830EB2B8363851D8E104
      cipher_suites (len=2)
        {0x13, 0x01} TLS_AES_128_GCM_SHA256
      compression_methods (len=1)
        No Compression (0x00)
      extensions, length = 148
        extension_type=ec_point_formats(11), length=4
          uncompressed (0)
          ansiX962_compressed_prime (1)
          ansiX962_compressed_char2 (2)
        extension_type=supported_groups(10), length=22
          ecdh_x25519 (29)
          secp256r1 (P-256) (23)
          ecdh_x448 (30)
          secp521r1 (P-521) (25)
          secp384r1 (P-384) (24)
          ffdhe2048 (256)
          ffdhe3072 (257)
          ffdhe4096 (258)
          ffdhe6144 (259)
          ffdhe8192 (260)
        extension_type=session_ticket(35), length=0
        extension_type=encrypt_then_mac(22), length=0
        extension_type=extended_master_secret(23), length=0
        extension_type=signature_algorithms(13), length=36
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
        extension_type=supported_versions(43), length=3
          TLS 1.3 (772)
        extension_type=psk_key_exchange_modes(45), length=2
          psk_dhe_ke (1)
        extension_type=key_share(51), length=38
            NamedGroup: ecdh_x25519 (29)
            key_exchange:  (len=32): C6F86891CB99EB2CCC1FC2054DA26FFAEE70D36982978DA89D2B1A40A3C77A42
        extension_type=compress_certificate(27), length=3
          zlib (1)

write to 0x248965c1a70 [0x24896a05c50] (232 bytes => 232 (0xE8))
0000 - 16 03 01 00 e3 01 00 00-df 03 03 80 9e 81 58 ce   ..............X.
0010 - 56 15 09 69 11 89 60 42-af a6 6b 1b df 63 67 8c   V..i..`B..k..cg.
0020 - 35 ac e0 66 18 e5 da 52-0c 2d ed 20 f7 9f 1a 7a   5..f...R.-. ...z
0030 - 3f ad 6e 27 80 28 4f 41-2c df 99 29 f0 2d 86 8e   ?.n'.(OA,..).-..
0040 - d4 0a 83 0e b2 b8 36 38-51 d8 e1 04 00 02 13 01   ......68Q.......
0050 - 01 00 00 94 00 0b 00 04-03 00 01 02 00 0a 00 16   ................
0060 - 00 14 00 1d 00 17 00 1e-00 19 00 18 01 00 01 01   ................
0070 - 01 02 01 03 01 04 00 23-00 00 00 16 00 00 00 17   .......#........
0080 - 00 00 00 0d 00 24 00 22-04 03 05 03 06 03 08 07   .....$."........
0090 - 08 08 08 1a 08 1b 08 1c-08 09 08 0a 08 0b 08 04   ................
00a0 - 08 05 08 06 04 01 05 01-06 01 00 2b 00 03 02 03   ...........+....
00b0 - 04 00 2d 00 02 01 01 00-33 00 26 00 24 00 1d 00   ..-.....3.&.$...
00c0 - 20 c6 f8 68 91 cb 99 eb-2c cc 1f c2 05 4d a2 6f    ..h....,....M.o
00d0 - fa ee 70 d3 69 82 97 8d-a8 9d 2b 1a 40 a3 c7 7a   ..p.i.....+.@..z
00e0 - 42 00 1b 00 03 02 00 01-                          B.......
SSL_connect:SSLv3/TLS write client hello
read from 0x248965c1a70 [0x24896a0ad23] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 7a                                    ....z
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 122
read from 0x248965c1a70 [0x24896a0ad28] (122 bytes => 122 (0x7A))
0000 - 02 00 00 76 03 03 1a ec-8f 05 c3 3b 74 5e 02 80   ...v.......;t^..
0010 - 08 53 a1 1a b9 28 a4 5f-26 0a 57 2f 6a f6 a6 da   .S...(._&.W/j...
0020 - 41 76 62 8e 59 59 20 f7-9f 1a 7a 3f ad 6e 27 80   Avb.YY ...z?.n'.
0030 - 28 4f 41 2c df 99 29 f0-2d 86 8e d4 0a 83 0e b2   (OA,..).-.......
0040 - b8 36 38 51 d8 e1 04 13-01 00 00 2e 00 2b 00 02   .68Q.........+..
0050 - 03 04 00 33 00 24 00 1d-00 20 11 53 8f 59 ea 97   ...3.$... .S.Y..
0060 - 5f 73 69 7e 93 b8 de 74-00 30 b5 1e a3 1e f6 7a   _si~...t.0.....z
0070 - fa db 43 55 8e 7f 93 2d-8f 37                     ..CU...-.7
SSL_connect:SSLv3/TLS write client hello
    ServerHello, Length=118
      server_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0x1AEC8F05
        random_bytes (len=28): C33B745E02800853A11AB928A45F260A572F6AF6A6DA4176628E5959
      session_id (len=32): F79F1A7A3FAD6E2780284F412CDF9929F02D868ED40A830EB2B8363851D8E104
      cipher_suite {0x13, 0x01} TLS_AES_128_GCM_SHA256
      compression_method: No Compression (0x00)
      extensions, length = 46
        extension_type=supported_versions(43), length=2
            TLS 1.3 (772)
        extension_type=key_share(51), length=36
            NamedGroup: ecdh_x25519 (29)
            key_exchange:  (len=32): 11538F59EA975F73697E93B8DE740030B51EA31EF67AFADB43558E7F932D8F37

read from 0x248965c1a70 [0x24896a0ad23] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ChangeCipherSpec (20)
  Length = 1
read from 0x248965c1a70 [0x24896a0ad28] (1 bytes => 1 (0x1))
0000 - 01                                                .
    change_cipher_spec (1)

read from 0x248965c1a70 [0x24896a0ad23] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 23
read from 0x248965c1a70 [0x24896a0ad28] (23 bytes => 23 (0x17))
0000 - f5 e2 92 8c 6c ae 19 63-88 fa 9d 36 f6 e8 4a 7b   ....l..c...6..J{
0010 - 6f 7d a1 64 51 48 39                              o}.dQH9
  Inner Content Type = Handshake (22)
SSL_connect:SSLv3/TLS read server hello
    EncryptedExtensions, Length=2
      No extensions

Can't use SSL_get_servername
read from 0x248965c1a70 [0x24896a0ad23] (5 bytes => 5 (0x5))
0000 - 17 03 03 02 2a                                    ....*
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 554
read from 0x248965c1a70 [0x24896a0ad28] (554 bytes => 554 (0x22A))
0000 - a9 68 4b bb 75 b7 76 c9-b7 ba 8a d6 a9 c5 42 f8   .hK.u.v.......B.
0010 - 26 8f 97 fe c2 a9 a2 ec-4d 5e 7d 71 73 03 84 a2   &.......M^}qs...
0020 - 31 87 b4 39 11 d6 29 37-4b b0 c0 22 30 1a 1f 85   1..9..)7K.."0...
0030 - 98 9c 71 86 57 8f 0a 38-01 f3 38 96 92 9c 3b d0   ..q.W..8..8...;.
0040 - da 6b dd 4f 7c 57 ad cf-60 9e 95 fe af b8 60 7d   .k.O|W..`.....`}
0050 - 89 25 6d 1f ba fa 82 7e-f5 f8 55 e4 72 21 ff fd   .%m....~..U.r!..
0060 - 38 4f b2 a0 2d 37 ad 5a-cd 19 e2 a7 be ce d5 76   8O..-7.Z.......v
0070 - ee c8 e1 83 7f c0 6c 45-d7 52 9a 7a 0f ab 8b 7f   ......lE.R.z....
0080 - e4 0b 34 32 29 60 6f 02-6c f3 62 00 9e c0 75 84   ..42)`o.l.b...u.
0090 - ca 4b 61 02 3c 40 b3 65-10 49 f4 26 93 29 16 2e   .Ka.<@.e.I.&.)..
00a0 - 63 93 01 3c bc 70 f4 b0-fa 22 42 6c 9f 9a 33 ad   c..<.p..."Bl..3.
00b0 - b9 4e 91 42 2d 96 6b 6a-47 62 06 30 8e 4f da 12   .N.B-.kjGb.0.O..
00c0 - 7b f1 11 6d 34 78 52 4b-db 09 d7 f0 39 52 fb eb   {..m4xRK....9R..
00d0 - 3d 65 ab a7 0f cf fc 6f-7d 50 db 5f 5d 18 a8 c5   =e.....o}P._]...
00e0 - d9 db 38 74 81 9d 4c b6-11 c2 57 98 31 42 ff 2f   ..8t..L...W.1B./
00f0 - ce d3 ca 16 4b fe f1 40-ae bd 0f bb 56 72 01 3c   ....K..@....Vr.<
0100 - 30 96 89 40 99 50 67 2b-9a 64 e9 87 36 cc 1c ee   0..@.Pg+.d..6...
0110 - 13 87 ff fd f5 b0 40 9b-78 82 ae c0 86 20 60 14   ......@.x.... `.
0120 - 16 ef 3a 83 35 f1 8c 7b-1a bc ce c8 ce 54 e9 81   ..:.5..{.....T..
0130 - 2e 4a 87 0f 4e a0 24 c5-11 bd c9 b6 f4 61 4a be   .J..N.$......aJ.
0140 - 00 2e ff 8b 3f db 46 8e-fb 5e b0 4a 59 2a 92 42   ....?.F..^.JY*.B
0150 - a5 c3 92 01 16 ad 76 a9-13 9a c0 4e 44 49 20 24   ......v....NDI $
0160 - e6 25 89 c9 78 08 db e0-ff 6f 43 5e 44 bc 3b a9   .%..x....oC^D.;.
0170 - f8 94 2d 60 da 95 36 24-7c cc 0d e2 1a 79 90 f6   ..-`..6$|....y..
0180 - bc 66 79 1b 1a 28 fc 66-8c 46 29 4e aa 6a a3 eb   .fy..(.f.F)N.j..
0190 - 28 d9 b3 7a 3a 92 03 53-a7 bb b9 26 e4 dc 0c 91   (..z:..S...&....
01a0 - 42 ac b3 d4 44 52 be c8-b1 d4 ce 5a 95 64 f7 cb   B...DR.....Z.d..
01b0 - 0a 6c 8e 7c 88 a1 f6 ef-58 d1 08 40 a9 5b b7 c9   .l.|....X..@.[..
01c0 - ad 8e b3 9a 53 b5 62 07-17 90 fa aa ff cb a7 b3   ....S.b.........
01d0 - ad bf 4d e2 a1 5f fb 4a-79 96 a7 3c 88 7c 8b 15   ..M.._.Jy..<.|..
01e0 - 57 20 ce 8a aa 74 02 c7-0c 5c 3b 99 45 89 b8 00   W ...t...\;.E...
01f0 - 08 a3 79 ae e9 96 54 80-41 e9 fe 30 88 9e af 1f   ..y...T.A..0....
0200 - 6c 23 f5 1d 1a 2f 3f e2-db eb ef b9 7d 19 3c b8   l#.../?.....}.<.
0210 - d2 5c 59 4c 00 2b b6 6a-0a b4 de e3 72 07 7f d1   .\YL.+.j....r...
0220 - f2 54 7f 60 ce 77 7e f5-43 c5                     .T.`.w~.C.
  Inner Content Type = Handshake (22)
SSL_connect:TLSv1.3 read encrypted extensions
    Certificate, Length=533
      context (len=0):
      certificate_list, length=529
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
        No extensions

depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
verify error:num=18:self-signed certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
verify return:1
read from 0x248965c1a70 [0x24896a0ad23] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 60                                    ....`
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 96
read from 0x248965c1a70 [0x24896a0ad28] (96 bytes => 96 (0x60))
0000 - 23 bc f5 d4 62 52 b5 11-0b 96 2a 93 87 02 e4 94   #...bR....*.....
0010 - 62 35 20 9b a5 c7 87 3d-54 fc e0 f2 74 a8 ec b4   b5 ....=T...t...
0020 - 98 0e 04 24 7c 47 b0 4f-40 65 b0 40 86 52 84 12   ...$|G.O@e.@.R..
0030 - df 8e 3e f0 4e 6d 7c 9a-bb 5b a1 93 ed 8d 02 45   ..>.Nm|..[.....E
0040 - 3d 16 3b 74 53 a0 db 05-2b bb 21 94 23 0d 84 35   =.;tS...+.!.#..5
0050 - c3 d6 ea 82 59 7d 30 53-cf 29 aa 8e 29 b4 d3 c1   ....Y}0S.)..)...
  Inner Content Type = Handshake (22)
SSL_connect:SSLv3/TLS read server certificate
    CertificateVerify, Length=75
      Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
      Signature (len=71): 3045022100C1DC3BA406C6305FF865B5369B0B438B38BAF4C7B9B5E193BB0B520703579451022076055530CCD5FB2892673A1D627A2987F335F4103063A9262A2105462FC6607D

read from 0x248965c1a70 [0x24896a0ad23] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 53
read from 0x248965c1a70 [0x24896a0ad28] (53 bytes => 53 (0x35))
0000 - 64 46 bb 8b f1 80 d7 a7-b0 08 ae 1d 4a 60 18 a2   dF..........J`..
0010 - 6e 3f c2 a3 ea d1 b3 02-19 b9 72 5b 69 7b c3 c6   n?........r[i{..
0020 - fd ab 83 cd 6c 52 eb 0c-08 80 3e e5 90 26 80 66   ....lR....>..&.f
0030 - a7 2f 98 5d 7e                                    ./.]~
  Inner Content Type = Handshake (22)
SSL_connect:TLSv1.3 read server certificate verify
    Finished, Length=32
      verify_data (len=32): 22F83216F641981F8CA03A04D568D482CEFEB9CC375EB448E3E8D6872B861596

SSL_connect:SSLv3/TLS read finished
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
  Content Type = ApplicationData (23)
  Length = 53
  Inner Content Type = Handshake (22)
    Finished, Length=32
      verify_data (len=32): 726F72307037961CC3C9937E72DB3D7EB38C0FFF3D86864BA0B481F81D0B9FA6

write to 0x248965c1a70 [0x24896a05c50] (64 bytes => 64 (0x40))
0000 - 14 03 03 00 01 01 17 03-03 00 35 51 11 89 9e 96   ..........5Q....
0010 - 36 37 43 e2 6c 51 36 59-79 87 1c cf 33 83 5e 01   67C.lQ6Yy...3.^.
0020 - d8 9d fe 33 d8 0d 91 a7-b3 16 f1 b0 35 5f c3 f2   ...3........5_..
0030 - 58 33 b9 27 94 a8 03 f2-08 57 97 b6 48 c3 7c ac   X3.'.....W..H.|.
SSL_connect:SSLv3/TLS write finished
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
SSL handshake has read 879 bytes and written 296 bytes
Verification error: self-signed certificate
---
New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256
Protocol: TLSv1.3
Server public key is 256 bit
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 18 (self-signed certificate)
---
read from 0x248965c1a70 [0x248969ff593] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 234
read from 0x248965c1a70 [0x248969ff598] (234 bytes => 234 (0xEA))
0000 - 37 46 36 b1 0b 9a ee d9-8a 7c d8 76 96 49 6d d5   7F6......|.v.Im.
0010 - 4d 30 7c 77 f4 e9 0d 2e-64 4f 93 3d 28 0a 5f fb   M0|w....dO.=(._.
0020 - 6b e9 76 12 0e bd ec b8-b3 f7 62 cd 63 3d eb bb   k.v.......b.c=..
0030 - fd b9 9d e1 db 53 cd 07-0c f8 4a e9 98 3d fa 2a   .....S....J..=.*
0040 - b8 90 73 7d bd 21 d2 b1-ca 33 8d 12 0d 08 40 23   ..s}.!...3....@#
0050 - fa e0 e2 21 9f b8 b8 29-1f 17 4f f6 bc a1 8d c1   ...!...)..O.....
0060 - 41 fc 10 da 5d 82 f5 f4-88 42 76 d2 ab 2a bc e1   A...]....Bv..*..
0070 - 2c 3f 5a 2a a1 1e 8d a6-08 28 ab fd c3 b7 17 06   ,?Z*.....(......
0080 - 7f b9 d0 97 13 d5 82 c9-37 c8 dd 6b 48 56 52 11   ........7..kHVR.
0090 - 30 b7 9d 80 8d 9f 29 e3-6d 61 98 65 03 b3 f7 ec   0.....).ma.e....
00a0 - 6e df 48 48 79 d3 2f a7-a9 51 d9 64 91 af 96 0d   n.HHy./..Q.d....
00b0 - 68 d7 77 d6 f4 93 69 1c-e9 d1 ab 76 bd 3c 96 95   h.w...i....v.<..
00c0 - f0 62 d2 db ac 14 0d ce-89 f4 04 ab 75 74 e9 b3   .b..........ut..
00d0 - ef fd 37 ac ff 7c 72 7b-b4 e8 ad 90 a8 b9 9d 03   ..7..|r{........
00e0 - 5d 61 29 e2 8b 0d 2d 10-33 08                     ]a)...-.3.
  Inner Content Type = Handshake (22)
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
    NewSessionTicket, Length=213
        ticket_lifetime_hint=7200
        ticket_age_add=510646069
        ticket_nonce (len=8): 0000000000000000
        ticket (len=192): 3B96A1CE0960F70B7AA9E4E9A56B32144CB34A4519ED2A64597290D54963274933F61D2BB061BDFA27352A973D82E7EEF70F568C785F4B2B65AEA83EE987204566BE5C9FBB059F89A627428BBCFB5F392C8EDB65BCF542180C17C429BFCF7100988C9C1356321C99FF2FC08FBF2DCE5AA2D9E7B5C969A3DFE79468B8F62D8882AD93D0B0F249944DC28C548B64E31CFB4EE3F41C531B34AEADAC5A41D2CC8CDED57ACAA242FB55156A6BDBADF9BBB3E303AFB02BEDCFBF46BADB300EE73462B4
        No extensions

---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_GCM_SHA256
    Session-ID: 241A5E3161C80D109D0DA568A16973693029F7BD8BB9DE3AA2DBC4938B77BDEF
    Session-ID-ctx:
    Resumption PSK: 90146E472CF5C61A4B4A8B453F87B0C0DA4CB817C8A61733644566AC5857FA5D
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 3b 96 a1 ce 09 60 f7 0b-7a a9 e4 e9 a5 6b 32 14   ;....`..z....k2.
    0010 - 4c b3 4a 45 19 ed 2a 64-59 72 90 d5 49 63 27 49   L.JE..*dYr..Ic'I
    0020 - 33 f6 1d 2b b0 61 bd fa-27 35 2a 97 3d 82 e7 ee   3..+.a..'5*.=...
    0030 - f7 0f 56 8c 78 5f 4b 2b-65 ae a8 3e e9 87 20 45   ..V.x_K+e..>.. E
    0040 - 66 be 5c 9f bb 05 9f 89-a6 27 42 8b bc fb 5f 39   f.\......'B..._9
    0050 - 2c 8e db 65 bc f5 42 18-0c 17 c4 29 bf cf 71 00   ,..e..B....)..q.
    0060 - 98 8c 9c 13 56 32 1c 99-ff 2f c0 8f bf 2d ce 5a   ....V2.../...-.Z
    0070 - a2 d9 e7 b5 c9 69 a3 df-e7 94 68 b8 f6 2d 88 82   .....i....h..-..
    0080 - ad 93 d0 b0 f2 49 94 4d-c2 8c 54 8b 64 e3 1c fb   .....I.M..T.d...
    0090 - 4e e3 f4 1c 53 1b 34 ae-ad ac 5a 41 d2 cc 8c de   N...S.4...ZA....
    00a0 - d5 7a ca a2 42 fb 55 15-6a 6b db ad f9 bb b3 e3   .z..B.U.jk......
    00b0 - 03 af b0 2b ed cf bf 46-ba db 30 0e e7 34 62 b4   ...+...F..0..4b.

    Start Time: 1748412238
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
read from 0x248965c1a70 [0x248969ff593] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 234
read from 0x248965c1a70 [0x248969ff598] (234 bytes => 234 (0xEA))
0000 - 15 0d c6 fc 46 1c 65 8c-be cd 80 bc a5 30 eb b7   ....F.e......0..
0010 - c5 e6 81 b4 15 91 87 bb-66 78 82 ae cc ae da df   ........fx......
0020 - 8d ed a3 0b 5a 61 61 1e-3d 98 c9 79 d3 30 a9 e4   ....Zaa.=..y.0..
0030 - 39 d5 a1 b5 ba 66 aa 7e-8c 98 ee f1 7b 32 27 47   9....f.~....{2'G
0040 - d7 75 02 53 eb 5b 4f e7-97 e1 ca 78 15 f2 16 dc   .u.S.[O....x....
0050 - 03 ec ad 08 a4 fa 63 7c-21 bb af 3b a5 7e aa 82   ......c|!..;.~..
0060 - a6 2b 5a d6 06 9d 53 8f-9e 3a ab 1c 84 0c 61 70   .+Z...S..:....ap
0070 - f4 75 1f 53 d1 e8 11 57-87 6e 7a fe 2c dd 6a d3   .u.S...W.nz.,.j.
0080 - 67 67 a0 41 de 0b fa 95-db d8 e6 92 26 c4 9a b3   gg.A........&...
0090 - 76 6f d4 ca a1 3d cb e1-5a b2 18 69 e8 31 29 e3   vo...=..Z..i.1).
00a0 - 7a fe 69 a0 96 17 b9 77-47 6e 86 a8 d6 93 fb dc   z.i....wGn......
00b0 - 8d b3 b1 b1 37 7a 2a b8-5c 1e f4 58 44 39 2c 6b   ....7z*.\..XD9,k
00c0 - 99 c2 d1 54 57 ab d3 ec-4e 80 15 c0 c5 d9 ae e7   ...TW...N.......
00d0 - 74 83 6a 74 13 bc 60 2d-44 a8 0b f6 eb 0c 41 4f   t.jt..`-D.....AO
00e0 - f9 19 bb 52 8e d6 53 28-00 3a                     ...R..S(.:
  Inner Content Type = Handshake (22)
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
    NewSessionTicket, Length=213
        ticket_lifetime_hint=7200
        ticket_age_add=2628647140
        ticket_nonce (len=8): 0000000000000001
        ticket (len=192): 3B96A1CE0960F70B7AA9E4E9A56B3214C2B1DBB925D02BB32F916C9D46989A1FB72B4781D1517F5E6063E6F805D15C4D260F4D448283839BF58E0EDB843F515F0FDAC63702EA8574B59153425E1946B1C7006A9602E0694A4B881573881EE63F44F3A8DE23B94A5E7821941BA816D20D770237687FBFA76539AD033E7BCD87BA65DA1D2DD7429FBEC1BC247B88A0718B240AB16EE023E562C35D3F9DF90F9244B0E688800504EDF97F5418A8AADD89B8448DD839384E47C6748E4F7F3FA37F65
        No extensions

---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_GCM_SHA256
    Session-ID: 8DE4B947A027746E999BD06CCC628F0F6F39C8FDF49CD85CB59EC50E4AE358A6
    Session-ID-ctx:
    Resumption PSK: E749635CC66CFD1BB13E91C25BC28AB959ACC6B4CC497191D6419823C4190755
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 3b 96 a1 ce 09 60 f7 0b-7a a9 e4 e9 a5 6b 32 14   ;....`..z....k2.
    0010 - c2 b1 db b9 25 d0 2b b3-2f 91 6c 9d 46 98 9a 1f   ....%.+./.l.F...
    0020 - b7 2b 47 81 d1 51 7f 5e-60 63 e6 f8 05 d1 5c 4d   .+G..Q.^`c....\M
    0030 - 26 0f 4d 44 82 83 83 9b-f5 8e 0e db 84 3f 51 5f   &.MD.........?Q_
    0040 - 0f da c6 37 02 ea 85 74-b5 91 53 42 5e 19 46 b1   ...7...t..SB^.F.
    0050 - c7 00 6a 96 02 e0 69 4a-4b 88 15 73 88 1e e6 3f   ..j...iJK..s...?
    0060 - 44 f3 a8 de 23 b9 4a 5e-78 21 94 1b a8 16 d2 0d   D...#.J^x!......
    0070 - 77 02 37 68 7f bf a7 65-39 ad 03 3e 7b cd 87 ba   w.7h...e9..>{...
    0080 - 65 da 1d 2d d7 42 9f be-c1 bc 24 7b 88 a0 71 8b   e..-.B....${..q.
    0090 - 24 0a b1 6e e0 23 e5 62-c3 5d 3f 9d f9 0f 92 44   $..n.#.b.]?....D
    00a0 - b0 e6 88 80 05 04 ed f9-7f 54 18 a8 aa dd 89 b8   .........T......
    00b0 - 44 8d d8 39 38 4e 47 c6-74 8e 4f 7f 3f a3 7f 65   D..98NG.t.O.?..e

    Start Time: 1748412238
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
test
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 23
  Inner Content Type = ApplicationData (23)
write to 0x248965c1a70 [0x24896a036e3] (28 bytes => 28 (0x1C))
0000 - 17 03 03 00 17 ab a5 35-84 e5 9c 28 a4 09 23 8f   .......5...(..#.
0010 - 2e 73 9e 56 84 79 01 9f-57 75 9b 98               .s.V.y..Wu..
Q
DONE
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 19
  Inner Content Type = Alert (21)
write to 0x248965c1a70 [0x24896a036e3] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 8d 24 ce-45 63 68 f0 c4 16 60 8a   ......$.Ech...`.
0010 - 73 c2 90 5f e2 31 38 e0-                          s.._.18.
    Level=warning(1), description=close notify(0)

SSL3 alert write:warning:close notify
read from 0x248965c1a70 [0x24896507cc0] (16384 bytes => 24 (0x18))
0000 - 17 03 03 00 13 d2 f3 f4-a5 33 e5 91 3d 7a 85 9e   .........3..=z..
0010 - 5b 97 cf 7e c1 1c ba 03-                          [..~....
read from 0x248965c1a70 [0x24896507cc0] (16384 bytes => 0)
````

[TOC](README.md)
