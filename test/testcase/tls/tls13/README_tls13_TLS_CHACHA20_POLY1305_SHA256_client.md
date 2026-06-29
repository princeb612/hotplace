#### client

````
$ openssl s_client -connect localhost:9000 -state -debug -trace -keylogfile sslkeylog -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256
Connecting to ::1
CONNECTED(000001DC)
SSL_connect:before SSL initialization
Sent TLS Record
Header:
  Version = TLS 1.0 (0x301)
  Content Type = Handshake (22)
  Length = 227
    ClientHello, Length=223
      client_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0xC55D7DE4
        random_bytes (len=28): CCA2EE3F725CA027CBB30A1BF3B857F2962AA4B7BCCF3106BBC9E7B3
      session_id (len=32): CDB02B3B2B06FECC9FFC320C46E755CC51417A3084E4BD8A647853FF34376E86
      cipher_suites (len=2)
        {0x13, 0x03} TLS_CHACHA20_POLY1305_SHA256
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
            key_exchange:  (len=32): 9008FF08343CAB2B322EA0B502CAC09C34BD07303998F91F96C6EF14C5F6CF43
        extension_type=compress_certificate(27), length=3
          zlib (1)

write to 0x215ba652870 [0x215baa41c30] (232 bytes => 232 (0xE8))
0000 - 16 03 01 00 e3 01 00 00-df 03 03 c5 5d 7d e4 cc   ............]}..
0010 - a2 ee 3f 72 5c a0 27 cb-b3 0a 1b f3 b8 57 f2 96   ..?r\.'......W..
0020 - 2a a4 b7 bc cf 31 06 bb-c9 e7 b3 20 cd b0 2b 3b   *....1..... ..+;
0030 - 2b 06 fe cc 9f fc 32 0c-46 e7 55 cc 51 41 7a 30   +.....2.F.U.QAz0
0040 - 84 e4 bd 8a 64 78 53 ff-34 37 6e 86 00 02 13 03   ....dxS.47n.....
0050 - 01 00 00 94 00 0b 00 04-03 00 01 02 00 0a 00 16   ................
0060 - 00 14 00 1d 00 17 00 1e-00 19 00 18 01 00 01 01   ................
0070 - 01 02 01 03 01 04 00 23-00 00 00 16 00 00 00 17   .......#........
0080 - 00 00 00 0d 00 24 00 22-04 03 05 03 06 03 08 07   .....$."........
0090 - 08 08 08 1a 08 1b 08 1c-08 09 08 0a 08 0b 08 04   ................
00a0 - 08 05 08 06 04 01 05 01-06 01 00 2b 00 03 02 03   ...........+....
00b0 - 04 00 2d 00 02 01 01 00-33 00 26 00 24 00 1d 00   ..-.....3.&.$...
00c0 - 20 90 08 ff 08 34 3c ab-2b 32 2e a0 b5 02 ca c0    ....4<.+2......
00d0 - 9c 34 bd 07 30 39 98 f9-1f 96 c6 ef 14 c5 f6 cf   .4..09..........
00e0 - 43 00 1b 00 03 02 00 01-                          C.......
SSL_connect:SSLv3/TLS write client hello
read from 0x215ba652870 [0x215baa46d03] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 7a                                    ....z
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 122
read from 0x215ba652870 [0x215baa46d08] (122 bytes => 122 (0x7A))
0000 - 02 00 00 76 03 03 94 d9-85 bd 42 8c 53 b2 85 92   ...v......B.S...
0010 - da cd 71 d6 95 96 78 17-80 19 8e 94 d4 f0 4f cc   ..q...x.......O.
0020 - 89 62 71 5f 6a f6 20 cd-b0 2b 3b 2b 06 fe cc 9f   .bq_j. ..+;+....
0030 - fc 32 0c 46 e7 55 cc 51-41 7a 30 84 e4 bd 8a 64   .2.F.U.QAz0....d
0040 - 78 53 ff 34 37 6e 86 13-03 00 00 2e 00 2b 00 02   xS.47n.......+..
0050 - 03 04 00 33 00 24 00 1d-00 20 20 72 6f 25 f8 d7   ...3.$...  ro%..
0060 - c3 08 35 83 10 1b 81 b7-c5 4e 02 cc d4 13 1b 7d   ..5......N.....}
0070 - 16 84 8a 8c e7 25 68 94-27 50                     .....%h.'P
SSL_connect:SSLv3/TLS write client hello
    ServerHello, Length=118
      server_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0x94D985BD
        random_bytes (len=28): 428C53B28592DACD71D69596781780198E94D4F04FCC8962715F6AF6
      session_id (len=32): CDB02B3B2B06FECC9FFC320C46E755CC51417A3084E4BD8A647853FF34376E86
      cipher_suite {0x13, 0x03} TLS_CHACHA20_POLY1305_SHA256
      compression_method: No Compression (0x00)
      extensions, length = 46
        extension_type=supported_versions(43), length=2
            TLS 1.3 (772)
        extension_type=key_share(51), length=36
            NamedGroup: ecdh_x25519 (29)
            key_exchange:  (len=32): 20726F25F8D7C3083583101B81B7C54E02CCD4131B7D16848A8CE72568942750

read from 0x215ba652870 [0x215baa46d03] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ChangeCipherSpec (20)
  Length = 1
read from 0x215ba652870 [0x215baa46d08] (1 bytes => 1 (0x1))
0000 - 01                                                .
    change_cipher_spec (1)

read from 0x215ba652870 [0x215baa46d03] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 23
read from 0x215ba652870 [0x215baa46d08] (23 bytes => 23 (0x17))
0000 - 49 e7 75 95 d0 5d 20 cc-42 7d ba 15 2c ef 4d 28   I.u..] .B}..,.M(
0010 - 0b 38 93 c1 18 9d 42                              .8....B
  Inner Content Type = Handshake (22)
SSL_connect:SSLv3/TLS read server hello
    EncryptedExtensions, Length=2
      No extensions

Can't use SSL_get_servername
read from 0x215ba652870 [0x215baa46d03] (5 bytes => 5 (0x5))
0000 - 17 03 03 02 2a                                    ....*
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 554
read from 0x215ba652870 [0x215baa46d08] (554 bytes => 554 (0x22A))
0000 - e3 37 0e 36 1a 40 06 56-9c 69 b9 f8 50 3e 30 0d   .7.6.@.V.i..P>0.
0010 - ce 59 8b c5 6d fb b0 a6-72 c3 10 13 9f d4 a9 de   .Y..m...r.......
0020 - a8 44 a2 f6 bf 1a e8 5e-52 64 bd b3 f4 e1 93 8e   .D.....^Rd......
0030 - e3 52 a5 25 05 c4 b1 6d-87 94 41 0e 71 60 bb 22   .R.%...m..A.q`."
0040 - 8c a1 82 0f 5f 40 44 74-ed 2b 44 59 3b b3 7f f2   ...._@Dt.+DY;...
0050 - 23 f4 1d 86 17 96 c2 20-7a 0b 2b c8 ff 4e 0e 4d   #...... z.+..N.M
0060 - eb a0 44 dc ea f7 64 95-df d3 2e e0 b0 84 70 35   ..D...d.......p5
0070 - e6 ba 80 a5 4b 82 db 49-7c f9 57 02 3c 50 c0 05   ....K..I|.W.<P..
0080 - 22 1e 84 e8 bc 11 53 da-5c 0a 8c 36 45 b0 60 d5   ".....S.\..6E.`.
0090 - 04 2d ea bb c7 82 d5 3c-08 cc 96 b4 99 dc 7b 60   .-.....<......{`
00a0 - 37 27 37 66 19 09 a5 9d-27 d4 d8 7a 24 2c 6f 23   7'7f....'..z$,o#
00b0 - 1a 63 ab b1 c3 e3 6c 07-e4 1e 7e 9b bf 29 d5 85   .c....l...~..)..
00c0 - 91 89 4c ef 14 a3 7f 20-22 99 f5 5d f1 47 db b4   ..L.... "..].G..
00d0 - 57 e6 07 38 7e 9f de 0f-2b ec e9 d0 24 a1 a2 e2   W..8~...+...$...
00e0 - ef a2 1f df ed 0c 2d 6d-c4 a9 a5 0c 89 ce 61 bc   ......-m......a.
00f0 - 64 5e d3 2e 4d cc 5a ed-29 a9 fa d1 33 8d 1b 3f   d^..M.Z.)...3..?
0100 - 48 b4 7c 79 bf af f9 fe-71 85 6d 60 1e 0e 2f c8   H.|y....q.m`../.
0110 - 2a cd 80 d2 ec f0 86 f4-df 9e 2f 72 9b 84 13 9b   *........./r....
0120 - b1 6e 87 ae 58 f0 75 06-30 83 22 74 82 09 1b b8   .n..X.u.0."t....
0130 - 01 66 65 49 41 70 ab 9e-e8 12 08 57 f3 af 51 9c   .feIAp.....W..Q.
0140 - 56 15 c5 b3 75 00 4d 9d-e5 b3 e0 c5 b5 59 4c ea   V...u.M......YL.
0150 - 2d a8 2d 06 bf 88 3a 50-7e 5e f4 19 5e 1b 4a ce   -.-...:P~^..^.J.
0160 - a6 e9 8d f9 ed 3d e1 57-ea b0 10 a4 f9 18 94 cc   .....=.W........
0170 - 7e 65 88 f3 0d e3 cb b4-bd fb f5 d4 c5 7a 68 3f   ~e...........zh?
0180 - 22 82 30 a1 90 37 7d 9c-b5 f0 6b 4e 6f f2 c8 c9   ".0..7}...kNo...
0190 - b0 79 a3 d1 c4 05 a6 ed-e0 a5 37 93 6b da 43 a7   .y........7.k.C.
01a0 - ee c0 ed 60 32 16 0f 0c-7a d4 67 71 3c d3 68 0f   ...`2...z.gq<.h.
01b0 - f2 b6 1d d7 31 a4 87 8d-42 06 d9 38 6c a1 ec a4   ....1...B..8l...
01c0 - ab 91 3f 77 a9 67 c1 7f-c6 27 6c 5b d2 7f 53 8d   ..?w.g...'l[..S.
01d0 - c5 d8 5c 07 eb c0 a9 0d-35 59 6c 4e d7 f4 f2 0c   ..\.....5YlN....
01e0 - 2d f8 4d 1c 78 16 dc 5c-48 b6 85 f2 ff af 17 17   -.M.x..\H.......
01f0 - b1 2c 7f 08 86 bf 89 c6-a7 70 80 f1 fb d2 af 7a   .,.......p.....z
0200 - e9 09 08 b9 df f1 03 54-76 66 15 4b 9d 5b a1 61   .......Tvf.K.[.a
0210 - 8f 6c 7b 4e 63 46 55 a7-b0 0a 58 fb fb c4 c2 d5   .l{NcFU...X.....
0220 - c2 37 e2 2c bd 46 23 7f-c6 1e                     .7.,.F#...
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
read from 0x215ba652870 [0x215baa46d03] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 60                                    ....`
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 96
read from 0x215ba652870 [0x215baa46d08] (96 bytes => 96 (0x60))
0000 - cb 6b 7d 79 1e 14 47 a5-d1 78 b9 b2 59 37 83 59   .k}y..G..x..Y7.Y
0010 - 90 dc 46 8e f3 28 19 a3-cd 7b d5 25 80 39 8e f7   ..F..(...{.%.9..
0020 - dd 6a b0 9c 91 c8 6d 66-af 00 a2 76 ea 26 0d 31   .j....mf...v.&.1
0030 - e1 61 9a bd 11 f6 42 fe-9d 76 ad 7d 62 50 da 42   .a....B..v.}bP.B
0040 - fe d5 52 37 0f 67 de ec-bf e1 e1 98 ed 69 91 2f   ..R7.g.......i./
0050 - 9e 37 20 ef cd 8b 68 8c-2f e9 5b 5c 32 21 9f 2c   .7 ...h./.[\2!.,
  Inner Content Type = Handshake (22)
SSL_connect:SSLv3/TLS read server certificate
    CertificateVerify, Length=75
      Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
      Signature (len=71): 3045022031C965298F713A5499471D77F33CE11F133C23934226A5151FEB4ED20469A57F0221009823DF407AEA5085D12C8D126201083DD4A5C3A1CA10EFA4E75F96D3AA439F84

read from 0x215ba652870 [0x215baa46d03] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 53
read from 0x215ba652870 [0x215baa46d08] (53 bytes => 53 (0x35))
0000 - 86 67 ea e2 4f 8a bb 08-87 59 b8 4a 27 fc 26 51   .g..O....Y.J'.&Q
0010 - 43 ba 68 cb 94 01 13 bc-db 9a 41 4a 50 c4 26 49   C.h.......AJP.&I
0020 - fa b6 73 e6 88 d5 55 1e-3c e7 2c 10 fb fe 53 8d   ..s...U.<.,...S.
0030 - ff cd dc d4 40                                    ....@
  Inner Content Type = Handshake (22)
SSL_connect:TLSv1.3 read server certificate verify
    Finished, Length=32
      verify_data (len=32): C4AA3D1C63A3C4EA3197E2457DB792863D293CB716CFDA3AB52810F42582A97B

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
      verify_data (len=32): 59E9B55CD07B02282B5C6AF746E80243AD191CA5661A633F2360AF040BE05F8E

write to 0x215ba652870 [0x215baa41c30] (64 bytes => 64 (0x40))
0000 - 14 03 03 00 01 01 17 03-03 00 35 de 19 ea 02 75   ..........5....u
0010 - ab 10 91 7a 37 c2 77 50-9e ac 25 8a 2e 0c 72 b5   ...z7.wP..%...r.
0020 - 15 62 5c d0 db df 0d b7-c2 2c 26 73 d6 a6 10 61   .b\......,&s...a
0030 - 34 c0 ad cf 26 90 cf b4-65 c5 bf 7c af 61 9d 85   4...&...e..|.a..
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
New, TLSv1.3, Cipher is TLS_CHACHA20_POLY1305_SHA256
Protocol: TLSv1.3
Server public key is 256 bit
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 18 (self-signed certificate)
---
read from 0x215ba652870 [0x215baa3b573] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 234
read from 0x215ba652870 [0x215baa3b578] (234 bytes => 234 (0xEA))
0000 - 2e 66 ba 03 04 78 98 2f-eb 84 96 67 70 5d 2f 63   .f...x./...gp]/c
0010 - d9 cf f1 df f8 d3 8a 83-eb c6 87 f4 b2 a0 f0 b3   ................
0020 - aa b7 fe 00 68 a7 9f 53-45 20 da c6 1d e0 54 33   ....h..SE ....T3
0030 - 8e 2b 25 ee 5a d3 92 42-d3 ae 89 d3 b6 61 c6 b0   .+%.Z..B.....a..
0040 - a4 f8 36 a0 05 ef a3 d8-db 67 c6 0b bc 48 43 8b   ..6......g...HC.
0050 - 62 e4 53 e7 78 85 11 ec-ef 41 3d 32 92 32 5a 8e   b.S.x....A=2.2Z.
0060 - f9 7c 33 96 1f 8b 5f 02-f8 1c b7 ca 33 72 44 c5   .|3..._.....3rD.
0070 - 50 0f 66 d6 06 a9 bc aa-d2 b1 0b 3e 54 90 0c a8   P.f........>T...
0080 - d9 4c f9 e0 83 df 0c 23-70 5a 59 15 c7 51 50 ad   .L.....#pZY..QP.
0090 - 44 77 c3 d7 bf f6 04 d7-42 06 2f 1a 03 ca 3b cc   Dw......B./...;.
00a0 - 41 04 98 36 3c c9 f3 04-3f 95 32 3d e3 b1 11 4b   A..6<...?.2=...K
00b0 - 9e 6c 94 bf e3 a7 ea c4-61 97 d5 9c 6b 3f 06 20   .l......a...k?.
00c0 - a1 f7 0f 65 8a 3f 4b 05-f1 a4 d2 88 51 65 71 2f   ...e.?K.....Qeq/
00d0 - 7d bd ff 31 88 cc 58 a9-4c 70 08 e5 c2 21 06 3c   }..1..X.Lp...!.<
00e0 - a2 b6 09 9e 7f ad 63 78-20 70                     ......cx p
  Inner Content Type = Handshake (22)
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
    NewSessionTicket, Length=213
        ticket_lifetime_hint=7200
        ticket_age_add=3529628528
        ticket_nonce (len=8): 0000000000000000
        ticket (len=192): 01F81988D6739F74DF4A0340CA4E578E3FB2C2CE5577DDECB35D900610E120E542D0BAB626DACCF6EEE5B9AA233FF37FCDD02C887DEE9D6ABFC3BA9D53B49FDB7538353851BADB5A1B6DEBB9F63B9C5904FF0F7645B1B3C3A0A30F0646A0777201B64734749695F9E940D483FF3BC484C6B1C004AD3311301AF4470BAF0ACA37B6463A00D16E4D30E915B98E982AAF1204061458D253328D6627E3B67738F80B7A6EE30EDAF6FE5C2F1EC2489FE86B67C418F8BFA4DD3C7F5E95C9EC2F8F6A21
        No extensions

---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_CHACHA20_POLY1305_SHA256
    Session-ID: 6F70D795BFE2F0A832ADA1B926640005C4F38811192065031BEE7FEE1A8BB932
    Session-ID-ctx:
    Resumption PSK: 894A09F0136A8A8B68CF0596BD0B29A7C6C37C1E600030AF7C143136243273CD
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 01 f8 19 88 d6 73 9f 74-df 4a 03 40 ca 4e 57 8e   .....s.t.J.@.NW.
    0010 - 3f b2 c2 ce 55 77 dd ec-b3 5d 90 06 10 e1 20 e5   ?...Uw...].... .
    0020 - 42 d0 ba b6 26 da cc f6-ee e5 b9 aa 23 3f f3 7f   B...&.......#?..
    0030 - cd d0 2c 88 7d ee 9d 6a-bf c3 ba 9d 53 b4 9f db   ..,.}..j....S...
    0040 - 75 38 35 38 51 ba db 5a-1b 6d eb b9 f6 3b 9c 59   u858Q..Z.m...;.Y
    0050 - 04 ff 0f 76 45 b1 b3 c3-a0 a3 0f 06 46 a0 77 72   ...vE.......F.wr
    0060 - 01 b6 47 34 74 96 95 f9-e9 40 d4 83 ff 3b c4 84   ..G4t....@...;..
    0070 - c6 b1 c0 04 ad 33 11 30-1a f4 47 0b af 0a ca 37   .....3.0..G....7
    0080 - b6 46 3a 00 d1 6e 4d 30-e9 15 b9 8e 98 2a af 12   .F:..nM0.....*..
    0090 - 04 06 14 58 d2 53 32 8d-66 27 e3 b6 77 38 f8 0b   ...X.S2.f'..w8..
    00a0 - 7a 6e e3 0e da f6 fe 5c-2f 1e c2 48 9f e8 6b 67   zn.....\/..H..kg
    00b0 - c4 18 f8 bf a4 dd 3c 7f-5e 95 c9 ec 2f 8f 6a 21   ......<.^.../.j!

    Start Time: 1748410239
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
read from 0x215ba652870 [0x215baa3b573] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 234
read from 0x215ba652870 [0x215baa3b578] (234 bytes => 234 (0xEA))
0000 - 2b 97 be 44 5a ca 9a 5f-14 18 76 46 ec 29 5f 01   +..DZ.._..vF.)_.
0010 - 69 8f b6 ac aa 2f fb 32-00 d8 ca b0 ea 77 e5 2b   i..../.2.....w.+
0020 - 60 0f 72 4f 85 a4 a9 b2-d3 c6 d9 ab ad 4b a9 b2   `.rO.........K..
0030 - f0 f0 94 07 c5 c2 48 a6-65 d8 91 2d 66 83 e6 f2   ......H.e..-f...
0040 - 44 a2 48 bf 64 76 ba e4-db 45 0b 3a e3 39 6e ae   D.H.dv...E.:.9n.
0050 - 9d db b6 00 ec 7f 07 a2-94 a3 3c 6d 87 33 99 4e   ..........<m.3.N
0060 - 86 30 52 4e 14 0e 05 f1-f7 67 eb d9 78 ec 54 a0   .0RN.....g..x.T.
0070 - 4d 8b 52 45 96 1f 25 9a-30 29 cc 3d 80 40 fc 01   M.RE..%.0).=.@..
0080 - c4 cc 1d 9b 91 82 64 32-84 be e8 08 ef ff 66 0e   ......d2......f.
0090 - 34 66 2c 94 80 cf f4 7b-89 b5 1a c4 57 df b8 f8   4f,....{....W...
00a0 - 89 01 53 6b ca f8 dc 86-7b 30 ae 6b 3f af d8 9f   ..Sk....{0.k?...
00b0 - fe 7c 2b 69 26 40 b2 42-87 31 e1 07 e1 e6 14 26   .|+i&@.B.1.....&
00c0 - cb 31 9f bc e6 5f 67 53-4c 62 9e 7f e8 75 0a 4b   .1..._gSLb...u.K
00d0 - ea af 6b 09 1b 72 87 82-3a f5 d4 14 f4 3b 72 98   ..k..r..:....;r.
00e0 - 46 07 ce 9d 34 1c 52 ee-ce e8                     F...4.R...
  Inner Content Type = Handshake (22)
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
    NewSessionTicket, Length=213
        ticket_lifetime_hint=7200
        ticket_age_add=2183433845
        ticket_nonce (len=8): 0000000000000001
        ticket (len=192): 01F81988D6739F74DF4A0340CA4E578E2F12FD451E14D74ACB04B5CEDE593D3F4A6626ACA5C6DD8C4750388DC78F0EFBC13AFDF28DF8D82EAA13FBDE9A5B79CEC8B2566B588262354A2DBE6C5F31BD754144C0C293A3AAE6D50D3B1EC55DB82BC300556BD7F74BF3B32A7881CB403D04CB74BA3E492490CAF5F2C52FA7753DF5CC58FEE3E83CA23528B0B7AB5E8B9C79214775542FB4D1C8AA8BEE5F79269EF53BD87A9DA37163537AB948A3E61A0FF3317A629C669CF274BB60801A59CC3511
        No extensions

---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_CHACHA20_POLY1305_SHA256
    Session-ID: 869162447B380E7CB49FA84FA36F7913AF6344E015FD53FA1BCC1048164A5424
    Session-ID-ctx:
    Resumption PSK: 15E85362EE6BC9DAD55081207885AD56B9C43EC74D4D8ACCD60964C1AB80B0AF
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 01 f8 19 88 d6 73 9f 74-df 4a 03 40 ca 4e 57 8e   .....s.t.J.@.NW.
    0010 - 2f 12 fd 45 1e 14 d7 4a-cb 04 b5 ce de 59 3d 3f   /..E...J.....Y=?
    0020 - 4a 66 26 ac a5 c6 dd 8c-47 50 38 8d c7 8f 0e fb   Jf&.....GP8.....
    0030 - c1 3a fd f2 8d f8 d8 2e-aa 13 fb de 9a 5b 79 ce   .:...........[y.
    0040 - c8 b2 56 6b 58 82 62 35-4a 2d be 6c 5f 31 bd 75   ..VkX.b5J-.l_1.u
    0050 - 41 44 c0 c2 93 a3 aa e6-d5 0d 3b 1e c5 5d b8 2b   AD........;..].+
    0060 - c3 00 55 6b d7 f7 4b f3-b3 2a 78 81 cb 40 3d 04   ..Uk..K..*x..@=.
    0070 - cb 74 ba 3e 49 24 90 ca-f5 f2 c5 2f a7 75 3d f5   .t.>I$...../.u=.
    0080 - cc 58 fe e3 e8 3c a2 35-28 b0 b7 ab 5e 8b 9c 79   .X...<.5(...^..y
    0090 - 21 47 75 54 2f b4 d1 c8-aa 8b ee 5f 79 26 9e f5   !GuT/......_y&..
    00a0 - 3b d8 7a 9d a3 71 63 53-7a b9 48 a3 e6 1a 0f f3   ;.z..qcSz.H.....
    00b0 - 31 7a 62 9c 66 9c f2 74-bb 60 80 1a 59 cc 35 11   1zb.f..t.`..Y.5.

    Start Time: 1748410239
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
write to 0x215ba652870 [0x215baa3f6c3] (28 bytes => 28 (0x1C))
0000 - 17 03 03 00 17 a7 08 39-a3 f8 53 2b 8b 1e e8 20   .......9..S+...
0010 - bb 86 cc ef 9f 8d a4 7c-e7 b7 68 79               .......|..hy
Q
DONE
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 19
  Inner Content Type = Alert (21)
write to 0x215ba652870 [0x215baa3f6c3] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 f9 81 52-9f a2 78 a7 b9 c4 f1 74   .......R..x....t
0010 - 16 f2 28 bf f2 e8 ed bc-                          ..(.....
    Level=warning(1), description=close notify(0)

SSL3 alert write:warning:close notify
read from 0x215ba652870 [0x215ba597c60] (16384 bytes => 24 (0x18))
0000 - 17 03 03 00 13 ec dc 93-21 f5 3b ce e3 dd 8b 6f   ........!.;....o
0010 - db e6 c6 20 b5 6c d8 a8-                          ... .l..
read from 0x215ba652870 [0x215ba597c60] (16384 bytes => 0)
````

[TOC](README.md)
