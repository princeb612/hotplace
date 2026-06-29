#### client

````
openssl s_client -connect localhost:9000 -state -debug -trace -keylogfile sslkeylog -tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256
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
        gmt_unix_time=0x20E46626
        random_bytes (len=28): 7B480ED91949CB1C275038026BE816B9B4BBD490CC1CE5645EB5C6B7
      session_id (len=32): F013DCE6E55BAB347273FE10B97E51F46E1C231B580EDFD99885F6C32A397BFC
      cipher_suites (len=2)
        {0x13, 0x04} TLS_AES_128_CCM_SHA256
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
            key_exchange:  (len=32): E05F8FD51DD435D22744D56E0FCC4BCDD4D254978C1BB508828EC6EDFB8DD424
        extension_type=compress_certificate(27), length=3
          zlib (1)

write to 0x2535ca43450 [0x2535cee5c50] (232 bytes => 232 (0xE8))
0000 - 16 03 01 00 e3 01 00 00-df 03 03 20 e4 66 26 7b   ........... .f&{
0010 - 48 0e d9 19 49 cb 1c 27-50 38 02 6b e8 16 b9 b4   H...I..'P8.k....
0020 - bb d4 90 cc 1c e5 64 5e-b5 c6 b7 20 f0 13 dc e6   ......d^... ....
0030 - e5 5b ab 34 72 73 fe 10-b9 7e 51 f4 6e 1c 23 1b   .[.4rs...~Q.n.#.
0040 - 58 0e df d9 98 85 f6 c3-2a 39 7b fc 00 02 13 04   X.......*9{.....
0050 - 01 00 00 94 00 0b 00 04-03 00 01 02 00 0a 00 16   ................
0060 - 00 14 00 1d 00 17 00 1e-00 19 00 18 01 00 01 01   ................
0070 - 01 02 01 03 01 04 00 23-00 00 00 16 00 00 00 17   .......#........
0080 - 00 00 00 0d 00 24 00 22-04 03 05 03 06 03 08 07   .....$."........
0090 - 08 08 08 1a 08 1b 08 1c-08 09 08 0a 08 0b 08 04   ................
00a0 - 08 05 08 06 04 01 05 01-06 01 00 2b 00 03 02 03   ...........+....
00b0 - 04 00 2d 00 02 01 01 00-33 00 26 00 24 00 1d 00   ..-.....3.&.$...
00c0 - 20 e0 5f 8f d5 1d d4 35-d2 27 44 d5 6e 0f cc 4b    ._....5.'D.n..K
00d0 - cd d4 d2 54 97 8c 1b b5-08 82 8e c6 ed fb 8d d4   ...T............
00e0 - 24 00 1b 00 03 02 00 01-                          $.......
SSL_connect:SSLv3/TLS write client hello
read from 0x2535ca43450 [0x2535ceead23] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 7a                                    ....z
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 122
read from 0x2535ca43450 [0x2535ceead28] (122 bytes => 122 (0x7A))
0000 - 02 00 00 76 03 03 49 33-3c d0 4d ce b0 2a 1e f7   ...v..I3<.M..*..
0010 - 19 5d d7 3f 2f f1 0f 14-be 20 c6 4a 5b 4d 61 a2   .].?/.... .J[Ma.
0020 - 6c 39 ac c3 9c 47 20 f0-13 dc e6 e5 5b ab 34 72   l9...G .....[.4r
0030 - 73 fe 10 b9 7e 51 f4 6e-1c 23 1b 58 0e df d9 98   s...~Q.n.#.X....
0040 - 85 f6 c3 2a 39 7b fc 13-04 00 00 2e 00 2b 00 02   ...*9{.......+..
0050 - 03 04 00 33 00 24 00 1d-00 20 c0 53 5b 9d e6 5b   ...3.$... .S[..[
0060 - ce 35 fe db 74 0a 10 5a-45 0b 6a 50 63 fa eb 08   .5..t..ZE.jPc...
0070 - ae 18 3d 74 27 8e fd c7-c7 65                     ..=t'....e
SSL_connect:SSLv3/TLS write client hello
    ServerHello, Length=118
      server_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0x49333CD0
        random_bytes (len=28): 4DCEB02A1EF7195DD73F2FF10F14BE20C64A5B4D61A26C39ACC39C47
      session_id (len=32): F013DCE6E55BAB347273FE10B97E51F46E1C231B580EDFD99885F6C32A397BFC
      cipher_suite {0x13, 0x04} TLS_AES_128_CCM_SHA256
      compression_method: No Compression (0x00)
      extensions, length = 46
        extension_type=supported_versions(43), length=2
            TLS 1.3 (772)
        extension_type=key_share(51), length=36
            NamedGroup: ecdh_x25519 (29)
            key_exchange:  (len=32): C0535B9DE65BCE35FEDB740A105A450B6A5063FAEB08AE183D74278EFDC7C765

read from 0x2535ca43450 [0x2535ceead23] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ChangeCipherSpec (20)
  Length = 1
read from 0x2535ca43450 [0x2535ceead28] (1 bytes => 1 (0x1))
0000 - 01                                                .
    change_cipher_spec (1)

read from 0x2535ca43450 [0x2535ceead23] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 23
read from 0x2535ca43450 [0x2535ceead28] (23 bytes => 23 (0x17))
0000 - 76 b9 00 be 11 57 da a3-5d 08 05 ba bf 35 48 9c   v....W..]....5H.
0010 - 0c 24 35 dd 7b eb 46                              .$5.{.F
  Inner Content Type = Handshake (22)
SSL_connect:SSLv3/TLS read server hello
    EncryptedExtensions, Length=2
      No extensions

Can't use SSL_get_servername
read from 0x2535ca43450 [0x2535ceead23] (5 bytes => 5 (0x5))
0000 - 17 03 03 02 2a                                    ....*
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 554
read from 0x2535ca43450 [0x2535ceead28] (554 bytes => 554 (0x22A))
0000 - 48 b0 dd f7 01 16 13 d1-7a db 26 51 c9 58 eb ef   H.......z.&Q.X..
0010 - 22 48 f8 eb 46 8b 89 3d-dc 91 28 1a 99 66 35 34   "H..F..=..(..f54
0020 - 56 af f2 91 8d 42 cc a3-4e 73 cd 87 af 6b f7 10   V....B..Ns...k..
0030 - c4 07 c4 82 21 f9 10 15-ae 57 91 bd 0a f2 06 96   ....!....W......
0040 - db 1c b2 15 a6 06 73 0b-4b 13 be b1 13 11 e6 d9   ......s.K.......
0050 - 60 d7 3f 69 73 1d 83 c8-d9 cf b5 ba a0 38 ae 3d   `.?is........8.=
0060 - b3 ff cf 13 96 2f df 8d-c3 ca a8 7c 3c 65 a3 dd   ...../.....|<e..
0070 - ff 04 53 09 88 82 64 50-1a e9 b3 27 b6 20 c3 8c   ..S...dP...'. ..
0080 - 49 bd 17 d6 c1 04 a7 2b-c5 d4 f5 6d 38 55 e1 37   I......+...m8U.7
0090 - 5a ff fb 02 b9 98 36 2b-fb 6b 00 9b 87 82 4f 1d   Z.....6+.k....O.
00a0 - d1 7f da c2 be 19 a5 41-68 6e 16 6e 94 7f ce 70   .......Ahn.n...p
00b0 - 12 96 16 98 57 92 3d 6e-db 8c 82 49 be f2 51 79   ....W.=n...I..Qy
00c0 - 6e 9c 50 db ed 1b f6 42-ee 9c 31 a9 53 c9 35 47   n.P....B..1.S.5G
00d0 - 34 93 e2 ee 74 78 c1 5c-17 16 b5 3c 39 79 a2 79   4...tx.\...<9y.y
00e0 - c2 56 b3 31 2a d0 8d 26-56 37 d0 86 cd 87 b8 d4   .V.1*..&V7......
00f0 - e3 20 40 f2 a0 a8 e3 d0-39 84 c9 38 de 02 34 de   . @.....9..8..4.
0100 - 04 9b bc dc 65 4a cf c2-df 69 cc 87 80 6c 05 ff   ....eJ...i...l..
0110 - 1c be 51 6b 23 38 90 c9-92 d9 e6 52 f8 8a 3d 13   ..Qk#8.....R..=.
0120 - b5 f0 29 83 37 86 72 39-78 45 e9 6f ba e2 6a 96   ..).7.r9xE.o..j.
0130 - 41 fe 9d 08 56 4d b5 7b-d1 cf 86 95 4e b4 ae f9   A...VM.{....N...
0140 - 84 2e 3e ae 80 bb 0d aa-81 64 f3 e2 ee 86 c8 ba   ..>......d......
0150 - 88 6e e2 49 ce f4 8c c0-6a 81 fe 62 35 ff e7 d1   .n.I....j..b5...
0160 - 11 47 e3 d6 da 57 3d 71-18 9e 93 cb 9d b4 0d a7   .G...W=q........
0170 - 39 c8 16 51 fb c6 7c 02-92 00 1a de 0a 7f 68 22   9..Q..|.......h"
0180 - b8 62 20 23 94 69 0e 46-b5 63 52 bf 27 87 79 d1   .b #.i.F.cR.'.y.
0190 - d4 b3 6f 63 87 ad c6 a0-d5 9d 11 c4 6a 99 69 55   ..oc........j.iU
01a0 - 34 6f d2 fb 68 7e d5 9e-5c a8 aa 79 6d 93 07 10   4o..h~..\..ym...
01b0 - c9 2f 5c 79 e3 33 82 86-5a c2 26 10 e2 b3 51 c0   ./\y.3..Z.&...Q.
01c0 - 05 c1 38 6d dc 7e 38 b1-70 8f c5 7d 0c 2c c5 af   ..8m.~8.p..}.,..
01d0 - 78 2c 34 26 a9 57 17 07-4f 94 e7 ea 53 b6 93 73   x,4&.W..O...S..s
01e0 - a2 e9 a9 cd b4 af e5 73-d9 a4 a0 bc 9f a9 d4 d5   .......s........
01f0 - f4 73 65 25 22 6c ca 66-e3 94 8e e1 0c a1 e4 33   .se%"l.f.......3
0200 - 3f 4e 20 c5 72 47 dc 1c-08 57 86 9c 95 3b ec 2a   ?N .rG...W...;.*
0210 - dc 8a b0 38 02 f8 07 65-52 fd 06 86 56 eb f7 08   ...8...eR...V...
0220 - 0a d3 5a 84 98 09 af 93-1c 86                     ..Z.......
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
read from 0x2535ca43450 [0x2535ceead23] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 60                                    ....`
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 96
read from 0x2535ca43450 [0x2535ceead28] (96 bytes => 96 (0x60))
0000 - c0 a6 0d 74 0e a9 c1 68-66 0c 1c e2 d6 d6 cf 29   ...t...hf......)
0010 - c0 2a c1 b6 36 d6 13 af-26 be 2d a8 0f 1d bc 8f   .*..6...&.-.....
0020 - 05 3e 8d bd f0 e9 6f f8-f4 76 32 c7 cb 93 52 15   .>....o..v2...R.
0030 - 0e ad ed 83 79 04 1f 98-c4 f0 fe 28 87 fb fd f1   ....y......(....
0040 - dd 2f 08 c8 e6 d3 eb 98-22 43 b0 c2 6e 54 ae 4f   ./......"C..nT.O
0050 - 79 02 ad e4 16 cb 84 10-d0 8b c5 67 28 5d 79 66   y..........g(]yf
  Inner Content Type = Handshake (22)
SSL_connect:SSLv3/TLS read server certificate
    CertificateVerify, Length=75
      Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
      Signature (len=71): 304502203244FE5B62EAC0117D59E2E42AF58065CD957596D7CCF698948ABCD468D96137022100D4BCE707950B8FE5CD960B3FF4F58DD9DA784C2EB8CDC70916A145F98BF857EA

read from 0x2535ca43450 [0x2535ceead23] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 53
read from 0x2535ca43450 [0x2535ceead28] (53 bytes => 53 (0x35))
0000 - e7 34 ee 17 47 04 7a fa-d7 b8 c5 ef 8d 1d 9f 9f   .4..G.z.........
0010 - c3 93 ed a3 d0 92 9a 4a-25 3c 98 f6 1e ec 58 df   .......J%<....X.
0020 - 54 76 01 ac 4e 5f 4d d5-32 31 1f 68 83 45 33 88   Tv..N_M.21.h.E3.
0030 - f7 15 ae f6 45                                    ....E
  Inner Content Type = Handshake (22)
SSL_connect:TLSv1.3 read server certificate verify
    Finished, Length=32
      verify_data (len=32): A0B416BDC08D92B84442F4477C6C9976C63F66DC3252EE9C5D1F73BFC7677EA8

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
      verify_data (len=32): 84082E021BC43F1C0BB17E2E5848998C2F8096F4141F89A6D122331EF694FA5E

write to 0x2535ca43450 [0x2535cee5c50] (64 bytes => 64 (0x40))
0000 - 14 03 03 00 01 01 17 03-03 00 35 10 e1 6d b0 73   ..........5..m.s
0010 - df 52 90 e2 d5 a6 3c 5a-c5 ea 2c b6 5f b4 2b 8b   .R....<Z..,._.+.
0020 - 92 ba 84 6d 27 aa d7 de-4e cb dd 8a 4f 8f 4b a5   ...m'...N...O.K.
0030 - 0d 84 44 22 2a 01 f5 87-45 b3 5c e0 1f 6a 44 a8   ..D"*...E.\..jD.
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
New, TLSv1.3, Cipher is TLS_AES_128_CCM_SHA256
Protocol: TLSv1.3
Server public key is 256 bit
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 18 (self-signed certificate)
---
read from 0x2535ca43450 [0x2535cedf593] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 234
read from 0x2535ca43450 [0x2535cedf598] (234 bytes => 234 (0xEA))
0000 - 74 57 a5 a5 37 db 2a 8f-b9 0c d4 ce d9 ad 0f 81   tW..7.*.........
0010 - d7 a3 ee c6 39 fb 18 fb-77 8e 07 d5 c0 5c c6 74   ....9...w....\.t
0020 - 05 9e b9 ef 99 13 ad c6-fb c8 96 b6 5c 1f 85 6c   ............\..l
0030 - b2 6e 15 45 24 d3 1b 52-de 2c 2f ee da 4c 3c c6   .n.E$..R.,/..L<.
0040 - 90 7e f3 aa 58 19 09 05-76 a7 0b 79 f5 cd 50 30   .~..X...v..y..P0
0050 - bb e1 d1 75 e1 85 dd 3e-02 eb 8f 66 ed a4 ff 20   ...u...>...f...
0060 - 49 6d 33 42 1e cd 64 db-02 84 1d 45 aa b1 6f 21   Im3B..d....E..o!
0070 - 55 47 ca 4c 2b 2d c9 30-68 d0 f3 02 aa 49 73 d6   UG.L+-.0h....Is.
0080 - e5 a5 07 a5 82 5a c8 15-6a 66 d7 b7 ff 52 03 fc   .....Z..jf...R..
0090 - 1a 24 1b 2c c9 21 71 eb-ff 58 76 db b8 af a2 af   .$.,.!q..Xv.....
00a0 - e5 e3 10 58 c2 15 0e 9a-f6 e2 8e 28 06 84 26 41   ...X.......(..&A
00b0 - 04 37 9f 5f a7 e8 1e 41-16 14 ad 8b a9 19 f1 49   .7._...A.......I
00c0 - 18 a7 12 37 37 eb 3d 6d-49 6a 07 98 e4 6c 24 83   ...77.=mIj...l$.
00d0 - 94 96 28 7b 12 fa 6e 51-e8 df 11 ef ed 53 87 e0   ..({..nQ.....S..
00e0 - c9 58 07 1e 97 9c 7e 42-d8 2e                     .X....~B..
  Inner Content Type = Handshake (22)
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
    NewSessionTicket, Length=213
        ticket_lifetime_hint=7200
        ticket_age_add=3158125152
        ticket_nonce (len=8): 0000000000000000
        ticket (len=192): 34C35B3681A34D57606D06926972C12CD6D559205A7BB0E3A2A15B3D072BC0D040AE94795F0E89140D5DA0325B021240F6707D8C1452AA1363BC1E606E717A8F21124D17840593ECDB414C9520C1D8D1ABA93D83D2E442E776D5CE868A1A433A4822C3A2EBC69F7D8F8F4748753B72B7493CC91778605F169992C18A95CF697859252CD5AAD697A690862E53427040F697B58D7786D011DB83DAC44010356520F3DCC10B2817DDFE7FEDF5914F758DF00F26671FFDE0C3EB759F9AE647153F54
        No extensions

---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_CCM_SHA256
    Session-ID: E23CF73ED50778CB25FE5A07FD4141E7420898848DF2A7124E347877E258CEE3
    Session-ID-ctx:
    Resumption PSK: 88A5910AF4444E661A3D04AB76A568BA3633B34DC5D93985373AD1837EE729CD
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 34 c3 5b 36 81 a3 4d 57-60 6d 06 92 69 72 c1 2c   4.[6..MW`m..ir.,
    0010 - d6 d5 59 20 5a 7b b0 e3-a2 a1 5b 3d 07 2b c0 d0   ..Y Z{....[=.+..
    0020 - 40 ae 94 79 5f 0e 89 14-0d 5d a0 32 5b 02 12 40   @..y_....].2[..@
    0030 - f6 70 7d 8c 14 52 aa 13-63 bc 1e 60 6e 71 7a 8f   .p}..R..c..`nqz.
    0040 - 21 12 4d 17 84 05 93 ec-db 41 4c 95 20 c1 d8 d1   !.M......AL. ...
    0050 - ab a9 3d 83 d2 e4 42 e7-76 d5 ce 86 8a 1a 43 3a   ..=...B.v.....C:
    0060 - 48 22 c3 a2 eb c6 9f 7d-8f 8f 47 48 75 3b 72 b7   H".....}..GHu;r.
    0070 - 49 3c c9 17 78 60 5f 16-99 92 c1 8a 95 cf 69 78   I<..x`_.......ix
    0080 - 59 25 2c d5 aa d6 97 a6-90 86 2e 53 42 70 40 f6   Y%,........SBp@.
    0090 - 97 b5 8d 77 86 d0 11 db-83 da c4 40 10 35 65 20   ...w.......@.5e
    00a0 - f3 dc c1 0b 28 17 dd fe-7f ed f5 91 4f 75 8d f0   ....(.......Ou..
    00b0 - 0f 26 67 1f fd e0 c3 eb-75 9f 9a e6 47 15 3f 54   .&g.....u...G.?T

    Start Time: 1748412972
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
read from 0x2535ca43450 [0x2535cedf593] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 234
read from 0x2535ca43450 [0x2535cedf598] (234 bytes => 234 (0xEA))
0000 - 57 44 a5 b6 b5 84 4c ad-e0 e3 0e 37 af 8d ac 4b   WD....L....7...K
0010 - 80 95 a4 d7 bd a0 45 34-44 ac e7 46 17 99 85 98   ......E4D..F....
0020 - 63 f2 8e d3 69 bc f9 37-82 35 99 be 13 ee ed f1   c...i..7.5......
0030 - e8 01 52 90 9a fb f1 0a-5e 47 eb f9 96 1d ff 7d   ..R.....^G.....}
0040 - 6a 08 ef e5 0d a9 32 78-6e 69 41 d4 73 14 13 d6   j.....2xniA.s...
0050 - 7c e1 0c e2 0f 1e 43 0b-80 60 f4 d8 a7 a8 c4 59   |.....C..`.....Y
0060 - 7b a9 34 5c a1 6f 1c ab-a4 07 b9 77 a3 bb 1f f5   {.4\.o.....w....
0070 - c6 9e 9a 0b 0b 58 5d 94-03 d0 8a 9e 34 7e 14 c9   .....X].....4~..
0080 - 29 02 d5 67 71 49 a2 6c-dd a8 f9 05 6d d4 89 e5   )..gqI.l....m...
0090 - 79 78 eb ea 23 85 d5 7e-a3 59 02 a8 ed fb 71 ec   yx..#..~.Y....q.
00a0 - b0 f3 00 76 f6 6f 4c 87-d5 da 3e da 9e 27 e5 5a   ...v.oL...>..'.Z
00b0 - 37 3e 84 f7 0b 0d 75 39-49 74 57 6d f8 c3 e6 fe   7>....u9ItWm....
00c0 - aa 9e 1d 4f 24 d9 a5 6f-4a e4 f7 dc d6 32 f0 ed   ...O$..oJ....2..
00d0 - 66 53 54 1b 16 ae 7d 89-07 13 43 ff 36 7d 3d 73   fST...}...C.6}=s
00e0 - 9d c8 8f 53 0a 0d ab 1f-a0 3e                     ...S.....>
  Inner Content Type = Handshake (22)
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
    NewSessionTicket, Length=213
        ticket_lifetime_hint=7200
        ticket_age_add=1215181142
        ticket_nonce (len=8): 0000000000000001
        ticket (len=192): 34C35B3681A34D57606D06926972C12CF71AC46D885268DA854137076719D96CDA00C95388D81CCDE06728F1CEC1A816D172544D308F2AD0705AA08EF7953BF04E19B80DE9D1CF3B1AF655D2C998D65F9FAC17A5EAE51D6984844C3135F2464EBAF06EA0FD443210B9A6A4CAAC2E7DCE8EE6F9A1D4D57810CFD725675F1DCDCC7CBFF7CC0CEBE5A9C1BC49B3CDFF3D1A659009B23C6C2F20BDB82BA133E3B3E840743209BFBE026CE59926551AF4F96D9E130DDFC64D0F23EA310A19ECB18F6D
        No extensions

---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_CCM_SHA256
    Session-ID: 153802DF9003CFAF45246E57F7A584233438339B1BBE328A5AA0B16961B2AEA4
    Session-ID-ctx:
    Resumption PSK: B0F696A63BEBBA5A4878448FA78EE0D94F50A6DDB381651492018BFE4F6830DC
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 34 c3 5b 36 81 a3 4d 57-60 6d 06 92 69 72 c1 2c   4.[6..MW`m..ir.,
    0010 - f7 1a c4 6d 88 52 68 da-85 41 37 07 67 19 d9 6c   ...m.Rh..A7.g..l
    0020 - da 00 c9 53 88 d8 1c cd-e0 67 28 f1 ce c1 a8 16   ...S.....g(.....
    0030 - d1 72 54 4d 30 8f 2a d0-70 5a a0 8e f7 95 3b f0   .rTM0.*.pZ....;.
    0040 - 4e 19 b8 0d e9 d1 cf 3b-1a f6 55 d2 c9 98 d6 5f   N......;..U...._
    0050 - 9f ac 17 a5 ea e5 1d 69-84 84 4c 31 35 f2 46 4e   .......i..L15.FN
    0060 - ba f0 6e a0 fd 44 32 10-b9 a6 a4 ca ac 2e 7d ce   ..n..D2.......}.
    0070 - 8e e6 f9 a1 d4 d5 78 10-cf d7 25 67 5f 1d cd cc   ......x...%g_...
    0080 - 7c bf f7 cc 0c eb e5 a9-c1 bc 49 b3 cd ff 3d 1a   |.........I...=.
    0090 - 65 90 09 b2 3c 6c 2f 20-bd b8 2b a1 33 e3 b3 e8   e...<l/ ..+.3...
    00a0 - 40 74 32 09 bf be 02 6c-e5 99 26 55 1a f4 f9 6d   @t2....l..&U...m
    00b0 - 9e 13 0d df c6 4d 0f 23-ea 31 0a 19 ec b1 8f 6d   .....M.#.1.....m

    Start Time: 1748412972
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
write to 0x2535ca43450 [0x2535cee36e3] (28 bytes => 28 (0x1C))
0000 - 17 03 03 00 17 de c7 2b-92 cd 5a eb d7 09 23 79   .......+..Z...#y
0010 - c2 ea 39 32 5f 3c ea 2e-ea 6e 6d 28               ..92_<...nm(
Q
DONE
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 19
  Inner Content Type = Alert (21)
write to 0x2535ca43450 [0x2535cee36e3] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 8d c4 d6-ce d5 f1 0c 0f b5 2d 3f   ..............-?
0010 - 9d 99 1c fd 95 42 04 87-                          .....B..
    Level=warning(1), description=close notify(0)

SSL3 alert write:warning:close notify
read from 0x2535ca43450 [0x2535c987cc0] (16384 bytes => 24 (0x18))
0000 - 17 03 03 00 13 06 a9 a4-a9 6f fd f2 cb 13 00 c1   .........o......
0010 - b0 3c 79 52 15 fb d8 db-                          .<yR....
read from 0x2535ca43450 [0x2535c987cc0] (16384 bytes => 0)
````

[TOC](README.md)
