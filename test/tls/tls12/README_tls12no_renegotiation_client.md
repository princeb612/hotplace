#### client

````
$ openssl s_client -connect localhost:9000 -state -debug -keylogfile client.keylog -tls1_2
Connecting to ::1
CONNECTED(000001DC)
SSL_connect:before SSL initialization
write to 0x1ffdcac21b0 [0x1ffde6c5d20] (197 bytes => 197 (0xC5))
0000 - 16 03 01 00 c0 01 00 00-bc 03 03 25 e7 68 32 9c   ...........%.h2.
0010 - 4e c7 33 a8 ad 1d 04 44-91 43 b0 b5 25 e8 b2 1e   N.3....D.C..%...
0020 - 4c e4 1f 8b a4 9f 21 f0-f4 9b d1 00 00 36 c0 2c   L.....!......6.,
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
read from 0x1ffdcac21b0 [0x1ffde6cadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 41                                    ....A
read from 0x1ffdcac21b0 [0x1ffde6cadf8] (65 bytes => 65 (0x41))
0000 - 02 00 00 3d 03 03 73 47-61 d6 b9 47 7e 93 c8 c0   ...=..sGa..G~...
0010 - d2 57 c6 c7 81 8c 38 67-e4 b4 02 4d 30 6c 44 4f   .W....8g...M0lDO
0020 - 57 4e 47 52 44 01 00 c0-30 00 00 15 ff 01 00 01   WNGRD...0.......
0030 - 00 00 0b 00 04 03 00 01-02 00 23 00 00 00 17 00   ..........#.....
0040 - 00                                                .
SSL_connect:SSLv3/TLS write client hello
Can't use SSL_get_servername
read from 0x1ffdcac21b0 [0x1ffde6cadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 03 6a                                    ....j
read from 0x1ffdcac21b0 [0x1ffde6cadf8] (874 bytes => 874 (0x36A))
0000 - 0b 00 03 66 00 03 63 00-03 60 30 82 03 5c 30 82   ...f..c..`0..\0.
0010 - 02 44 a0 03 02 01 02 02-14 63 a6 71 10 79 d6 a6   .D.......c.q.y..
0020 - 48 59 da 67 a9 04 e8 e3-5f e2 03 a3 26 30 0d 06   HY.g...._...&0..
0030 - 09 2a 86 48 86 f7 0d 01-01 0b 05 00 30 59 31 0b   .*.H........0Y1.
0040 - 30 09 06 03 55 04 06 13-02 4b 52 31 0b 30 09 06   0...U....KR1.0..
0050 - 03 55 04 08 0c 02 47 47-31 0b 30 09 06 03 55 04   .U....GG1.0...U.
0060 - 07 0c 02 59 49 31 0d 30-0b 06 03 55 04 0a 0c 04   ...YI1.0...U....
0070 - 54 65 73 74 31 0d 30 0b-06 03 55 04 0b 0c 04 54   Test1.0...U....T
0080 - 65 73 74 31 12 30 10 06-03 55 04 03 0c 09 54 65   est1.0...U....Te
0090 - 73 74 20 52 6f 6f 74 30-1e 17 0d 32 34 30 38 32   st Root0...24082
00a0 - 39 30 36 32 37 31 37 5a-17 0d 32 35 30 38 32 39   9062717Z..250829
00b0 - 30 36 32 37 31 37 5a 30-54 31 0b 30 09 06 03 55   062717Z0T1.0...U
00c0 - 04 06 13 02 4b 52 31 0b-30 09 06 03 55 04 08 0c   ....KR1.0...U...
00d0 - 02 47 47 31 0b 30 09 06-03 55 04 07 0c 02 59 49   .GG1.0...U....YI
00e0 - 31 0d 30 0b 06 03 55 04-0a 0c 04 54 65 73 74 31   1.0...U....Test1
00f0 - 0d 30 0b 06 03 55 04 0b-0c 04 54 65 73 74 31 0d   .0...U....Test1.
0100 - 30 0b 06 03 55 04 03 0c-04 54 65 73 74 30 82 01   0...U....Test0..
0110 - 22 30 0d 06 09 2a 86 48-86 f7 0d 01 01 01 05 00   "0...*.H........
0120 - 03 82 01 0f 00 30 82 01-0a 02 82 01 01 00 ad 9a   .....0..........
0130 - 29 67 5f f3 a4 79 b4 c6-e6 32 73 d8 d7 ed 88 94   )g_..y...2s.....
0140 - 15 83 e4 31 00 04 6c b5-8c ac 87 ab 74 44 13 76   ...1..l.....tD.v
0150 - ca 0b 74 29 40 9e 97 2a-01 d7 8b 46 26 6e 19 35   ..t)@..*...F&n.5
0160 - 4d c0 d3 b5 ea 0e 93 3a-06 e8 e5 85 b5 27 05 63   M......:.....'.c
0170 - db 28 b8 92 da 5a 14 39-0f da 68 6d 6f 0a fb 52   .(...Z.9..hmo..R
0180 - dc 08 0f 54 d3 e4 a2 28-9d a0 71 50 82 e0 db ca   ...T...(..qP....
0190 - d1 94 dd 42 98 3a 09 33-a8 d9 ef fb d2 35 43 b1   ...B.:.3.....5C.
01a0 - 22 a2 be 41 6d ba 91 dc-0b 31 4e 88 f9 4d 9c 61   "..Am....1N..M.a
01b0 - 2d ec b2 13 0a c2 91 8e-a2 d6 e9 40 b9 32 b9 80   -..........@.2..
01c0 - 8f b3 18 a3 33 13 23 d5-d0 7e d9 d0 7f 93 e0 2d   ....3.#..~.....-
01d0 - 4d 90 c5 58 24 56 d5 c9-10 13 4a b2 99 23 7d 34   M..X$V....J..#}4
01e0 - b9 8e 97 19 69 6f ce c6-3f d6 17 a7 d2 43 e0 36   ....io..?....C.6
01f0 - cb 51 7b 2f 18 8b c2 33-f8 57 cf d1 61 0b 7c ed   .Q{/...3.W..a.|.
0200 - 37 35 e3 13 7a 24 2e 77-08 c2 e3 d9 e6 17 d3 a5   75..z$.w........
0210 - c6 34 5a da 86 a7 f8 02-36 1d 66 63 cf e9 c0 3d   .4Z.....6.fc...=
0220 - 82 fb 39 a2 8d 92 01 4a-83 cf e2 76 3d 87 02 03   ..9....J...v=...
0230 - 01 00 01 a3 21 30 1f 30-1d 06 03 55 1d 11 04 16   ....!0.0...U....
0240 - 30 14 82 12 74 65 73 74-2e 70 72 69 6e 63 65 62   0...test.princeb
0250 - 36 31 32 2e 70 65 30 0d-06 09 2a 86 48 86 f7 0d   612.pe0...*.H...
0260 - 01 01 0b 05 00 03 82 01-01 00 00 a5 f5 54 18 ab   .............T..
0270 - ad 36 38 c8 fc 0b 66 60-dd 9f 75 9d 86 5b 79 2f   .68...f`..u..[y/
0280 - ee 57 f1 79 1c 15 a1 34-23 d0 1c a9 58 51 a4 d0   .W.y...4#...XQ..
0290 - 08 f5 d8 f7 49 e9 c5 b5-65 91 51 2d 6d e4 3b 0e   ....I...e.Q-m.;.
02a0 - 77 02 1f 45 8e 34 e5 bb-eb f6 9d df 4a 40 60 21   w..E.4......J@`!
02b0 - b3 8e 16 33 3f f4 b6 90-d3 3c 34 ce e6 d9 47 07   ...3?....<4...G.
02c0 - a7 57 14 0c f9 78 0b 36-72 a9 88 07 07 93 b4 d7   .W...x.6r.......
02d0 - fe 29 5e e8 41 37 20 a5-03 c7 97 cb 82 ca db 14   .)^.A7 .........
02e0 - e5 8b 96 1f a9 e9 20 3d-6b 25 ae f4 89 4c 60 8d   ...... =k%...L`.
02f0 - e9 14 33 47 4b 88 54 a2-47 19 81 c8 7b 0e 32 52   ..3GK.T.G...{.2R
0300 - 2b 91 88 ad 0f 6d 73 30-8c 00 af d5 fc 46 46 af   +....ms0.....FF.
0310 - 3a c2 17 89 ec c8 83 ae-da e6 69 63 e0 9c 84 22   :.........ic..."
0320 - c5 7a de e8 23 6b 53 9d-6f 94 d2 7f 5c be 1d 0c   .z..#kS.o...\...
0330 - de 0e 07 0d 52 a5 43 8c-e8 05 ef c0 ff f0 73 fa   ....R.C.......s.
0340 - dc 5a 51 4c 24 09 65 45-7d ab 52 8b 7e 5d f0 fb   .ZQL$.eE}.R.~]..
0350 - de a7 3d 43 c5 af 76 e3-6e f9 a1 dc 78 a2 bd 54   ..=C..v.n...x..T
0360 - 41 04 99 e5 56 32 ba 02-fd 72                     A...V2...r
SSL_connect:SSLv3/TLS read server hello
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify return:1
read from 0x1ffdcac21b0 [0x1ffde6cadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 01 2c                                    ....,
read from 0x1ffdcac21b0 [0x1ffde6cadf8] (300 bytes => 300 (0x12C))
0000 - 0c 00 01 28 03 00 1d 20-1c 2e 68 cb 2f b1 bc c4   ...(... ..h./...
0010 - 88 bb 2c 8d ca bb 87 bb-a5 71 57 5e a1 1b 8d c5   ..,......qW^....
0020 - a5 07 2a 5f 14 2d 41 01-08 04 01 00 2d ce b7 00   ..*_.-A.....-...
0030 - cc f0 6d 5a c5 b7 41 a8-3d 2a be 38 fe 73 ce fb   ..mZ..A.=*.8.s..
0040 - 03 7b 03 e8 a2 8d 5d aa-5b 4d 84 d1 5d e9 77 cb   .{....].[M..].w.
0050 - 18 14 e8 b2 17 27 f6 af-8f 29 49 5d bc 7a 7e a2   .....'...)I].z~.
0060 - 6e db a7 c6 42 82 b7 90-2f e6 bc d2 76 b2 d1 20   n...B.../...v..
0070 - 2b 07 4a d5 92 77 24 3f-cd be 2b 31 01 f7 f8 c5   +.J..w$?..+1....
0080 - 17 ca 77 5d 27 c0 66 22-5a 5e 4d ff 65 06 d7 d5   ..w]'.f"Z^M.e...
0090 - 2c 7e 31 19 33 cf be 1e-14 db 85 d4 3c 5f b3 02   ,~1.3.......<_..
00a0 - 95 78 04 d3 a0 2d 5e e2-83 22 14 a2 09 a1 6a 8d   .x...-^.."....j.
00b0 - a9 13 92 4c ca 81 d2 ac-07 ac 43 de a2 83 1c 86   ...L......C.....
00c0 - e3 1f d5 b0 15 40 a2 c3-77 fa 19 27 e9 d8 ad 13   .....@..w..'....
00d0 - 4a 17 82 4d 8e cd 5d d6-5b 22 a9 e9 44 e5 5c 95   J..M..].["..D.\.
00e0 - fe 3e 0c 8b c8 23 c1 89-85 61 8e ed 77 bd df b2   .>...#...a..w...
00f0 - a7 1c 66 7c 40 d7 c8 21-fc 0f da 5c b9 dd 3d 00   ..f|@..!...\..=.
0100 - 5f 1e d8 01 e6 5f a3 d0-29 e0 e5 75 ab 7f a9 85   _...._..)..u....
0110 - f7 c3 6f 1b 02 20 ed 48-32 c9 8b 79 a9 4c f7 33   ..o.. .H2..y.L.3
0120 - 91 50 3e 6e 6c 02 be 4a-6a 4b 03 b7               .P>nl..JjK..
SSL_connect:SSLv3/TLS read server certificate
read from 0x1ffdcac21b0 [0x1ffde6cadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 04                                    .....
read from 0x1ffdcac21b0 [0x1ffde6cadf8] (4 bytes => 4 (0x4))
0000 - 0e 00 00 00                                       ....
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client key exchange
SSL_connect:SSLv3/TLS write change cipher spec
write to 0x1ffdcac21b0 [0x1ffde6c5d20] (93 bytes => 93 (0x5D))
0000 - 16 03 03 00 25 10 00 00-21 20 64 04 9b ef f7 13   ....%...! d.....
0010 - 53 22 aa 19 08 e3 7d e2-92 9d e2 38 ee 87 16 9c   S"....}....8....
0020 - c6 b2 cc ed 73 15 a4 d5-94 5a 14 03 03 00 01 01   ....s....Z......
0030 - 16 03 03 00 28 8a 5b 61-16 92 1b a3 3f 73 85 eb   ....(.[a....?s..
0040 - d2 2c e0 3f 71 84 1f 82-79 d7 4e 47 d7 42 b3 f7   .,.?q...y.NG.B..
0050 - 39 5c 2d a0 dc 1f f9 ce-eb ef 7a e7 92            9\-.......z..
SSL_connect:SSLv3/TLS write finished
read from 0x1ffdcac21b0 [0x1ffde6cadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 ba                                    .....
read from 0x1ffdcac21b0 [0x1ffde6cadf8] (186 bytes => 186 (0xBA))
0000 - 04 00 00 b6 00 00 1c 20-00 b0 3a b4 2f 4b 76 c7   ....... ..:./Kv.
0010 - 63 73 e5 0b 29 8c 67 60-19 66 6c 2b 9f 25 40 42   cs..).g`.fl+.%@B
0020 - 31 23 b5 cb a9 55 cf 26-9a 1c 91 34 08 3b 6a 63   1#...U.&...4.;jc
0030 - 9d d4 c4 01 5f 2e 75 6b-5a a4 0a b8 50 b1 cf 7f   ...._.ukZ...P...
0040 - a3 f8 ec fa 06 b0 ae 97-43 b7 cd 74 7e 6e ee 94   ........C..t~n..
0050 - 8b d1 03 a1 e4 0a 42 47-e3 d6 bf e8 67 9a 83 4b   ......BG....g..K
0060 - 52 e8 d5 36 17 74 17 03-47 94 f4 dc ff aa 0b 7d   R..6.t..G......}
0070 - a1 6a 20 a8 88 1c 54 b2-ac 7c a3 60 3c bf e3 9c   .j ...T..|.`<...
0080 - 88 8f 8d 70 4e 9b 81 f1-c8 eb b9 0b e0 35 02 10   ...pN........5..
0090 - 20 69 ac 72 7f 21 c5 83-b0 6b 43 13 81 de 70 1d    i.r.!...kC...p.
00a0 - eb 55 38 cb 89 b7 9e 66-55 0a cd 5f 1c 78 7e 23   .U8....fU.._.x~#
00b0 - cd 12 d6 04 40 ac aa 6a-e4 b1                     ....@..j..
SSL_connect:SSLv3/TLS write finished
read from 0x1ffdcac21b0 [0x1ffde6cadf3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x1ffdcac21b0 [0x1ffde6cadf8] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_connect:SSLv3/TLS read server session ticket
read from 0x1ffdcac21b0 [0x1ffde6c6d33] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 28                                    ....(
read from 0x1ffdcac21b0 [0x1ffde6c6d38] (40 bytes => 40 (0x28))
0000 - 55 41 cc 48 47 9a 42 e0-8d 90 83 e2 c6 1f 20 ed   UA.HG.B....... .
0010 - 13 77 d0 3e 36 ea 90 19-e7 cd 8d cd 40 44 22 fc   .w.>6.......@D".
0020 - ac 91 ca 11 70 5a a7 e5-                          ....pZ..
SSL_connect:SSLv3/TLS read change cipher spec
SSL_connect:SSLv3/TLS read finished
---
Certificate chain
 0 s:C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
   i:C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Aug 29 06:27:17 2024 GMT; NotAfter: Aug 29 06:27:17 2025 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIDXDCCAkSgAwIBAgIUY6ZxEHnWpkhZ2mepBOjjX+IDoyYwDQYJKoZIhvcNAQEL
BQAwWTELMAkGA1UEBhMCS1IxCzAJBgNVBAgMAkdHMQswCQYDVQQHDAJZSTENMAsG
A1UECgwEVGVzdDENMAsGA1UECwwEVGVzdDESMBAGA1UEAwwJVGVzdCBSb290MB4X
DTI0MDgyOTA2MjcxN1oXDTI1MDgyOTA2MjcxN1owVDELMAkGA1UEBhMCS1IxCzAJ
BgNVBAgMAkdHMQswCQYDVQQHDAJZSTENMAsGA1UECgwEVGVzdDENMAsGA1UECwwE
VGVzdDENMAsGA1UEAwwEVGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAK2aKWdf86R5tMbmMnPY1+2IlBWD5DEABGy1jKyHq3REE3bKC3QpQJ6XKgHX
i0Ymbhk1TcDTteoOkzoG6OWFtScFY9souJLaWhQ5D9pobW8K+1LcCA9U0+SiKJ2g
cVCC4NvK0ZTdQpg6CTOo2e/70jVDsSKivkFtupHcCzFOiPlNnGEt7LITCsKRjqLW
6UC5MrmAj7MYozMTI9XQftnQf5PgLU2QxVgkVtXJEBNKspkjfTS5jpcZaW/Oxj/W
F6fSQ+A2y1F7LxiLwjP4V8/RYQt87Tc14xN6JC53CMLj2eYX06XGNFrahqf4AjYd
ZmPP6cA9gvs5oo2SAUqDz+J2PYcCAwEAAaMhMB8wHQYDVR0RBBYwFIISdGVzdC5w
cmluY2ViNjEyLnBlMA0GCSqGSIb3DQEBCwUAA4IBAQAApfVUGKutNjjI/AtmYN2f
dZ2GW3kv7lfxeRwVoTQj0BypWFGk0Aj12PdJ6cW1ZZFRLW3kOw53Ah9FjjTlu+v2
nd9KQGAhs44WMz/0tpDTPDTO5tlHB6dXFAz5eAs2cqmIBweTtNf+KV7oQTcgpQPH
l8uCytsU5YuWH6npID1rJa70iUxgjekUM0dLiFSiRxmByHsOMlIrkYitD21zMIwA
r9X8RkavOsIXiezIg67a5mlj4JyEIsV63ugja1Odb5TSf1y+HQzeDgcNUqVDjOgF
78D/8HP63FpRTCQJZUV9q1KLfl3w+96nPUPFr3bjbvmh3HiivVRBBJnlVjK6Av1y
-----END CERTIFICATE-----
subject=C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
issuer=C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1505 bytes and written 290 bytes
Verification error: unable to verify the first certificate
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Protocol: TLSv1.2
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 1B2BE77A8C3A687BC748E7FF523925F8A7843214BF9DDC3093086E8CCF7C0173
    Session-ID-ctx:
    Master-Key: FD8C2B5E884609294FC244522F1ADEAEF3685A20071946981747CA998BC4855F86F3F7965A23C0E8CCEEB24DC569C50B
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 3a b4 2f 4b 76 c7 63 73-e5 0b 29 8c 67 60 19 66   :./Kv.cs..).g`.f
    0010 - 6c 2b 9f 25 40 42 31 23-b5 cb a9 55 cf 26 9a 1c   l+.%@B1#...U.&..
    0020 - 91 34 08 3b 6a 63 9d d4-c4 01 5f 2e 75 6b 5a a4   .4.;jc...._.ukZ.
    0030 - 0a b8 50 b1 cf 7f a3 f8-ec fa 06 b0 ae 97 43 b7   ..P...........C.
    0040 - cd 74 7e 6e ee 94 8b d1-03 a1 e4 0a 42 47 e3 d6   .t~n........BG..
    0050 - bf e8 67 9a 83 4b 52 e8-d5 36 17 74 17 03 47 94   ..g..KR..6.t..G.
    0060 - f4 dc ff aa 0b 7d a1 6a-20 a8 88 1c 54 b2 ac 7c   .....}.j ...T..|
    0070 - a3 60 3c bf e3 9c 88 8f-8d 70 4e 9b 81 f1 c8 eb   .`<......pN.....
    0080 - b9 0b e0 35 02 10 20 69-ac 72 7f 21 c5 83 b0 6b   ...5.. i.r.!...k
    0090 - 43 13 81 de 70 1d eb 55-38 cb 89 b7 9e 66 55 0a   C...p..U8....fU.
    00a0 - cd 5f 1c 78 7e 23 cd 12-d6 04 40 ac aa 6a e4 b1   ._.x~#....@..j..

    Start Time: 1746849944
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: yes
---
test
write to 0x1ffdcac21b0 [0x1ffde6daaa3] (35 bytes => 35 (0x23))
0000 - 17 03 03 00 1e 8a 5b 61-16 92 1b a3 40 53 db 49   ......[a....@S.I
0010 - 92 ba 66 81 f3 16 9b 69-7d 4d b7 9d bd 6a eb 49   ..f....i}M...j.I
0020 - 20 7c 00                                           |.
R
RENEGOTIATING
SSL_connect:SSL negotiation finished successfully
write to 0x1ffdcac21b0 [0x1ffde6c4d10] (233 bytes => 233 (0xE9))
0000 - 16 03 03 00 e4 8a 5b 61-16 92 1b a3 41 dd 1f 02   ......[a....A...
0010 - d9 67 ec ef 79 34 93 73-bf f7 39 96 ab fd 05 19   .g..y4.s..9.....
0020 - 38 ff ae b0 60 7f e1 13-67 01 f4 ba 04 7d d4 1d   8...`...g....}..
0030 - cc c8 c5 23 1b 73 44 15-0d 8e 7f 06 17 92 3d 11   ...#.sD.......=.
0040 - 91 e9 f2 33 7b 46 e2 9e-a8 b8 c0 51 bf a3 49 de   ...3{F.....Q..I.
0050 - b8 e3 3c 26 65 58 e2 1f-75 45 ca 89 e2 e6 1a 2e   ..<&eX..uE......
0060 - 72 06 97 a3 b2 0b ad 5e-e3 12 85 5b 42 a4 04 87   r......^...[B...
0070 - bc 73 23 72 c3 03 bd db-f9 1b 5e 18 ec cc 9b 1c   .s#r......^.....
0080 - c6 9f 59 93 72 0a 64 fd-46 0a 82 b0 92 54 e9 10   ..Y.r.d.F....T..
0090 - c3 f0 33 9b a0 2b 2b e6-4e 21 11 7c 6e b9 62 be   ..3..++.N!.|n.b.
00a0 - e8 22 81 fb 0a 51 4b 42-f5 ad e9 d8 42 d6 96 31   ."...QKB....B..1
00b0 - 1b 70 ef 23 e8 e2 d0 57-52 d1 c7 50 6b 49 ad 65   .p.#...WR..PkI.e
00c0 - 90 31 41 92 9b 26 97 2c-c2 1e f8 b6 50 2b e8 3e   .1A..&.,....P+.>
00d0 - 1f dd 80 8f 78 1c 56 09-34 cb 7f c1 70 b1 be ac   ....x.V.4...p...
00e0 - 77 2a 95 87 8f fb 77 a8-a9                        w*....w..
SSL_connect:SSLv3/TLS write client hello
read from 0x1ffdcac21b0 [0x1ffde6c6d33] (5 bytes => 5 (0x5))
0000 - 15 03 03 00 1a                                    .....
read from 0x1ffdcac21b0 [0x1ffde6c6d38] (26 bytes => 26 (0x1A))
0000 - 55 41 cc 48 47 9a 42 e1-64 9f 2b 27 ff dd 03 66   UA.HG.B.d.+'...f
0010 - f9 29 5b 37 38 84 0c db-e7 79                     .)[78....y
SSL3 alert read:warning:no renegotiation
write to 0x1ffdcac21b0 [0x1ffde6c4d10] (31 bytes => 31 (0x1F))
0000 - 15 03 03 00 1a 8a 5b 61-16 92 1b a3 42 5c 42 d2   ......[a....B\B.
0010 - 65 f4 e3 4e 1f 9a 91 38-fc 3c b0 4e f2 f9 42      e..N...8.<.N..B
SSL3 alert write:fatal:handshake failure
SSL_connect:error in error
2C3B0000:error:0A000153:SSL routines:ssl3_read_bytes:no renegotiation:../openssl-3.4.0/ssl/record/rec_layer_s3.c:925:
read from 0x1ffdcac21b0 [0x1ffdca07cf0] (16384 bytes => 0)
````

[TOC](README.md)
