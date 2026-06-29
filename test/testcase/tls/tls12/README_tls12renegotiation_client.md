#### client

````
$ openssl s_client -connect localhost:9000 -state -debug -keylogfile sslkeylog -tls1_2
Connecting to ::1
CONNECTED(000001D8)
SSL_connect:before SSL initialization
write to 0x1703a001ca0 [0x1703bdd5d20] (197 bytes => 197 (0xC5))
0000 - 16 03 01 00 c0 01 00 00-bc 03 03 61 15 ec ae 8b   ...........a....
0010 - 32 e5 a8 bf b9 88 70 06-8d 71 5c 0b ed 91 1f de   2.....p..q\.....
0020 - a1 57 75 64 2e 9d b8 db-16 0e 27 00 00 36 c0 2c   .Wud......'..6.,
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
read from 0x1703a001ca0 [0x1703bddadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 41                                    ....A
read from 0x1703a001ca0 [0x1703bddadf8] (65 bytes => 65 (0x41))
0000 - 02 00 00 3d 03 03 ea 57-d2 b5 45 e3 fa 38 5e 8d   ...=...W..E..8^.
0010 - e3 7c 78 bf 56 bf 27 28-99 1c 8a 95 f3 e8 44 4f   .|x.V.'(......DO
0020 - 57 4e 47 52 44 01 00 c0-30 00 00 15 ff 01 00 01   WNGRD...0.......
0030 - 00 00 0b 00 04 03 00 01-02 00 23 00 00 00 17 00   ..........#.....
0040 - 00                                                .
SSL_connect:SSLv3/TLS write client hello
Can't use SSL_get_servername
read from 0x1703a001ca0 [0x1703bddadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 03 6a                                    ....j
read from 0x1703a001ca0 [0x1703bddadf8] (874 bytes => 874 (0x36A))
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
read from 0x1703a001ca0 [0x1703bddadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 01 2c                                    ....,
read from 0x1703a001ca0 [0x1703bddadf8] (300 bytes => 300 (0x12C))
0000 - 0c 00 01 28 03 00 1d 20-b3 71 d4 f1 88 bc d8 95   ...(... .q......
0010 - 8c 9d 5d 9d 16 5a da e4-1f ac 93 0a fa c1 11 43   ..]..Z.........C
0020 - 31 53 33 22 1c 7b b5 43-08 04 01 00 1d 6b 83 aa   1S3".{.C.....k..
0030 - 1e e5 42 da 7f e5 7a 33-f7 24 58 f8 af 80 2d 19   ..B...z3.$X...-.
0040 - 55 d2 9b 94 a7 fb 92 81-fe c2 f8 72 84 7e fa c5   U..........r.~..
0050 - 2f bf af 5c 18 a0 fa 11-f4 a8 e7 6a 6c 35 a3 50   /..\.......jl5.P
0060 - df 5e 4f a3 bf f5 96 6d-e9 b8 93 95 92 51 c0 b8   .^O....m.....Q..
0070 - 42 aa 35 82 69 d4 a9 e5-b2 cd 09 0d c1 39 92 31   B.5.i........9.1
0080 - b5 42 93 91 df 66 b0 05-fc 13 0d 2f a6 6b b6 d6   .B...f...../.k..
0090 - 67 48 a9 81 55 58 28 12-f8 08 a7 7c 5c 58 5e f5   gH..UX(....|\X^.
00a0 - 8c 91 1c 85 81 79 6b d3-b5 5c 75 17 f8 32 b6 3c   .....yk..\u..2.<
00b0 - e1 02 a2 41 14 7a d8 e9-4a 20 5a a6 c2 a2 c1 68   ...A.z..J Z....h
00c0 - b0 ac 5e 77 53 00 e6 a7-fd f5 7a dd 82 af 53 45   ..^wS.....z...SE
00d0 - 26 6b 54 c1 a0 11 b9 5a-60 a3 c3 99 76 89 e1 55   &kT....Z`...v..U
00e0 - b7 7b ef a5 51 ea 5c 91-f5 bd c7 1f 10 63 d1 54   .{..Q.\......c.T
00f0 - 43 84 48 4a 60 c8 3c b8-ee 64 a4 a2 6c f5 66 75   C.HJ`.<..d..l.fu
0100 - 8e 36 93 ce e5 3d e9 a3-72 82 5b 35 fc ba 8f a4   .6...=..r.[5....
0110 - 5b 56 83 f2 2f 47 ea de-9d e4 5a f0 a6 15 29 eb   [V../G....Z...).
0120 - f1 0e fc 90 d1 04 5c 41-eb 13 e9 70               ......\A...p
SSL_connect:SSLv3/TLS read server certificate
read from 0x1703a001ca0 [0x1703bddadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 04                                    .....
read from 0x1703a001ca0 [0x1703bddadf8] (4 bytes => 4 (0x4))
0000 - 0e 00 00 00                                       ....
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client key exchange
SSL_connect:SSLv3/TLS write change cipher spec
write to 0x1703a001ca0 [0x1703bdd5d20] (93 bytes => 93 (0x5D))
0000 - 16 03 03 00 25 10 00 00-21 20 73 3c 5e ff 4c b1   ....%...! s<^.L.
0010 - 22 cd 39 5c da 22 24 32-28 4c be 10 dc 37 97 a8   ".9\."$2(L...7..
0020 - 12 af cd be d6 45 12 06-b6 15 14 03 03 00 01 01   .....E..........
0030 - 16 03 03 00 28 9d a5 b3-05 32 8d cd 77 94 34 be   ....(....2..w.4.
0040 - df 9b e0 e6 94 c4 85 8c-ee 9a 2c 7b c9 77 61 a7   ..........,{.wa.
0050 - c6 36 38 f4 0b d4 6f 61-bc f9 7d 44 55            .68...oa..}DU
SSL_connect:SSLv3/TLS write finished
read from 0x1703a001ca0 [0x1703bddadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 ba                                    .....
read from 0x1703a001ca0 [0x1703bddadf8] (186 bytes => 186 (0xBA))
0000 - 04 00 00 b6 00 00 1c 20-00 b0 c7 ea d5 c3 e3 32   ....... .......2
0010 - 93 93 f0 47 bd b6 e0 85-af ed d0 80 70 04 7e cd   ...G........p.~.
0020 - 88 4e 00 3a 97 81 2b 0c-f9 da 2f 0c 52 d1 e2 e8   .N.:..+.../.R...
0030 - 70 08 fd 22 ed 44 c6 26-44 67 1f cf eb 68 70 a8   p..".D.&Dg...hp.
0040 - 54 2d 22 71 59 fe 91 1f-af 49 a9 be 12 90 8d 57   T-"qY....I.....W
0050 - e1 09 84 f6 3f f5 f9 86-6b ee 37 4c f9 cd a5 a5   ....?...k.7L....
0060 - 65 4c ee 94 40 18 28 b8-9e 2b 03 26 7d a8 02 d0   eL..@.(..+.&}...
0070 - 51 76 f1 e5 13 76 c4 00-40 92 55 c3 cb 2b 21 a9   Qv...v..@.U..+!.
0080 - 26 81 84 7b a9 13 bf aa-e5 94 fa 11 c8 47 7b 06   &..{.........G{.
0090 - ce 5d 34 f5 83 86 98 cb-29 3c 33 be 94 8e 14 40   .]4.....)<3....@
00a0 - 5c a5 13 21 48 0f 91 5f-54 34 4f da 7a 08 d1 cc   \..!H.._T4O.z...
00b0 - 01 da 73 0f b1 a4 da 3a-22 f3                     ..s....:".
SSL_connect:SSLv3/TLS write finished
read from 0x1703a001ca0 [0x1703bddadf3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x1703a001ca0 [0x1703bddadf8] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_connect:SSLv3/TLS read server session ticket
read from 0x1703a001ca0 [0x1703bdd6d33] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 28                                    ....(
read from 0x1703a001ca0 [0x1703bdd6d38] (40 bytes => 40 (0x28))
0000 - 26 ad a0 79 e8 34 cf cc-70 35 67 7e f6 46 39 2b   &..y.4..p5g~.F9+
0010 - fb 0f d0 8f 68 bb a1 8d-7c 58 7a 43 e4 df 82 d8   ....h...|XzC....
0020 - 6c 95 cf da 53 9c 2d ca-                          l...S.-.
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
    Session-ID: A3349E1DB56D141AFF7E349FA158980DE5D6DB2B435272A494ADE4E60C396ADB
    Session-ID-ctx:
    Master-Key: 987CE499B21747D6D81E6795D58E6112E8BA22EC1F10F31B9623A126A09FE51FB14B3840455C5A53463D17C2F5627005
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - c7 ea d5 c3 e3 32 93 93-f0 47 bd b6 e0 85 af ed   .....2...G......
    0010 - d0 80 70 04 7e cd 88 4e-00 3a 97 81 2b 0c f9 da   ..p.~..N.:..+...
    0020 - 2f 0c 52 d1 e2 e8 70 08-fd 22 ed 44 c6 26 44 67   /.R...p..".D.&Dg
    0030 - 1f cf eb 68 70 a8 54 2d-22 71 59 fe 91 1f af 49   ...hp.T-"qY....I
    0040 - a9 be 12 90 8d 57 e1 09-84 f6 3f f5 f9 86 6b ee   .....W....?...k.
    0050 - 37 4c f9 cd a5 a5 65 4c-ee 94 40 18 28 b8 9e 2b   7L....eL..@.(..+
    0060 - 03 26 7d a8 02 d0 51 76-f1 e5 13 76 c4 00 40 92   .&}...Qv...v..@.
    0070 - 55 c3 cb 2b 21 a9 26 81-84 7b a9 13 bf aa e5 94   U..+!.&..{......
    0080 - fa 11 c8 47 7b 06 ce 5d-34 f5 83 86 98 cb 29 3c   ...G{..]4.....)<
    0090 - 33 be 94 8e 14 40 5c a5-13 21 48 0f 91 5f 54 34   3....@\..!H.._T4
    00a0 - 4f da 7a 08 d1 cc 01 da-73 0f b1 a4 da 3a 22 f3   O.z.....s....:".

    Start Time: 1746849245
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: yes
---
test
write to 0x1703a001ca0 [0x1703bdeaaa3] (35 bytes => 35 (0x23))
0000 - 17 03 03 00 1e 9d a5 b3-05 32 8d cd 78 bb 0b 7d   .........2..x..}
0010 - df 87 0e a5 5c 57 08 5a-d4 5e 68 30 41 18 fa cc   ....\W.Z.^h0A...
0020 - df 65 4e                                          .eN
R
RENEGOTIATING
SSL_connect:SSL negotiation finished successfully
write to 0x1703a001ca0 [0x1703bdd4d10] (233 bytes => 233 (0xE9))
0000 - 16 03 03 00 e4 9d a5 b3-05 32 8d cd 79 5b e1 71   .........2..y[.q
0010 - 23 22 af cb 28 68 d8 f9-32 b7 05 d7 1d 05 ee 44   #"..(h..2......D
0020 - a9 ea 96 89 52 a6 57 30-22 20 1b 0e e4 28 ce c1   ....R.W0" ...(..
0030 - d8 35 3e 9e ae 68 ab 0e-db 77 16 d3 a5 ff fb e6   .5>..h...w......
0040 - ea 57 56 7f f1 84 03 b8-eb 5a 9c 96 e8 c4 e1 08   .WV......Z......
0050 - 23 03 44 7f 88 b1 58 87-5a 93 51 d1 2e ea ff c6   #.D...X.Z.Q.....
0060 - d0 9e 0a 3e ff a2 ad 4d-b8 fd 0f 5b fb cd 72 d6   ...>...M...[..r.
0070 - a8 a8 28 07 20 c5 f7 9c-c3 90 f9 05 af b5 73 df   ..(. .........s.
0080 - 9f af d4 b0 9f 3a 89 62-26 75 7f 04 bc d4 3b 63   .....:.b&u....;c
0090 - ab 86 38 e9 37 2f 62 9f-b3 16 06 7f 2a 5c a2 55   ..8.7/b.....*\.U
00a0 - 73 40 44 91 b3 13 d0 b6-9b f7 39 49 36 e5 6c b8   s@D.......9I6.l.
00b0 - b8 00 3d 1c fd 21 5c 84-ea 02 96 d0 36 94 e0 f6   ..=..!\.....6...
00c0 - 00 3b bd ee bf 73 d1 e1-f6 36 bf 40 57 53 44 0b   .;...s...6.@WSD.
00d0 - 00 ea da ef 91 10 3a 52-9e 74 31 6d ef b8 e8 df   ......:R.t1m....
00e0 - 6b 72 58 f1 e7 72 44 6b-cd                        krX..rDk.
SSL_connect:SSLv3/TLS write client hello
read from 0x1703a001ca0 [0x1703bdd6d33] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 71                                    ....q
read from 0x1703a001ca0 [0x1703bdd6d38] (113 bytes => 113 (0x71))
0000 - 26 ad a0 79 e8 34 cf cd-a7 43 df 19 4d b6 31 5f   &..y.4...C..M.1_
0010 - 6a a2 f1 fd 08 3e c8 17-84 b1 b4 c7 a3 32 a4 75   j....>.......2.u
0020 - 1b 35 64 fa f1 44 07 ad-8e 70 56 7a 78 0f f1 07   .5d..D...pVzx...
0030 - c3 7f 7b b3 f2 5d 98 aa-66 4e bb d5 30 a1 94 87   ..{..]..fN..0...
0040 - 75 dc 15 f0 9d 54 e4 12-8d f8 e1 66 cc e9 fe 81   u....T.....f....
0050 - 7e 90 ee f1 bc d3 2f 6b-e5 de 89 c2 84 6a cb 6d   ~...../k.....j.m
0060 - c8 70 41 12 02 8f 5d 20-62 e1 61 a7 d9 c5 92 e2   .pA...] b.a.....
0070 - dd                                                .
SSL_connect:SSLv3/TLS write client hello
Can't use SSL_get_servername
read from 0x1703a001ca0 [0x1703bdd6d33] (5 bytes => 5 (0x5))
0000 - 16 03 03 03 82                                    .....
read from 0x1703a001ca0 [0x1703bdd6d38] (898 bytes => 898 (0x382))
0000 - 26 ad a0 79 e8 34 cf ce-ab fe d2 e5 ef bf fb 8e   &..y.4..........
0010 - c5 d4 ee d9 da bd 26 e6-e3 c8 2d 54 fc 6a dd 90   ......&...-T.j..
0020 - 47 47 55 fd 31 6c a9 fd-5e 0e 9e 96 8c ef 94 60   GGU.1l..^......`
0030 - 88 47 7d 90 3e 9c 42 3d-0d a4 8d 30 31 2a 25 de   .G}.>.B=...01*%.
0040 - 14 2c 31 5e 35 88 43 2a-75 f3 63 cd 15 22 3b 61   .,1^5.C*u.c..";a
0050 - ec e4 c8 e2 83 13 5b ed-b4 6e a4 ab 75 08 ee 2f   ......[..n..u../
0060 - d6 9b d7 1c 28 a7 92 08-0b 91 68 fa 58 ef a4 27   ....(.....h.X..'
0070 - 57 fd 20 af a4 66 a4 d3-21 7c 47 ac 15 f8 41 1e   W. ..f..!|G...A.
0080 - 35 99 5c 39 99 0f d0 fa-b1 df e2 c5 5e f1 65 ac   5.\9........^.e.
0090 - 95 cb 4f ef 5b 72 42 f0-e4 b0 b7 4c ac 29 3f 35   ..O.[rB....L.)?5
00a0 - 80 99 8a 2f 8a 60 69 a2-33 24 9f aa 75 27 88 03   .../.`i.3$..u'..
00b0 - 9d d2 6b e2 11 4b 8c db-21 97 0d 42 0e d6 fc b7   ..k..K..!..B....
00c0 - dd ac 86 8a 60 18 58 ba-b6 11 4f 3a 1f 1b 08 5f   ....`.X...O:..._
00d0 - b8 bd 50 08 30 0a 34 d4-46 42 fa 7f c4 92 3f a5   ..P.0.4.FB....?.
00e0 - 7e ec 01 56 cb 41 b0 19-4e 76 4f f8 aa 88 e4 fb   ~..V.A..NvO.....
00f0 - 48 0b ab 93 2d 75 3d b9-d5 2d 55 db fe 5b 86 4f   H...-u=..-U..[.O
0100 - 58 53 b4 42 fa 93 93 f5-b7 6c d9 f8 26 e0 c1 7f   XS.B.....l..&...
0110 - 69 be 19 e2 29 c2 da 8c-60 09 10 1b ec 63 3c c4   i...)...`....c<.
0120 - b6 15 34 bb 69 ec f9 19-14 70 22 c9 8a a5 f1 9c   ..4.i....p".....
0130 - f3 ce 1f e9 2c 70 4a ac-b6 d2 8e 88 1d 6a f8 f7   ....,pJ......j..
0140 - ce 26 d8 8c ad d8 5f c3-f7 46 69 69 c6 1a 10 1f   .&...._..Fii....
0150 - 12 e7 a5 91 68 be eb 5e-b4 8e e6 b0 65 5d 1c 75   ....h..^....e].u
0160 - 64 91 fb 1c 26 b4 be 4f-12 4e 49 eb e9 96 e3 32   d...&..O.NI....2
0170 - ae 3f f1 9c 32 24 70 19-4f 6b 87 e9 b7 b6 92 b4   .?..2$p.Ok......
0180 - 5e 7d 01 f8 73 e6 4e 82-93 78 a6 b7 58 81 6e 91   ^}..s.N..x..X.n.
0190 - 57 30 58 1f e3 76 b8 04-be 13 68 90 aa b7 af e8   W0X..v....h.....
01a0 - db 03 f1 23 b3 ac f9 f9-ac 99 92 c7 e6 f5 fa a3   ...#............
01b0 - ec 5d b3 c8 02 b7 6c 23-82 83 22 af 79 db 4b 18   .]....l#..".y.K.
01c0 - 4b 0c eb 89 5b 29 4c 89-9e ac b3 09 7e 4d 94 da   K...[)L.....~M..
01d0 - 7c 2b 59 ca 82 9b ab 2a-e4 70 aa ec 88 ed d8 30   |+Y....*.p.....0
01e0 - 0b c4 88 d3 b8 89 03 e8-b7 48 7f 88 7b f4 da a3   .........H..{...
01f0 - 9c b3 90 e7 23 87 bf fe-e0 5d ac b1 de f3 78 87   ....#....]....x.
0200 - 6a b6 bb c2 02 a3 26 ba-77 e0 dc 70 c5 ac a2 e2   j.....&.w..p....
0210 - 4f a8 b5 c5 82 ae 66 b2-1b 45 20 41 ab 33 c8 94   O.....f..E A.3..
0220 - 80 e9 1e 96 e2 ce d2 cb-b5 50 78 4f 9b 65 2d 94   .........PxO.e-.
0230 - 8d 4a b5 7e 86 bb 94 20-cf 77 55 4c a7 aa 59 ac   .J.~... .wUL..Y.
0240 - e7 68 64 bf db 36 38 69-cc 52 19 d0 b9 a0 f7 4b   .hd..68i.R.....K
0250 - b0 0c a8 e2 24 22 7b 09-17 1a 6c df b0 40 02 ee   ....$"{...l..@..
0260 - 20 6c 75 d9 df d7 7f 8e-39 40 b2 a5 0b 39 0d ee    lu.....9@...9..
0270 - 0e fd 19 d6 e8 18 da 6f-66 71 6f 6c c1 7e f6 06   .......ofqol.~..
0280 - a3 13 e8 a1 35 58 23 1a-dc f7 57 3c b6 94 1b 02   ....5X#...W<....
0290 - ca 96 84 ec 87 9a a8 4f-5a b2 ac 17 b4 a0 67 e9   .......OZ.....g.
02a0 - ed 91 99 96 05 00 30 fc-b5 85 a3 47 5f 7d a4 b9   ......0....G_}..
02b0 - ca 23 4c 03 a5 17 14 b0-82 24 8e 1a 78 50 67 82   .#L......$..xPg.
02c0 - 7c 60 f9 55 1e bf 8a 06-f7 2c de 65 c9 4a 9e 49   |`.U.....,.e.J.I
02d0 - d3 ab af 9f 31 3c 6a 8a-0f f9 d8 10 ef 07 f7 c3   ....1<j.........
02e0 - e7 63 57 b4 be 85 fe 94-31 87 4a dd 1f 65 90 e7   .cW.....1.J..e..
02f0 - d7 66 6b fc 18 8d 9a d1-02 bf 0a 32 cb bf d5 7b   .fk........2...{
0300 - 3f 2d bd 63 db b6 7d 4a-e7 41 f3 3c 2d 66 54 5e   ?-.c..}J.A.<-fT^
0310 - cb b2 8a d1 de 5b e8 c7-e2 f6 2f ed c9 08 fc 4e   .....[..../....N
0320 - a5 c9 e1 58 81 54 9a 18-9c 51 69 cf d4 22 50 7d   ...X.T...Qi.."P}
0330 - 0c 71 ad b6 2d 36 cd 0f-97 50 3d 12 d7 20 58 c3   .q..-6...P=.. X.
0340 - f2 b0 89 86 c0 86 7c 96-e8 2c e7 df 0e f3 f2 3d   ......|..,.....=
0350 - a1 84 03 d3 d0 55 97 2a-d8 0e ce e0 26 e2 12 a1   .....U.*....&...
0360 - 43 66 77 7f be 33 1e 9f-da dd 2b c2 65 38 c7 3c   Cfw..3....+.e8.<
0370 - 84 a6 2d aa 2e 61 cb fe-52 6e cb 6c bb 0b 3d 3b   ..-..a..Rn.l..=;
0380 - 8e c9                                             ..
SSL_connect:SSLv3/TLS read server hello
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify return:1
read from 0x1703a001ca0 [0x1703bdd6d33] (5 bytes => 5 (0x5))
0000 - 16 03 03 01 44                                    ....D
read from 0x1703a001ca0 [0x1703bdd6d38] (324 bytes => 324 (0x144))
0000 - 26 ad a0 79 e8 34 cf cf-a2 f5 a8 67 6c 70 7b f8   &..y.4.....glp{.
0010 - 2c 76 e0 93 96 3b cb 4e-16 53 2e 99 bd 9a d6 10   ,v...;.N.S......
0020 - b6 a8 81 56 21 42 c9 f6-46 ea 2d cc 5b 4f 8e f0   ...V!B..F.-.[O..
0030 - f5 36 1a 16 ca 87 3b b4-ff d4 81 b4 42 41 60 ac   .6....;.....BA`.
0040 - bd d2 5f b5 df c2 36 8b-4a 1d 57 1a c0 f9 c8 4e   .._...6.J.W....N
0050 - 14 c5 bd f1 20 ac fd b2-dd 1c f7 e5 dd 62 1b 95   .... ........b..
0060 - 7e 05 f2 db c5 7a 8e 14-6a e9 cb e7 b5 be d8 35   ~....z..j......5
0070 - 1d be cd 1e 39 0b 3b a2-e1 6b 68 4b ef f0 a9 c7   ....9.;..khK....
0080 - 08 0f e0 29 f4 84 6f 6d-54 d7 f5 df 91 79 e7 11   ...)..omT....y..
0090 - dd 51 f4 02 95 ec ea ff-05 a3 a9 29 d6 21 e7 2e   .Q.........).!..
00a0 - 82 73 c0 b2 6d ab 91 35-72 e1 89 f8 65 21 20 91   .s..m..5r...e! .
00b0 - df 92 d7 2c 73 08 6c bf-04 18 37 c3 a4 86 00 72   ...,s.l...7....r
00c0 - 55 bd 93 e4 ac e9 19 31-af c0 6e 64 ca 40 82 78   U......1..nd.@.x
00d0 - 42 41 4d 1e 95 0c 97 15-c2 ae 97 74 0c a2 c3 24   BAM........t...$
00e0 - 37 3d 16 c9 26 0f d4 db-e9 80 f6 0e 6b 9e 99 a1   7=..&.......k...
00f0 - 86 a9 66 88 f0 76 6a cd-32 9d 2c 9c c0 87 b4 4d   ..f..vj.2.,....M
0100 - e6 06 39 5a ba 7e 9c dc-31 df fd a0 e7 0f ae 48   ..9Z.~..1......H
0110 - 26 1f 12 6f 27 5d 08 8e-c8 0f 9a 9e 46 75 28 32   &..o']......Fu(2
0120 - 97 30 c2 b8 3f fc 29 48-a6 a5 d5 5c 96 66 5a cc   .0..?.)H...\.fZ.
0130 - 23 69 de 31 42 f0 ad c0-2e ac 24 0e 4a 40 37 7e   #i.1B.....$.J@7~
0140 - 98 2b 86 a8                                       .+..
SSL_connect:SSLv3/TLS read server certificate
read from 0x1703a001ca0 [0x1703bdd6d33] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 1c                                    .....
read from 0x1703a001ca0 [0x1703bdd6d38] (28 bytes => 28 (0x1C))
0000 - 26 ad a0 79 e8 34 cf d0-8c 6c 23 18 d2 04 f1 b5   &..y.4...l#.....
0010 - b6 b0 94 b0 1f d9 5b 75-46 f0 0c 54               ......[uF..T
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client key exchange
SSL_connect:SSLv3/TLS write change cipher spec
write to 0x1703a001ca0 [0x1703bdd4d10] (141 bytes => 141 (0x8D))
0000 - 16 03 03 00 3d 9d a5 b3-05 32 8d cd 7a 0a 8c 68   ....=....2..z..h
0010 - 2c 36 f4 f2 d7 fc a9 bc-d5 e6 d7 5e 10 6a 47 78   ,6.........^.jGx
0020 - d8 0d 32 35 c3 c0 fd 06-27 df 52 06 95 d8 08 bd   ..25....'.R.....
0030 - 9e ec 9f 35 4a 47 21 5b-e6 f7 cf 22 3b e5 27 b3   ...5JG![...";.'.
0040 - d5 f7 14 03 03 00 19 9d-a5 b3 05 32 8d cd 7b 29   ...........2..{)
0050 - d7 28 0f f3 df 99 74 cb-9f e6 c9 3c 8c 7e 2f 79   .(....t....<.~/y
0060 - 16 03 03 00 28 66 4e ec-00 9d 31 e0 90 0e 40 2f   ....(fN...1...@/
0070 - c3 56 8e 1d 26 14 f2 d3-a5 c0 dc 23 3b ae 06 9a   .V..&......#;...
0080 - 77 41 b6 0f a3 25 fb b5-7e f8 6d 24 ff            wA...%..~.m$.
SSL_connect:SSLv3/TLS write finished
read from 0x1703a001ca0 [0x1703bdd6d33] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 d2                                    .....
read from 0x1703a001ca0 [0x1703bdd6d38] (210 bytes => 210 (0xD2))
0000 - 26 ad a0 79 e8 34 cf d1-ca 41 fc 47 40 e0 06 8c   &..y.4...A.G@...
0010 - 05 c9 6e 8b 78 34 8a 90-c0 0e cc a4 71 77 b0 5b   ..n.x4......qw.[
0020 - 2c c9 0d 71 ee 90 dc 5d-9f a3 92 ea 5c 6f 9c 0f   ,..q...]....\o..
0030 - ae 81 30 d0 4e 31 bc cb-7f 95 66 2d 3a bd 3b 83   ..0.N1....f-:.;.
0040 - 54 97 8b 0c 6a 45 81 7a-9e f0 56 3c 7e 25 b0 e4   T...jE.z..V<~%..
0050 - 18 9b 5a bb dc f7 dc 09-e9 f8 af bc a1 52 ae e3   ..Z..........R..
0060 - 9f f1 df e4 b8 4a d0 41-e9 23 e8 48 a1 5a 85 e2   .....J.A.#.H.Z..
0070 - 4e 84 be 9e 25 2f f7 7a-c6 42 72 92 23 e7 93 7c   N...%/.z.Br.#..|
0080 - 80 b1 30 67 2b 49 61 4d-2f 91 af b4 31 b2 7b 0e   ..0g+IaM/...1.{.
0090 - 85 59 07 47 f8 2b b5 97-22 3b 5a f3 40 77 22 b6   .Y.G.+..";Z.@w".
00a0 - be b6 62 3c bd fb a5 d6-2d 62 e6 f9 0d 6f 0b c4   ..b<....-b...o..
00b0 - ba 9b 01 49 66 69 d3 fb-13 97 7b 98 fb c6 52 31   ...Ifi....{...R1
00c0 - 82 f8 55 8a 95 ba bc c7-f6 47 0a ee 96 78 a7 18   ..U......G...x..
00d0 - dd 8a                                             ..
SSL_connect:SSLv3/TLS write finished
read from 0x1703a001ca0 [0x1703bdd6d33] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 19                                    .....
read from 0x1703a001ca0 [0x1703bdd6d38] (25 bytes => 25 (0x19))
0000 - 26 ad a0 79 e8 34 cf d2-5a ac 12 67 ad 35 4e 56   &..y.4..Z..g.5NV
0010 - 0f ff 98 65 05 52 e3 a4-55                        ...e.R..U
SSL_connect:SSLv3/TLS read server session ticket
read from 0x1703a001ca0 [0x1703bdd6553] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 28                                    ....(
read from 0x1703a001ca0 [0x1703bdd6558] (40 bytes => 40 (0x28))
0000 - 55 09 bc ad b1 c1 c8 1e-d3 a8 ce c1 a0 29 40 51   U............)@Q
0010 - 01 48 ea 67 2b 49 ce 50-00 66 37 d6 c8 e8 76 54   .H.g+I.P.f7...vT
0020 - aa b5 fa f7 da 07 e4 17-                          ........
SSL_connect:SSLv3/TLS read change cipher spec
SSL_connect:SSLv3/TLS read finished
test
write to 0x1703a001ca0 [0x1703bde9573] (35 bytes => 35 (0x23))
0000 - 17 03 03 00 1e 66 4e ec-00 9d 31 e0 91 bd 95 c6   .....fN...1.....
0010 - 3d 32 fd 84 8f 60 84 bb-ae 3b c4 ce d4 43 78 d9   =2...`...;...Cx.
0020 - 0e 3c 13                                          .<.
Q
DONE
write to 0x1703a001ca0 [0x1703bde9573] (31 bytes => 31 (0x1F))
0000 - 15 03 03 00 1a 66 4e ec-00 9d 31 e0 92 7d af 0b   .....fN...1..}..
0010 - 2e 41 88 1b fa 68 d3 fe-06 04 c3 66 0d b6 8a      .A...h.....f...
SSL3 alert write:warning:close notify
read from 0x1703a001ca0 [0x17039f47cf0] (16384 bytes => 31 (0x1F))
0000 - 15 03 03 00 1a 55 09 bc-ad b1 c1 c8 1f 08 04 95   .....U..........
0010 - 36 7c 38 25 7d 7d 37 45-14 7f 3b 17 39 a5 4c      6|8%}}7E..;.9.L
read from 0x1703a001ca0 [0x17039f47cf0] (16384 bytes => 0)
````

[TOC](README.md)
