#### tls12etm.pcapng - client

````
$ openssl s_client -connect localhost:9000 -state -debug -keylogfile sslkeylog -tls1_2
Connecting to ::1
CONNECTED(00000074)
SSL_connect:before SSL initialization
write to 0x17eebe223f0 [0x17eec2e5d20] (197 bytes => 197 (0xC5))
0000 - 16 03 01 00 c0 01 00 00-bc 03 03 96 89 88 b1 0e   ................
0010 - d8 d7 2b e8 7f ae a5 64-a0 d8 15 a4 62 f1 41 ca   ..+....d....b.A.
0020 - 80 19 ad c5 33 ae c9 89-15 2b ff 00 00 36 c0 2c   ....3....+...6.,
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
read from 0x17eebe223f0 [0x17eec2eadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 45                                    ....E
read from 0x17eebe223f0 [0x17eec2eadf8] (69 bytes => 69 (0x45))
0000 - 02 00 00 41 03 03 65 8b-66 a2 af 4e 1b 13 dd 8b   ...A..e.f..N....
0010 - 50 51 78 90 21 13 a5 bf-b0 21 ee 8b 24 30 cf ab   PQx.!....!..$0..
0020 - 97 20 b1 37 6d 63 00 c0-27 00 00 19 ff 01 00 01   . .7mc..'.......
0030 - 00 00 0b 00 04 03 00 01-02 00 23 00 00 00 16 00   ..........#.....
0040 - 00 00 17 00 00                                    .....
SSL_connect:SSLv3/TLS write client hello
Can't use SSL_get_servername
read from 0x17eebe223f0 [0x17eec2eadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 03 6a                                    ....j
read from 0x17eebe223f0 [0x17eec2eadf8] (874 bytes => 874 (0x36A))
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
read from 0x17eebe223f0 [0x17eec2eadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 01 2c                                    ....,
read from 0x17eebe223f0 [0x17eec2eadf8] (300 bytes => 300 (0x12C))
0000 - 0c 00 01 28 03 00 1d 20-8e 93 3b 4c a7 02 61 06   ...(... ..;L..a.
0010 - 89 0b e2 d0 3e 0e 05 64-a7 37 9e b8 b9 0b 5b 3d   ....>..d.7....[=
0020 - 68 2c 55 f4 a5 ef 46 67-08 04 01 00 50 ec 45 47   h,U...Fg....P.EG
0030 - 75 24 3b 9c af e9 2f 3a-af 50 bb aa 85 f0 67 5c   u$;.../:.P....g\
0040 - b6 cd 12 e6 7d 01 1a 3f-a5 f4 0a 38 a2 4b 7d 90   ....}..?...8.K}.
0050 - b1 3f 7e 41 3b c6 d2 e0-c6 97 39 6f 22 aa 2b ee   .?~A;.....9o".+.
0060 - 09 d6 83 b9 ab 77 c0 a4-63 e8 cb f2 0a 67 1d 72   .....w..c....g.r
0070 - 71 b8 7a a9 36 b4 90 ad-6d 22 25 01 ee 52 3b ce   q.z.6...m"%..R;.
0080 - b9 56 8b f6 46 38 cf d9-dc d5 30 8e 3c aa e8 05   .V..F8....0.<...
0090 - d7 05 c4 bb 25 33 43 8f-a7 5c 72 a6 c1 c1 f9 3d   ....%3C..\r....=
00a0 - 89 a8 9c b2 15 86 82 11-0e 1f 9c 00 12 6f cd 64   .............o.d
00b0 - 01 57 08 fa 5a 85 f6 5a-be 58 e4 18 20 79 d8 13   .W..Z..Z.X.. y..
00c0 - 6a cf 9a 3a 81 b7 ba 08-e4 4c ed e6 53 f9 f9 a5   j..:.....L..S...
00d0 - 7d 25 27 b7 84 a2 73 86-83 fe 28 d5 50 c4 ad c6   }%'...s...(.P...
00e0 - c2 10 24 f7 89 ec b1 18-a7 75 84 ef d5 52 08 dc   ..$......u...R..
00f0 - 6d 74 0e 99 a7 2e 0b cf-af 85 3b c7 15 a3 52 29   mt........;...R)
0100 - 26 19 d0 cf fc 29 f2 1d-d8 59 b1 5d 4a 54 2b 9e   &....)...Y.]JT+.
0110 - 1e dd 52 fe d8 74 a2 78-ca f5 1b c8 3a c1 06 16   ..R..t.x....:...
0120 - ad 35 4a 84 be 16 2b c6-10 a8 b2 f7               .5J...+.....
SSL_connect:SSLv3/TLS read server certificate
read from 0x17eebe223f0 [0x17eec2eadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 04                                    .....
read from 0x17eebe223f0 [0x17eec2eadf8] (4 bytes => 4 (0x4))
0000 - 0e 00 00 00                                       ....
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client key exchange
SSL_connect:SSLv3/TLS write change cipher spec
write to 0x17eebe223f0 [0x17eec2e5d20] (133 bytes => 133 (0x85))
0000 - 16 03 03 00 25 10 00 00-21 20 86 be ac 52 20 97   ....%...! ...R .
0010 - 62 d5 c1 50 61 5c 9b c5-ba b2 11 89 6c 70 a2 e8   b..Pa\......lp..
0020 - 21 27 b8 80 f4 a1 b1 03-3a 28 14 03 03 00 01 01   !'......:(......
0030 - 16 03 03 00 50 b2 08 4a-5b 1d d6 15 cd 05 6d 1f   ....P..J[.....m.
0040 - 28 8f b8 e5 7b 7e eb d2-6f bb 00 18 32 c0 6c de   (...{~..o...2.l.
0050 - 4b 8f a4 77 10 43 71 e5-ba 2a 09 1b 70 3b bc 80   K..w.Cq..*..p;..
0060 - 69 bc 97 bc 2d d0 d2 36-fa 30 89 55 3b 17 e9 6e   i...-..6.0.U;..n
0070 - c6 a4 64 10 c0 00 2d ab-9e 5c e6 df b4 a8 53 9c   ..d...-..\....S.
0080 - 90 63 48 d9 ab                                    .cH..
SSL_connect:SSLv3/TLS write finished
read from 0x17eebe223f0 [0x17eec2eadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 ba                                    .....
read from 0x17eebe223f0 [0x17eec2eadf8] (186 bytes => 186 (0xBA))
0000 - 04 00 00 b6 00 00 1c 20-00 b0 96 67 2d fe 2d c6   ....... ...g-.-.
0010 - 99 a8 e9 d1 0f 5a 23 4b-99 af 2a f6 45 88 e7 d5   .....Z#K..*.E...
0020 - 34 6c 9c 09 62 46 73 32-9a dc a9 e8 0b 1c f0 77   4l..bFs2.......w
0030 - b2 e7 cf e8 a1 2c c9 39-34 31 9a af b1 95 e3 b8   .....,.941......
0040 - 4d 78 96 d1 7d 12 4d c6-d7 72 34 1d 3c e5 56 07   Mx..}.M..r4.<.V.
0050 - f1 92 a2 4a ed 9e cb 0a-b3 e6 ea a5 4b fb 14 5e   ...J........K..^
0060 - 2f 93 e6 0e 1b 04 9c c1-54 64 4b c3 b5 d0 50 0a   /.......TdK...P.
0070 - 59 19 9e 42 5a 7f e7 ac-80 f7 c7 2f 06 74 50 3d   Y..BZ....../.tP=
0080 - 5b 2d 34 a5 4f e6 2a 14-74 42 91 a0 4c 51 00 7a   [-4.O.*.tB..LQ.z
0090 - e1 41 e2 b5 c2 a0 8b 25-a6 8e 64 fd 4a 82 21 22   .A.....%..d.J.!"
00a0 - ff 76 eb 72 ce ed 26 80-d7 13 27 48 cd d1 da 89   .v.r..&...'H....
00b0 - d8 fc d8 fe 47 0b 4c 5c-93 b0                     ....G.L\..
SSL_connect:SSLv3/TLS write finished
read from 0x17eebe223f0 [0x17eec2eadf3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x17eebe223f0 [0x17eec2eadf8] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_connect:SSLv3/TLS read server session ticket
read from 0x17eebe223f0 [0x17eec2e8d43] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 50                                    ....P
read from 0x17eebe223f0 [0x17eec2e8d48] (80 bytes => 80 (0x50))
0000 - aa 69 b7 80 25 eb 0b 3d-f4 0c 35 dc 01 a8 95 fc   .i..%..=..5.....
0010 - d2 53 66 af 6b b1 83 46-a7 27 5f 5c 48 2d 62 39   .Sf.k..F.'_\H-b9
0020 - 80 c2 b3 84 20 c1 ea ba-bb b2 08 2a 41 c9 e1 e1   .... ......*A...
0030 - 29 a5 ce c9 a8 66 eb f1-f8 ef e4 e5 62 86 be e2   )....f......b...
0040 - 8a b6 c6 93 42 92 4f 2b-76 91 e7 9e 40 f4 33 31   ....B.O+v...@.31
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
SSL handshake has read 1549 bytes and written 330 bytes
Verification error: unable to verify the first certificate
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES128-SHA256
Protocol: TLSv1.2
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES128-SHA256
    Session-ID: BAA6E64595379987438B33FE734229ADCB2B6B1E333FC75E35B6BCCC145B99A7
    Session-ID-ctx:
    Master-Key: 3A3847A4D20F9766FF81040B9DB89F85F56B1B9526AFC626C0138E5B89D62C74680AF78BA4D827EE38989518845BC985
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 96 67 2d fe 2d c6 99 a8-e9 d1 0f 5a 23 4b 99 af   .g-.-......Z#K..
    0010 - 2a f6 45 88 e7 d5 34 6c-9c 09 62 46 73 32 9a dc   *.E...4l..bFs2..
    0020 - a9 e8 0b 1c f0 77 b2 e7-cf e8 a1 2c c9 39 34 31   .....w.....,.941
    0030 - 9a af b1 95 e3 b8 4d 78-96 d1 7d 12 4d c6 d7 72   ......Mx..}.M..r
    0040 - 34 1d 3c e5 56 07 f1 92-a2 4a ed 9e cb 0a b3 e6   4.<.V....J......
    0050 - ea a5 4b fb 14 5e 2f 93-e6 0e 1b 04 9c c1 54 64   ..K..^/.......Td
    0060 - 4b c3 b5 d0 50 0a 59 19-9e 42 5a 7f e7 ac 80 f7   K...P.Y..BZ.....
    0070 - c7 2f 06 74 50 3d 5b 2d-34 a5 4f e6 2a 14 74 42   ./.tP=[-4.O.*.tB
    0080 - 91 a0 4c 51 00 7a e1 41-e2 b5 c2 a0 8b 25 a6 8e   ..LQ.z.A.....%..
    0090 - 64 fd 4a 82 21 22 ff 76-eb 72 ce ed 26 80 d7 13   d.J.!".v.r..&...
    00a0 - 27 48 cd d1 da 89 d8 fc-d8 fe 47 0b 4c 5c 93 b0   'H........G.L\..

    Start Time: 1744421673
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: yes
---
hello
write to 0x17eebe223f0 [0x17eec2fa6e3] (69 bytes => 69 (0x45))
0000 - 17 03 03 00 40 94 b3 62-f1 1e 8d 44 5d 51 bb 33   ....@..b...D]Q.3
0010 - 6b bd 23 65 75 f8 7e b6-4f 32 e9 fe 23 16 a3 7f   k.#eu.~.O2..#...
0020 - 05 5f 6f 54 66 49 a0 05-59 df e3 9d 94 d8 82 9f   ._oTfI..Y.......
0030 - 85 e7 76 49 14 73 48 d7-e3 9e 02 e3 f6 20 f8 d7   ..vI.sH...... ..
0040 - b2 95 09 c0 6a                                    ....j
Q
DONE
write to 0x17eebe223f0 [0x17eec2fa6e3] (69 bytes => 69 (0x45))
0000 - 15 03 03 00 40 61 43 21-ca 8f 02 65 10 a4 d4 b4   ....@aC!...e....
0010 - 4a 0c 85 41 9f cc c6 f6-95 4c 21 3e e2 13 12 6b   J..A.....L!>...k
0020 - 29 47 3e 3f d6 17 9f cd-f2 81 0c 1b 6c ef 28 5c   )G>?........l.(\
0030 - d2 e7 1a 97 2f d0 96 ac-0e 98 f7 d3 ae ee 48 1b   ..../.........H.
0040 - c5 c1 7d b1 88                                    ..}..
SSL3 alert write:warning:close notify
read from 0x17eebe223f0 [0x17eebd67cf0] (16384 bytes => 69 (0x45))
0000 - 15 03 03 00 40 57 61 d6-68 76 c5 bd b4 bc 5d 3d   ....@Wa.hv....]=
0010 - c6 67 3b db 44 96 67 0d-24 2e 67 6d 23 24 f5 75   .g;.D.g.$.gm#$.u
0020 - 4c 67 be e5 57 11 54 29-00 85 c6 0d 43 83 a6 67   Lg..W.T)....C..g
0030 - fe b8 b2 58 a2 26 1b 9b-ec dc eb 52 6e 49 c0 a1   ...X.&.....RnI..
0040 - 1f 93 e5 d6 ea                                    .....
read from 0x17eebe223f0 [0x17eebd67cf0] (16384 bytes => 0)
````

[TOC](README.md)
