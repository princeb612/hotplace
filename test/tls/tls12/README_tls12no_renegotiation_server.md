#### server

````
$ openssl s_server -accept 9000 -cert server.crt -key server.key -state -debug -status_verbose -keylogfile sslkeylog
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x1d8b32d29c0 [0x1d8b3745f93] (5 bytes => 5 (0x5))
0000 - 16 03 01 00 c0                                    .....
read from 0x1d8b32d29c0 [0x1d8b3745f98] (192 bytes => 192 (0xC0))
0000 - 01 00 00 bc 03 03 25 e7-68 32 9c 4e c7 33 a8 ad   ......%.h2.N.3..
0010 - 1d 04 44 91 43 b0 b5 25-e8 b2 1e 4c e4 1f 8b a4   ..D.C..%...L....
0020 - 9f 21 f0 f4 9b d1 00 00-36 c0 2c c0 30 00 9f cc   .!......6.,.0...
0030 - a9 cc a8 cc aa c0 2b c0-2f 00 9e c0 24 c0 28 00   ......+./...$.(.
0040 - 6b c0 23 c0 27 00 67 c0-0a c0 14 00 39 c0 09 c0   k.#.'.g.....9...
0050 - 13 00 33 00 9d 00 9c 00-3d 00 3c 00 35 00 2f 01   ..3.....=.<.5./.
0060 - 00 00 5d ff 01 00 01 00-00 0b 00 04 03 00 01 02   ..].............
0070 - 00 0a 00 0c 00 0a 00 1d-00 17 00 1e 00 19 00 18   ................
0080 - 00 23 00 00 00 16 00 00-00 17 00 00 00 0d 00 30   .#.............0
0090 - 00 2e 04 03 05 03 06 03-08 07 08 08 08 1a 08 1b   ................
00a0 - 08 1c 08 09 08 0a 08 0b-08 04 08 05 08 06 04 01   ................
00b0 - 05 01 06 01 03 03 03 01-03 02 04 02 05 02 06 02   ................
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write certificate
SSL_accept:SSLv3/TLS write key exchange
write to 0x1d8b32d29c0 [0x1d8b3744f80] (1263 bytes => 1263 (0x4EF))
0000 - 16 03 03 00 41 02 00 00-3d 03 03 73 47 61 d6 b9   ....A...=..sGa..
0010 - 47 7e 93 c8 c0 d2 57 c6-c7 81 8c 38 67 e4 b4 02   G~....W....8g...
0020 - 4d 30 6c 44 4f 57 4e 47-52 44 01 00 c0 30 00 00   M0lDOWNGRD...0..
0030 - 15 ff 01 00 01 00 00 0b-00 04 03 00 01 02 00 23   ...............#
0040 - 00 00 00 17 00 00 16 03-03 03 6a 0b 00 03 66 00   ..........j...f.
0050 - 03 63 00 03 60 30 82 03-5c 30 82 02 44 a0 03 02   .c..`0..\0..D...
0060 - 01 02 02 14 63 a6 71 10-79 d6 a6 48 59 da 67 a9   ....c.q.y..HY.g.
0070 - 04 e8 e3 5f e2 03 a3 26-30 0d 06 09 2a 86 48 86   ..._...&0...*.H.
0080 - f7 0d 01 01 0b 05 00 30-59 31 0b 30 09 06 03 55   .......0Y1.0...U
0090 - 04 06 13 02 4b 52 31 0b-30 09 06 03 55 04 08 0c   ....KR1.0...U...
00a0 - 02 47 47 31 0b 30 09 06-03 55 04 07 0c 02 59 49   .GG1.0...U....YI
00b0 - 31 0d 30 0b 06 03 55 04-0a 0c 04 54 65 73 74 31   1.0...U....Test1
00c0 - 0d 30 0b 06 03 55 04 0b-0c 04 54 65 73 74 31 12   .0...U....Test1.
00d0 - 30 10 06 03 55 04 03 0c-09 54 65 73 74 20 52 6f   0...U....Test Ro
00e0 - 6f 74 30 1e 17 0d 32 34-30 38 32 39 30 36 32 37   ot0...2408290627
00f0 - 31 37 5a 17 0d 32 35 30-38 32 39 30 36 32 37 31   17Z..25082906271
0100 - 37 5a 30 54 31 0b 30 09-06 03 55 04 06 13 02 4b   7Z0T1.0...U....K
0110 - 52 31 0b 30 09 06 03 55-04 08 0c 02 47 47 31 0b   R1.0...U....GG1.
0120 - 30 09 06 03 55 04 07 0c-02 59 49 31 0d 30 0b 06   0...U....YI1.0..
0130 - 03 55 04 0a 0c 04 54 65-73 74 31 0d 30 0b 06 03   .U....Test1.0...
0140 - 55 04 0b 0c 04 54 65 73-74 31 0d 30 0b 06 03 55   U....Test1.0...U
0150 - 04 03 0c 04 54 65 73 74-30 82 01 22 30 0d 06 09   ....Test0.."0...
0160 - 2a 86 48 86 f7 0d 01 01-01 05 00 03 82 01 0f 00   *.H.............
0170 - 30 82 01 0a 02 82 01 01-00 ad 9a 29 67 5f f3 a4   0..........)g_..
0180 - 79 b4 c6 e6 32 73 d8 d7-ed 88 94 15 83 e4 31 00   y...2s........1.
0190 - 04 6c b5 8c ac 87 ab 74-44 13 76 ca 0b 74 29 40   .l.....tD.v..t)@
01a0 - 9e 97 2a 01 d7 8b 46 26-6e 19 35 4d c0 d3 b5 ea   ..*...F&n.5M....
01b0 - 0e 93 3a 06 e8 e5 85 b5-27 05 63 db 28 b8 92 da   ..:.....'.c.(...
01c0 - 5a 14 39 0f da 68 6d 6f-0a fb 52 dc 08 0f 54 d3   Z.9..hmo..R...T.
01d0 - e4 a2 28 9d a0 71 50 82-e0 db ca d1 94 dd 42 98   ..(..qP.......B.
01e0 - 3a 09 33 a8 d9 ef fb d2-35 43 b1 22 a2 be 41 6d   :.3.....5C."..Am
01f0 - ba 91 dc 0b 31 4e 88 f9-4d 9c 61 2d ec b2 13 0a   ....1N..M.a-....
0200 - c2 91 8e a2 d6 e9 40 b9-32 b9 80 8f b3 18 a3 33   ......@.2......3
0210 - 13 23 d5 d0 7e d9 d0 7f-93 e0 2d 4d 90 c5 58 24   .#..~.....-M..X$
0220 - 56 d5 c9 10 13 4a b2 99-23 7d 34 b9 8e 97 19 69   V....J..#}4....i
0230 - 6f ce c6 3f d6 17 a7 d2-43 e0 36 cb 51 7b 2f 18   o..?....C.6.Q{/.
0240 - 8b c2 33 f8 57 cf d1 61-0b 7c ed 37 35 e3 13 7a   ..3.W..a.|.75..z
0250 - 24 2e 77 08 c2 e3 d9 e6-17 d3 a5 c6 34 5a da 86   $.w.........4Z..
0260 - a7 f8 02 36 1d 66 63 cf-e9 c0 3d 82 fb 39 a2 8d   ...6.fc...=..9..
0270 - 92 01 4a 83 cf e2 76 3d-87 02 03 01 00 01 a3 21   ..J...v=.......!
0280 - 30 1f 30 1d 06 03 55 1d-11 04 16 30 14 82 12 74   0.0...U....0...t
0290 - 65 73 74 2e 70 72 69 6e-63 65 62 36 31 32 2e 70   est.princeb612.p
02a0 - 65 30 0d 06 09 2a 86 48-86 f7 0d 01 01 0b 05 00   e0...*.H........
02b0 - 03 82 01 01 00 00 a5 f5-54 18 ab ad 36 38 c8 fc   ........T...68..
02c0 - 0b 66 60 dd 9f 75 9d 86-5b 79 2f ee 57 f1 79 1c   .f`..u..[y/.W.y.
02d0 - 15 a1 34 23 d0 1c a9 58-51 a4 d0 08 f5 d8 f7 49   ..4#...XQ......I
02e0 - e9 c5 b5 65 91 51 2d 6d-e4 3b 0e 77 02 1f 45 8e   ...e.Q-m.;.w..E.
02f0 - 34 e5 bb eb f6 9d df 4a-40 60 21 b3 8e 16 33 3f   4......J@`!...3?
0300 - f4 b6 90 d3 3c 34 ce e6-d9 47 07 a7 57 14 0c f9   ....<4...G..W...
0310 - 78 0b 36 72 a9 88 07 07-93 b4 d7 fe 29 5e e8 41   x.6r........)^.A
0320 - 37 20 a5 03 c7 97 cb 82-ca db 14 e5 8b 96 1f a9   7 ..............
0330 - e9 20 3d 6b 25 ae f4 89-4c 60 8d e9 14 33 47 4b   . =k%...L`...3GK
0340 - 88 54 a2 47 19 81 c8 7b-0e 32 52 2b 91 88 ad 0f   .T.G...{.2R+....
0350 - 6d 73 30 8c 00 af d5 fc-46 46 af 3a c2 17 89 ec   ms0.....FF.:....
0360 - c8 83 ae da e6 69 63 e0-9c 84 22 c5 7a de e8 23   .....ic...".z..#
0370 - 6b 53 9d 6f 94 d2 7f 5c-be 1d 0c de 0e 07 0d 52   kS.o...\.......R
0380 - a5 43 8c e8 05 ef c0 ff-f0 73 fa dc 5a 51 4c 24   .C.......s..ZQL$
0390 - 09 65 45 7d ab 52 8b 7e-5d f0 fb de a7 3d 43 c5   .eE}.R.~]....=C.
03a0 - af 76 e3 6e f9 a1 dc 78-a2 bd 54 41 04 99 e5 56   .v.n...x..TA...V
03b0 - 32 ba 02 fd 72 16 03 03-01 2c 0c 00 01 28 03 00   2...r....,...(..
03c0 - 1d 20 1c 2e 68 cb 2f b1-bc c4 88 bb 2c 8d ca bb   . ..h./.....,...
03d0 - 87 bb a5 71 57 5e a1 1b-8d c5 a5 07 2a 5f 14 2d   ...qW^......*_.-
03e0 - 41 01 08 04 01 00 2d ce-b7 00 cc f0 6d 5a c5 b7   A.....-.....mZ..
03f0 - 41 a8 3d 2a be 38 fe 73-ce fb 03 7b 03 e8 a2 8d   A.=*.8.s...{....
0400 - 5d aa 5b 4d 84 d1 5d e9-77 cb 18 14 e8 b2 17 27   ].[M..].w......'
0410 - f6 af 8f 29 49 5d bc 7a-7e a2 6e db a7 c6 42 82   ...)I].z~.n...B.
0420 - b7 90 2f e6 bc d2 76 b2-d1 20 2b 07 4a d5 92 77   ../...v.. +.J..w
0430 - 24 3f cd be 2b 31 01 f7-f8 c5 17 ca 77 5d 27 c0   $?..+1......w]'.
0440 - 66 22 5a 5e 4d ff 65 06-d7 d5 2c 7e 31 19 33 cf   f"Z^M.e...,~1.3.
0450 - be 1e 14 db 85 d4 3c 5f-b3 02 95 78 04 d3 a0 2d   ......<_...x...-
0460 - 5e e2 83 22 14 a2 09 a1-6a 8d a9 13 92 4c ca 81   ^.."....j....L..
0470 - d2 ac 07 ac 43 de a2 83-1c 86 e3 1f d5 b0 15 40   ....C..........@
0480 - a2 c3 77 fa 19 27 e9 d8-ad 13 4a 17 82 4d 8e cd   ..w..'....J..M..
0490 - 5d d6 5b 22 a9 e9 44 e5-5c 95 fe 3e 0c 8b c8 23   ].["..D.\..>...#
04a0 - c1 89 85 61 8e ed 77 bd-df b2 a7 1c 66 7c 40 d7   ...a..w.....f|@.
04b0 - c8 21 fc 0f da 5c b9 dd-3d 00 5f 1e d8 01 e6 5f   .!...\..=._...._
04c0 - a3 d0 29 e0 e5 75 ab 7f-a9 85 f7 c3 6f 1b 02 20   ..)..u......o..
04d0 - ed 48 32 c9 8b 79 a9 4c-f7 33 91 50 3e 6e 6c 02   .H2..y.L.3.P>nl.
04e0 - be 4a 6a 4b 03 b7 16 03-03 00 04 0e 00 00 00      .JjK...........
SSL_accept:SSLv3/TLS write server done
read from 0x1d8b32d29c0 [0x1d8b3745f93] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 25                                    ....%
read from 0x1d8b32d29c0 [0x1d8b3745f98] (37 bytes => 37 (0x25))
0000 - 10 00 00 21 20 64 04 9b-ef f7 13 53 22 aa 19 08   ...! d.....S"...
0010 - e3 7d e2 92 9d e2 38 ee-87 16 9c c6 b2 cc ed 73   .}....8........s
0020 - 15 a4 d5 94 5a                                    ....Z
SSL_accept:SSLv3/TLS write server done
read from 0x1d8b32d29c0 [0x1d8b3745f93] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x1d8b32d29c0 [0x1d8b3745f98] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_accept:SSLv3/TLS read client key exchange
read from 0x1d8b32d29c0 [0x1d8b3745f93] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 28                                    ....(
read from 0x1d8b32d29c0 [0x1d8b3745f98] (40 bytes => 40 (0x28))
0000 - 8a 5b 61 16 92 1b a3 3f-73 85 eb d2 2c e0 3f 71   .[a....?s...,.?q
0010 - 84 1f 82 79 d7 4e 47 d7-42 b3 f7 39 5c 2d a0 dc   ...y.NG.B..9\-..
0020 - 1f f9 ce eb ef 7a e7 92-                          .....z..
SSL_accept:SSLv3/TLS read change cipher spec
SSL_accept:SSLv3/TLS read finished
SSL_accept:SSLv3/TLS write session ticket
SSL_accept:SSLv3/TLS write change cipher spec
write to 0x1d8b32d29c0 [0x1d8b3744f80] (242 bytes => 242 (0xF2))
0000 - 16 03 03 00 ba 04 00 00-b6 00 00 1c 20 00 b0 3a   ............ ..:
0010 - b4 2f 4b 76 c7 63 73 e5-0b 29 8c 67 60 19 66 6c   ./Kv.cs..).g`.fl
0020 - 2b 9f 25 40 42 31 23 b5-cb a9 55 cf 26 9a 1c 91   +.%@B1#...U.&...
0030 - 34 08 3b 6a 63 9d d4 c4-01 5f 2e 75 6b 5a a4 0a   4.;jc...._.ukZ..
0040 - b8 50 b1 cf 7f a3 f8 ec-fa 06 b0 ae 97 43 b7 cd   .P...........C..
0050 - 74 7e 6e ee 94 8b d1 03-a1 e4 0a 42 47 e3 d6 bf   t~n........BG...
0060 - e8 67 9a 83 4b 52 e8 d5-36 17 74 17 03 47 94 f4   .g..KR..6.t..G..
0070 - dc ff aa 0b 7d a1 6a 20-a8 88 1c 54 b2 ac 7c a3   ....}.j ...T..|.
0080 - 60 3c bf e3 9c 88 8f 8d-70 4e 9b 81 f1 c8 eb b9   `<......pN......
0090 - 0b e0 35 02 10 20 69 ac-72 7f 21 c5 83 b0 6b 43   ..5.. i.r.!...kC
00a0 - 13 81 de 70 1d eb 55 38-cb 89 b7 9e 66 55 0a cd   ...p..U8....fU..
00b0 - 5f 1c 78 7e 23 cd 12 d6-04 40 ac aa 6a e4 b1 14   _.x~#....@..j...
00c0 - 03 03 00 01 01 16 03 03-00 28 55 41 cc 48 47 9a   .........(UA.HG.
00d0 - 42 e0 8d 90 83 e2 c6 1f-20 ed 13 77 d0 3e 36 ea   B....... ..w.>6.
00e0 - 90 19 e7 cd 8d cd 40 44-22 fc ac 91 ca 11 70 5a   ......@D".....pZ
00f0 - a7 e5                                             ..
SSL_accept:SSLv3/TLS write finished
-----BEGIN SSL SESSION PARAMETERS-----
MF8CAQECAgMDBALAMAQABDD9jCteiEYJKU/CRFIvGt6u82haIAcZRpgXR8qZi8SF
X4bz95ZaI8DozO6yTcVpxQuhBgIEaB7QmKIEAgIcIKQGBAQBAAAArQMCAQGzAwIB
HQ==
-----END SSL SESSION PARAMETERS-----
Shared ciphers:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Supported Elliptic Curve Point Formats: uncompressed:ansiX962_compressed_prime:ansiX962_compressed_char2
Supported groups: x25519:secp256r1:x448:secp521r1:secp384r1
Shared groups: x25519:secp256r1:x448:secp521r1:secp384r1
CIPHER is ECDHE-RSA-AES256-GCM-SHA384
Secure Renegotiation IS supported
read from 0x1d8b32d29c0 [0x1d8b3745f93] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 1e                                    .....
read from 0x1d8b32d29c0 [0x1d8b3745f98] (30 bytes => 30 (0x1E))
0000 - 8a 5b 61 16 92 1b a3 40-53 db 49 92 ba 66 81 f3   .[a....@S.I..f..
0010 - 16 9b 69 7d 4d b7 9d bd-6a eb 49 20 7c 00         ..i}M...j.I |.
test
read from 0x1d8b32d29c0 [0x1d8b3745f93] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 e4                                    .....
read from 0x1d8b32d29c0 [0x1d8b3745f98] (228 bytes => 228 (0xE4))
0000 - 8a 5b 61 16 92 1b a3 41-dd 1f 02 d9 67 ec ef 79   .[a....A....g..y
0010 - 34 93 73 bf f7 39 96 ab-fd 05 19 38 ff ae b0 60   4.s..9.....8...`
0020 - 7f e1 13 67 01 f4 ba 04-7d d4 1d cc c8 c5 23 1b   ...g....}.....#.
0030 - 73 44 15 0d 8e 7f 06 17-92 3d 11 91 e9 f2 33 7b   sD.......=....3{
0040 - 46 e2 9e a8 b8 c0 51 bf-a3 49 de b8 e3 3c 26 65   F.....Q..I...<&e
0050 - 58 e2 1f 75 45 ca 89 e2-e6 1a 2e 72 06 97 a3 b2   X..uE......r....
0060 - 0b ad 5e e3 12 85 5b 42-a4 04 87 bc 73 23 72 c3   ..^...[B....s#r.
0070 - 03 bd db f9 1b 5e 18 ec-cc 9b 1c c6 9f 59 93 72   .....^.......Y.r
0080 - 0a 64 fd 46 0a 82 b0 92-54 e9 10 c3 f0 33 9b a0   .d.F....T....3..
0090 - 2b 2b e6 4e 21 11 7c 6e-b9 62 be e8 22 81 fb 0a   ++.N!.|n.b.."...
00a0 - 51 4b 42 f5 ad e9 d8 42-d6 96 31 1b 70 ef 23 e8   QKB....B..1.p.#.
00b0 - e2 d0 57 52 d1 c7 50 6b-49 ad 65 90 31 41 92 9b   ..WR..PkI.e.1A..
00c0 - 26 97 2c c2 1e f8 b6 50-2b e8 3e 1f dd 80 8f 78   &.,....P+.>....x
00d0 - 1c 56 09 34 cb 7f c1 70-b1 be ac 77 2a 95 87 8f   .V.4...p...w*...
00e0 - fb 77 a8 a9                                       .w..
SSL_accept:SSL negotiation finished successfully
SSL_accept:SSL negotiation finished successfully
write to 0x1d8b32d29c0 [0x1d8b375a400] (31 bytes => 31 (0x1F))
0000 - 15 03 03 00 1a 55 41 cc-48 47 9a 42 e1 64 9f 2b   .....UA.HG.B.d.+
0010 - 27 ff dd 03 66 f9 29 5b-37 38 84 0c db e7 79      '...f.)[78....y
SSL3 alert write:warning:no renegotiation
SSL_accept:SSLv3/TLS read client hello
Read BLOCK
read from 0x1d8b32d29c0 [0x1d8b3745f93] (5 bytes => 5 (0x5))
0000 - 15 03 03 00 1a                                    .....
read from 0x1d8b32d29c0 [0x1d8b3745f98] (26 bytes => 26 (0x1A))
0000 - 8a 5b 61 16 92 1b a3 42-5c 42 d2 65 f4 e3 4e 1f   .[a....B\B.e..N.
0010 - 9a 91 38 fc 3c b0 4e f2-f9 42                     ..8.<.N..B
SSL3 alert read:fatal:handshake failure
ERROR
AC8C0000:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake failure:../openssl-3.4.0/ssl/record/rec_layer_s3.c:908:SSL alert number 40
shutting down SSL
CONNECTION CLOSED
````

[TOC](README.md)
