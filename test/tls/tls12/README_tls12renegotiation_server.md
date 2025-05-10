#### server

````
$ openssl s_server -accept 9000 -cert server.crt -key server.key -state -debug -status_verbose -keylogfile server.keylog -client_renegotiation
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x261604dcdd0 [0x261605354d3] (5 bytes => 5 (0x5))
0000 - 16 03 01 00 c0                                    .....
read from 0x261604dcdd0 [0x261605354d8] (192 bytes => 192 (0xC0))
0000 - 01 00 00 bc 03 03 61 15-ec ae 8b 32 e5 a8 bf b9   ......a....2....
0010 - 88 70 06 8d 71 5c 0b ed-91 1f de a1 57 75 64 2e   .p..q\......Wud.
0020 - 9d b8 db 16 0e 27 00 00-36 c0 2c c0 30 00 9f cc   .....'..6.,.0...
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
write to 0x261604dcdd0 [0x261605344c0] (1263 bytes => 1263 (0x4EF))
0000 - 16 03 03 00 41 02 00 00-3d 03 03 ea 57 d2 b5 45   ....A...=...W..E
0010 - e3 fa 38 5e 8d e3 7c 78-bf 56 bf 27 28 99 1c 8a   ..8^..|x.V.'(...
0020 - 95 f3 e8 44 4f 57 4e 47-52 44 01 00 c0 30 00 00   ...DOWNGRD...0..
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
03c0 - 1d 20 b3 71 d4 f1 88 bc-d8 95 8c 9d 5d 9d 16 5a   . .q........]..Z
03d0 - da e4 1f ac 93 0a fa c1-11 43 31 53 33 22 1c 7b   .........C1S3".{
03e0 - b5 43 08 04 01 00 1d 6b-83 aa 1e e5 42 da 7f e5   .C.....k....B...
03f0 - 7a 33 f7 24 58 f8 af 80-2d 19 55 d2 9b 94 a7 fb   z3.$X...-.U.....
0400 - 92 81 fe c2 f8 72 84 7e-fa c5 2f bf af 5c 18 a0   .....r.~../..\..
0410 - fa 11 f4 a8 e7 6a 6c 35-a3 50 df 5e 4f a3 bf f5   .....jl5.P.^O...
0420 - 96 6d e9 b8 93 95 92 51-c0 b8 42 aa 35 82 69 d4   .m.....Q..B.5.i.
0430 - a9 e5 b2 cd 09 0d c1 39-92 31 b5 42 93 91 df 66   .......9.1.B...f
0440 - b0 05 fc 13 0d 2f a6 6b-b6 d6 67 48 a9 81 55 58   ...../.k..gH..UX
0450 - 28 12 f8 08 a7 7c 5c 58-5e f5 8c 91 1c 85 81 79   (....|\X^......y
0460 - 6b d3 b5 5c 75 17 f8 32-b6 3c e1 02 a2 41 14 7a   k..\u..2.<...A.z
0470 - d8 e9 4a 20 5a a6 c2 a2-c1 68 b0 ac 5e 77 53 00   ..J Z....h..^wS.
0480 - e6 a7 fd f5 7a dd 82 af-53 45 26 6b 54 c1 a0 11   ....z...SE&kT...
0490 - b9 5a 60 a3 c3 99 76 89-e1 55 b7 7b ef a5 51 ea   .Z`...v..U.{..Q.
04a0 - 5c 91 f5 bd c7 1f 10 63-d1 54 43 84 48 4a 60 c8   \......c.TC.HJ`.
04b0 - 3c b8 ee 64 a4 a2 6c f5-66 75 8e 36 93 ce e5 3d   <..d..l.fu.6...=
04c0 - e9 a3 72 82 5b 35 fc ba-8f a4 5b 56 83 f2 2f 47   ..r.[5....[V../G
04d0 - ea de 9d e4 5a f0 a6 15-29 eb f1 0e fc 90 d1 04   ....Z...).......
04e0 - 5c 41 eb 13 e9 70 16 03-03 00 04 0e 00 00 00      \A...p.........
SSL_accept:SSLv3/TLS write server done
read from 0x261604dcdd0 [0x261605354d3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 25                                    ....%
read from 0x261604dcdd0 [0x261605354d8] (37 bytes => 37 (0x25))
0000 - 10 00 00 21 20 73 3c 5e-ff 4c b1 22 cd 39 5c da   ...! s<^.L.".9\.
0010 - 22 24 32 28 4c be 10 dc-37 97 a8 12 af cd be d6   "$2(L...7.......
0020 - 45 12 06 b6 15                                    E....
SSL_accept:SSLv3/TLS write server done
read from 0x261604dcdd0 [0x261605354d3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x261604dcdd0 [0x261605354d8] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_accept:SSLv3/TLS read client key exchange
read from 0x261604dcdd0 [0x261605354d3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 28                                    ....(
read from 0x261604dcdd0 [0x261605354d8] (40 bytes => 40 (0x28))
0000 - 9d a5 b3 05 32 8d cd 77-94 34 be df 9b e0 e6 94   ....2..w.4......
0010 - c4 85 8c ee 9a 2c 7b c9-77 61 a7 c6 36 38 f4 0b   .....,{.wa..68..
0020 - d4 6f 61 bc f9 7d 44 55-                          .oa..}DU
SSL_accept:SSLv3/TLS read change cipher spec
SSL_accept:SSLv3/TLS read finished
SSL_accept:SSLv3/TLS write session ticket
SSL_accept:SSLv3/TLS write change cipher spec
write to 0x261604dcdd0 [0x261605344c0] (242 bytes => 242 (0xF2))
0000 - 16 03 03 00 ba 04 00 00-b6 00 00 1c 20 00 b0 c7   ............ ...
0010 - ea d5 c3 e3 32 93 93 f0-47 bd b6 e0 85 af ed d0   ....2...G.......
0020 - 80 70 04 7e cd 88 4e 00-3a 97 81 2b 0c f9 da 2f   .p.~..N.:..+.../
0030 - 0c 52 d1 e2 e8 70 08 fd-22 ed 44 c6 26 44 67 1f   .R...p..".D.&Dg.
0040 - cf eb 68 70 a8 54 2d 22-71 59 fe 91 1f af 49 a9   ..hp.T-"qY....I.
0050 - be 12 90 8d 57 e1 09 84-f6 3f f5 f9 86 6b ee 37   ....W....?...k.7
0060 - 4c f9 cd a5 a5 65 4c ee-94 40 18 28 b8 9e 2b 03   L....eL..@.(..+.
0070 - 26 7d a8 02 d0 51 76 f1-e5 13 76 c4 00 40 92 55   &}...Qv...v..@.U
0080 - c3 cb 2b 21 a9 26 81 84-7b a9 13 bf aa e5 94 fa   ..+!.&..{.......
0090 - 11 c8 47 7b 06 ce 5d 34-f5 83 86 98 cb 29 3c 33   ..G{..]4.....)<3
00a0 - be 94 8e 14 40 5c a5 13-21 48 0f 91 5f 54 34 4f   ....@\..!H.._T4O
00b0 - da 7a 08 d1 cc 01 da 73-0f b1 a4 da 3a 22 f3 14   .z.....s....:"..
00c0 - 03 03 00 01 01 16 03 03-00 28 26 ad a0 79 e8 34   .........(&..y.4
00d0 - cf cc 70 35 67 7e f6 46-39 2b fb 0f d0 8f 68 bb   ..p5g~.F9+....h.
00e0 - a1 8d 7c 58 7a 43 e4 df-82 d8 6c 95 cf da 53 9c   ..|XzC....l...S.
00f0 - 2d ca                                             -.
SSL_accept:SSLv3/TLS write finished
-----BEGIN SSL SESSION PARAMETERS-----
MF8CAQECAgMDBALAMAQABDCYfOSZshdH1tgeZ5XVjmES6Loi7B8Q8xuWI6EmoJ/l
H7FLOEBFXFpTRj0XwvVicAWhBgIEaB7N3aIEAgIcIKQGBAQBAAAArQMCAQGzAwIB
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
read from 0x261604dcdd0 [0x261605354d3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 1e                                    .....
read from 0x261604dcdd0 [0x261605354d8] (30 bytes => 30 (0x1E))
0000 - 9d a5 b3 05 32 8d cd 78-bb 0b 7d df 87 0e a5 5c   ....2..x..}....\
0010 - 57 08 5a d4 5e 68 30 41-18 fa cc df 65 4e         W.Z.^h0A....eN
test
read from 0x261604dcdd0 [0x261605354d3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 e4                                    .....
read from 0x261604dcdd0 [0x261605354d8] (228 bytes => 228 (0xE4))
0000 - 9d a5 b3 05 32 8d cd 79-5b e1 71 23 22 af cb 28   ....2..y[.q#"..(
0010 - 68 d8 f9 32 b7 05 d7 1d-05 ee 44 a9 ea 96 89 52   h..2......D....R
0020 - a6 57 30 22 20 1b 0e e4-28 ce c1 d8 35 3e 9e ae   .W0" ...(...5>..
0030 - 68 ab 0e db 77 16 d3 a5-ff fb e6 ea 57 56 7f f1   h...w.......WV..
0040 - 84 03 b8 eb 5a 9c 96 e8-c4 e1 08 23 03 44 7f 88   ....Z......#.D..
0050 - b1 58 87 5a 93 51 d1 2e-ea ff c6 d0 9e 0a 3e ff   .X.Z.Q........>.
0060 - a2 ad 4d b8 fd 0f 5b fb-cd 72 d6 a8 a8 28 07 20   ..M...[..r...(.
0070 - c5 f7 9c c3 90 f9 05 af-b5 73 df 9f af d4 b0 9f   .........s......
0080 - 3a 89 62 26 75 7f 04 bc-d4 3b 63 ab 86 38 e9 37   :.b&u....;c..8.7
0090 - 2f 62 9f b3 16 06 7f 2a-5c a2 55 73 40 44 91 b3   /b.....*\.Us@D..
00a0 - 13 d0 b6 9b f7 39 49 36-e5 6c b8 b8 00 3d 1c fd   .....9I6.l...=..
00b0 - 21 5c 84 ea 02 96 d0 36-94 e0 f6 00 3b bd ee bf   !\.....6....;...
00c0 - 73 d1 e1 f6 36 bf 40 57-53 44 0b 00 ea da ef 91   s...6.@WSD......
00d0 - 10 3a 52 9e 74 31 6d ef-b8 e8 df 6b 72 58 f1 e7   .:R.t1m....krX..
00e0 - 72 44 6b cd                                       rDk.
SSL_accept:SSL negotiation finished successfully
SSL_accept:SSL negotiation finished successfully
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write certificate
SSL_accept:SSLv3/TLS write key exchange
write to 0x261604dcdd0 [0x261605480a0] (1383 bytes => 1383 (0x567))
0000 - 16 03 03 00 71 26 ad a0-79 e8 34 cf cd a7 43 df   ....q&..y.4...C.
0010 - 19 4d b6 31 5f 6a a2 f1-fd 08 3e c8 17 84 b1 b4   .M.1_j....>.....
0020 - c7 a3 32 a4 75 1b 35 64-fa f1 44 07 ad 8e 70 56   ..2.u.5d..D...pV
0030 - 7a 78 0f f1 07 c3 7f 7b-b3 f2 5d 98 aa 66 4e bb   zx.....{..]..fN.
0040 - d5 30 a1 94 87 75 dc 15-f0 9d 54 e4 12 8d f8 e1   .0...u....T.....
0050 - 66 cc e9 fe 81 7e 90 ee-f1 bc d3 2f 6b e5 de 89   f....~...../k...
0060 - c2 84 6a cb 6d c8 70 41-12 02 8f 5d 20 62 e1 61   ..j.m.pA...] b.a
0070 - a7 d9 c5 92 e2 dd 16 03-03 03 82 26 ad a0 79 e8   ...........&..y.
0080 - 34 cf ce ab fe d2 e5 ef-bf fb 8e c5 d4 ee d9 da   4...............
0090 - bd 26 e6 e3 c8 2d 54 fc-6a dd 90 47 47 55 fd 31   .&...-T.j..GGU.1
00a0 - 6c a9 fd 5e 0e 9e 96 8c-ef 94 60 88 47 7d 90 3e   l..^......`.G}.>
00b0 - 9c 42 3d 0d a4 8d 30 31-2a 25 de 14 2c 31 5e 35   .B=...01*%..,1^5
00c0 - 88 43 2a 75 f3 63 cd 15-22 3b 61 ec e4 c8 e2 83   .C*u.c..";a.....
00d0 - 13 5b ed b4 6e a4 ab 75-08 ee 2f d6 9b d7 1c 28   .[..n..u../....(
00e0 - a7 92 08 0b 91 68 fa 58-ef a4 27 57 fd 20 af a4   .....h.X..'W. ..
00f0 - 66 a4 d3 21 7c 47 ac 15-f8 41 1e 35 99 5c 39 99   f..!|G...A.5.\9.
0100 - 0f d0 fa b1 df e2 c5 5e-f1 65 ac 95 cb 4f ef 5b   .......^.e...O.[
0110 - 72 42 f0 e4 b0 b7 4c ac-29 3f 35 80 99 8a 2f 8a   rB....L.)?5.../.
0120 - 60 69 a2 33 24 9f aa 75-27 88 03 9d d2 6b e2 11   `i.3$..u'....k..
0130 - 4b 8c db 21 97 0d 42 0e-d6 fc b7 dd ac 86 8a 60   K..!..B........`
0140 - 18 58 ba b6 11 4f 3a 1f-1b 08 5f b8 bd 50 08 30   .X...O:..._..P.0
0150 - 0a 34 d4 46 42 fa 7f c4-92 3f a5 7e ec 01 56 cb   .4.FB....?.~..V.
0160 - 41 b0 19 4e 76 4f f8 aa-88 e4 fb 48 0b ab 93 2d   A..NvO.....H...-
0170 - 75 3d b9 d5 2d 55 db fe-5b 86 4f 58 53 b4 42 fa   u=..-U..[.OXS.B.
0180 - 93 93 f5 b7 6c d9 f8 26-e0 c1 7f 69 be 19 e2 29   ....l..&...i...)
0190 - c2 da 8c 60 09 10 1b ec-63 3c c4 b6 15 34 bb 69   ...`....c<...4.i
01a0 - ec f9 19 14 70 22 c9 8a-a5 f1 9c f3 ce 1f e9 2c   ....p".........,
01b0 - 70 4a ac b6 d2 8e 88 1d-6a f8 f7 ce 26 d8 8c ad   pJ......j...&...
01c0 - d8 5f c3 f7 46 69 69 c6-1a 10 1f 12 e7 a5 91 68   ._..Fii........h
01d0 - be eb 5e b4 8e e6 b0 65-5d 1c 75 64 91 fb 1c 26   ..^....e].ud...&
01e0 - b4 be 4f 12 4e 49 eb e9-96 e3 32 ae 3f f1 9c 32   ..O.NI....2.?..2
01f0 - 24 70 19 4f 6b 87 e9 b7-b6 92 b4 5e 7d 01 f8 73   $p.Ok......^}..s
0200 - e6 4e 82 93 78 a6 b7 58-81 6e 91 57 30 58 1f e3   .N..x..X.n.W0X..
0210 - 76 b8 04 be 13 68 90 aa-b7 af e8 db 03 f1 23 b3   v....h........#.
0220 - ac f9 f9 ac 99 92 c7 e6-f5 fa a3 ec 5d b3 c8 02   ............]...
0230 - b7 6c 23 82 83 22 af 79-db 4b 18 4b 0c eb 89 5b   .l#..".y.K.K...[
0240 - 29 4c 89 9e ac b3 09 7e-4d 94 da 7c 2b 59 ca 82   )L.....~M..|+Y..
0250 - 9b ab 2a e4 70 aa ec 88-ed d8 30 0b c4 88 d3 b8   ..*.p.....0.....
0260 - 89 03 e8 b7 48 7f 88 7b-f4 da a3 9c b3 90 e7 23   ....H..{.......#
0270 - 87 bf fe e0 5d ac b1 de-f3 78 87 6a b6 bb c2 02   ....]....x.j....
0280 - a3 26 ba 77 e0 dc 70 c5-ac a2 e2 4f a8 b5 c5 82   .&.w..p....O....
0290 - ae 66 b2 1b 45 20 41 ab-33 c8 94 80 e9 1e 96 e2   .f..E A.3.......
02a0 - ce d2 cb b5 50 78 4f 9b-65 2d 94 8d 4a b5 7e 86   ....PxO.e-..J.~.
02b0 - bb 94 20 cf 77 55 4c a7-aa 59 ac e7 68 64 bf db   .. .wUL..Y..hd..
02c0 - 36 38 69 cc 52 19 d0 b9-a0 f7 4b b0 0c a8 e2 24   68i.R.....K....$
02d0 - 22 7b 09 17 1a 6c df b0-40 02 ee 20 6c 75 d9 df   "{...l..@.. lu..
02e0 - d7 7f 8e 39 40 b2 a5 0b-39 0d ee 0e fd 19 d6 e8   ...9@...9.......
02f0 - 18 da 6f 66 71 6f 6c c1-7e f6 06 a3 13 e8 a1 35   ..ofqol.~......5
0300 - 58 23 1a dc f7 57 3c b6-94 1b 02 ca 96 84 ec 87   X#...W<.........
0310 - 9a a8 4f 5a b2 ac 17 b4-a0 67 e9 ed 91 99 96 05   ..OZ.....g......
0320 - 00 30 fc b5 85 a3 47 5f-7d a4 b9 ca 23 4c 03 a5   .0....G_}...#L..
0330 - 17 14 b0 82 24 8e 1a 78-50 67 82 7c 60 f9 55 1e   ....$..xPg.|`.U.
0340 - bf 8a 06 f7 2c de 65 c9-4a 9e 49 d3 ab af 9f 31   ....,.e.J.I....1
0350 - 3c 6a 8a 0f f9 d8 10 ef-07 f7 c3 e7 63 57 b4 be   <j..........cW..
0360 - 85 fe 94 31 87 4a dd 1f-65 90 e7 d7 66 6b fc 18   ...1.J..e...fk..
0370 - 8d 9a d1 02 bf 0a 32 cb-bf d5 7b 3f 2d bd 63 db   ......2...{?-.c.
0380 - b6 7d 4a e7 41 f3 3c 2d-66 54 5e cb b2 8a d1 de   .}J.A.<-fT^.....
0390 - 5b e8 c7 e2 f6 2f ed c9-08 fc 4e a5 c9 e1 58 81   [..../....N...X.
03a0 - 54 9a 18 9c 51 69 cf d4-22 50 7d 0c 71 ad b6 2d   T...Qi.."P}.q..-
03b0 - 36 cd 0f 97 50 3d 12 d7-20 58 c3 f2 b0 89 86 c0   6...P=.. X......
03c0 - 86 7c 96 e8 2c e7 df 0e-f3 f2 3d a1 84 03 d3 d0   .|..,.....=.....
03d0 - 55 97 2a d8 0e ce e0 26-e2 12 a1 43 66 77 7f be   U.*....&...Cfw..
03e0 - 33 1e 9f da dd 2b c2 65-38 c7 3c 84 a6 2d aa 2e   3....+.e8.<..-..
03f0 - 61 cb fe 52 6e cb 6c bb-0b 3d 3b 8e c9 16 03 03   a..Rn.l..=;.....
0400 - 01 44 26 ad a0 79 e8 34-cf cf a2 f5 a8 67 6c 70   .D&..y.4.....glp
0410 - 7b f8 2c 76 e0 93 96 3b-cb 4e 16 53 2e 99 bd 9a   {.,v...;.N.S....
0420 - d6 10 b6 a8 81 56 21 42-c9 f6 46 ea 2d cc 5b 4f   .....V!B..F.-.[O
0430 - 8e f0 f5 36 1a 16 ca 87-3b b4 ff d4 81 b4 42 41   ...6....;.....BA
0440 - 60 ac bd d2 5f b5 df c2-36 8b 4a 1d 57 1a c0 f9   `..._...6.J.W...
0450 - c8 4e 14 c5 bd f1 20 ac-fd b2 dd 1c f7 e5 dd 62   .N.... ........b
0460 - 1b 95 7e 05 f2 db c5 7a-8e 14 6a e9 cb e7 b5 be   ..~....z..j.....
0470 - d8 35 1d be cd 1e 39 0b-3b a2 e1 6b 68 4b ef f0   .5....9.;..khK..
0480 - a9 c7 08 0f e0 29 f4 84-6f 6d 54 d7 f5 df 91 79   .....)..omT....y
0490 - e7 11 dd 51 f4 02 95 ec-ea ff 05 a3 a9 29 d6 21   ...Q.........).!
04a0 - e7 2e 82 73 c0 b2 6d ab-91 35 72 e1 89 f8 65 21   ...s..m..5r...e!
04b0 - 20 91 df 92 d7 2c 73 08-6c bf 04 18 37 c3 a4 86    ....,s.l...7...
04c0 - 00 72 55 bd 93 e4 ac e9-19 31 af c0 6e 64 ca 40   .rU......1..nd.@
04d0 - 82 78 42 41 4d 1e 95 0c-97 15 c2 ae 97 74 0c a2   .xBAM........t..
04e0 - c3 24 37 3d 16 c9 26 0f-d4 db e9 80 f6 0e 6b 9e   .$7=..&.......k.
04f0 - 99 a1 86 a9 66 88 f0 76-6a cd 32 9d 2c 9c c0 87   ....f..vj.2.,...
0500 - b4 4d e6 06 39 5a ba 7e-9c dc 31 df fd a0 e7 0f   .M..9Z.~..1.....
0510 - ae 48 26 1f 12 6f 27 5d-08 8e c8 0f 9a 9e 46 75   .H&..o']......Fu
0520 - 28 32 97 30 c2 b8 3f fc-29 48 a6 a5 d5 5c 96 66   (2.0..?.)H...\.f
0530 - 5a cc 23 69 de 31 42 f0-ad c0 2e ac 24 0e 4a 40   Z.#i.1B.....$.J@
0540 - 37 7e 98 2b 86 a8 16 03-03 00 1c 26 ad a0 79 e8   7~.+.......&..y.
0550 - 34 cf d0 8c 6c 23 18 d2-04 f1 b5 b6 b0 94 b0 1f   4...l#..........
0560 - d9 5b 75 46 f0 0c 54                              .[uF..T
SSL_accept:SSLv3/TLS write server done
read from 0x261604dcdd0 [0x261605354d3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 3d                                    ....=
read from 0x261604dcdd0 [0x261605354d8] (61 bytes => 61 (0x3D))
0000 - 9d a5 b3 05 32 8d cd 7a-0a 8c 68 2c 36 f4 f2 d7   ....2..z..h,6...
0010 - fc a9 bc d5 e6 d7 5e 10-6a 47 78 d8 0d 32 35 c3   ......^.jGx..25.
0020 - c0 fd 06 27 df 52 06 95-d8 08 bd 9e ec 9f 35 4a   ...'.R........5J
0030 - 47 21 5b e6 f7 cf 22 3b-e5 27 b3 d5 f7            G![...";.'...
SSL_accept:SSLv3/TLS write server done
read from 0x261604dcdd0 [0x261605354d3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 19                                    .....
read from 0x261604dcdd0 [0x261605354d8] (25 bytes => 25 (0x19))
0000 - 9d a5 b3 05 32 8d cd 7b-29 d7 28 0f f3 df 99 74   ....2..{).(....t
0010 - cb 9f e6 c9 3c 8c 7e 2f-79                        ....<.~/y
SSL_accept:SSLv3/TLS read client key exchange
read from 0x261604dcdd0 [0x261605344c3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 28                                    ....(
read from 0x261604dcdd0 [0x261605344c8] (40 bytes => 40 (0x28))
0000 - 66 4e ec 00 9d 31 e0 90-0e 40 2f c3 56 8e 1d 26   fN...1...@/.V..&
0010 - 14 f2 d3 a5 c0 dc 23 3b-ae 06 9a 77 41 b6 0f a3   ......#;...wA...
0020 - 25 fb b5 7e f8 6d 24 ff-                          %..~.m$.
SSL_accept:SSLv3/TLS read change cipher spec
SSL_accept:SSLv3/TLS read finished
SSL_accept:SSLv3/TLS write session ticket
SSL_accept:SSLv3/TLS write change cipher spec
write to 0x261604dcdd0 [0x261605480a0] (290 bytes => 290 (0x122))
0000 - 16 03 03 00 d2 26 ad a0-79 e8 34 cf d1 ca 41 fc   .....&..y.4...A.
0010 - 47 40 e0 06 8c 05 c9 6e-8b 78 34 8a 90 c0 0e cc   G@.....n.x4.....
0020 - a4 71 77 b0 5b 2c c9 0d-71 ee 90 dc 5d 9f a3 92   .qw.[,..q...]...
0030 - ea 5c 6f 9c 0f ae 81 30-d0 4e 31 bc cb 7f 95 66   .\o....0.N1....f
0040 - 2d 3a bd 3b 83 54 97 8b-0c 6a 45 81 7a 9e f0 56   -:.;.T...jE.z..V
0050 - 3c 7e 25 b0 e4 18 9b 5a-bb dc f7 dc 09 e9 f8 af   <~%....Z........
0060 - bc a1 52 ae e3 9f f1 df-e4 b8 4a d0 41 e9 23 e8   ..R.......J.A.#.
0070 - 48 a1 5a 85 e2 4e 84 be-9e 25 2f f7 7a c6 42 72   H.Z..N...%/.z.Br
0080 - 92 23 e7 93 7c 80 b1 30-67 2b 49 61 4d 2f 91 af   .#..|..0g+IaM/..
0090 - b4 31 b2 7b 0e 85 59 07-47 f8 2b b5 97 22 3b 5a   .1.{..Y.G.+..";Z
00a0 - f3 40 77 22 b6 be b6 62-3c bd fb a5 d6 2d 62 e6   .@w"...b<....-b.
00b0 - f9 0d 6f 0b c4 ba 9b 01-49 66 69 d3 fb 13 97 7b   ..o.....Ifi....{
00c0 - 98 fb c6 52 31 82 f8 55-8a 95 ba bc c7 f6 47 0a   ...R1..U......G.
00d0 - ee 96 78 a7 18 dd 8a 14-03 03 00 19 26 ad a0 79   ..x.........&..y
00e0 - e8 34 cf d2 5a ac 12 67-ad 35 4e 56 0f ff 98 65   .4..Z..g.5NV...e
00f0 - 05 52 e3 a4 55 16 03 03-00 28 55 09 bc ad b1 c1   .R..U....(U.....
0100 - c8 1e d3 a8 ce c1 a0 29-40 51 01 48 ea 67 2b 49   .......)@Q.H.g+I
0110 - ce 50 00 66 37 d6 c8 e8-76 54 aa b5 fa f7 da 07   .P.f7...vT......
0120 - e4 17                                             ..
SSL_accept:SSLv3/TLS write finished
Read BLOCK
read from 0x261604dcdd0 [0x261605344c3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 1e                                    .....
read from 0x261604dcdd0 [0x261605344c8] (30 bytes => 30 (0x1E))
0000 - 66 4e ec 00 9d 31 e0 91-bd 95 c6 3d 32 fd 84 8f   fN...1.....=2...
0010 - 60 84 bb ae 3b c4 ce d4-43 78 d9 0e 3c 13         `...;...Cx..<.
test
read from 0x261604dcdd0 [0x261605344c3] (5 bytes => 5 (0x5))
0000 - 15 03 03 00 1a                                    .....
read from 0x261604dcdd0 [0x261605344c8] (26 bytes => 26 (0x1A))
0000 - 66 4e ec 00 9d 31 e0 92-7d af 0b 2e 41 88 1b fa   fN...1..}...A...
0010 - 68 d3 fe 06 04 c3 66 0d-b6 8a                     h.....f...
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x261604dcdd0 [0x26160543c03] (31 bytes => 31 (0x1F))
0000 - 15 03 03 00 1a 55 09 bc-ad b1 c1 c8 1f 08 04 95   .....U..........
0010 - 36 7c 38 25 7d 7d 37 45-14 7f 3b 17 39 a5 4c      6|8%}}7E..;.9.L
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
