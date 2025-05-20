#### tls12etm_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384.pcapng - server

````
$ openssl s_server -accept 9000 -cert server.crt -key server.key -state -debug -status_verbose -keylogfile sslkeylog
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x1e4944fb800 [0x1e49491ce43] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 b9                                    .....
read from 0x1e4944fb800 [0x1e49491ce48] (185 bytes => 185 (0xB9))
0000 - 01 00 00 b5 03 03 5b d8-10 fc 94 e2 3f 4e 88 98   ......[.....?N..
0010 - db 26 77 17 85 0c f6 85-c6 89 34 58 24 fb 91 85   .&w.......4X$...
0020 - e6 42 8f da 1a 83 00 00-10 c0 23 c0 24 c0 27 c0   .B........#.$.'.
0030 - 28 c0 72 c0 73 c0 76 c0-77 01 00 00 7c ff 01 00   (.r.s.v.w...|...
0040 - 01 00 00 23 00 00 00 16-00 00 00 0b 00 02 01 00   ...#............
0050 - 00 0a 00 0c 00 0a 00 1d-00 17 00 1e 00 19 00 18   ................
0060 - 00 0d 00 1e 00 1c 04 03-05 03 06 03 08 07 08 08   ................
0070 - 04 01 05 01 06 01 08 09-08 0a 08 0b 08 04 08 05   ................
0080 - 08 06 00 2b 00 03 02 03-03 00 2d 00 02 01 01 00   ...+......-.....
0090 - 33 00 26 00 24 00 1d 00-20 81 ad d9 d4 28 f7 37   3.&.$... ....(.7
00a0 - 9a 1c 02 2f 6c cc d4 b2-1d 98 85 d4 d5 c0 d4 0a   .../l...........
00b0 - 44 16 93 00 2a e8 ba 55-4c                        D...*..UL
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write certificate
SSL_accept:SSLv3/TLS write key exchange
write to 0x1e4944fb800 [0x1e49491be30] (1263 bytes => 1263 (0x4EF))
0000 - 16 03 03 00 41 02 00 00-3d 03 03 be f4 8e 83 c5   ....A...=.......
0010 - da 09 ab a6 c2 99 30 3e-2b 7a 33 1c 1d 72 6e 61   ......0>+z3..rna
0020 - 2e 3c 9b 44 4f 57 4e 47-52 44 01 00 c0 28 00 00   .<.DOWNGRD...(..
0030 - 15 ff 01 00 01 00 00 0b-00 04 03 00 01 02 00 23   ...............#
0040 - 00 00 00 16 00 00 16 03-03 03 6a 0b 00 03 66 00   ..........j...f.
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
03c0 - 1d 20 af 57 28 c9 9d 2d-3a 2e de 89 53 7d 85 d1   . .W(..-:...S}..
03d0 - 82 37 a2 d5 92 45 26 a0-c1 ea b7 51 63 46 35 b6   .7...E&....QcF5.
03e0 - 22 75 04 01 01 00 93 a8-14 f7 c4 61 b6 df d4 de   "u.........a....
03f0 - 30 bf 41 ca 40 1c b3 57-5f 60 93 9e d0 ba 72 8b   0.A.@..W_`....r.
0400 - 67 09 5e 23 da e8 65 56-c7 09 2f 66 64 9e 1d d2   g.^#..eV../fd...
0410 - da 7b d0 07 35 81 6f 70-f6 5a 75 24 67 7b 58 66   .{..5.op.Zu$g{Xf
0420 - 61 26 35 f0 2f 8a c1 32-3d e1 65 f0 26 52 07 bc   a&5./..2=.e.&R..
0430 - 63 0c a3 60 e1 00 64 58-71 35 b1 3a 1e 2e 8b 96   c..`..dXq5.:....
0440 - 7a a5 e3 1e 5a b4 f7 79-a0 89 ce ee 47 80 5e e8   z...Z..y....G.^.
0450 - 8b 37 d2 56 a3 8e df 3a-90 76 95 d0 be a5 39 49   .7.V...:.v....9I
0460 - 07 5f 50 88 fb 9d ce 3b-00 60 4e 0b b5 34 57 b4   ._P....;.`N..4W.
0470 - d3 2a 31 5f 09 b6 44 91-b0 e9 5a 34 0a fd 7d 45   .*1_..D...Z4..}E
0480 - dc 32 78 3c 56 5c 4e a7-1c a6 3c 93 86 fc 63 88   .2x<V\N...<...c.
0490 - eb 9d a6 b9 86 bf 20 d7-a9 34 a8 27 89 c9 9b 8a   ...... ..4.'....
04a0 - a0 63 a9 dd 24 d2 15 40-76 49 0b 26 d9 3a 5b fe   .c..$..@vI.&.:[.
04b0 - 11 8b dc 3a 74 80 e8 10-aa 6f ed 00 62 4a 34 96   ...:t....o..bJ4.
04c0 - 4e f6 c5 0c 3b b4 fe aa-da 30 4f 2c 33 93 b9 bc   N...;....0O,3...
04d0 - 00 07 bd b3 a2 f4 0c 5e-33 6c 2a c7 11 b8 cc e1   .......^3l*.....
04e0 - 04 d3 bc 37 c3 6b 16 03-03 00 04 0e 00 00 00      ...7.k.........
SSL_accept:SSLv3/TLS write server done
read from 0x1e4944fb800 [0x1e49491ce43] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 25                                    ....%
read from 0x1e4944fb800 [0x1e49491ce48] (37 bytes => 37 (0x25))
0000 - 10 00 00 21 20 1a 15 b0-3f 91 f5 a1 40 74 bb f2   ...! ...?...@t..
0010 - 5b cd f3 13 9e 6d 9d ef-2b b8 79 76 4b be f1 a0   [....m..+.yvK...
0020 - f6 4a 6a f4 70                                    .Jj.p
SSL_accept:SSLv3/TLS write server done
read from 0x1e4944fb800 [0x1e49491ce43] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x1e4944fb800 [0x1e49491ce48] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_accept:SSLv3/TLS read client key exchange
read from 0x1e4944fb800 [0x1e49491ce43] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 60                                    ....`
read from 0x1e4944fb800 [0x1e49491ce48] (96 bytes => 96 (0x60))
0000 - 6a 82 08 87 c3 73 1a e6-bd 4e fa 91 8e de 53 7d   j....s...N....S}
0010 - b4 4b b5 0a 6c 9c 52 03-c7 63 d9 fc f6 8f d9 b9   .K..l.R..c......
0020 - 70 b3 32 84 c7 ce 91 73-5c fa 5e a2 bc cb f6 34   p.2....s\.^....4
0030 - 5e 3f b5 b1 f9 20 78 27-ba 8f b0 0c bb d8 df 61   ^?... x'.......a
0040 - 30 ae 18 bf dc 29 03 05-12 f5 1d 08 54 7f c7 5e   0....)......T..^
0050 - 0b 43 48 dc 68 a6 23 be-c4 2e 6a d2 b0 00 33 57   .CH.h.#...j...3W
SSL_accept:SSLv3/TLS read change cipher spec
SSL_accept:SSLv3/TLS read finished
SSL_accept:SSLv3/TLS write session ticket
SSL_accept:SSLv3/TLS write change cipher spec
write to 0x1e4944fb800 [0x1e49491be30] (282 bytes => 282 (0x11A))
0000 - 16 03 03 00 aa 04 00 00-a6 00 00 1c 20 00 a0 6f   ............ ..o
0010 - a9 92 5b dd f6 37 7a f9-ea c1 0f 8a f5 e9 77 7e   ..[..7z.......w~
0020 - c4 b8 a2 0b 85 09 54 2f-fa 6e ab 03 1c 41 c9 58   ......T/.n...A.X
0030 - fc 0d b9 6b 27 47 ea c0-50 cd db 1d a1 43 76 90   ...k'G..P....Cv.
0040 - 1f c8 56 da e1 04 6e d8-6b 8b e7 22 c1 71 2f b7   ..V...n.k..".q/.
0050 - ed 76 d4 4d ab 6e 25 06-2e b9 50 47 7e 76 5a cd   .v.M.n%...PG~vZ.
0060 - 56 c7 5a 2c 60 fc 71 ea-5d 99 8a 21 1c 7b 01 2a   V.Z,`.q.]..!.{.*
0070 - 20 56 b1 8b 86 73 ff 6a-71 a5 e9 5a f4 b5 a6 32    V...s.jq..Z...2
0080 - 9e 3f 5e 30 5d 5b 37 8f-fb 1d 05 ed 61 e0 eb b1   .?^0][7.....a...
0090 - c7 1c e6 9a d5 99 96 7d-0e e0 e4 b3 0b 63 28 51   .......}.....c(Q
00a0 - 45 0b e4 d3 2a 81 cd 3f-82 1e 5d 6c 2e 7f 96 14   E...*..?..]l....
00b0 - 03 03 00 01 01 16 03 03-00 60 0b f3 55 42 a9 47   .........`..UB.G
00c0 - f3 97 dc e9 d5 f7 85 ca-51 39 76 19 e2 78 a7 83   ........Q9v..x..
00d0 - 7b 7f 0b c9 42 82 5c e8-ad 90 66 83 32 07 19 17   {...B.\...f.2...
00e0 - 29 a5 06 cb 16 d6 4b 0a-9b c8 63 48 c2 b5 bd 8f   ).....K...cH....
00f0 - d5 6b 8f eb 00 65 5d b6-fb 74 59 81 9e f0 b1 44   .k...e]..tY....D
0100 - 6b 79 4a 87 88 c5 7f ba-bd 56 3c 80 60 4a 5f f8   kyJ......V<.`J_.
0110 - a2 bf 69 a1 65 53 d6 7a-b1 c8                     ..i.eS.z..
SSL_accept:SSLv3/TLS write finished
-----BEGIN SSL SESSION PARAMETERS-----
MFoCAQECAgMDBALAKAQABDAcNTmIRwbBBgKhyDIbQIt+rApm/zpwBaP6Rd2JW+QR
7hoMfu5bJn4HRLW9tzmpmZChBgIEaAR8haIEAgIcIKQGBAQBAAAAswMCAR0=
-----END SSL SESSION PARAMETERS-----
Shared ciphers:ECDHE-RSA-AES256-SHA384
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA+SHA256:RSA+SHA384:RSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA+SHA256:RSA+SHA384:RSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512
Supported Elliptic Curve Point Formats: uncompressed
Supported groups: x25519:secp256r1:x448:secp521r1:secp384r1
Shared groups: x25519:secp256r1:x448:secp521r1:secp384r1
CIPHER is ECDHE-RSA-AES256-SHA384
Secure Renegotiation IS supported
read from 0x1e4944fb800 [0x1e49491ce43] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 50                                    ....P
read from 0x1e4944fb800 [0x1e49491ce48] (80 bytes => 80 (0x50))
0000 - d6 c4 e8 29 58 c7 dd 23-1f 66 0d 25 b9 39 0b fd   ...)X..#.f.%.9..
0010 - ca 2b c1 68 f2 e2 b5 5e-2e 0d f0 c1 78 24 6b e6   .+.h...^....x$k.
0020 - 92 ae bd 91 98 5c 29 aa-40 51 d9 cd 29 2d d7 ae   .....\).@Q..)-..
0030 - cf f7 00 d4 c4 d4 f1 82-df ee 35 11 5c e8 fd 7d   ..........5.\..}
0040 - f2 eb 82 3b 99 99 28 ad-02 6d a8 e2 78 39 23 87   ...;..(..m..x9#.
helloread from 0x1e4944fb800 [0x1e49491ce43] (5 bytes => 5 (0x5))
0000 - 15 03 03 00 50                                    ....P
read from 0x1e4944fb800 [0x1e49491ce48] (80 bytes => 80 (0x50))
0000 - ab df c9 0c b0 3d 68 67-1f 35 fa 16 b4 1c e9 62   .....=hg.5.....b
0010 - dd a9 fc e2 35 75 3c a6-28 8a 43 eb 0c ba 54 50   ....5u<.(.C...TP
0020 - ab f2 31 89 89 69 38 59-66 14 6c 1e 99 a5 78 a0   ..1..i8Yf.l...x.
0030 - ad 28 c0 b7 3a 1a 0d 9e-19 2c 1d 60 fe 4d 21 2b   .(..:....,.`.M!+
0040 - 77 fe 04 85 88 c4 f4 4d-a4 ac f2 01 41 86 35 58   w......M....A.5X
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x1e4944fb800 [0x1e49492da13] (85 bytes => 85 (0x55))
0000 - 15 03 03 00 50 15 28 a8-87 4f 13 fb 46 1b 54 7b   ....P.(..O..F.T{
0010 - 9d 61 c3 41 0d 34 4f c2-12 77 80 40 67 2e 5f 75   .a.A.4O..w.@g._u
0020 - 35 78 58 27 2b 84 27 a3-89 69 69 ae 1b 2f f2 fc   5xX'+.'..ii../..
0030 - 8f 2a 3d 8b 05 51 a9 03-49 d5 bd 1d 9e eb 0b 79   .*=..Q..I......y
0040 - a5 4a 09 bc 5f d3 df fd-36 72 a5 3f a2 fe b7 5d   .J.._...6r.?...]
0050 - 25 5c 44 bc 50                                    %\D.P
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
