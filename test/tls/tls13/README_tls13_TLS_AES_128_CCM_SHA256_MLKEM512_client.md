#### client

````
$ openssl s_client -connect localhost:9000 -state -debug -keylogfile sslkeylog -tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256 -groups MLKEM512
Connecting to ::1
CONNECTED(000001F8)
SSL_connect:before SSL initialization
write to 0x1f4286a7570 [0x1f42a292b60] (980 bytes => 980 (0x3D4))
0000 - 16 03 01 03 cf 01 00 03-cb 03 03 0e ad c6 a1 78   ...............x
0010 - 89 16 e5 19 9d c2 4c a9-80 d3 04 48 9f 92 e1 80   ......L....H....
0020 - c5 0c 55 8c b2 c5 dc dc-e6 6f 96 20 c3 2c 81 5c   ..U......o. .,.\
0030 - 4f 0f cb f1 c1 ce 0a 6a-4b 00 98 f9 63 40 0d 44   O......jK...c@.D
0040 - a3 24 33 5f 9f a2 c1 8e-62 b3 2e 04 00 02 13 04   .$3_....b.......
0050 - 01 00 03 80 00 0a 00 04-00 02 02 00 00 23 00 00   .............#..
0060 - 00 16 00 00 00 17 00 00-00 0d 00 2a 00 28 09 05   ...........*.(..
0070 - 09 06 09 04 04 03 05 03-06 03 08 07 08 08 08 1a   ................
0080 - 08 1b 08 1c 08 09 08 0a-08 0b 08 04 08 05 08 06   ................
0090 - 04 01 05 01 06 01 00 2b-00 03 02 03 04 00 2d 00   .......+......-.
00a0 - 02 01 01 00 33 03 26 03-24 02 00 03 20 1f 2b 42   ....3.&.$... .+B
00b0 - 92 eb c6 2f cb 59 72 16-16 19 66 49 4c 75 40 2a   .../.Yr...fILu@*
00c0 - 79 13 68 aa 26 c0 c8 74-da e5 36 d2 73 c7 74 7c   y.h.&..t..6.s.t|
00d0 - ab 38 63 00 da c6 06 9a-55 48 5b 15 6f 71 29 54   .8c.....UH[.oq)T
00e0 - 53 49 6c 8a 2b ab 26 b1-c8 10 c9 61 e2 2c 8e 9a   SIl.+.&....a.,..
00f0 - f8 66 1a c4 5b 0e f3 be-73 6c 84 5d c2 cf 59 23   .f..[...sl.]..Y#
0100 - 38 b9 cc 55 74 06 37 14-c9 c6 bf 0b 79 d9 0a 5e   8..Ut.7.....y..^
0110 - f7 ec 60 cb 85 12 44 27-76 f1 4b 67 e6 e4 7f 7a   ..`...D'v.Kg...z
0120 - 4c 55 3b 81 4f 04 48 61-e6 c5 93 24 01 56 66 6b   LU;.O.Ha...$.Vfk
0130 - c5 db 92 54 82 60 89 71-50 c5 b9 82 8a 84 a6 0b   ...T.`.qP.......
0140 - a3 b4 b4 78 bb b4 95 c7-03 21 82 6b 77 b5 34 68   ...x.....!.kw.4h
0150 - e2 35 a9 20 9b 4e 81 11-01 c5 6b 0e 00 96 cd c6   .5. .N....k.....
0160 - 50 34 fa 94 14 ea 49 f6-59 59 33 a9 43 37 47 20   P4....I.YY3.C7G
0170 - 3f 42 2d a3 43 85 ba c6-86 6c 61 a8 42 52 94 01   ?B-.C....la.BR..
0180 - 52 27 37 86 13 c2 10 8f-34 58 24 fb 85 9c 71 e2   R'7.....4X$...q.
0190 - b6 9e 89 54 5e e0 9a 14-75 04 46 e9 cc c8 ca a8   ...T^...u.F.....
01a0 - 45 10 35 d7 a9 15 78 b5-21 d9 c7 44 31 e7 54 cd   E.5...x.!..D1.T.
01b0 - 0a 95 a2 09 40 a1 54 bb-bf 1b 77 44 47 03 88 7c   ....@.T...wDG..|
01c0 - 61 06 23 05 c0 e0 b7 84-25 ad 85 15 01 3a 56 50   a.#.....%....:VP
01d0 - 41 fc 43 8f 21 43 6e 97-50 ed 02 71 fe d7 89 36   A.C.!Cn.P..q...6
01e0 - c4 30 fa f6 53 94 9c cb-40 06 c7 04 69 b4 29 57   .0..S...@...i.)W
01f0 - c6 88 ba 4d b3 e8 42 f2-1b 2b 78 0a 40 e6 a8 cb   ...M..B..+x.@...
0200 - 30 0b 4b cd 6a 2d e0 20-6d 67 d6 23 32 b5 c1 07   0.K.j-. mg.#2...
0210 - c1 c8 fb 88 41 fc 90 ab-4f a0 09 69 08 9a fd 5b   ....A...O..i...[
0220 - 3b 12 14 6f b8 53 7b e8-e0 aa e7 02 6f 75 11 c1   ;..o.S{.....ou..
0230 - 92 37 66 dc 41 37 2a 63-7d ed 6a 35 73 4b 16 a7   .7f.A7*c}.j5sK..
0240 - 88 8e a6 c8 58 81 41 64-5c d1 14 34 c4 7f e5 04   ....X.Ad\..4....
0250 - 91 4a f4 54 b6 8c 9e 81-6b 0b f4 f1 56 0d 64 a0   .J.T....k...V.d.
0260 - 22 89 2b 09 66 12 9a 6b-45 f3 33 0a dd 34 7f 52   ".+.f..kE.3..4.R
0270 - c7 48 e3 c0 44 6d 19 8b-2f d4 8a 63 dc b9 44 db   .H..Dm../..c..D.
0280 - 38 2f 91 59 a4 18 8b 91-67 6a c3 85 c8 a3 14 c0   8/.Y....gj......
0290 - d5 c2 33 08 36 a1 8f a9-a0 06 26 45 8c 69 a1 63   ..3.6.....&E.i.c
02a0 - 0b 97 66 b9 bd 54 f7 78-3f 52 3a f7 e1 96 4e e5   ..f..T.x?R:...N.
02b0 - 22 80 82 73 94 17 9d da-23 6a ad 70 74 3d 0c 81   "..s....#j.pt=..
02c0 - 54 25 62 f2 a3 bd 6c a7-50 63 19 83 b0 25 59 b5   T%b...l.Pc...%Y.
02d0 - db c6 40 eb 99 9c 15 6b-bf 09 05 06 82 2c 61 7c   ..@....k.....,a|
02e0 - 38 5c 3c 3e 27 a9 14 e4-0a 3c 60 20 a8 37 a2 a5   8\<>'....<` .7..
02f0 - cc 16 21 2a 57 7a d4 bb-a7 0a 7b c3 8a b0 bf f3   ..!*Wz....{.....
0300 - a0 14 3f 61 03 2d c7 36-b0 0c 45 fa b2 c5 ba f6   ..?a.-.6..E.....
0310 - b7 65 dc 4d 2a d7 31 a9-95 99 47 d0 78 22 db 60   .e.M*.1...G.x".`
0320 - 5e cb 44 9f a9 00 e4 b1-96 a0 9a 12 19 dc c4 cb   ^.D.............
0330 - 61 ce 46 b2 c8 c8 31 b0-91 b5 10 79 a3 31 e2 81   a.F...1....y.1..
0340 - 1a 52 81 cb 02 2a 83 19-04 7c d5 11 1d 38 51 b2   .R...*...|...8Q.
0350 - f3 20 c1 b4 00 93 d3 d6-1e 36 12 0e 15 33 40 47   . .......6...3@G
0360 - c5 50 f3 94 7a 27 b1 56-04 d2 a2 70 e5 08 4f c6   .P..z'.V...p..O.
0370 - af 7f e9 6c e6 67 78 08-5c ae 0a 47 30 86 e5 3d   ...l.gx.\..G0..=
0380 - 4b 84 b8 61 eb 4f 2f cb-80 26 0a 73 13 81 5c 32   K..a.O/..&.s..\2
0390 - f0 15 25 a7 8d 29 d6 93-aa 7b 2b ea 6c b0 70 b9   ..%..)...{+.l.p.
03a0 - 9c 18 4a 51 af a1 c3 4f-fb 62 3f 61 8b 32 9a e4   ..JQ...O.b?a.2..
03b0 - f5 e5 7e 74 de 47 9d 13-bd db 2e 8c bf 5a 5f 19   ..~t.G.......Z_.
03c0 - d9 95 2d 19 fc cb 97 0b-5c 52 d4 b1 91 00 1b 00   ..-.....\R......
03d0 - 03 02 00 01                                       ....
SSL_connect:SSLv3/TLS write client hello
read from 0x1f4286a7570 [0x1f42a298c83] (5 bytes => 5 (0x5))
0000 - 16 03 03 03 5a                                    ....Z
read from 0x1f4286a7570 [0x1f42a298c88] (858 bytes => 858 (0x35A))
0000 - 02 00 03 56 03 03 1f 0f-15 b6 f1 06 9d 79 b6 02   ...V.........y..
0010 - 19 f1 95 61 00 96 a7 97-48 7c b5 61 7e 95 56 a9   ...a....H|.a~.V.
0020 - 7a 38 2f 4f 7c af 20 c3-2c 81 5c 4f 0f cb f1 c1   z8/O|. .,.\O....
0030 - ce 0a 6a 4b 00 98 f9 63-40 0d 44 a3 24 33 5f 9f   ..jK...c@.D.$3_.
0040 - a2 c1 8e 62 b3 2e 04 13-04 00 03 0e 00 2b 00 02   ...b.........+..
0050 - 03 04 00 33 03 04 02 00-03 00 9e e9 38 9c af 29   ...3........8..)
0060 - a9 0f 60 87 b3 36 51 5e-6d 3a 78 df 6c 88 a3 40   ..`..6Q^m:x.l..@
0070 - b5 77 38 be a7 bd ff 9d-a3 a6 21 63 07 38 c6 d3   .w8.......!c.8..
0080 - 76 33 d2 08 a6 7d 93 fd-58 38 90 66 83 e4 80 8c   v3...}..X8.f....
0090 - 0e 20 82 46 a4 5c e5 60-f8 3e de cb e5 d4 97 f7   . .F.\.`.>......
00a0 - 31 9d bb 74 65 a4 66 3b-45 1b 5e a5 78 e0 54 84   1..te.f;E.^.x.T.
00b0 - 85 c8 43 52 b4 6e 75 ac-bc 5c ed 7b 56 a2 c7 de   ..CR.nu..\.{V...
00c0 - a2 d4 4d cf 8b 2b 2d b5-1b 27 f0 58 1e f1 7e 01   ..M..+-..'.X..~.
00d0 - 1f 63 8c 16 12 05 4a d9-5f 36 d8 05 04 ca 63 3a   .c....J._6....c:
00e0 - e8 2f 4d 5f ba 92 85 be-81 a6 a6 3e 72 bc 99 b2   ./M_.......>r...
00f0 - 66 37 46 55 e5 c1 e5 9c-53 30 68 0a be 6e f5 c4   f7FU....S0h..n..
0100 - 21 bd 87 01 eb 7c a9 07-c6 90 ac 9c 83 bd db 36   !....|.........6
0110 - 64 a3 8f e7 94 09 5b f4-6c cd 73 c0 bb e3 82 d7   d.....[.l.s.....
0120 - 03 96 3c 8b a2 d4 89 a2-f7 c2 a6 c1 32 a8 58 52   ..<.........2.XR
0130 - db 41 a9 86 0d 34 ec 5c-4b 31 9a 6f b3 87 aa 1a   .A...4.\K1.o....
0140 - d4 70 e7 02 ac 6b 47 77-8e cc f5 38 46 af 82 52   .p...kGw...8F..R
0150 - dd 9a b1 1b a9 c0 95 3a-72 c8 ba 05 4a a1 5a 88   .......:r...J.Z.
0160 - cb 20 7a d1 a8 b3 99 e5-07 e3 1b 89 33 cd 54 4e   . z.........3.TN
0170 - e4 34 d3 80 8d 54 3d 4e-27 62 54 4f 9e 70 54 03   .4...T=N'bTO.pT.
0180 - d5 1f 31 27 e8 93 7d a9-b3 20 52 9d dc 19 91 34   ..1'..}.. R....4
0190 - 04 e0 36 e5 a5 52 4d 74-ea e5 bc 55 0e c3 cc 4a   ..6..RMt...U...J
01a0 - 9b 30 5f 6c 60 97 5f 0d-5d f7 f2 4c 99 93 26 62   .0_l`._.]..L..&b
01b0 - d0 0f e1 e0 69 a1 a9 12-02 e2 26 0a ee c6 2f 78   ....i.....&.../x
01c0 - 44 55 4d dd 67 03 2b dd-7f 22 54 4f ec 04 65 6a   DUM.g.+.."TO..ej
01d0 - e3 9a fd 64 ab e5 b0 e7-50 48 58 ac 86 69 94 42   ...d....PHX..i.B
01e0 - 82 40 25 1e 05 97 66 6f-66 34 d0 52 87 3b 25 54   .@%...fof4.R.;%T
01f0 - ae 85 20 f0 b4 20 41 dc-ab 07 b8 42 d3 a2 cc 17   .. .. A....B....
0200 - f9 76 19 fb 3f fc c1 a2-60 50 18 8e 56 f3 4b 5c   .v..?...`P..V.K\
0210 - c5 e4 37 84 87 7f cb c8-5d 48 4c 23 d7 65 ce 14   ..7.....]HL#.e..
0220 - ac 5b 4d 73 87 d8 e4 3e-ad a9 e3 d1 c0 dd 42 48   .[Ms...>......BH
0230 - c7 7b 40 ed 9b 53 32 96-e4 0b 22 15 17 13 8c 71   .{@..S2..."....q
0240 - f9 ed 1a 3f f6 0f e1 35-90 97 bd 36 33 ab 28 a7   ...?...5...63.(.
0250 - ce 82 a0 74 6c 59 03 e7-e0 65 d9 a0 ae 1b 17 26   ...tlY...e.....&
0260 - 0e b8 27 47 76 64 ac 42-4f 6a 76 87 00 21 d2 fd   ..'Gvd.BOjv..!..
0270 - ef ce 1b d8 79 6a 4c fd-ad c5 ea 3e ba 4c da 8f   ....yjL....>.L..
0280 - c8 29 ea 34 7a 4c 88 01-9d b0 8c 0c 56 d6 65 ae   .).4zL......V.e.
0290 - 16 5f b8 01 48 02 de 68-d4 ba 7c bb 33 af 93 f5   ._..H..h..|.3...
02a0 - a4 60 78 6b 93 a7 dd 11-67 00 40 82 74 82 ef 89   .`xk....g.@.t...
02b0 - 62 d1 9e 8b 80 71 2f e9-6b 88 43 0e 44 e2 cc 11   b....q/.k.C.D...
02c0 - 32 25 a5 7f c6 61 de 19-eb a5 93 27 ee ff 86 15   2%...a.....'....
02d0 - f9 50 3f 4a 81 51 fc 77-e9 77 06 d9 15 1c eb 58   .P?J.Q.w.w.....X
02e0 - 80 82 70 21 51 d4 d8 2e-9b 68 bf 0f aa c5 bb 35   ..p!Q....h.....5
02f0 - 1c d0 45 5b f0 4b 5e 67-0d a3 49 9d 7c 9a 93 51   ..E[.K^g..I.|..Q
0300 - 07 ac 0e 8b b5 1e f7 36-15 ef 22 7a be 08 ff f5   .......6.."z....
0310 - 77 e5 3f 6e 5b f7 0c a1-f6 2b 09 e1 cf 72 22 cb   w.?n[....+...r".
0320 - 1d f8 91 b7 f4 b8 f0 d8-d3 e0 32 2a 33 26 fb d4   ..........2*3&..
0330 - 9b 10 8c 7d 77 76 42 7f-d7 8b 74 eb d5 9e 07 65   ...}wvB...t....e
0340 - 1f 1f 45 0d b7 8e 79 1c-cd 38 0f d8 06 37 65 58   ..E...y..8...7eX
0350 - e2 9f 15 7d 46 b2 6f 5b-80 ec                     ...}F.o[..
SSL_connect:SSLv3/TLS write client hello
read from 0x1f4286a7570 [0x1f42a298c83] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x1f4286a7570 [0x1f42a298c88] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x1f4286a7570 [0x1f42a298c83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x1f4286a7570 [0x1f42a298c88] (23 bytes => 23 (0x17))
0000 - 0f 6a 43 de cd 09 7c b6-dc af 64 95 ef 33 76 9a   .jC...|...d..3v.
0010 - e5 4b 0f ee 44 0b e0                              .K..D..
SSL_connect:SSLv3/TLS read server hello
Can't use SSL_get_servername
read from 0x1f4286a7570 [0x1f42a298c83] (5 bytes => 5 (0x5))
0000 - 17 03 03 02 2a                                    ....*
read from 0x1f4286a7570 [0x1f42a298c88] (554 bytes => 554 (0x22A))
0000 - c8 55 e0 a4 15 e8 9e 84-86 e2 08 e0 0d 1a 15 02   .U..............
0010 - fc 50 a1 4e d0 08 d9 a6-cc 4a 37 b3 b9 b0 e6 ab   .P.N.....J7.....
0020 - 3c 9d 08 43 df 9d ca 83-9a e1 38 12 3b 4a fc d3   <..C......8.;J..
0030 - 00 13 1f 1d 79 82 60 4e-e5 e7 4a 25 b1 22 84 d5   ....y.`N..J%."..
0040 - 26 d6 4e 92 8c 1e 6b de-22 36 b6 e1 9c 15 4a 42   &.N...k."6....JB
0050 - f0 a5 18 81 a4 b3 63 51-61 57 97 3b 65 ee cd a3   ......cQaW.;e...
0060 - 88 7e a1 01 67 51 44 d3-cf 4a 7f fc 14 7b 23 af   .~..gQD..J...{#.
0070 - c1 29 8b db 75 e3 6d 62-bc f8 c4 17 6b 7f 9e 00   .)..u.mb....k...
0080 - d7 42 5e da ed 75 87 5b-28 5f 77 bb 9e 81 f9 88   .B^..u.[(_w.....
0090 - 42 29 cd 10 ab f8 99 58-4e ec ae 48 7b a0 47 27   B).....XN..H{.G'
00a0 - 9a 73 fd a5 c7 d5 bb 61-d9 f0 87 58 e2 86 7d 46   .s.....a...X..}F
00b0 - a2 dc f2 a3 f7 92 49 9e-f7 55 6e 8a f1 a4 c4 82   ......I..Un.....
00c0 - c1 36 8e 54 a8 16 86 3e-c1 df 0c 5d 9e bf d8 ec   .6.T...>...]....
00d0 - 17 c0 a0 29 f7 87 4f ac-0a 7f 54 86 7d 18 c7 43   ...)..O...T.}..C
00e0 - 10 78 69 58 52 69 44 0b-ab c2 d7 85 50 91 77 06   .xiXRiD.....P.w.
00f0 - eb 6d db 19 a2 10 5f 77-3a 02 72 5d 84 45 81 8f   .m...._w:.r].E..
0100 - 46 31 c9 a7 5c 1e eb 51-ae 9c 8c 7c 69 52 f0 5e   F1..\..Q...|iR.^
0110 - a5 c5 95 df e1 f7 34 c2-bc bb e3 bf b0 90 5b 36   ......4.......[6
0120 - 22 23 a7 2b 46 9b d5 61-2e c7 e3 3e e5 47 1f ec   "#.+F..a...>.G..
0130 - 49 a9 5b 52 3b 97 db 11-84 b1 a7 08 22 dc fa ec   I.[R;......."...
0140 - ef be 76 e2 fc 41 74 10-71 67 b5 3c 35 66 d5 6f   ..v..At.qg.<5f.o
0150 - d5 b8 b1 e2 4c 98 26 9b-bd b9 86 2d 2a f5 77 37   ....L.&....-*.w7
0160 - c2 53 06 9a 10 e4 ee 1c-2e af 4a 24 cb b6 67 f8   .S........J$..g.
0170 - 5e f1 cc 46 4a 72 a3 bd-bf e7 5a de 25 c0 88 e7   ^..FJr....Z.%...
0180 - c0 a5 47 8d 5f fa 51 0e-fd 64 8c 0a 80 a5 8c 0a   ..G._.Q..d......
0190 - 44 93 c9 93 17 e5 8a d7-0a 5c 37 a2 f7 b3 d8 73   D........\7....s
01a0 - 21 e0 84 ce 84 d0 df a1-f0 77 9e 60 ff 6b fa 8f   !........w.`.k..
01b0 - eb 3d b9 49 98 17 6c f2-a1 01 2a 87 ed 92 06 11   .=.I..l...*.....
01c0 - 87 3a 1a 14 26 cb d4 83-2b 54 df 0e b1 07 03 be   .:..&...+T......
01d0 - 97 59 10 2b e7 fa 28 dd-ed 37 77 fe b0 a5 b6 6b   .Y.+..(..7w....k
01e0 - ed e9 ad 5f 07 5f 37 f6-3e c3 35 8e 7f 95 8e 90   ..._._7.>.5.....
01f0 - bd 09 40 c9 82 62 ee aa-3f 4a 01 86 ce db 82 72   ..@..b..?J.....r
0200 - 64 12 74 09 29 c9 15 3d-16 50 ca 44 99 10 76 9d   d.t.)..=.P.D..v.
0210 - 74 74 6a 16 cc a9 13 30-7c ce f8 c2 95 76 17 42   ttj....0|....v.B
0220 - 85 3e 87 0e 16 44 f6 a9-f9 09                     .>...D....
SSL_connect:TLSv1.3 read encrypted extensions
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
verify error:num=18:self-signed certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
verify return:1
read from 0x1f4286a7570 [0x1f42a298c83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 5f                                    ...._
read from 0x1f4286a7570 [0x1f42a298c88] (95 bytes => 95 (0x5F))
0000 - 80 3d f8 22 6c 0e 4c fa-08 1d d0 53 68 59 04 cc   .=."l.L....ShY..
0010 - 0c 5a 97 c4 30 e4 c4 9c-47 92 ff 17 30 c8 52 b7   .Z..0...G...0.R.
0020 - 05 e1 b2 30 9b 93 ec b7-a3 11 f2 bd 28 f1 b5 57   ...0........(..W
0030 - b5 51 a3 4b 55 f2 42 c4-42 44 fb 5e a5 af 67 8b   .Q.KU.B.BD.^..g.
0040 - de c9 24 b6 c1 8c 8c a1-a0 ff 70 09 98 6e a2 81   ..$.......p..n..
0050 - 98 e2 ea 52 c3 79 dd 0d-2c 90 62 fc b0 de 7e      ...R.y..,.b...~
SSL_connect:SSLv3/TLS read server certificate
read from 0x1f4286a7570 [0x1f42a298c83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
read from 0x1f4286a7570 [0x1f42a298c88] (53 bytes => 53 (0x35))
0000 - b1 93 0c 58 47 e3 c9 a9-9f 75 ed e8 a8 b6 47 2a   ...XG....u....G*
0010 - 54 69 f8 81 e1 0d 11 5d-d2 dd 73 8d 57 b2 0a 31   Ti.....]..s.W..1
0020 - 76 ba 60 2e 62 69 0e d0-89 23 0a ca 32 9b f8 22   v.`.bi...#..2.."
0030 - ce 16 41 0a c1                                    ..A..
SSL_connect:TLSv1.3 read server certificate verify
SSL_connect:SSLv3/TLS read finished
SSL_connect:SSLv3/TLS write change cipher spec
write to 0x1f4286a7570 [0x1f42a292b60] (64 bytes => 64 (0x40))
0000 - 14 03 03 00 01 01 17 03-03 00 35 70 eb f3 8d 54   ..........5p...T
0010 - 38 a4 28 14 35 bc 75 bf-a5 be e4 27 97 01 b2 47   8.(.5.u....'...G
0020 - d8 1d cf c8 3d 6d 76 92-40 81 e1 9b 85 39 41 b6   ....=mv.@....9A.
0030 - eb a8 5e 56 66 de 89 1d-4d 85 fe b6 f1 fb 05 5a   ..^Vf...M......Z
SSL_connect:SSLv3/TLS write finished
---
Certificate chain
 0 s:C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
   i:C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
   a:PKEY: EC, (prime256v1); sigalg: ecdsa-with-SHA256
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
Peer signature type: ecdsa_secp256r1_sha256
Negotiated TLS1.3 group: MLKEM512
---
SSL handshake has read 1614 bytes and written 1044 bytes
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
read from 0x1f4286a7570 [0x1f42a28c5f3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
read from 0x1f4286a7570 [0x1f42a28c5f8] (234 bytes => 234 (0xEA))
0000 - 65 f3 e6 fa b6 c2 94 22-f8 70 08 a5 6b 20 63 c3   e......".p..k c.
0010 - 31 3e 3d f9 97 01 6d 24-82 cb a3 32 45 b7 fc a9   1>=...m$...2E...
0020 - 5a 43 c0 43 98 b6 57 74-98 7e 23 c4 24 dd 33 48   ZC.C..Wt.~#.$.3H
0030 - 52 3f 24 ca a2 78 8b cd-bb 2c f9 19 c6 21 47 d2   R?$..x...,...!G.
0040 - c6 c1 ce df 8a 89 cf c1-79 b6 bd 00 19 62 d5 47   ........y....b.G
0050 - 9e dc 31 fd b4 af e2 7c-b5 e5 5b 00 45 bc 3f 0d   ..1....|..[.E.?.
0060 - 18 38 0e 16 d4 4b 25 98-2f 68 2b 46 c4 45 3c f5   .8...K%./h+F.E<.
0070 - c3 d7 6a 51 a2 6a f3 42-6d b5 a6 66 54 85 93 38   ..jQ.j.Bm..fT..8
0080 - af 07 d8 4a 5d c0 d7 69-28 9a 41 f6 9e 3e 8c 57   ...J]..i(.A..>.W
0090 - d0 f3 fe 1a ce 52 93 61-1c c7 52 cc 73 5f e7 34   .....R.a..R.s_.4
00a0 - c6 c1 ef 06 bf c8 f1 d6-a4 53 5e 82 fe e8 7a 59   .........S^...zY
00b0 - 4a 84 98 56 06 30 33 ab-5f 50 ee 1f 0c 16 39 f5   J..V.03._P....9.
00c0 - 43 0b e0 8c c3 1f 3b 31-e0 c3 5e 3a 31 a7 d2 ab   C.....;1..^:1...
00d0 - 09 5a 85 11 e5 66 96 3b-5d 71 61 fe 5f d3 6b 0e   .Z...f.;]qa._.k.
00e0 - 05 21 3d 25 69 6a fc ae-31 91                     .!=%ij..1.
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_CCM_SHA256
    Session-ID: 43734E04ADCCE2458EAF4D09B8DCDBBE7575B49DF47C32944763F6738566B5D5
    Session-ID-ctx:
    Resumption PSK: E78158AD83557F2D018CFE4E410523546A596EAB79EB68A985E92E10B77A38E8
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - d5 3f 53 13 fb dc 12 70-80 25 44 28 68 f0 a7 3c   .?S....p.%D(h..<
    0010 - b6 6f 80 df bf b2 bc 0f-cf 82 a5 66 05 d4 45 1e   .o.........f..E.
    0020 - 7a bb db d7 3f 4e 83 36-ac 5c 8b 33 e4 0c 77 d3   z...?N.6.\.3..w.
    0030 - 0f d1 4e 0a 60 6f 60 64-68 bc e2 e2 75 8a 01 26   ..N.`o`dh...u..&
    0040 - f2 11 dd 50 30 c3 7a 30-4f 50 f7 b8 84 95 58 9d   ...P0.z0OP....X.
    0050 - 79 4d 5a 17 30 9f 51 ec-c9 c1 43 d8 c1 c1 67 d2   yMZ.0.Q...C...g.
    0060 - 92 ff d0 22 02 8c 06 99-0d 90 b4 a1 f9 fc 09 5a   ..."...........Z
    0070 - 4e 75 2b 36 45 5b 3a 41-35 44 f9 d2 68 2c 4c 89   Nu+6E[:A5D..h,L.
    0080 - 48 3f c1 ea 8d f2 cb 11-15 ce f7 34 42 25 36 41   H?.........4B%6A
    0090 - 23 f1 1d c3 a7 7b cc 1f-de e6 2a 6c 28 d7 7f 0c   #....{....*l(...
    00a0 - b8 2d 73 e4 34 31 1f c3-88 33 a0 a6 a0 ad 88 a6   .-s.41...3......
    00b0 - f2 a9 d2 8d 72 ad b8 b5-1b 77 16 eb 0e a2 b3 c9   ....r....w......

    Start Time: 1760178909
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
read from 0x1f4286a7570 [0x1f42a28c5f3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
read from 0x1f4286a7570 [0x1f42a28c5f8] (234 bytes => 234 (0xEA))
0000 - 73 3e 78 fe f8 1a 85 4a-2d af 92 4e 62 df 07 a5   s>x....J-..Nb...
0010 - 7e 99 ac c6 23 4b e7 ce-ae d0 36 6a 0c bc 9e 02   ~...#K....6j....
0020 - c6 23 ec af 5d b7 37 0d-13 aa 98 ac e5 99 a8 6a   .#..].7........j
0030 - 3b 87 db 4f 96 13 4f 82-8b 40 9d 8d 9b 44 8e 53   ;..O..O..@...D.S
0040 - 4b c8 23 de fb 70 4f 55-a2 63 17 51 7f 14 3b da   K.#..pOU.c.Q..;.
0050 - 37 51 cf 69 9a ee 59 5e-0f 50 fd 9e 2a 88 de 83   7Q.i..Y^.P..*...
0060 - a6 c5 ce 7b e1 23 00 41-e9 cf ee f6 7f 2c 9a 81   ...{.#.A.....,..
0070 - c3 0d f8 9e 87 6a 66 45-63 64 a3 84 cc 4e fe 03   .....jfEcd...N..
0080 - ff 39 60 7f 84 ff 9f 29-86 28 16 0f 8a 02 c5 97   .9`....).(......
0090 - e1 ea 0e 90 bf 47 75 fd-53 9e 0c 92 57 49 80 8d   .....Gu.S...WI..
00a0 - 4b 5f d4 18 01 91 b7 fd-c7 42 4c 05 68 7b 8d 61   K_.......BL.h{.a
00b0 - 9c 14 13 7a 51 83 d4 22-4a d8 e3 8a 50 74 78 eb   ...zQ.."J...Ptx.
00c0 - 1d db 53 10 25 9e 20 4b-40 5f 27 3a 3a 7f 14 ee   ..S.%. K@_'::...
00d0 - c3 3e d2 63 ad 41 62 e7-ec 03 78 36 98 f7 a3 00   .>.c.Ab...x6....
00e0 - f0 7e 90 d3 f2 7d 7d e8-9c b1                     .~...}}...
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_CCM_SHA256
    Session-ID: 8F68452ECEAFBC9C7CE5E866DB28CF3D15131560A1D413D3F00DF7555946CFE6
    Session-ID-ctx:
    Resumption PSK: B82F1290D01F54992748969E90E1E9050B8525779C56DCFFFC7F4EA0809BACED
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - d5 3f 53 13 fb dc 12 70-80 25 44 28 68 f0 a7 3c   .?S....p.%D(h..<
    0010 - a8 1e c7 a2 2f 61 24 82-29 b6 7f f3 20 a5 a7 47   ..../a$.)... ..G
    0020 - 72 fe c1 2e c4 c6 13 cb-69 61 25 4f 1b 5a 4c 46   r.......ia%O.ZLF
    0030 - e8 91 92 26 dd 89 e1 7c-43 6d 8a 15 ae a9 e2 2a   ...&...|Cm.....*
    0040 - bc 18 ee 32 4d 5a 44 8c-f9 e6 aa 09 14 42 2d e6   ...2MZD......B-.
    0050 - e7 a3 d5 41 30 5b 9f 5c-f1 b9 e4 0a 87 ff 5d f2   ...A0[.\......].
    0060 - 6d ea cb f6 9e 64 30 c1-58 b9 f2 d8 fd 3d 02 6e   m....d0.X....=.n
    0070 - 35 37 8b 68 f9 79 3c de-f8 c6 e6 f3 c5 a6 0f 17   57.h.y<.........
    0080 - 3f e5 d8 f3 ae 51 ab 7a-89 71 05 7c 0b 36 f3 65   ?....Q.z.q.|.6.e
    0090 - b8 3c 8f b4 c3 d4 7b f8-7e ed 54 62 98 bf 82 f5   .<....{.~.Tb....
    00a0 - ac 1f 23 e0 dc b9 d7 20-b2 3d 49 e9 9f 48 42 3a   ..#.... .=I..HB:
    00b0 - 3f e0 16 40 4f 97 f5 83-ef ec 13 65 b4 2b c6 d4   ?..@O......e.+..

    Start Time: 1760178909
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
test
write to 0x1f4286a7570 [0x1f42a294bc3] (28 bytes => 28 (0x1C))
0000 - 17 03 03 00 17 6e 05 65-90 13 e7 3a ca 90 6e 7e   .....n.e...:..n~
0010 - 08 f1 6c 48 76 83 53 f4-ae 6f 5a 3d               ..lHv.S..oZ=
Q
DONE
write to 0x1f4286a7570 [0x1f42a294bc3] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 f8 89 db-e6 d9 8f cb 84 49 6d 69   .............Imi
0010 - 71 4b d7 c7 5d b1 75 a5-                          qK..].u.
SSL3 alert write:warning:close notify
read from 0x1f4286a7570 [0x1f4285cffa0] (16384 bytes => 24 (0x18))
0000 - 17 03 03 00 13 72 db 8f-ff 2b cf cd b4 34 ea e2   .....r...+...4..
0010 - 76 0a 93 28 5c e2 55 a3-                          v..(\.U.
read from 0x1f4286a7570 [0x1f4285cffa0] (16384 bytes => 0)
````

[TOC](README.md)
