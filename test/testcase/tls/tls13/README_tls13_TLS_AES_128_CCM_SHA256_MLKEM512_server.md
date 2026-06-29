#### server

````
$ openssl s_server -accept 9000 -cert ecdsa.crt -key ecdsa.key -state -debug -status_verbose -keylogfile sslkeylog -tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256 -groups MLKEM512
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x1e67eae7d00 [0x1e67f2d4be3] (5 bytes => 5 (0x5))
0000 - 16 03 01 03 cf                                    .....
read from 0x1e67eae7d00 [0x1e67f2d4be8] (975 bytes => 975 (0x3CF))
0000 - 01 00 03 cb 03 03 0e ad-c6 a1 78 89 16 e5 19 9d   ..........x.....
0010 - c2 4c a9 80 d3 04 48 9f-92 e1 80 c5 0c 55 8c b2   .L....H......U..
0020 - c5 dc dc e6 6f 96 20 c3-2c 81 5c 4f 0f cb f1 c1   ....o. .,.\O....
0030 - ce 0a 6a 4b 00 98 f9 63-40 0d 44 a3 24 33 5f 9f   ..jK...c@.D.$3_.
0040 - a2 c1 8e 62 b3 2e 04 00-02 13 04 01 00 03 80 00   ...b............
0050 - 0a 00 04 00 02 02 00 00-23 00 00 00 16 00 00 00   ........#.......
0060 - 17 00 00 00 0d 00 2a 00-28 09 05 09 06 09 04 04   ......*.(.......
0070 - 03 05 03 06 03 08 07 08-08 08 1a 08 1b 08 1c 08   ................
0080 - 09 08 0a 08 0b 08 04 08-05 08 06 04 01 05 01 06   ................
0090 - 01 00 2b 00 03 02 03 04-00 2d 00 02 01 01 00 33   ..+......-.....3
00a0 - 03 26 03 24 02 00 03 20-1f 2b 42 92 eb c6 2f cb   .&.$... .+B.../.
00b0 - 59 72 16 16 19 66 49 4c-75 40 2a 79 13 68 aa 26   Yr...fILu@*y.h.&
00c0 - c0 c8 74 da e5 36 d2 73-c7 74 7c ab 38 63 00 da   ..t..6.s.t|.8c..
00d0 - c6 06 9a 55 48 5b 15 6f-71 29 54 53 49 6c 8a 2b   ...UH[.oq)TSIl.+
00e0 - ab 26 b1 c8 10 c9 61 e2-2c 8e 9a f8 66 1a c4 5b   .&....a.,...f..[
00f0 - 0e f3 be 73 6c 84 5d c2-cf 59 23 38 b9 cc 55 74   ...sl.]..Y#8..Ut
0100 - 06 37 14 c9 c6 bf 0b 79-d9 0a 5e f7 ec 60 cb 85   .7.....y..^..`..
0110 - 12 44 27 76 f1 4b 67 e6-e4 7f 7a 4c 55 3b 81 4f   .D'v.Kg...zLU;.O
0120 - 04 48 61 e6 c5 93 24 01-56 66 6b c5 db 92 54 82   .Ha...$.Vfk...T.
0130 - 60 89 71 50 c5 b9 82 8a-84 a6 0b a3 b4 b4 78 bb   `.qP..........x.
0140 - b4 95 c7 03 21 82 6b 77-b5 34 68 e2 35 a9 20 9b   ....!.kw.4h.5. .
0150 - 4e 81 11 01 c5 6b 0e 00-96 cd c6 50 34 fa 94 14   N....k.....P4...
0160 - ea 49 f6 59 59 33 a9 43-37 47 20 3f 42 2d a3 43   .I.YY3.C7G ?B-.C
0170 - 85 ba c6 86 6c 61 a8 42-52 94 01 52 27 37 86 13   ....la.BR..R'7..
0180 - c2 10 8f 34 58 24 fb 85-9c 71 e2 b6 9e 89 54 5e   ...4X$...q....T^
0190 - e0 9a 14 75 04 46 e9 cc-c8 ca a8 45 10 35 d7 a9   ...u.F.....E.5..
01a0 - 15 78 b5 21 d9 c7 44 31-e7 54 cd 0a 95 a2 09 40   .x.!..D1.T.....@
01b0 - a1 54 bb bf 1b 77 44 47-03 88 7c 61 06 23 05 c0   .T...wDG..|a.#..
01c0 - e0 b7 84 25 ad 85 15 01-3a 56 50 41 fc 43 8f 21   ...%....:VPA.C.!
01d0 - 43 6e 97 50 ed 02 71 fe-d7 89 36 c4 30 fa f6 53   Cn.P..q...6.0..S
01e0 - 94 9c cb 40 06 c7 04 69-b4 29 57 c6 88 ba 4d b3   ...@...i.)W...M.
01f0 - e8 42 f2 1b 2b 78 0a 40-e6 a8 cb 30 0b 4b cd 6a   .B..+x.@...0.K.j
0200 - 2d e0 20 6d 67 d6 23 32-b5 c1 07 c1 c8 fb 88 41   -. mg.#2.......A
0210 - fc 90 ab 4f a0 09 69 08-9a fd 5b 3b 12 14 6f b8   ...O..i...[;..o.
0220 - 53 7b e8 e0 aa e7 02 6f-75 11 c1 92 37 66 dc 41   S{.....ou...7f.A
0230 - 37 2a 63 7d ed 6a 35 73-4b 16 a7 88 8e a6 c8 58   7*c}.j5sK......X
0240 - 81 41 64 5c d1 14 34 c4-7f e5 04 91 4a f4 54 b6   .Ad\..4.....J.T.
0250 - 8c 9e 81 6b 0b f4 f1 56-0d 64 a0 22 89 2b 09 66   ...k...V.d.".+.f
0260 - 12 9a 6b 45 f3 33 0a dd-34 7f 52 c7 48 e3 c0 44   ..kE.3..4.R.H..D
0270 - 6d 19 8b 2f d4 8a 63 dc-b9 44 db 38 2f 91 59 a4   m../..c..D.8/.Y.
0280 - 18 8b 91 67 6a c3 85 c8-a3 14 c0 d5 c2 33 08 36   ...gj........3.6
0290 - a1 8f a9 a0 06 26 45 8c-69 a1 63 0b 97 66 b9 bd   .....&E.i.c..f..
02a0 - 54 f7 78 3f 52 3a f7 e1-96 4e e5 22 80 82 73 94   T.x?R:...N."..s.
02b0 - 17 9d da 23 6a ad 70 74-3d 0c 81 54 25 62 f2 a3   ...#j.pt=..T%b..
02c0 - bd 6c a7 50 63 19 83 b0-25 59 b5 db c6 40 eb 99   .l.Pc...%Y...@..
02d0 - 9c 15 6b bf 09 05 06 82-2c 61 7c 38 5c 3c 3e 27   ..k.....,a|8\<>'
02e0 - a9 14 e4 0a 3c 60 20 a8-37 a2 a5 cc 16 21 2a 57   ....<` .7....!*W
02f0 - 7a d4 bb a7 0a 7b c3 8a-b0 bf f3 a0 14 3f 61 03   z....{.......?a.
0300 - 2d c7 36 b0 0c 45 fa b2-c5 ba f6 b7 65 dc 4d 2a   -.6..E......e.M*
0310 - d7 31 a9 95 99 47 d0 78-22 db 60 5e cb 44 9f a9   .1...G.x".`^.D..
0320 - 00 e4 b1 96 a0 9a 12 19-dc c4 cb 61 ce 46 b2 c8   ...........a.F..
0330 - c8 31 b0 91 b5 10 79 a3-31 e2 81 1a 52 81 cb 02   .1....y.1...R...
0340 - 2a 83 19 04 7c d5 11 1d-38 51 b2 f3 20 c1 b4 00   *...|...8Q.. ...
0350 - 93 d3 d6 1e 36 12 0e 15-33 40 47 c5 50 f3 94 7a   ....6...3@G.P..z
0360 - 27 b1 56 04 d2 a2 70 e5-08 4f c6 af 7f e9 6c e6   '.V...p..O....l.
0370 - 67 78 08 5c ae 0a 47 30-86 e5 3d 4b 84 b8 61 eb   gx.\..G0..=K..a.
0380 - 4f 2f cb 80 26 0a 73 13-81 5c 32 f0 15 25 a7 8d   O/..&.s..\2..%..
0390 - 29 d6 93 aa 7b 2b ea 6c-b0 70 b9 9c 18 4a 51 af   )...{+.l.p...JQ.
03a0 - a1 c3 4f fb 62 3f 61 8b-32 9a e4 f5 e5 7e 74 de   ..O.b?a.2....~t.
03b0 - 47 9d 13 bd db 2e 8c bf-5a 5f 19 d9 95 2d 19 fc   G.......Z_...-..
03c0 - cb 97 0b 5c 52 d4 b1 91-00 1b 00 03 02 00 01      ...\R..........
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write change cipher spec
SSL_accept:TLSv1.3 write encrypted extensions
SSL_accept:SSLv3/TLS write certificate
SSL_accept:TLSv1.3 write server certificate verify
write to 0x1e67eae7d00 [0x1e67f2d3bd0] (1614 bytes => 1614 (0x64E))
0000 - 16 03 03 03 5a 02 00 03-56 03 03 1f 0f 15 b6 f1   ....Z...V.......
0010 - 06 9d 79 b6 02 19 f1 95-61 00 96 a7 97 48 7c b5   ..y.....a....H|.
0020 - 61 7e 95 56 a9 7a 38 2f-4f 7c af 20 c3 2c 81 5c   a~.V.z8/O|. .,.\
0030 - 4f 0f cb f1 c1 ce 0a 6a-4b 00 98 f9 63 40 0d 44   O......jK...c@.D
0040 - a3 24 33 5f 9f a2 c1 8e-62 b3 2e 04 13 04 00 03   .$3_....b.......
0050 - 0e 00 2b 00 02 03 04 00-33 03 04 02 00 03 00 9e   ..+.....3.......
0060 - e9 38 9c af 29 a9 0f 60-87 b3 36 51 5e 6d 3a 78   .8..)..`..6Q^m:x
0070 - df 6c 88 a3 40 b5 77 38-be a7 bd ff 9d a3 a6 21   .l..@.w8.......!
0080 - 63 07 38 c6 d3 76 33 d2-08 a6 7d 93 fd 58 38 90   c.8..v3...}..X8.
0090 - 66 83 e4 80 8c 0e 20 82-46 a4 5c e5 60 f8 3e de   f..... .F.\.`.>.
00a0 - cb e5 d4 97 f7 31 9d bb-74 65 a4 66 3b 45 1b 5e   .....1..te.f;E.^
00b0 - a5 78 e0 54 84 85 c8 43-52 b4 6e 75 ac bc 5c ed   .x.T...CR.nu..\.
00c0 - 7b 56 a2 c7 de a2 d4 4d-cf 8b 2b 2d b5 1b 27 f0   {V.....M..+-..'.
00d0 - 58 1e f1 7e 01 1f 63 8c-16 12 05 4a d9 5f 36 d8   X..~..c....J._6.
00e0 - 05 04 ca 63 3a e8 2f 4d-5f ba 92 85 be 81 a6 a6   ...c:./M_.......
00f0 - 3e 72 bc 99 b2 66 37 46-55 e5 c1 e5 9c 53 30 68   >r...f7FU....S0h
0100 - 0a be 6e f5 c4 21 bd 87-01 eb 7c a9 07 c6 90 ac   ..n..!....|.....
0110 - 9c 83 bd db 36 64 a3 8f-e7 94 09 5b f4 6c cd 73   ....6d.....[.l.s
0120 - c0 bb e3 82 d7 03 96 3c-8b a2 d4 89 a2 f7 c2 a6   .......<........
0130 - c1 32 a8 58 52 db 41 a9-86 0d 34 ec 5c 4b 31 9a   .2.XR.A...4.\K1.
0140 - 6f b3 87 aa 1a d4 70 e7-02 ac 6b 47 77 8e cc f5   o.....p...kGw...
0150 - 38 46 af 82 52 dd 9a b1-1b a9 c0 95 3a 72 c8 ba   8F..R.......:r..
0160 - 05 4a a1 5a 88 cb 20 7a-d1 a8 b3 99 e5 07 e3 1b   .J.Z.. z........
0170 - 89 33 cd 54 4e e4 34 d3-80 8d 54 3d 4e 27 62 54   .3.TN.4...T=N'bT
0180 - 4f 9e 70 54 03 d5 1f 31-27 e8 93 7d a9 b3 20 52   O.pT...1'..}.. R
0190 - 9d dc 19 91 34 04 e0 36-e5 a5 52 4d 74 ea e5 bc   ....4..6..RMt...
01a0 - 55 0e c3 cc 4a 9b 30 5f-6c 60 97 5f 0d 5d f7 f2   U...J.0_l`._.]..
01b0 - 4c 99 93 26 62 d0 0f e1-e0 69 a1 a9 12 02 e2 26   L..&b....i.....&
01c0 - 0a ee c6 2f 78 44 55 4d-dd 67 03 2b dd 7f 22 54   .../xDUM.g.+.."T
01d0 - 4f ec 04 65 6a e3 9a fd-64 ab e5 b0 e7 50 48 58   O..ej...d....PHX
01e0 - ac 86 69 94 42 82 40 25-1e 05 97 66 6f 66 34 d0   ..i.B.@%...fof4.
01f0 - 52 87 3b 25 54 ae 85 20-f0 b4 20 41 dc ab 07 b8   R.;%T.. .. A....
0200 - 42 d3 a2 cc 17 f9 76 19-fb 3f fc c1 a2 60 50 18   B.....v..?...`P.
0210 - 8e 56 f3 4b 5c c5 e4 37-84 87 7f cb c8 5d 48 4c   .V.K\..7.....]HL
0220 - 23 d7 65 ce 14 ac 5b 4d-73 87 d8 e4 3e ad a9 e3   #.e...[Ms...>...
0230 - d1 c0 dd 42 48 c7 7b 40-ed 9b 53 32 96 e4 0b 22   ...BH.{@..S2..."
0240 - 15 17 13 8c 71 f9 ed 1a-3f f6 0f e1 35 90 97 bd   ....q...?...5...
0250 - 36 33 ab 28 a7 ce 82 a0-74 6c 59 03 e7 e0 65 d9   63.(....tlY...e.
0260 - a0 ae 1b 17 26 0e b8 27-47 76 64 ac 42 4f 6a 76   ....&..'Gvd.BOjv
0270 - 87 00 21 d2 fd ef ce 1b-d8 79 6a 4c fd ad c5 ea   ..!......yjL....
0280 - 3e ba 4c da 8f c8 29 ea-34 7a 4c 88 01 9d b0 8c   >.L...).4zL.....
0290 - 0c 56 d6 65 ae 16 5f b8-01 48 02 de 68 d4 ba 7c   .V.e.._..H..h..|
02a0 - bb 33 af 93 f5 a4 60 78-6b 93 a7 dd 11 67 00 40   .3....`xk....g.@
02b0 - 82 74 82 ef 89 62 d1 9e-8b 80 71 2f e9 6b 88 43   .t...b....q/.k.C
02c0 - 0e 44 e2 cc 11 32 25 a5-7f c6 61 de 19 eb a5 93   .D...2%...a.....
02d0 - 27 ee ff 86 15 f9 50 3f-4a 81 51 fc 77 e9 77 06   '.....P?J.Q.w.w.
02e0 - d9 15 1c eb 58 80 82 70-21 51 d4 d8 2e 9b 68 bf   ....X..p!Q....h.
02f0 - 0f aa c5 bb 35 1c d0 45-5b f0 4b 5e 67 0d a3 49   ....5..E[.K^g..I
0300 - 9d 7c 9a 93 51 07 ac 0e-8b b5 1e f7 36 15 ef 22   .|..Q.......6.."
0310 - 7a be 08 ff f5 77 e5 3f-6e 5b f7 0c a1 f6 2b 09   z....w.?n[....+.
0320 - e1 cf 72 22 cb 1d f8 91-b7 f4 b8 f0 d8 d3 e0 32   ..r"...........2
0330 - 2a 33 26 fb d4 9b 10 8c-7d 77 76 42 7f d7 8b 74   *3&.....}wvB...t
0340 - eb d5 9e 07 65 1f 1f 45-0d b7 8e 79 1c cd 38 0f   ....e..E...y..8.
0350 - d8 06 37 65 58 e2 9f 15-7d 46 b2 6f 5b 80 ec 14   ..7eX...}F.o[...
0360 - 03 03 00 01 01 17 03 03-00 17 0f 6a 43 de cd 09   ...........jC...
0370 - 7c b6 dc af 64 95 ef 33-76 9a e5 4b 0f ee 44 0b   |...d..3v..K..D.
0380 - e0 17 03 03 02 2a c8 55-e0 a4 15 e8 9e 84 86 e2   .....*.U........
0390 - 08 e0 0d 1a 15 02 fc 50-a1 4e d0 08 d9 a6 cc 4a   .......P.N.....J
03a0 - 37 b3 b9 b0 e6 ab 3c 9d-08 43 df 9d ca 83 9a e1   7.....<..C......
03b0 - 38 12 3b 4a fc d3 00 13-1f 1d 79 82 60 4e e5 e7   8.;J......y.`N..
03c0 - 4a 25 b1 22 84 d5 26 d6-4e 92 8c 1e 6b de 22 36   J%."..&.N...k."6
03d0 - b6 e1 9c 15 4a 42 f0 a5-18 81 a4 b3 63 51 61 57   ....JB......cQaW
03e0 - 97 3b 65 ee cd a3 88 7e-a1 01 67 51 44 d3 cf 4a   .;e....~..gQD..J
03f0 - 7f fc 14 7b 23 af c1 29-8b db 75 e3 6d 62 bc f8   ...{#..)..u.mb..
0400 - c4 17 6b 7f 9e 00 d7 42-5e da ed 75 87 5b 28 5f   ..k....B^..u.[(_
0410 - 77 bb 9e 81 f9 88 42 29-cd 10 ab f8 99 58 4e ec   w.....B).....XN.
0420 - ae 48 7b a0 47 27 9a 73-fd a5 c7 d5 bb 61 d9 f0   .H{.G'.s.....a..
0430 - 87 58 e2 86 7d 46 a2 dc-f2 a3 f7 92 49 9e f7 55   .X..}F......I..U
0440 - 6e 8a f1 a4 c4 82 c1 36-8e 54 a8 16 86 3e c1 df   n......6.T...>..
0450 - 0c 5d 9e bf d8 ec 17 c0-a0 29 f7 87 4f ac 0a 7f   .].......)..O...
0460 - 54 86 7d 18 c7 43 10 78-69 58 52 69 44 0b ab c2   T.}..C.xiXRiD...
0470 - d7 85 50 91 77 06 eb 6d-db 19 a2 10 5f 77 3a 02   ..P.w..m...._w:.
0480 - 72 5d 84 45 81 8f 46 31-c9 a7 5c 1e eb 51 ae 9c   r].E..F1..\..Q..
0490 - 8c 7c 69 52 f0 5e a5 c5-95 df e1 f7 34 c2 bc bb   .|iR.^......4...
04a0 - e3 bf b0 90 5b 36 22 23-a7 2b 46 9b d5 61 2e c7   ....[6"#.+F..a..
04b0 - e3 3e e5 47 1f ec 49 a9-5b 52 3b 97 db 11 84 b1   .>.G..I.[R;.....
04c0 - a7 08 22 dc fa ec ef be-76 e2 fc 41 74 10 71 67   ..".....v..At.qg
04d0 - b5 3c 35 66 d5 6f d5 b8-b1 e2 4c 98 26 9b bd b9   .<5f.o....L.&...
04e0 - 86 2d 2a f5 77 37 c2 53-06 9a 10 e4 ee 1c 2e af   .-*.w7.S........
04f0 - 4a 24 cb b6 67 f8 5e f1-cc 46 4a 72 a3 bd bf e7   J$..g.^..FJr....
0500 - 5a de 25 c0 88 e7 c0 a5-47 8d 5f fa 51 0e fd 64   Z.%.....G._.Q..d
0510 - 8c 0a 80 a5 8c 0a 44 93-c9 93 17 e5 8a d7 0a 5c   ......D........\
0520 - 37 a2 f7 b3 d8 73 21 e0-84 ce 84 d0 df a1 f0 77   7....s!........w
0530 - 9e 60 ff 6b fa 8f eb 3d-b9 49 98 17 6c f2 a1 01   .`.k...=.I..l...
0540 - 2a 87 ed 92 06 11 87 3a-1a 14 26 cb d4 83 2b 54   *......:..&...+T
0550 - df 0e b1 07 03 be 97 59-10 2b e7 fa 28 dd ed 37   .......Y.+..(..7
0560 - 77 fe b0 a5 b6 6b ed e9-ad 5f 07 5f 37 f6 3e c3   w....k..._._7.>.
0570 - 35 8e 7f 95 8e 90 bd 09-40 c9 82 62 ee aa 3f 4a   5.......@..b..?J
0580 - 01 86 ce db 82 72 64 12-74 09 29 c9 15 3d 16 50   .....rd.t.)..=.P
0590 - ca 44 99 10 76 9d 74 74-6a 16 cc a9 13 30 7c ce   .D..v.ttj....0|.
05a0 - f8 c2 95 76 17 42 85 3e-87 0e 16 44 f6 a9 f9 09   ...v.B.>...D....
05b0 - 17 03 03 00 5f 80 3d f8-22 6c 0e 4c fa 08 1d d0   ...._.=."l.L....
05c0 - 53 68 59 04 cc 0c 5a 97-c4 30 e4 c4 9c 47 92 ff   ShY...Z..0...G..
05d0 - 17 30 c8 52 b7 05 e1 b2-30 9b 93 ec b7 a3 11 f2   .0.R....0.......
05e0 - bd 28 f1 b5 57 b5 51 a3-4b 55 f2 42 c4 42 44 fb   .(..W.Q.KU.B.BD.
05f0 - 5e a5 af 67 8b de c9 24-b6 c1 8c 8c a1 a0 ff 70   ^..g...$.......p
0600 - 09 98 6e a2 81 98 e2 ea-52 c3 79 dd 0d 2c 90 62   ..n.....R.y..,.b
0610 - fc b0 de 7e 17 03 03 00-35 b1 93 0c 58 47 e3 c9   ...~....5...XG..
0620 - a9 9f 75 ed e8 a8 b6 47-2a 54 69 f8 81 e1 0d 11   ..u....G*Ti.....
0630 - 5d d2 dd 73 8d 57 b2 0a-31 76 ba 60 2e 62 69 0e   ]..s.W..1v.`.bi.
0640 - d0 89 23 0a ca 32 9b f8-22 ce 16 41 0a c1         ..#..2.."..A..
SSL_accept:SSLv3/TLS write finished
SSL_accept:TLSv1.3 early data
read from 0x1e67eae7d00 [0x1e67f2d4be3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x1e67eae7d00 [0x1e67f2d4be8] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x1e67eae7d00 [0x1e67f2d4be3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
read from 0x1e67eae7d00 [0x1e67f2d4be8] (53 bytes => 53 (0x35))
0000 - 70 eb f3 8d 54 38 a4 28-14 35 bc 75 bf a5 be e4   p...T8.(.5.u....
0010 - 27 97 01 b2 47 d8 1d cf-c8 3d 6d 76 92 40 81 e1   '...G....=mv.@..
0020 - 9b 85 39 41 b6 eb a8 5e-56 66 de 89 1d 4d 85 fe   ..9A...^Vf...M..
0030 - b6 f1 fb 05 5a                                    ....Z
SSL_accept:TLSv1.3 early data
SSL_accept:SSLv3/TLS read finished
write to 0x1e67eae7d00 [0x1e67f2d3bd0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea 65 f3 e6-fa b6 c2 94 22 f8 70 08   .....e......".p.
0010 - a5 6b 20 63 c3 31 3e 3d-f9 97 01 6d 24 82 cb a3   .k c.1>=...m$...
0020 - 32 45 b7 fc a9 5a 43 c0-43 98 b6 57 74 98 7e 23   2E...ZC.C..Wt.~#
0030 - c4 24 dd 33 48 52 3f 24-ca a2 78 8b cd bb 2c f9   .$.3HR?$..x...,.
0040 - 19 c6 21 47 d2 c6 c1 ce-df 8a 89 cf c1 79 b6 bd   ..!G.........y..
0050 - 00 19 62 d5 47 9e dc 31-fd b4 af e2 7c b5 e5 5b   ..b.G..1....|..[
0060 - 00 45 bc 3f 0d 18 38 0e-16 d4 4b 25 98 2f 68 2b   .E.?..8...K%./h+
0070 - 46 c4 45 3c f5 c3 d7 6a-51 a2 6a f3 42 6d b5 a6   F.E<...jQ.j.Bm..
0080 - 66 54 85 93 38 af 07 d8-4a 5d c0 d7 69 28 9a 41   fT..8...J]..i(.A
0090 - f6 9e 3e 8c 57 d0 f3 fe-1a ce 52 93 61 1c c7 52   ..>.W.....R.a..R
00a0 - cc 73 5f e7 34 c6 c1 ef-06 bf c8 f1 d6 a4 53 5e   .s_.4.........S^
00b0 - 82 fe e8 7a 59 4a 84 98-56 06 30 33 ab 5f 50 ee   ...zYJ..V.03._P.
00c0 - 1f 0c 16 39 f5 43 0b e0-8c c3 1f 3b 31 e0 c3 5e   ...9.C.....;1..^
00d0 - 3a 31 a7 d2 ab 09 5a 85-11 e5 66 96 3b 5d 71 61   :1....Z...f.;]qa
00e0 - fe 5f d3 6b 0e 05 21 3d-25 69 6a fc ae 31 91      ._.k..!=%ij..1.
SSL_accept:SSLv3/TLS write session ticket
write to 0x1e67eae7d00 [0x1e67f2d3bd0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea 73 3e 78-fe f8 1a 85 4a 2d af 92   .....s>x....J-..
0010 - 4e 62 df 07 a5 7e 99 ac-c6 23 4b e7 ce ae d0 36   Nb...~...#K....6
0020 - 6a 0c bc 9e 02 c6 23 ec-af 5d b7 37 0d 13 aa 98   j.....#..].7....
0030 - ac e5 99 a8 6a 3b 87 db-4f 96 13 4f 82 8b 40 9d   ....j;..O..O..@.
0040 - 8d 9b 44 8e 53 4b c8 23-de fb 70 4f 55 a2 63 17   ..D.SK.#..pOU.c.
0050 - 51 7f 14 3b da 37 51 cf-69 9a ee 59 5e 0f 50 fd   Q..;.7Q.i..Y^.P.
0060 - 9e 2a 88 de 83 a6 c5 ce-7b e1 23 00 41 e9 cf ee   .*......{.#.A...
0070 - f6 7f 2c 9a 81 c3 0d f8-9e 87 6a 66 45 63 64 a3   ..,.......jfEcd.
0080 - 84 cc 4e fe 03 ff 39 60-7f 84 ff 9f 29 86 28 16   ..N...9`....).(.
0090 - 0f 8a 02 c5 97 e1 ea 0e-90 bf 47 75 fd 53 9e 0c   ..........Gu.S..
00a0 - 92 57 49 80 8d 4b 5f d4-18 01 91 b7 fd c7 42 4c   .WI..K_.......BL
00b0 - 05 68 7b 8d 61 9c 14 13-7a 51 83 d4 22 4a d8 e3   .h{.a...zQ.."J..
00c0 - 8a 50 74 78 eb 1d db 53-10 25 9e 20 4b 40 5f 27   .Ptx...S.%. K@_'
00d0 - 3a 3a 7f 14 ee c3 3e d2-63 ad 41 62 e7 ec 03 78   ::....>.c.Ab...x
00e0 - 36 98 f7 a3 00 f0 7e 90-d3 f2 7d 7d e8 9c b1      6.....~...}}...
SSL_accept:SSLv3/TLS write session ticket
-----BEGIN SSL SESSION PARAMETERS-----
MHMCAQECAgMEBAITBAQgsGQGftzAB2n42wtSrd0T9d+WgYmWNphJc4hPm12kH1QE
ILgvEpDQH1SZJ0iWnpDh6QULhSV3nFbc//x/TqCAm6ztoQYCBGjqMt2iBAICHCCk
BgQEAQAAAK4GAgRbZF4ZswQCAgIA
-----END SSL SESSION PARAMETERS-----
Shared ciphers:TLS_AES_128_CCM_SHA256
Signature Algorithms: id-ml-dsa-65:id-ml-dsa-87:id-ml-dsa-44:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:ed448:ecdsa_brainpoolP256r1_sha256:ecdsa_brainpoolP384r1_sha384:ecdsa_brainpoolP512r1_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Shared Signature Algorithms: id-ml-dsa-65:id-ml-dsa-87:id-ml-dsa-44:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:ed448:ecdsa_brainpoolP256r1_sha256:ecdsa_brainpoolP384r1_sha384:ecdsa_brainpoolP512r1_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Supported groups: MLKEM512
Shared groups: MLKEM512
CIPHER is TLS_AES_128_CCM_SHA256
This TLS version forbids renegotiation.
read from 0x1e67eae7d00 [0x1e67f2e3593] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x1e67eae7d00 [0x1e67f2e3598] (23 bytes => 23 (0x17))
0000 - 6e 05 65 90 13 e7 3a ca-90 6e 7e 08 f1 6c 48 76   n.e...:..n~..lHv
0010 - 83 53 f4 ae 6f 5a 3d                              .S..oZ=
test
read from 0x1e67eae7d00 [0x1e67f2e3593] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 13                                    .....
read from 0x1e67eae7d00 [0x1e67f2e3598] (19 bytes => 19 (0x13))
0000 - f8 89 db e6 d9 8f cb 84-49 6d 69 71 4b d7 c7 5d   ........ImiqK..]
0010 - b1 75 a5                                          .u.
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x1e67eae7d00 [0x1e67f2d4be3] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 72 db 8f-ff 2b cf cd b4 34 ea e2   .....r...+...4..
0010 - 76 0a 93 28 5c e2 55 a3-                          v..(\.U.
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
