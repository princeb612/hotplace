#### server

````
$ openssl s_server -accept 9000 -cert ecdsa.crt -key ecdsa.key -state -debug -status_verbose -keylogfile sslkeylog -tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256 -groups MLKEM1024
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x1ba028ab270 [0x1ba044d4be3] (5 bytes => 5 (0x5))
0000 - 16 03 01 06 cf                                    .....
read from 0x1ba028ab270 [0x1ba044d4be8] (1743 bytes => 1743 (0x6CF))
0000 - 01 00 06 cb 03 03 00 ab-11 e5 90 76 2d aa 4d 17   ...........v-.M.
0010 - 56 7f fb 8e 53 b2 fe 1c-a5 69 bd 9b 84 1d 64 d3   V...S....i....d.
0020 - 1f e1 30 ca a8 2e 20 c8-95 f1 42 4c d6 fb a4 34   ..0... ...BL...4
0030 - ba 03 d1 a2 96 78 b4 bb-b7 79 6d 8c 78 62 73 1d   .....x...ym.xbs.
0040 - e6 bb a9 ba d0 10 a3 00-02 13 04 01 00 06 80 00   ................
0050 - 0a 00 04 00 02 02 02 00-23 00 00 00 16 00 00 00   ........#.......
0060 - 17 00 00 00 0d 00 2a 00-28 09 05 09 06 09 04 04   ......*.(.......
0070 - 03 05 03 06 03 08 07 08-08 08 1a 08 1b 08 1c 08   ................
0080 - 09 08 0a 08 0b 08 04 08-05 08 06 04 01 05 01 06   ................
0090 - 01 00 2b 00 03 02 03 04-00 2d 00 02 01 01 00 33   ..+......-.....3
00a0 - 06 26 06 24 02 02 06 20-c1 73 6a 5a 55 93 76 4a   .&.$... .sjZU.vJ
00b0 - ba 23 84 72 6b e9 46 5d-53 2b ff 6a 0f 5c f7 5a   .#.rk.F]S+.j.\.Z
00c0 - 1e b6 69 87 9c 25 7d 64-0c 92 22 47 f5 b2 ae dc   ..i..%}d.."G....
00d0 - 66 ad 21 e8 72 46 10 b7-71 b6 64 9c 35 be ab bc   f.!.rF..q.d.5...
00e0 - ae c3 8a 4a 2e 48 ad ee-77 56 7a 48 65 75 25 a8   ...J.H..wVzHeu%.
00f0 - 7b fb 98 2c b7 1f 98 25-91 8b b4 2c 3b 2c 23 bb   {..,...%...,;,#.
0100 - fb 4b f4 b2 7d 9c 36 bd-60 17 39 ad 60 17 53 05   .K..}.6.`.9.`.S.
0110 - ad 4a 80 33 37 26 a5 a1-d8 4f ed 75 a6 90 f3 3c   .J.37&...O.u...<
0120 - f8 29 bd 89 0b 0a 9b 38-3f c0 30 98 87 48 be 61   .).....8?.0..H.a
0130 - 26 63 80 ea 19 ae d0 b7-60 61 42 1d e4 cd 8b 3b   &c......`aB....;
0140 - 69 3c 77 a8 2f 42 13 89-91 79 a5 14 ab f5 eb 10   i<w./B...y......
0150 - 28 eb 3d 8e a8 81 1d e7-a7 c0 fa 76 b5 a7 3c bc   (.=........v..<.
0160 - 86 8e 3f e8 48 d6 c9 7a-ad d3 80 5f f3 8e da 4b   ..?.H..z..._...K
0170 - 17 60 89 66 90 c6 02 6f-db 7f 58 46 71 80 89 42   .`.f...o..XFq..B
0180 - 0d 64 78 3a 4c 44 fc 18-ca 51 01 04 42 14 49 65   .dx:LD...Q..B.Ie
0190 - 75 8d 19 89 b0 45 40 aa-a0 b2 17 d9 34 69 c0 c1   u....E@.....4i..
01a0 - cc 37 3a bf 6d d2 4a 19-3a 2a 73 c6 b5 cd 20 06   .7:.m.J.:*s... .
01b0 - 9a b6 cd d2 cc c8 55 43-94 4f 18 a6 69 3a 34 30   ......UC.O..i:40
01c0 - 56 8a 51 cb 54 76 24 62-d0 17 75 9e 2b a5 ea d2   V.Q.Tv$b..u.+...
01d0 - 46 e3 1c b4 8a b2 16 c1-a7 11 bf a9 39 70 f7 3b   F...........9p.;
01e0 - d9 e7 23 65 8b bc 21 f1-2e 8a 9b 3f d6 a9 71 65   ..#e..!....?..qe
01f0 - 17 7d 73 8a 38 d0 84 7c-4b 00 c7 a1 76 35 90 0c   .}s.8..|K...v5..
0200 - 88 9a bb 54 fc 1a 88 7a-2b 4e c2 f5 06 05 b0 7c   ...T...z+N.....|
0210 - ca cc 83 8d 8a 53 90 ec-28 8a 83 53 9d 12 49 4c   .....S..(..S..IL
0220 - 67 64 24 ba 83 a6 eb c4-83 8b c2 71 33 3b b3 08   gd$........q3;..
0230 - 08 e1 15 45 c3 65 b5 4e-e4 cb d5 e8 91 5a a6 41   ...E.e.N.....Z.A
0240 - c1 55 4a ef 5a 43 19 75-ab f1 8c 5b 64 68 3f f7   .UJ.ZC.u...[dh?.
0250 - 46 9b 0e da 2a b9 5c 21-46 ac 03 65 79 75 08 c7   F...*.\!F..eyu..
0260 - b4 03 09 83 8e 37 26 27-1b b8 66 aa 9f 0a 56 58   .....7&'..f...VX
0270 - 51 b3 6d cb a3 07 bc 02-c8 f7 ab 70 a1 d3 ce 4e   Q.m........p...N
0280 - c4 c5 4d 29 a6 72 16 7f-cf d7 b5 fe 62 5c bb e6   ..M).r......b\..
0290 - 93 03 c2 98 db 75 31 7a-26 2f ff 32 7f f3 6a 31   .....u1z&/.2..j1
02a0 - 51 ab a4 db 07 11 93 e8-86 14 d4 59 14 a8 c5 28   Q..........Y...(
02b0 - 31 65 44 02 71 de fb 1b-7b ec 85 a1 75 4b a7 24   1eD.q...{...uK.$
02c0 - bc 2e a2 9b b6 e8 9a c6-64 bc e4 53 a0 12 a3 cd   ........d..S....
02d0 - b6 d9 52 9e 0a 51 ba e6-37 03 a8 75 50 88 8e e2   ..R..Q..7..uP...
02e0 - 21 1d 93 70 16 2d 29 17-4e 66 50 7a 6b 0e fa bc   !..p.-).NfPzk...
02f0 - 03 4c 36 a6 6f 42 70 a6-44 2e 99 13 10 7d b6 60   .L6.oBp.D....}.`
0300 - a9 f2 76 97 e3 9b 3d 5b-63 49 97 94 70 36 18 de   ..v...=[cI..p6..
0310 - 80 b5 82 f1 8a c5 44 c1-08 94 89 9b d7 90 a3 49   ......D........I
0320 - 6b 6e 59 31 2c d0 44 ec-6a 5b c4 e3 c0 76 b4 b5   knY1,.D.j[...v..
0330 - bb 28 17 e3 d3 4c fa 73-6f 0f d2 bc 91 9a c1 89   .(...L.so.......
0340 - 82 71 10 50 12 be 41 b8-c8 b5 4b e4 c0 62 e4 60   .q.P..A...K..b.`
0350 - 46 59 e6 45 ec 36 34 24-e9 c6 96 f9 2a 2f 61 38   FY.E.64$....*/a8
0360 - 9e f1 15 50 09 8b 8a 79-0d 5f b5 a0 3f 80 bd ca   ...P...y._..?...
0370 - 4a a1 9e 4b aa 7a 85 22-ca 5a 1b 1f c8 32 2f c8   J..K.z.".Z...2/.
0380 - 65 44 28 c4 6d b1 be 44-83 84 77 7c a1 04 22 a6   eD(.m..D..w|..".
0390 - 95 e2 8d a2 43 50 12 c3-9c eb f0 cc bd a3 57 8d   ....CP........W.
03a0 - 51 90 d5 60 0b 6f 09 78-68 d1 a2 54 24 07 2b d2   Q..`.o.xh..T$.+.
03b0 - 2f 61 db 71 fe 41 71 60-48 40 7d d1 ab 43 90 c2   /a.q.Aq`H@}..C..
03c0 - e5 46 bf 14 a7 08 5b b4-cb 0f 39 89 8c ca c1 a5   .F....[...9.....
03d0 - 61 12 ff 07 20 82 34 67-21 16 25 a9 a7 14 fc 7b   a... .4g!.%....{
03e0 - b7 73 a0 64 19 f7 22 06-18 58 a0 c6 3d 57 38 32   .s.d.."..X..=W82
03f0 - 55 e4 63 db ea 65 6d e6-29 06 e7 8f 82 59 72 c7   U.c..em.)....Yr.
0400 - 95 2d db 43 7e 9c 8c 8c-26 dc b6 7c 1b b5 33 c6   .-.C~...&..|..3.
0410 - 85 96 58 14 ac 21 57 57-43 c5 b5 e8 c1 aa dc 53   ..X..!WWC......S
0420 - 2f 21 20 c0 36 87 09 11-10 29 b8 8a b9 96 22 86   /! .6....)....".
0430 - f5 5d 36 73 03 20 d4 ca-89 e2 28 d4 34 40 8d ac   .]6s. ....(.4@..
0440 - 80 4e 9a 23 e9 c2 0f 93-7b b5 f4 a0 9b 6c 5b c8   .N.#....{....l[.
0450 - 08 82 78 5a 93 a9 5f 94-0f 5e 02 9f ab d0 1b 99   ..xZ.._..^......
0460 - 08 1e 1c 30 55 ae fa 00-4d 69 52 49 da 67 37 65   ...0U...MiRI.g7e
0470 - ca 75 03 05 f0 d8 5a e7-58 51 91 8c 60 62 cb 34   .u....Z.XQ..`b.4
0480 - 5d 20 66 04 3c 89 6b d2-4d 0f 04 1b 94 1c 70 98   ] f.<.k.M.....p.
0490 - 64 7f 1f a1 65 26 d8 c1-f1 f6 29 bc fb 1c 28 e8   d...e&....)...(.
04a0 - 99 6d 28 92 da 88 42 73-03 45 44 ec b3 97 3a b1   .m(...Bs.ED...:.
04b0 - f7 a7 ba a8 60 9f 95 f7-ca da 0c ac 44 99 89 b0   ....`.......D...
04c0 - ea 19 7d c1 71 e2 d3 63-8f e1 3e fd d1 90 24 f1   ..}.q..c..>...$.
04d0 - 88 86 16 13 f8 ba 5b 4f-c3 48 09 c0 20 08 9a bc   ......[O.H.. ...
04e0 - 09 59 40 9d c0 cc 31 d0-5b 1c d3 ce 3c 47 c5 76   .Y@...1.[...<G.v
04f0 - 28 07 7a 34 1b 90 a9 87-3d 9a 8b 52 29 49 f2 91   (.z4....=..R)I..
0500 - 84 7b 89 0c 49 9c 86 56-51 2d ed 1a 49 43 59 08   .{..I..VQ-..ICY.
0510 - 3c fc cd b4 59 87 aa 64-0b d2 91 89 9b 18 10 fd   <...Y..d........
0520 - 00 63 9d f5 af 9f 37 13-22 9c 20 57 11 b9 3f 00   .c....7.". W..?.
0530 - 28 f0 74 70 5d 25 67 ff-24 38 c2 f6 68 3f a3 7c   (.tp]%g.$8..h?.|
0540 - a1 50 72 20 40 b8 b0 82-92 74 f9 06 7f 87 80 87   .Pr @....t......
0550 - 06 6b c9 8b 62 a0 20 1c-ee 92 ca 57 a6 4f 66 79   .k..b. ....W.Ofy
0560 - 09 39 81 cd 88 45 7b fb-29 3b 61 42 c6 8a 00 9c   .9...E{.);aB....
0570 - 95 f8 7c 35 c6 6f 99 65-a3 e1 d7 cc b7 8a a7 1e   ..|5.o.e........
0580 - b0 19 71 f6 46 2d 43 27-d4 46 b3 82 46 ad c7 78   ..q.F-C'.F..F..x
0590 - 84 bc 91 19 e7 a4 80 ec-0b 1d e4 10 6f cc 80 35   ............o..5
05a0 - 8f e0 94 b8 bc c3 ca 5a-4c 8d a1 64 d3 08 81 c4   .......ZL..d....
05b0 - c8 af 3e a2 a4 d9 00 7e-93 10 23 54 01 b1 1a 2a   ..>....~..#T...*
05c0 - a8 25 b1 5d 25 d0 1e 4d-b5 62 ae 03 76 02 2a 80   .%.]%..M.b..v.*.
05d0 - ba d9 9d c6 90 ae 66 24-78 18 4b 59 5d 27 8f 6f   ......f$x.KY]'.o
05e0 - 61 8c 5d 85 5b f5 78 b1-6f c0 cc 8b 86 cf 13 f9   a.].[.x.o.......
05f0 - 5c e1 6a 6c e1 6a 0f 5e-58 81 42 2a 33 87 d3 cf   \.jl.j.^X.B*3...
0600 - d8 83 ca 3a 65 46 c2 62-98 e0 aa ce b2 16 c6 06   ...:eF.b........
0610 - 9a 4b b3 a6 51 70 85 96-6d 33 98 0f 75 16 9e 16   .K..Qp..m3..u...
0620 - cc c9 18 58 97 c5 a4 63-a2 6c 71 ca 37 00 64 28   ...X...c.lq.7.d(
0630 - 19 4b 4a 3f da 98 c3 e9-a2 4b 33 8e 59 48 a1 95   .KJ?.....K3.YH..
0640 - d5 73 59 27 c8 f8 25 4e-f9 14 76 d8 34 a3 c2 3c   .sY'..%N..v.4..<
0650 - 62 77 49 15 a5 2c ac 5b-2a ce 13 e5 15 55 78 94   bwI..,.[*....Ux.
0660 - a7 d3 4d 15 7c b3 f4 27-c6 b3 67 65 3d d6 33 b9   ..M.|..'..ge=.3.
0670 - 67 54 56 78 bf 62 76 74-bb b9 20 aa b0 65 a2 57   gTVx.bvt.. ..e.W
0680 - 52 f9 28 9c cb ba 5d d7-42 2a f1 63 c2 a4 c8 51   R.(...].B*.c...Q
0690 - 01 1a 07 da c2 33 52 29-c5 6d e6 5b 84 0b 32 7b   .....3R).m.[..2{
06a0 - 2a 91 51 04 91 2b a3 3c-45 82 0b 97 01 6c 12 b2   *.Q..+.<E....l..
06b0 - bc 3e 0e 0c 6b 86 af 92-26 ec af 6d be 56 a4 64   .>..k...&..m.V.d
06c0 - dd c8 0f 57 76 f5 b6 dc-00 1b 00 03 02 00 01      ...Wv..........
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write change cipher spec
SSL_accept:TLSv1.3 write encrypted extensions
SSL_accept:SSLv3/TLS write certificate
SSL_accept:TLSv1.3 write server certificate verify
write to 0x1ba028ab270 [0x1ba044d3bd0] (2415 bytes => 2415 (0x96F))
0000 - 16 03 03 06 7a 02 00 06-76 03 03 9c 25 94 d5 36   ....z...v...%..6
0010 - f5 92 47 66 51 6c 97 36-06 32 1b f8 fc 7e d3 8c   ..GfQl.6.2...~..
0020 - ae 5b fe 6f 7a 11 8a b6-f2 19 35 20 c8 95 f1 42   .[.oz.....5 ...B
0030 - 4c d6 fb a4 34 ba 03 d1-a2 96 78 b4 bb b7 79 6d   L...4.....x...ym
0040 - 8c 78 62 73 1d e6 bb a9-ba d0 10 a3 13 04 00 06   .xbs............
0050 - 2e 00 2b 00 02 03 04 00-33 06 24 02 02 06 20 bc   ..+.....3.$... .
0060 - b1 ff fa 69 bf d7 54 ea-3f a0 b6 65 08 c9 03 1a   ...i..T.?..e....
0070 - 66 ec 8c c4 ea 4a 63 af-f6 be d2 12 8d 3d 97 d0   f....Jc......=..
0080 - 61 4e ab cf bd b8 48 e4-b4 bf 2e 13 d3 94 59 e5   aN....H.......Y.
0090 - 1a 8d 72 e6 1d 20 ea df-31 45 ec 98 f0 b4 4a f4   ..r.. ..1E....J.
00a0 - 44 3d c1 a8 ed 46 8c 60-44 61 30 eb 32 17 91 60   D=...F.`Da0.2..`
00b0 - 49 db 91 03 3d 0b b2 d9-73 1c 5e 13 c8 07 7a 7f   I...=...s.^...z.
00c0 - 94 87 fb 66 c5 e2 76 f8-6b 4b 6e bb a5 bf 31 3a   ...f..v.kKn...1:
00d0 - 10 42 9a fa 2e e2 37 d9-3f eb 90 e5 ed af f5 92   .B....7.?.......
00e0 - 56 0f 05 c5 0d 10 52 3d-71 13 3d bd 8a 1c 3e fd   V.....R=q.=...>.
00f0 - 3f dc 9d ca f9 83 b9 79-d7 07 80 19 2d ad 1b 3e   ?......y....-..>
0100 - 9e 4e 92 19 46 a3 60 89-0f e3 51 1a be 67 c3 67   .N..F.`...Q..g.g
0110 - 19 94 84 2a 24 15 b6 38-f0 a8 ef 3a ab b9 48 46   ...*$..8...:..HF
0120 - 78 bc 19 74 64 2c b4 bb-59 91 35 19 22 c7 5d 04   x..td,..Y.5.".].
0130 - 2e 4f a4 d1 5f 21 86 c8-f6 57 ed 2b 9e a7 1f a8   .O.._!...W.+....
0140 - d5 32 c3 9d 08 9c 8e a5-14 1e d3 63 e0 fc a2 5c   .2.........c...\
0150 - f1 26 87 64 91 82 f4 06-8a fc 81 e5 41 7c 89 02   .&.d........A|..
0160 - c4 86 1f 88 42 18 99 09-c5 df 4f cc 0f 9f 89 db   ....B.....O.....
0170 - 02 a0 a9 6d cd d8 a5 5d-d6 d5 b3 e7 0f dc fe 54   ...m...].......T
0180 - 5c 69 60 83 99 bf ea d1-95 2f 5e 19 fe 64 16 16   \i`....../^..d..
0190 - 45 35 0a 4c 82 7a 41 33-dc 3c 32 11 25 fe c2 63   E5.L.zA3.<2.%..c
01a0 - 43 4a a3 43 0a 3d 6c 10-6a f7 97 aa fb fc 67 a1   CJ.C.=l.j.....g.
01b0 - 61 d5 a1 32 77 22 d2 1e-be d4 24 ca c5 94 0a 8b   a..2w"....$.....
01c0 - 4d 37 20 c8 72 a7 27 76-73 1b 36 1c f8 70 f0 63   M7 .r.'vs.6..p.c
01d0 - 0b aa 5c ce 43 08 ea f0-a2 d8 f7 25 1c 1d 33 5a   ..\.C......%..3Z
01e0 - c5 d2 d8 2d 24 d5 22 59-5d a8 18 51 40 70 a7 b8   ...-$."Y]..Q@p..
01f0 - 22 7f 88 37 02 97 fa c8-35 36 23 4f 9b 21 b2 65   "..7....56#O.!.e
0200 - 48 b3 fa 98 75 b0 25 8a-ed 5b 77 24 1a 8c c5 78   H...u.%..[w$...x
0210 - 15 b7 a2 d9 6b 08 44 ac-a2 13 7f cf c3 be 54 2e   ....k.D.......T.
0220 - d1 60 57 4a 0b bc 06 07-93 eb 03 8a 15 72 7f 57   .`WJ.........r.W
0230 - 15 e5 52 29 c2 b7 21 27-05 b2 3c 64 81 e3 f9 e2   ..R)..!'..<d....
0240 - 66 97 a3 fa 07 4e 03 0d-a2 69 f3 8c f3 0b 80 1d   f....N...i......
0250 - 73 a4 3b d1 66 7e b3 a6-7b b5 e8 a0 15 9c 1d 6d   s.;.f~..{......m
0260 - 79 e8 be 79 fc 7f 85 61-61 86 99 16 b9 70 c6 b6   y..y...aa....p..
0270 - ff 83 c1 3d 7b 31 ce 54-3f 49 26 4a 66 e8 97 21   ...={1.T?I&Jf..!
0280 - 42 b9 7d fc d5 56 68 5a-16 28 b0 00 98 89 dd f2   B.}..VhZ.(......
0290 - 1c 9f 0a 9c 8d a7 62 fb-3c c6 0e 4f ba 80 0e 3d   ......b.<..O...=
02a0 - e1 b8 9e 05 ab 6b 9d 63-71 b4 b0 29 01 87 01 f5   .....k.cq..)....
02b0 - 05 32 81 bc 5f 43 39 64-c3 b3 3d a4 63 53 a7 66   .2.._C9d..=.cS.f
02c0 - e8 1e 49 48 49 32 a4 be-c9 2d d2 1d 9a 09 04 f9   ..IHI2...-......
02d0 - 50 aa 39 c2 2e 1c 0e 70-82 ba fe e4 df 80 c4 ce   P.9....p........
02e0 - b3 5c bc d9 95 b1 1f 2e-9b 15 46 95 16 cb b1 f8   .\........F.....
02f0 - 4b be 38 e8 ba 78 47 fc-7e f0 6e 8e 8a ee 94 0b   K.8..xG.~.n.....
0300 - fb b3 3e 55 b2 09 a6 2f-28 41 ae c3 6e 35 70 32   ..>U.../(A..n5p2
0310 - 47 bb e3 45 05 a4 81 2a-cc c5 6c 40 37 4b 24 78   G..E...*..l@7K$x
0320 - 5d f5 88 b8 ef 50 8a 9f-29 f5 89 70 82 c5 77 ad   ]....P..)..p..w.
0330 - 05 1f fa c8 c1 e5 02 5b-a2 0a 2e f9 8e d6 f2 c0   .......[........
0340 - db c2 ec 71 5f 63 75 a9-6c 2e d7 66 b4 66 42 fc   ...q_cu.l..f.fB.
0350 - a7 1d d9 d8 18 9e b1 cc-87 14 20 5c 48 bf 62 89   .......... \H.b.
0360 - e5 ae fb b6 4e ab d4 f8-be ce 06 33 72 40 e8 13   ....N......3r@..
0370 - 9d a8 be 18 6f 9a 24 7c-30 dd 42 c1 bd 65 84 09   ....o.$|0.B..e..
0380 - 48 0b 03 24 5e 5b e4 58-c7 2f d0 23 58 3c 5f 17   H..$^[.X./.#X<_.
0390 - fa e4 6c 7b 8b 51 82 41-88 69 45 11 f2 2d b3 42   ..l{.Q.A.iE..-.B
03a0 - ea 64 6b 8d 48 70 81 64-7f 1b 70 09 e3 fd cc ed   .dk.Hp.d..p.....
03b0 - 63 57 f3 f2 f4 a0 77 2a-3e a9 74 e7 c6 5d 7a 0f   cW....w*>.t..]z.
03c0 - 5c d5 d9 9f 1e be 62 02-4e 48 37 b2 39 b2 9a 38   \.....b.NH7.9..8
03d0 - 8e 0b 77 49 69 57 78 2f-34 e2 df 6d 48 95 06 8d   ..wIiWx/4..mH...
03e0 - bd 0b dd e7 22 f7 50 ac-43 bb 06 27 12 53 db d2   ....".P.C..'.S..
03f0 - 6b 62 38 c7 e1 76 9b c3-ea 80 04 6d 32 42 8e 40   kb8..v.....m2B.@
0400 - e7 05 09 2d 3a 9c cc 4e-09 d8 b2 b9 3c f7 3c 08   ...-:..N....<.<.
0410 - 62 51 ca e8 6f 79 66 61-21 06 10 03 ea 04 cd ec   bQ..oyfa!.......
0420 - 88 23 37 60 77 c8 d6 8a-1f fa da a2 de 19 86 b4   .#7`w...........
0430 - 10 41 f4 48 44 4f 5a 36-0d db 20 e3 27 2f 10 7b   .A.HDOZ6.. .'/.{
0440 - 7e ee 1f 48 a4 8c 98 5b-da 51 21 44 94 b0 59 e7   ~..H...[.Q!D..Y.
0450 - 93 fb 96 a7 27 92 0f 35-d9 00 1e ec 32 45 d8 82   ....'..5....2E..
0460 - f6 be d3 af 3b 31 ff 9b-b1 ff c2 11 54 4e 22 f9   ....;1......TN".
0470 - 3e 27 57 2d c6 50 19 63-ac 0e 29 9a 60 98 3d 8e   >'W-.P.c..).`.=.
0480 - 8e 14 89 67 20 c4 bb 83-af ac f5 77 de ce 00 4a   ...g ......w...J
0490 - 26 5d 06 39 e3 0a f7 3b-fe da 27 93 1f 49 73 ca   &].9...;..'..Is.
04a0 - 54 31 cd ca 1e a4 0b 3a-9e 1b 71 4e f4 76 1c df   T1.....:..qN.v..
04b0 - 35 d9 31 37 23 2e c3 70-40 c0 8e ce cb 10 14 46   5.17#..p@......F
04c0 - 38 71 34 ee 3e 34 e2 29-8c de d8 37 87 c1 e1 4a   8q4.>4.)...7...J
04d0 - 5f 4d 3e 27 57 ab dd f1-93 a5 04 62 e0 69 17 a3   _M>'W......b.i..
04e0 - 21 03 61 87 97 43 63 70-07 73 3e 0d 44 0f 81 0d   !.a..Ccp.s>.D...
04f0 - b6 44 61 86 9a 79 6e d4-21 f9 a3 28 3a 67 a4 49   .Da..yn.!..(:g.I
0500 - 36 42 b9 41 ee 44 4e e7-73 24 a4 eb 2c 46 4f 10   6B.A.DN.s$..,FO.
0510 - 4a c1 13 36 eb 28 22 08-6a 44 c2 59 a4 fb 77 ea   J..6.(".jD.Y..w.
0520 - 7e a7 a4 4c 6a 3e 3a 28-81 3c a3 0b 7c 75 91 f4   ~..Lj>:(.<..|u..
0530 - 01 6a 8f 7c b4 de 70 0a-b2 1f a0 e2 74 0a ae 4b   .j.|..p.....t..K
0540 - 14 e1 25 5d 1c 23 4d a9-b4 40 05 2e b9 ae f5 2f   ..%].#M..@...../
0550 - 34 81 2c e8 b6 8d 73 b7-77 bf 1a 62 fe d0 a6 43   4.,...s.w..b...C
0560 - cf c1 77 10 48 16 7d 72-28 85 07 4a f2 3a a5 fe   ..w.H.}r(..J.:..
0570 - 11 b8 bb 1a 78 02 86 aa-25 0e 2b e5 3b 43 28 f2   ....x...%.+.;C(.
0580 - d2 16 c8 3b d2 94 e0 df-9b 50 a0 ea 45 e1 6e 80   ...;.....P..E.n.
0590 - b4 55 31 37 60 64 c0 67-ff 4a a8 4b 79 81 e4 7c   .U17`d.g.J.Ky..|
05a0 - b9 f4 42 19 0d ad 25 32-1b 16 c7 c6 cb b7 5c 8d   ..B...%2......\.
05b0 - e3 66 df 6b 5c b7 d5 5a-63 93 4c 68 6e 36 fa c5   .f.k\..Zc.Lhn6..
05c0 - 13 c7 69 fb fc dc 83 ed-20 ba 27 e8 a0 73 49 52   ..i..... .'..sIR
05d0 - 9e f7 63 5f 91 a8 44 39-19 c2 dd be 4f 3d a3 31   ..c_..D9....O=.1
05e0 - 9c ef 46 06 87 e1 ce fb-8e cb fd 6d a8 2d ea eb   ..F........m.-..
05f0 - 46 04 99 de 8c c1 e5 74-c0 85 d7 73 5f 82 93 78   F......t...s_..x
0600 - b0 02 10 47 dd 95 d5 03-a7 47 38 61 7c 18 de df   ...G.....G8a|...
0610 - 99 f7 b9 f1 49 b6 c6 af-b4 d1 5e a7 5a ed 77 44   ....I.....^.Z.wD
0620 - 58 3f e6 cd ad e8 8f 8a-d4 9e c8 14 dd 36 85 18   X?...........6..
0630 - c7 3f 66 bc 4f b3 a1 43-ca f6 18 17 58 6d b0 1e   .?f.O..C....Xm..
0640 - 78 3a 96 20 b4 15 a3 94-b8 cc c1 61 f6 74 8e ae   x:. .......a.t..
0650 - a8 55 6a 5b 26 ea 65 c9-de 70 f2 57 c7 a3 dc 92   .Uj[&.e..p.W....
0660 - 2c 61 12 bc 90 8f 07 35-f0 16 ac dd 98 16 02 f6   ,a.....5........
0670 - e7 70 82 84 83 87 2b bb-59 99 77 87 83 a5 aa 14   .p....+.Y.w.....
0680 - 03 03 00 01 01 17 03 03-00 17 36 c9 4d 97 ae f3   ..........6.M...
0690 - c6 7c 05 af e7 26 e6 bb-ff 0f ef 6d 71 6d 2d 42   .|...&.....mqm-B
06a0 - a6 17 03 03 02 2a cf 69-17 e4 de c2 1e be e7 ed   .....*.i........
06b0 - c0 13 9c 6a 08 0e ab 9a-8a e6 4d 47 09 a8 83 e2   ...j......MG....
06c0 - 51 6e 87 7a a2 61 49 67-02 0b 75 72 f3 0b e8 b9   Qn.z.aIg..ur....
06d0 - dd e0 65 ee bf b0 fe 37-c5 16 5f 0a 54 b5 c5 87   ..e....7.._.T...
06e0 - ad 04 03 4d fb cc 2e c6-ad 2d 35 ec 4a 32 ab e2   ...M.....-5.J2..
06f0 - a4 0c 66 2d d3 a0 22 d7-9f db 3e 87 a3 7d 40 c7   ..f-.."...>..}@.
0700 - 0f 7f bc 4c 3e e3 7c 91-83 50 c7 7e 1d a1 75 e8   ...L>.|..P.~..u.
0710 - 5d ce c9 18 2a 74 9a 58-2c ae 99 d2 11 73 55 c1   ]...*t.X,....sU.
0720 - 1e 75 af 97 53 ff 38 5f-c9 2c 96 ba 3d 5f 2f fb   .u..S.8_.,..=_/.
0730 - 58 24 0b e8 f0 6d e3 a9-39 d1 b7 18 06 b4 69 03   X$...m..9.....i.
0740 - b4 db ef ac 95 79 de 71-5b 80 ea 1d 1a 70 4a 51   .....y.q[....pJQ
0750 - 56 66 a5 5d 28 3e 26 17-ab 1d 35 34 fc c7 16 9c   Vf.](>&...54....
0760 - a7 23 24 2d 30 ef fb d0-67 9c a2 2c 85 70 99 d2   .#$-0...g..,.p..
0770 - 09 a7 1c 70 4b 81 fd 4b-00 9d a1 b6 e6 30 17 6c   ...pK..K.....0.l
0780 - 16 60 a4 2b 7d 65 c1 58-7b 2e 4a 8a 7b 69 23 5f   .`.+}e.X{.J.{i#_
0790 - 54 1d 8e 3c 17 e2 d2 3d-9e 8b a8 ca f4 0c 94 71   T..<...=.......q
07a0 - 68 54 81 fc ab e7 67 8f-8b f3 2d 89 21 b4 e5 aa   hT....g...-.!...
07b0 - 47 76 b8 03 a7 f1 0d 98-33 ed a3 c8 70 ac fc 20   Gv......3...p..
07c0 - 70 06 7a 00 04 69 b5 ed-6b 31 06 ae 7c bf c6 8a   p.z..i..k1..|...
07d0 - cb 91 dd 9c ba 0e a6 70-08 3b 28 8f 8c 4e af 2e   .......p.;(..N..
07e0 - c2 b7 8c 85 d7 57 44 54-a9 47 01 1e 9e 6e f5 a6   .....WDT.G...n..
07f0 - 16 0a a1 cf 18 79 02 f7-84 2b 7c a7 8a 77 4a f2   .....y...+|..wJ.
0800 - d9 22 59 ca 05 ab 55 06-93 66 b1 41 88 53 1c ba   ."Y...U..f.A.S..
0810 - c7 c6 de 5e c4 22 76 95-96 60 55 e5 b3 ee b6 dd   ...^."v..`U.....
0820 - 74 1a f7 dd 8e 9e 64 0d-8c 32 6d a4 80 66 32 db   t.....d..2m..f2.
0830 - 84 16 db 24 60 95 19 2a-a9 0d b8 2c 76 0e ac 99   ...$`..*...,v...
0840 - 0e 1a 29 b0 1e ad d1 f4-bf 06 91 18 3b 9c 42 f0   ..).........;.B.
0850 - ac 86 13 c8 6f c4 b0 fc-c3 9f b8 f4 28 dd 7d 64   ....o.......(.}d
0860 - 63 f9 55 6b 38 bb 95 61-4b cb 2f 2f d3 21 95 a3   c.Uk8..aK.//.!..
0870 - 6f ac 64 d5 b4 1f 9e d8-62 49 3e d8 5f 58 ea 9d   o.d.....bI>._X..
0880 - a2 54 41 09 67 24 07 0b-b7 4b 96 c6 bb cf a6 c6   .TA.g$...K......
0890 - ac c0 3e 70 72 8b 76 00-19 ea 92 07 0b 1f 9a 8c   ..>pr.v.........
08a0 - bf 2f d2 62 52 1d fa cd-fd 7c 38 76 56 46 44 98   ./.bR....|8vVFD.
08b0 - 11 e3 a0 8a 41 f7 6b 99-54 2d d4 f0 55 8a 66 f7   ....A.k.T-..U.f.
08c0 - 40 7c 91 75 d2 d4 09 48-7a 18 17 09 35 63 35 88   @|.u...Hz...5c5.
08d0 - 17 03 03 00 60 a9 2c 27-d4 78 c8 f7 b9 e3 d2 10   ....`.,'.x......
08e0 - 77 31 03 56 fb 28 6a e8-ad ce f2 70 80 31 2b 29   w1.V.(j....p.1+)
08f0 - f1 de 5c aa 3f bc 55 d3-fd ed c9 ba c4 28 bc 91   ..\.?.U......(..
0900 - d9 ff ee 2c ec a8 d5 bb-d6 03 35 8f 4d f0 99 5d   ...,......5.M..]
0910 - e9 8d 6c 01 ff 07 fb a2-d6 3e ec e3 c8 25 55 db   ..l......>...%U.
0920 - e3 ff dd 48 23 3c d9 b7-46 7f ff f2 5c d7 95 06   ...H#<..F...\...
0930 - 2a b0 fd bf 2a 17 03 03-00 35 c8 8c 67 6e 5f 25   *...*....5..gn_%
0940 - 23 23 4b ce 33 92 76 6d-e9 08 17 1e bc 1d 8b 5d   ##K.3.vm.......]
0950 - b6 36 09 ab d9 6a f8 55-d1 4b 7f 34 fb 47 42 f9   .6...j.U.K.4.GB.
0960 - 91 fb 58 e1 b9 1c 20 13-d3 ba e4 58 97 6d 43      ..X... ....X.mC
SSL_accept:SSLv3/TLS write finished
SSL_accept:TLSv1.3 early data
read from 0x1ba028ab270 [0x1ba044d4be3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x1ba028ab270 [0x1ba044d4be8] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x1ba028ab270 [0x1ba044d4be3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
read from 0x1ba028ab270 [0x1ba044d4be8] (53 bytes => 53 (0x35))
0000 - 09 a8 af 8f 2f 1e db ae-31 30 81 1a 4a 15 32 d8   ..../...10..J.2.
0010 - c7 54 10 26 e9 de f7 f0-19 a3 a8 e6 04 21 27 be   .T.&.........!'.
0020 - a0 ba cf db 05 33 16 b7-69 dd 24 58 0f 15 17 5f   .....3..i.$X..._
0030 - 7a 8f 6b 35 e0                                    z.k5.
SSL_accept:TLSv1.3 early data
SSL_accept:SSLv3/TLS read finished
write to 0x1ba028ab270 [0x1ba044d3bd0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea 68 f3 ee-e1 d4 ba 00 e4 40 ca 71   .....h.......@.q
0010 - 46 6e da e4 81 e2 d9 3b-91 f3 66 f9 c4 44 66 2e   Fn.....;..f..Df.
0020 - 18 e3 e3 66 df af d2 bd-4b 6d 6a d6 88 25 44 5c   ...f....Kmj..%D\
0030 - ff 7d 6c 72 a4 72 ae eb-d4 37 3a 94 10 d4 d9 5b   .}lr.r...7:....[
0040 - e2 68 c9 05 37 9e 8e 6e-dc 43 cd 55 af b3 21 af   .h..7..n.C.U..!.
0050 - 50 31 43 c5 6b e2 5f e4-99 fc 49 77 46 2d c2 ff   P1C.k._...IwF-..
0060 - c1 85 7a cf d4 82 0f 9b-36 9e 10 60 5c ef 08 a2   ..z.....6..`\...
0070 - 80 31 5c f8 00 2a e2 14-a6 b0 7a 2c aa eb db cb   .1\..*....z,....
0080 - d5 ed ab 14 a4 83 48 25-26 01 89 4e 58 ab f1 13   ......H%&..NX...
0090 - 34 ec b5 1d fe 97 86 7d-be 4f 6d 93 ea 5c 37 77   4......}.Om..\7w
00a0 - 64 7a 26 21 85 23 2a bc-b4 a5 5e fd 9d ad ab 0a   dz&!.#*...^.....
00b0 - 7b 35 42 78 5a a1 6b 60-1e d2 1d a1 91 4a 74 0c   {5BxZ.k`.....Jt.
00c0 - 1f 37 46 47 60 55 f0 46-f0 78 8a 3d 0b 83 a7 98   .7FG`U.F.x.=....
00d0 - e0 5b b2 cf cf 42 84 5f-46 b8 2a b3 be 96 6c 58   .[...B._F.*...lX
00e0 - 2f ce e7 dd 09 4d 5f d9-a6 0a 8b a6 2d ec 2d      /....M_.....-.-
SSL_accept:SSLv3/TLS write session ticket
write to 0x1ba028ab270 [0x1ba044d3bd0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea 78 6a 18-67 6a 51 fc 9b 5e 19 e8   .....xj.gjQ..^..
0010 - cd 5e 03 f8 b9 f6 0b 6d-d4 e9 0a b9 27 9a d9 16   .^.....m....'...
0020 - 0e 5d 44 fa c8 85 e9 e6-59 33 a7 ae ab 68 e3 97   .]D.....Y3...h..
0030 - 30 23 b4 fe 00 d3 24 d7-7c 75 d4 ec e6 6f 15 96   0#....$.|u...o..
0040 - b5 3d f6 3d 2f b4 52 2d-75 e4 fa 6e 77 02 16 7c   .=.=/.R-u..nw..|
0050 - ce c3 3a 2d 4a 4e ee 62-19 89 76 c8 7a d0 b7 5d   ..:-JN.b..v.z..]
0060 - 51 c3 2e f5 ef e2 49 6b-09 8d 2b 1c ce 81 fd 46   Q.....Ik..+....F
0070 - ea fa 6d 86 b2 a1 83 d1-89 81 db 40 c4 58 2f df   ..m........@.X/.
0080 - 87 32 33 68 71 3b 83 24-d9 a8 38 0b 8e 2a 3a c6   .23hq;.$..8..*:.
0090 - c6 64 79 09 c0 41 ce 02-04 54 99 f4 e8 b9 48 6d   .dy..A...T....Hm
00a0 - 82 56 f5 92 6b 8a 27 2e-66 94 51 e7 1e 38 3b a9   .V..k.'.f.Q..8;.
00b0 - c0 4c 89 74 5f b9 26 04-13 33 42 fe d4 6f 74 1f   .L.t_.&..3B..ot.
00c0 - b4 3f 9f 27 33 7c 53 a8-85 dc 2c 71 ee 45 1a 0b   .?.'3|S...,q.E..
00d0 - 31 5e 11 c8 1a 64 28 93-f1 0a ee b7 f9 96 ed ff   1^...d(.........
00e0 - 60 21 12 b0 6e 7b fd 37-25 eb ef a5 44 f9 ea      `!..n{.7%...D..
SSL_accept:SSLv3/TLS write session ticket
-----BEGIN SSL SESSION PARAMETERS-----
MHMCAQECAgMEBAITBAQg9DT6WtfkwYCh4taGkFtFb9lo7QOk0NuTHSuQ+F0Xv3gE
IH3i7CFfcOGtYesNULF8TvERAwDPn9wGa/y95k3nNE+JoQYCBGjqNXmiBAICHCCk
BgQEAQAAAK4GAgRQod0YswQCAgIC
-----END SSL SESSION PARAMETERS-----
Shared ciphers:TLS_AES_128_CCM_SHA256
Signature Algorithms: id-ml-dsa-65:id-ml-dsa-87:id-ml-dsa-44:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:ed448:ecdsa_brainpoolP256r1_sha256:ecdsa_brainpoolP384r1_sha384:ecdsa_brainpoolP512r1_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Shared Signature Algorithms: id-ml-dsa-65:id-ml-dsa-87:id-ml-dsa-44:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:ed448:ecdsa_brainpoolP256r1_sha256:ecdsa_brainpoolP384r1_sha384:ecdsa_brainpoolP512r1_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Supported groups: MLKEM1024
Shared groups: MLKEM1024
CIPHER is TLS_AES_128_CCM_SHA256
This TLS version forbids renegotiation.
read from 0x1ba028ab270 [0x1ba044e4313] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x1ba028ab270 [0x1ba044e4318] (23 bytes => 23 (0x17))
0000 - d6 d2 74 14 67 d3 33 58-84 95 d5 2a 4e be 45 04   ..t.g.3X...*N.E.
0010 - fc ff 5e 19 89 53 0e                              ..^..S.
test
read from 0x1ba028ab270 [0x1ba044e4313] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 13                                    .....
read from 0x1ba028ab270 [0x1ba044e4318] (19 bytes => 19 (0x13))
0000 - 25 99 80 57 51 f1 c8 53-e4 8d 2a 2c 89 c3 54 58   %..WQ..S..*,..TX
0010 - f5 15 10                                          ...
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x1ba028ab270 [0x1ba044d4be3] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 da e5 e6-24 00 15 f4 67 30 a3 ec   ........$...g0..
0010 - aa 10 56 28 1b e3 c9 10-                          ..V(....
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
