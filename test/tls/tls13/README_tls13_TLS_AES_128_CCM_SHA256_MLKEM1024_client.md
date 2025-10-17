#### client

````
$ openssl s_client -connect localhost:9000 -state -debug -keylogfile sslkeylog -tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256 -groups MLKEM1024
Connecting to ::1
CONNECTED(000001E8)
SSL_connect:before SSL initialization
write to 0x2c1a40c6490 [0x2c1a44b2b60] (1748 bytes => 1748 (0x6D4))
0000 - 16 03 01 06 cf 01 00 06-cb 03 03 00 ab 11 e5 90   ................
0010 - 76 2d aa 4d 17 56 7f fb-8e 53 b2 fe 1c a5 69 bd   v-.M.V...S....i.
0020 - 9b 84 1d 64 d3 1f e1 30-ca a8 2e 20 c8 95 f1 42   ...d...0... ...B
0030 - 4c d6 fb a4 34 ba 03 d1-a2 96 78 b4 bb b7 79 6d   L...4.....x...ym
0040 - 8c 78 62 73 1d e6 bb a9-ba d0 10 a3 00 02 13 04   .xbs............
0050 - 01 00 06 80 00 0a 00 04-00 02 02 02 00 23 00 00   .............#..
0060 - 00 16 00 00 00 17 00 00-00 0d 00 2a 00 28 09 05   ...........*.(..
0070 - 09 06 09 04 04 03 05 03-06 03 08 07 08 08 08 1a   ................
0080 - 08 1b 08 1c 08 09 08 0a-08 0b 08 04 08 05 08 06   ................
0090 - 04 01 05 01 06 01 00 2b-00 03 02 03 04 00 2d 00   .......+......-.
00a0 - 02 01 01 00 33 06 26 06-24 02 02 06 20 c1 73 6a   ....3.&.$... .sj
00b0 - 5a 55 93 76 4a ba 23 84-72 6b e9 46 5d 53 2b ff   ZU.vJ.#.rk.F]S+.
00c0 - 6a 0f 5c f7 5a 1e b6 69-87 9c 25 7d 64 0c 92 22   j.\.Z..i..%}d.."
00d0 - 47 f5 b2 ae dc 66 ad 21-e8 72 46 10 b7 71 b6 64   G....f.!.rF..q.d
00e0 - 9c 35 be ab bc ae c3 8a-4a 2e 48 ad ee 77 56 7a   .5......J.H..wVz
00f0 - 48 65 75 25 a8 7b fb 98-2c b7 1f 98 25 91 8b b4   Heu%.{..,...%...
0100 - 2c 3b 2c 23 bb fb 4b f4-b2 7d 9c 36 bd 60 17 39   ,;,#..K..}.6.`.9
0110 - ad 60 17 53 05 ad 4a 80-33 37 26 a5 a1 d8 4f ed   .`.S..J.37&...O.
0120 - 75 a6 90 f3 3c f8 29 bd-89 0b 0a 9b 38 3f c0 30   u...<.).....8?.0
0130 - 98 87 48 be 61 26 63 80-ea 19 ae d0 b7 60 61 42   ..H.a&c......`aB
0140 - 1d e4 cd 8b 3b 69 3c 77-a8 2f 42 13 89 91 79 a5   ....;i<w./B...y.
0150 - 14 ab f5 eb 10 28 eb 3d-8e a8 81 1d e7 a7 c0 fa   .....(.=........
0160 - 76 b5 a7 3c bc 86 8e 3f-e8 48 d6 c9 7a ad d3 80   v..<...?.H..z...
0170 - 5f f3 8e da 4b 17 60 89-66 90 c6 02 6f db 7f 58   _...K.`.f...o..X
0180 - 46 71 80 89 42 0d 64 78-3a 4c 44 fc 18 ca 51 01   Fq..B.dx:LD...Q.
0190 - 04 42 14 49 65 75 8d 19-89 b0 45 40 aa a0 b2 17   .B.Ieu....E@....
01a0 - d9 34 69 c0 c1 cc 37 3a-bf 6d d2 4a 19 3a 2a 73   .4i...7:.m.J.:*s
01b0 - c6 b5 cd 20 06 9a b6 cd-d2 cc c8 55 43 94 4f 18   ... .......UC.O.
01c0 - a6 69 3a 34 30 56 8a 51-cb 54 76 24 62 d0 17 75   .i:40V.Q.Tv$b..u
01d0 - 9e 2b a5 ea d2 46 e3 1c-b4 8a b2 16 c1 a7 11 bf   .+...F..........
01e0 - a9 39 70 f7 3b d9 e7 23-65 8b bc 21 f1 2e 8a 9b   .9p.;..#e..!....
01f0 - 3f d6 a9 71 65 17 7d 73-8a 38 d0 84 7c 4b 00 c7   ?..qe.}s.8..|K..
0200 - a1 76 35 90 0c 88 9a bb-54 fc 1a 88 7a 2b 4e c2   .v5.....T...z+N.
0210 - f5 06 05 b0 7c ca cc 83-8d 8a 53 90 ec 28 8a 83   ....|.....S..(..
0220 - 53 9d 12 49 4c 67 64 24-ba 83 a6 eb c4 83 8b c2   S..ILgd$........
0230 - 71 33 3b b3 08 08 e1 15-45 c3 65 b5 4e e4 cb d5   q3;.....E.e.N...
0240 - e8 91 5a a6 41 c1 55 4a-ef 5a 43 19 75 ab f1 8c   ..Z.A.UJ.ZC.u...
0250 - 5b 64 68 3f f7 46 9b 0e-da 2a b9 5c 21 46 ac 03   [dh?.F...*.\!F..
0260 - 65 79 75 08 c7 b4 03 09-83 8e 37 26 27 1b b8 66   eyu.......7&'..f
0270 - aa 9f 0a 56 58 51 b3 6d-cb a3 07 bc 02 c8 f7 ab   ...VXQ.m........
0280 - 70 a1 d3 ce 4e c4 c5 4d-29 a6 72 16 7f cf d7 b5   p...N..M).r.....
0290 - fe 62 5c bb e6 93 03 c2-98 db 75 31 7a 26 2f ff   .b\.......u1z&/.
02a0 - 32 7f f3 6a 31 51 ab a4-db 07 11 93 e8 86 14 d4   2..j1Q..........
02b0 - 59 14 a8 c5 28 31 65 44-02 71 de fb 1b 7b ec 85   Y...(1eD.q...{..
02c0 - a1 75 4b a7 24 bc 2e a2-9b b6 e8 9a c6 64 bc e4   .uK.$........d..
02d0 - 53 a0 12 a3 cd b6 d9 52-9e 0a 51 ba e6 37 03 a8   S......R..Q..7..
02e0 - 75 50 88 8e e2 21 1d 93-70 16 2d 29 17 4e 66 50   uP...!..p.-).NfP
02f0 - 7a 6b 0e fa bc 03 4c 36-a6 6f 42 70 a6 44 2e 99   zk....L6.oBp.D..
0300 - 13 10 7d b6 60 a9 f2 76-97 e3 9b 3d 5b 63 49 97   ..}.`..v...=[cI.
0310 - 94 70 36 18 de 80 b5 82-f1 8a c5 44 c1 08 94 89   .p6........D....
0320 - 9b d7 90 a3 49 6b 6e 59-31 2c d0 44 ec 6a 5b c4   ....IknY1,.D.j[.
0330 - e3 c0 76 b4 b5 bb 28 17-e3 d3 4c fa 73 6f 0f d2   ..v...(...L.so..
0340 - bc 91 9a c1 89 82 71 10-50 12 be 41 b8 c8 b5 4b   ......q.P..A...K
0350 - e4 c0 62 e4 60 46 59 e6-45 ec 36 34 24 e9 c6 96   ..b.`FY.E.64$...
0360 - f9 2a 2f 61 38 9e f1 15-50 09 8b 8a 79 0d 5f b5   .*/a8...P...y._.
0370 - a0 3f 80 bd ca 4a a1 9e-4b aa 7a 85 22 ca 5a 1b   .?...J..K.z.".Z.
0380 - 1f c8 32 2f c8 65 44 28-c4 6d b1 be 44 83 84 77   ..2/.eD(.m..D..w
0390 - 7c a1 04 22 a6 95 e2 8d-a2 43 50 12 c3 9c eb f0   |..".....CP.....
03a0 - cc bd a3 57 8d 51 90 d5-60 0b 6f 09 78 68 d1 a2   ...W.Q..`.o.xh..
03b0 - 54 24 07 2b d2 2f 61 db-71 fe 41 71 60 48 40 7d   T$.+./a.q.Aq`H@}
03c0 - d1 ab 43 90 c2 e5 46 bf-14 a7 08 5b b4 cb 0f 39   ..C...F....[...9
03d0 - 89 8c ca c1 a5 61 12 ff-07 20 82 34 67 21 16 25   .....a... .4g!.%
03e0 - a9 a7 14 fc 7b b7 73 a0-64 19 f7 22 06 18 58 a0   ....{.s.d.."..X.
03f0 - c6 3d 57 38 32 55 e4 63-db ea 65 6d e6 29 06 e7   .=W82U.c..em.)..
0400 - 8f 82 59 72 c7 95 2d db-43 7e 9c 8c 8c 26 dc b6   ..Yr..-.C~...&..
0410 - 7c 1b b5 33 c6 85 96 58-14 ac 21 57 57 43 c5 b5   |..3...X..!WWC..
0420 - e8 c1 aa dc 53 2f 21 20-c0 36 87 09 11 10 29 b8   ....S/! .6....).
0430 - 8a b9 96 22 86 f5 5d 36-73 03 20 d4 ca 89 e2 28   ..."..]6s. ....(
0440 - d4 34 40 8d ac 80 4e 9a-23 e9 c2 0f 93 7b b5 f4   .4@...N.#....{..
0450 - a0 9b 6c 5b c8 08 82 78-5a 93 a9 5f 94 0f 5e 02   ..l[...xZ.._..^.
0460 - 9f ab d0 1b 99 08 1e 1c-30 55 ae fa 00 4d 69 52   ........0U...MiR
0470 - 49 da 67 37 65 ca 75 03-05 f0 d8 5a e7 58 51 91   I.g7e.u....Z.XQ.
0480 - 8c 60 62 cb 34 5d 20 66-04 3c 89 6b d2 4d 0f 04   .`b.4] f.<.k.M..
0490 - 1b 94 1c 70 98 64 7f 1f-a1 65 26 d8 c1 f1 f6 29   ...p.d...e&....)
04a0 - bc fb 1c 28 e8 99 6d 28-92 da 88 42 73 03 45 44   ...(..m(...Bs.ED
04b0 - ec b3 97 3a b1 f7 a7 ba-a8 60 9f 95 f7 ca da 0c   ...:.....`......
04c0 - ac 44 99 89 b0 ea 19 7d-c1 71 e2 d3 63 8f e1 3e   .D.....}.q..c..>
04d0 - fd d1 90 24 f1 88 86 16-13 f8 ba 5b 4f c3 48 09   ...$.......[O.H.
04e0 - c0 20 08 9a bc 09 59 40-9d c0 cc 31 d0 5b 1c d3   . ....Y@...1.[..
04f0 - ce 3c 47 c5 76 28 07 7a-34 1b 90 a9 87 3d 9a 8b   .<G.v(.z4....=..
0500 - 52 29 49 f2 91 84 7b 89-0c 49 9c 86 56 51 2d ed   R)I...{..I..VQ-.
0510 - 1a 49 43 59 08 3c fc cd-b4 59 87 aa 64 0b d2 91   .ICY.<...Y..d...
0520 - 89 9b 18 10 fd 00 63 9d-f5 af 9f 37 13 22 9c 20   ......c....7.".
0530 - 57 11 b9 3f 00 28 f0 74-70 5d 25 67 ff 24 38 c2   W..?.(.tp]%g.$8.
0540 - f6 68 3f a3 7c a1 50 72-20 40 b8 b0 82 92 74 f9   .h?.|.Pr @....t.
0550 - 06 7f 87 80 87 06 6b c9-8b 62 a0 20 1c ee 92 ca   ......k..b. ....
0560 - 57 a6 4f 66 79 09 39 81-cd 88 45 7b fb 29 3b 61   W.Ofy.9...E{.);a
0570 - 42 c6 8a 00 9c 95 f8 7c-35 c6 6f 99 65 a3 e1 d7   B......|5.o.e...
0580 - cc b7 8a a7 1e b0 19 71-f6 46 2d 43 27 d4 46 b3   .......q.F-C'.F.
0590 - 82 46 ad c7 78 84 bc 91-19 e7 a4 80 ec 0b 1d e4   .F..x...........
05a0 - 10 6f cc 80 35 8f e0 94-b8 bc c3 ca 5a 4c 8d a1   .o..5.......ZL..
05b0 - 64 d3 08 81 c4 c8 af 3e-a2 a4 d9 00 7e 93 10 23   d......>....~..#
05c0 - 54 01 b1 1a 2a a8 25 b1-5d 25 d0 1e 4d b5 62 ae   T...*.%.]%..M.b.
05d0 - 03 76 02 2a 80 ba d9 9d-c6 90 ae 66 24 78 18 4b   .v.*.......f$x.K
05e0 - 59 5d 27 8f 6f 61 8c 5d-85 5b f5 78 b1 6f c0 cc   Y]'.oa.].[.x.o..
05f0 - 8b 86 cf 13 f9 5c e1 6a-6c e1 6a 0f 5e 58 81 42   .....\.jl.j.^X.B
0600 - 2a 33 87 d3 cf d8 83 ca-3a 65 46 c2 62 98 e0 aa   *3......:eF.b...
0610 - ce b2 16 c6 06 9a 4b b3-a6 51 70 85 96 6d 33 98   ......K..Qp..m3.
0620 - 0f 75 16 9e 16 cc c9 18-58 97 c5 a4 63 a2 6c 71   .u......X...c.lq
0630 - ca 37 00 64 28 19 4b 4a-3f da 98 c3 e9 a2 4b 33   .7.d(.KJ?.....K3
0640 - 8e 59 48 a1 95 d5 73 59-27 c8 f8 25 4e f9 14 76   .YH...sY'..%N..v
0650 - d8 34 a3 c2 3c 62 77 49-15 a5 2c ac 5b 2a ce 13   .4..<bwI..,.[*..
0660 - e5 15 55 78 94 a7 d3 4d-15 7c b3 f4 27 c6 b3 67   ..Ux...M.|..'..g
0670 - 65 3d d6 33 b9 67 54 56-78 bf 62 76 74 bb b9 20   e=.3.gTVx.bvt..
0680 - aa b0 65 a2 57 52 f9 28-9c cb ba 5d d7 42 2a f1   ..e.WR.(...].B*.
0690 - 63 c2 a4 c8 51 01 1a 07-da c2 33 52 29 c5 6d e6   c...Q.....3R).m.
06a0 - 5b 84 0b 32 7b 2a 91 51-04 91 2b a3 3c 45 82 0b   [..2{*.Q..+.<E..
06b0 - 97 01 6c 12 b2 bc 3e 0e-0c 6b 86 af 92 26 ec af   ..l...>..k...&..
06c0 - 6d be 56 a4 64 dd c8 0f-57 76 f5 b6 dc 00 1b 00   m.V.d...Wv......
06d0 - 03 02 00 01                                       ....
SSL_connect:SSLv3/TLS write client hello
read from 0x2c1a40c6490 [0x2c1a44bb5a3] (5 bytes => 5 (0x5))
0000 - 16 03 03 06 7a                                    ....z
read from 0x2c1a40c6490 [0x2c1a44bb5a8] (1658 bytes => 1658 (0x67A))
0000 - 02 00 06 76 03 03 9c 25-94 d5 36 f5 92 47 66 51   ...v...%..6..GfQ
0010 - 6c 97 36 06 32 1b f8 fc-7e d3 8c ae 5b fe 6f 7a   l.6.2...~...[.oz
0020 - 11 8a b6 f2 19 35 20 c8-95 f1 42 4c d6 fb a4 34   .....5 ...BL...4
0030 - ba 03 d1 a2 96 78 b4 bb-b7 79 6d 8c 78 62 73 1d   .....x...ym.xbs.
0040 - e6 bb a9 ba d0 10 a3 13-04 00 06 2e 00 2b 00 02   .............+..
0050 - 03 04 00 33 06 24 02 02-06 20 bc b1 ff fa 69 bf   ...3.$... ....i.
0060 - d7 54 ea 3f a0 b6 65 08-c9 03 1a 66 ec 8c c4 ea   .T.?..e....f....
0070 - 4a 63 af f6 be d2 12 8d-3d 97 d0 61 4e ab cf bd   Jc......=..aN...
0080 - b8 48 e4 b4 bf 2e 13 d3-94 59 e5 1a 8d 72 e6 1d   .H.......Y...r..
0090 - 20 ea df 31 45 ec 98 f0-b4 4a f4 44 3d c1 a8 ed    ..1E....J.D=...
00a0 - 46 8c 60 44 61 30 eb 32-17 91 60 49 db 91 03 3d   F.`Da0.2..`I...=
00b0 - 0b b2 d9 73 1c 5e 13 c8-07 7a 7f 94 87 fb 66 c5   ...s.^...z....f.
00c0 - e2 76 f8 6b 4b 6e bb a5-bf 31 3a 10 42 9a fa 2e   .v.kKn...1:.B...
00d0 - e2 37 d9 3f eb 90 e5 ed-af f5 92 56 0f 05 c5 0d   .7.?.......V....
00e0 - 10 52 3d 71 13 3d bd 8a-1c 3e fd 3f dc 9d ca f9   .R=q.=...>.?....
00f0 - 83 b9 79 d7 07 80 19 2d-ad 1b 3e 9e 4e 92 19 46   ..y....-..>.N..F
0100 - a3 60 89 0f e3 51 1a be-67 c3 67 19 94 84 2a 24   .`...Q..g.g...*$
0110 - 15 b6 38 f0 a8 ef 3a ab-b9 48 46 78 bc 19 74 64   ..8...:..HFx..td
0120 - 2c b4 bb 59 91 35 19 22-c7 5d 04 2e 4f a4 d1 5f   ,..Y.5.".]..O.._
0130 - 21 86 c8 f6 57 ed 2b 9e-a7 1f a8 d5 32 c3 9d 08   !...W.+.....2...
0140 - 9c 8e a5 14 1e d3 63 e0-fc a2 5c f1 26 87 64 91   ......c...\.&.d.
0150 - 82 f4 06 8a fc 81 e5 41-7c 89 02 c4 86 1f 88 42   .......A|......B
0160 - 18 99 09 c5 df 4f cc 0f-9f 89 db 02 a0 a9 6d cd   .....O........m.
0170 - d8 a5 5d d6 d5 b3 e7 0f-dc fe 54 5c 69 60 83 99   ..].......T\i`..
0180 - bf ea d1 95 2f 5e 19 fe-64 16 16 45 35 0a 4c 82   ..../^..d..E5.L.
0190 - 7a 41 33 dc 3c 32 11 25-fe c2 63 43 4a a3 43 0a   zA3.<2.%..cCJ.C.
01a0 - 3d 6c 10 6a f7 97 aa fb-fc 67 a1 61 d5 a1 32 77   =l.j.....g.a..2w
01b0 - 22 d2 1e be d4 24 ca c5-94 0a 8b 4d 37 20 c8 72   "....$.....M7 .r
01c0 - a7 27 76 73 1b 36 1c f8-70 f0 63 0b aa 5c ce 43   .'vs.6..p.c..\.C
01d0 - 08 ea f0 a2 d8 f7 25 1c-1d 33 5a c5 d2 d8 2d 24   ......%..3Z...-$
01e0 - d5 22 59 5d a8 18 51 40-70 a7 b8 22 7f 88 37 02   ."Y]..Q@p.."..7.
01f0 - 97 fa c8 35 36 23 4f 9b-21 b2 65 48 b3 fa 98 75   ...56#O.!.eH...u
0200 - b0 25 8a ed 5b 77 24 1a-8c c5 78 15 b7 a2 d9 6b   .%..[w$...x....k
0210 - 08 44 ac a2 13 7f cf c3-be 54 2e d1 60 57 4a 0b   .D.......T..`WJ.
0220 - bc 06 07 93 eb 03 8a 15-72 7f 57 15 e5 52 29 c2   ........r.W..R).
0230 - b7 21 27 05 b2 3c 64 81-e3 f9 e2 66 97 a3 fa 07   .!'..<d....f....
0240 - 4e 03 0d a2 69 f3 8c f3-0b 80 1d 73 a4 3b d1 66   N...i......s.;.f
0250 - 7e b3 a6 7b b5 e8 a0 15-9c 1d 6d 79 e8 be 79 fc   ~..{......my..y.
0260 - 7f 85 61 61 86 99 16 b9-70 c6 b6 ff 83 c1 3d 7b   ..aa....p.....={
0270 - 31 ce 54 3f 49 26 4a 66-e8 97 21 42 b9 7d fc d5   1.T?I&Jf..!B.}..
0280 - 56 68 5a 16 28 b0 00 98-89 dd f2 1c 9f 0a 9c 8d   VhZ.(...........
0290 - a7 62 fb 3c c6 0e 4f ba-80 0e 3d e1 b8 9e 05 ab   .b.<..O...=.....
02a0 - 6b 9d 63 71 b4 b0 29 01-87 01 f5 05 32 81 bc 5f   k.cq..).....2.._
02b0 - 43 39 64 c3 b3 3d a4 63-53 a7 66 e8 1e 49 48 49   C9d..=.cS.f..IHI
02c0 - 32 a4 be c9 2d d2 1d 9a-09 04 f9 50 aa 39 c2 2e   2...-......P.9..
02d0 - 1c 0e 70 82 ba fe e4 df-80 c4 ce b3 5c bc d9 95   ..p.........\...
02e0 - b1 1f 2e 9b 15 46 95 16-cb b1 f8 4b be 38 e8 ba   .....F.....K.8..
02f0 - 78 47 fc 7e f0 6e 8e 8a-ee 94 0b fb b3 3e 55 b2   xG.~.n.......>U.
0300 - 09 a6 2f 28 41 ae c3 6e-35 70 32 47 bb e3 45 05   ../(A..n5p2G..E.
0310 - a4 81 2a cc c5 6c 40 37-4b 24 78 5d f5 88 b8 ef   ..*..l@7K$x]....
0320 - 50 8a 9f 29 f5 89 70 82-c5 77 ad 05 1f fa c8 c1   P..)..p..w......
0330 - e5 02 5b a2 0a 2e f9 8e-d6 f2 c0 db c2 ec 71 5f   ..[...........q_
0340 - 63 75 a9 6c 2e d7 66 b4-66 42 fc a7 1d d9 d8 18   cu.l..f.fB......
0350 - 9e b1 cc 87 14 20 5c 48-bf 62 89 e5 ae fb b6 4e   ..... \H.b.....N
0360 - ab d4 f8 be ce 06 33 72-40 e8 13 9d a8 be 18 6f   ......3r@......o
0370 - 9a 24 7c 30 dd 42 c1 bd-65 84 09 48 0b 03 24 5e   .$|0.B..e..H..$^
0380 - 5b e4 58 c7 2f d0 23 58-3c 5f 17 fa e4 6c 7b 8b   [.X./.#X<_...l{.
0390 - 51 82 41 88 69 45 11 f2-2d b3 42 ea 64 6b 8d 48   Q.A.iE..-.B.dk.H
03a0 - 70 81 64 7f 1b 70 09 e3-fd cc ed 63 57 f3 f2 f4   p.d..p.....cW...
03b0 - a0 77 2a 3e a9 74 e7 c6-5d 7a 0f 5c d5 d9 9f 1e   .w*>.t..]z.\....
03c0 - be 62 02 4e 48 37 b2 39-b2 9a 38 8e 0b 77 49 69   .b.NH7.9..8..wIi
03d0 - 57 78 2f 34 e2 df 6d 48-95 06 8d bd 0b dd e7 22   Wx/4..mH......."
03e0 - f7 50 ac 43 bb 06 27 12-53 db d2 6b 62 38 c7 e1   .P.C..'.S..kb8..
03f0 - 76 9b c3 ea 80 04 6d 32-42 8e 40 e7 05 09 2d 3a   v.....m2B.@...-:
0400 - 9c cc 4e 09 d8 b2 b9 3c-f7 3c 08 62 51 ca e8 6f   ..N....<.<.bQ..o
0410 - 79 66 61 21 06 10 03 ea-04 cd ec 88 23 37 60 77   yfa!........#7`w
0420 - c8 d6 8a 1f fa da a2 de-19 86 b4 10 41 f4 48 44   ............A.HD
0430 - 4f 5a 36 0d db 20 e3 27-2f 10 7b 7e ee 1f 48 a4   OZ6.. .'/.{~..H.
0440 - 8c 98 5b da 51 21 44 94-b0 59 e7 93 fb 96 a7 27   ..[.Q!D..Y.....'
0450 - 92 0f 35 d9 00 1e ec 32-45 d8 82 f6 be d3 af 3b   ..5....2E......;
0460 - 31 ff 9b b1 ff c2 11 54-4e 22 f9 3e 27 57 2d c6   1......TN".>'W-.
0470 - 50 19 63 ac 0e 29 9a 60-98 3d 8e 8e 14 89 67 20   P.c..).`.=....g
0480 - c4 bb 83 af ac f5 77 de-ce 00 4a 26 5d 06 39 e3   ......w...J&].9.
0490 - 0a f7 3b fe da 27 93 1f-49 73 ca 54 31 cd ca 1e   ..;..'..Is.T1...
04a0 - a4 0b 3a 9e 1b 71 4e f4-76 1c df 35 d9 31 37 23   ..:..qN.v..5.17#
04b0 - 2e c3 70 40 c0 8e ce cb-10 14 46 38 71 34 ee 3e   ..p@......F8q4.>
04c0 - 34 e2 29 8c de d8 37 87-c1 e1 4a 5f 4d 3e 27 57   4.)...7...J_M>'W
04d0 - ab dd f1 93 a5 04 62 e0-69 17 a3 21 03 61 87 97   ......b.i..!.a..
04e0 - 43 63 70 07 73 3e 0d 44-0f 81 0d b6 44 61 86 9a   Ccp.s>.D....Da..
04f0 - 79 6e d4 21 f9 a3 28 3a-67 a4 49 36 42 b9 41 ee   yn.!..(:g.I6B.A.
0500 - 44 4e e7 73 24 a4 eb 2c-46 4f 10 4a c1 13 36 eb   DN.s$..,FO.J..6.
0510 - 28 22 08 6a 44 c2 59 a4-fb 77 ea 7e a7 a4 4c 6a   (".jD.Y..w.~..Lj
0520 - 3e 3a 28 81 3c a3 0b 7c-75 91 f4 01 6a 8f 7c b4   >:(.<..|u...j.|.
0530 - de 70 0a b2 1f a0 e2 74-0a ae 4b 14 e1 25 5d 1c   .p.....t..K..%].
0540 - 23 4d a9 b4 40 05 2e b9-ae f5 2f 34 81 2c e8 b6   #M..@...../4.,..
0550 - 8d 73 b7 77 bf 1a 62 fe-d0 a6 43 cf c1 77 10 48   .s.w..b...C..w.H
0560 - 16 7d 72 28 85 07 4a f2-3a a5 fe 11 b8 bb 1a 78   .}r(..J.:......x
0570 - 02 86 aa 25 0e 2b e5 3b-43 28 f2 d2 16 c8 3b d2   ...%.+.;C(....;.
0580 - 94 e0 df 9b 50 a0 ea 45-e1 6e 80 b4 55 31 37 60   ....P..E.n..U17`
0590 - 64 c0 67 ff 4a a8 4b 79-81 e4 7c b9 f4 42 19 0d   d.g.J.Ky..|..B..
05a0 - ad 25 32 1b 16 c7 c6 cb-b7 5c 8d e3 66 df 6b 5c   .%2......\..f.k\
05b0 - b7 d5 5a 63 93 4c 68 6e-36 fa c5 13 c7 69 fb fc   ..Zc.Lhn6....i..
05c0 - dc 83 ed 20 ba 27 e8 a0-73 49 52 9e f7 63 5f 91   ... .'..sIR..c_.
05d0 - a8 44 39 19 c2 dd be 4f-3d a3 31 9c ef 46 06 87   .D9....O=.1..F..
05e0 - e1 ce fb 8e cb fd 6d a8-2d ea eb 46 04 99 de 8c   ......m.-..F....
05f0 - c1 e5 74 c0 85 d7 73 5f-82 93 78 b0 02 10 47 dd   ..t...s_..x...G.
0600 - 95 d5 03 a7 47 38 61 7c-18 de df 99 f7 b9 f1 49   ....G8a|.......I
0610 - b6 c6 af b4 d1 5e a7 5a-ed 77 44 58 3f e6 cd ad   .....^.Z.wDX?...
0620 - e8 8f 8a d4 9e c8 14 dd-36 85 18 c7 3f 66 bc 4f   ........6...?f.O
0630 - b3 a1 43 ca f6 18 17 58-6d b0 1e 78 3a 96 20 b4   ..C....Xm..x:. .
0640 - 15 a3 94 b8 cc c1 61 f6-74 8e ae a8 55 6a 5b 26   ......a.t...Uj[&
0650 - ea 65 c9 de 70 f2 57 c7-a3 dc 92 2c 61 12 bc 90   .e..p.W....,a...
0660 - 8f 07 35 f0 16 ac dd 98-16 02 f6 e7 70 82 84 83   ..5.........p...
0670 - 87 2b bb 59 99 77 87 83-a5 aa                     .+.Y.w....
SSL_connect:SSLv3/TLS write client hello
read from 0x2c1a40c6490 [0x2c1a44bac83] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x2c1a40c6490 [0x2c1a44bac88] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x2c1a40c6490 [0x2c1a44bac83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x2c1a40c6490 [0x2c1a44bac88] (23 bytes => 23 (0x17))
0000 - 36 c9 4d 97 ae f3 c6 7c-05 af e7 26 e6 bb ff 0f   6.M....|...&....
0010 - ef 6d 71 6d 2d 42 a6                              .mqm-B.
SSL_connect:SSLv3/TLS read server hello
Can't use SSL_get_servername
read from 0x2c1a40c6490 [0x2c1a44bac83] (5 bytes => 5 (0x5))
0000 - 17 03 03 02 2a                                    ....*
read from 0x2c1a40c6490 [0x2c1a44bac88] (554 bytes => 554 (0x22A))
0000 - cf 69 17 e4 de c2 1e be-e7 ed c0 13 9c 6a 08 0e   .i...........j..
0010 - ab 9a 8a e6 4d 47 09 a8-83 e2 51 6e 87 7a a2 61   ....MG....Qn.z.a
0020 - 49 67 02 0b 75 72 f3 0b-e8 b9 dd e0 65 ee bf b0   Ig..ur......e...
0030 - fe 37 c5 16 5f 0a 54 b5-c5 87 ad 04 03 4d fb cc   .7.._.T......M..
0040 - 2e c6 ad 2d 35 ec 4a 32-ab e2 a4 0c 66 2d d3 a0   ...-5.J2....f-..
0050 - 22 d7 9f db 3e 87 a3 7d-40 c7 0f 7f bc 4c 3e e3   "...>..}@....L>.
0060 - 7c 91 83 50 c7 7e 1d a1-75 e8 5d ce c9 18 2a 74   |..P.~..u.]...*t
0070 - 9a 58 2c ae 99 d2 11 73-55 c1 1e 75 af 97 53 ff   .X,....sU..u..S.
0080 - 38 5f c9 2c 96 ba 3d 5f-2f fb 58 24 0b e8 f0 6d   8_.,..=_/.X$...m
0090 - e3 a9 39 d1 b7 18 06 b4-69 03 b4 db ef ac 95 79   ..9.....i......y
00a0 - de 71 5b 80 ea 1d 1a 70-4a 51 56 66 a5 5d 28 3e   .q[....pJQVf.](>
00b0 - 26 17 ab 1d 35 34 fc c7-16 9c a7 23 24 2d 30 ef   &...54.....#$-0.
00c0 - fb d0 67 9c a2 2c 85 70-99 d2 09 a7 1c 70 4b 81   ..g..,.p.....pK.
00d0 - fd 4b 00 9d a1 b6 e6 30-17 6c 16 60 a4 2b 7d 65   .K.....0.l.`.+}e
00e0 - c1 58 7b 2e 4a 8a 7b 69-23 5f 54 1d 8e 3c 17 e2   .X{.J.{i#_T..<..
00f0 - d2 3d 9e 8b a8 ca f4 0c-94 71 68 54 81 fc ab e7   .=.......qhT....
0100 - 67 8f 8b f3 2d 89 21 b4-e5 aa 47 76 b8 03 a7 f1   g...-.!...Gv....
0110 - 0d 98 33 ed a3 c8 70 ac-fc 20 70 06 7a 00 04 69   ..3...p.. p.z..i
0120 - b5 ed 6b 31 06 ae 7c bf-c6 8a cb 91 dd 9c ba 0e   ..k1..|.........
0130 - a6 70 08 3b 28 8f 8c 4e-af 2e c2 b7 8c 85 d7 57   .p.;(..N.......W
0140 - 44 54 a9 47 01 1e 9e 6e-f5 a6 16 0a a1 cf 18 79   DT.G...n.......y
0150 - 02 f7 84 2b 7c a7 8a 77-4a f2 d9 22 59 ca 05 ab   ...+|..wJ.."Y...
0160 - 55 06 93 66 b1 41 88 53-1c ba c7 c6 de 5e c4 22   U..f.A.S.....^."
0170 - 76 95 96 60 55 e5 b3 ee-b6 dd 74 1a f7 dd 8e 9e   v..`U.....t.....
0180 - 64 0d 8c 32 6d a4 80 66-32 db 84 16 db 24 60 95   d..2m..f2....$`.
0190 - 19 2a a9 0d b8 2c 76 0e-ac 99 0e 1a 29 b0 1e ad   .*...,v.....)...
01a0 - d1 f4 bf 06 91 18 3b 9c-42 f0 ac 86 13 c8 6f c4   ......;.B.....o.
01b0 - b0 fc c3 9f b8 f4 28 dd-7d 64 63 f9 55 6b 38 bb   ......(.}dc.Uk8.
01c0 - 95 61 4b cb 2f 2f d3 21-95 a3 6f ac 64 d5 b4 1f   .aK.//.!..o.d...
01d0 - 9e d8 62 49 3e d8 5f 58-ea 9d a2 54 41 09 67 24   ..bI>._X...TA.g$
01e0 - 07 0b b7 4b 96 c6 bb cf-a6 c6 ac c0 3e 70 72 8b   ...K........>pr.
01f0 - 76 00 19 ea 92 07 0b 1f-9a 8c bf 2f d2 62 52 1d   v........../.bR.
0200 - fa cd fd 7c 38 76 56 46-44 98 11 e3 a0 8a 41 f7   ...|8vVFD.....A.
0210 - 6b 99 54 2d d4 f0 55 8a-66 f7 40 7c 91 75 d2 d4   k.T-..U.f.@|.u..
0220 - 09 48 7a 18 17 09 35 63-35 88                     .Hz...5c5.
SSL_connect:TLSv1.3 read encrypted extensions
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
verify error:num=18:self-signed certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
verify return:1
read from 0x2c1a40c6490 [0x2c1a44bac83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 60                                    ....`
read from 0x2c1a40c6490 [0x2c1a44bac88] (96 bytes => 96 (0x60))
0000 - a9 2c 27 d4 78 c8 f7 b9-e3 d2 10 77 31 03 56 fb   .,'.x......w1.V.
0010 - 28 6a e8 ad ce f2 70 80-31 2b 29 f1 de 5c aa 3f   (j....p.1+)..\.?
0020 - bc 55 d3 fd ed c9 ba c4-28 bc 91 d9 ff ee 2c ec   .U......(.....,.
0030 - a8 d5 bb d6 03 35 8f 4d-f0 99 5d e9 8d 6c 01 ff   .....5.M..]..l..
0040 - 07 fb a2 d6 3e ec e3 c8-25 55 db e3 ff dd 48 23   ....>...%U....H#
0050 - 3c d9 b7 46 7f ff f2 5c-d7 95 06 2a b0 fd bf 2a   <..F...\...*...*
SSL_connect:SSLv3/TLS read server certificate
read from 0x2c1a40c6490 [0x2c1a44bac83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
read from 0x2c1a40c6490 [0x2c1a44bac88] (53 bytes => 53 (0x35))
0000 - c8 8c 67 6e 5f 25 23 23-4b ce 33 92 76 6d e9 08   ..gn_%##K.3.vm..
0010 - 17 1e bc 1d 8b 5d b6 36-09 ab d9 6a f8 55 d1 4b   .....].6...j.U.K
0020 - 7f 34 fb 47 42 f9 91 fb-58 e1 b9 1c 20 13 d3 ba   .4.GB...X... ...
0030 - e4 58 97 6d 43                                    .X.mC
SSL_connect:TLSv1.3 read server certificate verify
SSL_connect:SSLv3/TLS read finished
SSL_connect:SSLv3/TLS write change cipher spec
write to 0x2c1a40c6490 [0x2c1a44b2b60] (64 bytes => 64 (0x40))
0000 - 14 03 03 00 01 01 17 03-03 00 35 09 a8 af 8f 2f   ..........5..../
0010 - 1e db ae 31 30 81 1a 4a-15 32 d8 c7 54 10 26 e9   ...10..J.2..T.&.
0020 - de f7 f0 19 a3 a8 e6 04-21 27 be a0 ba cf db 05   ........!'......
0030 - 33 16 b7 69 dd 24 58 0f-15 17 5f 7a 8f 6b 35 e0   3..i.$X..._z.k5.
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
Negotiated TLS1.3 group: MLKEM1024
---
SSL handshake has read 2415 bytes and written 1812 bytes
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
read from 0x2c1a40c6490 [0x2c1a44ac5f3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
read from 0x2c1a40c6490 [0x2c1a44ac5f8] (234 bytes => 234 (0xEA))
0000 - 68 f3 ee e1 d4 ba 00 e4-40 ca 71 46 6e da e4 81   h.......@.qFn...
0010 - e2 d9 3b 91 f3 66 f9 c4-44 66 2e 18 e3 e3 66 df   ..;..f..Df....f.
0020 - af d2 bd 4b 6d 6a d6 88-25 44 5c ff 7d 6c 72 a4   ...Kmj..%D\.}lr.
0030 - 72 ae eb d4 37 3a 94 10-d4 d9 5b e2 68 c9 05 37   r...7:....[.h..7
0040 - 9e 8e 6e dc 43 cd 55 af-b3 21 af 50 31 43 c5 6b   ..n.C.U..!.P1C.k
0050 - e2 5f e4 99 fc 49 77 46-2d c2 ff c1 85 7a cf d4   ._...IwF-....z..
0060 - 82 0f 9b 36 9e 10 60 5c-ef 08 a2 80 31 5c f8 00   ...6..`\....1\..
0070 - 2a e2 14 a6 b0 7a 2c aa-eb db cb d5 ed ab 14 a4   *....z,.........
0080 - 83 48 25 26 01 89 4e 58-ab f1 13 34 ec b5 1d fe   .H%&..NX...4....
0090 - 97 86 7d be 4f 6d 93 ea-5c 37 77 64 7a 26 21 85   ..}.Om..\7wdz&!.
00a0 - 23 2a bc b4 a5 5e fd 9d-ad ab 0a 7b 35 42 78 5a   #*...^.....{5BxZ
00b0 - a1 6b 60 1e d2 1d a1 91-4a 74 0c 1f 37 46 47 60   .k`.....Jt..7FG`
00c0 - 55 f0 46 f0 78 8a 3d 0b-83 a7 98 e0 5b b2 cf cf   U.F.x.=.....[...
00d0 - 42 84 5f 46 b8 2a b3 be-96 6c 58 2f ce e7 dd 09   B._F.*...lX/....
00e0 - 4d 5f d9 a6 0a 8b a6 2d-ec 2d                     M_.....-.-
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_CCM_SHA256
    Session-ID: FD8D1C63F3BEEEC17F35538DB113BA29A25503B78E842D3E07CC0C3C477A0C56
    Session-ID-ctx:
    Resumption PSK: D3E9FA13550BE6AEF5C29B97C1EC10387D521D9EDBA482A732361D8BEBEA1BFC
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 44 0f 07 10 7c 87 23 b2-b6 e9 3f 1f 75 99 d4 5a   D...|.#...?.u..Z
    0010 - ce 87 1f 87 02 24 12 0d-90 c4 40 15 cc 50 3e 03   .....$....@..P>.
    0020 - 36 bf 22 96 5d 1f 2d bf-1b b4 17 84 81 5e fe 72   6.".].-......^.r
    0030 - cb 89 50 e7 c1 71 65 f2-73 5a 70 2d 6a 1b a4 aa   ..P..qe.sZp-j...
    0040 - 42 21 ee a6 08 1a 8c 7f-7d 5c 1f 13 8f 73 4d c1   B!......}\...sM.
    0050 - ee 1b 18 f0 be 73 85 38-fa 23 1c 7c 5b 8b 4c 25   .....s.8.#.|[.L%
    0060 - 16 5f 88 32 3a 06 8a b3-d8 2c e4 27 b9 ba 6c aa   ._.2:....,.'..l.
    0070 - f7 6d 66 26 34 f2 10 8d-6e 55 e1 7e 8e 00 4e b3   .mf&4...nU.~..N.
    0080 - 45 47 5f 91 3b 16 f5 cf-e5 85 a1 5f 1a 0b 25 18   EG_.;......_..%.
    0090 - ff 1a e4 73 2e e1 e4 bf-78 f0 b2 1c b3 2b eb de   ...s....x....+..
    00a0 - c9 f7 90 cc 2d a8 f4 51-e4 bd 91 99 65 15 28 d7   ....-..Q....e.(.
    00b0 - ca 8a 99 aa e8 3c 9d 7d-7f e6 ca 07 d2 7d ad 86   .....<.}.....}..

    Start Time: 1760179577
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
read from 0x2c1a40c6490 [0x2c1a44ac5f3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
read from 0x2c1a40c6490 [0x2c1a44ac5f8] (234 bytes => 234 (0xEA))
0000 - 78 6a 18 67 6a 51 fc 9b-5e 19 e8 cd 5e 03 f8 b9   xj.gjQ..^...^...
0010 - f6 0b 6d d4 e9 0a b9 27-9a d9 16 0e 5d 44 fa c8   ..m....'....]D..
0020 - 85 e9 e6 59 33 a7 ae ab-68 e3 97 30 23 b4 fe 00   ...Y3...h..0#...
0030 - d3 24 d7 7c 75 d4 ec e6-6f 15 96 b5 3d f6 3d 2f   .$.|u...o...=.=/
0040 - b4 52 2d 75 e4 fa 6e 77-02 16 7c ce c3 3a 2d 4a   .R-u..nw..|..:-J
0050 - 4e ee 62 19 89 76 c8 7a-d0 b7 5d 51 c3 2e f5 ef   N.b..v.z..]Q....
0060 - e2 49 6b 09 8d 2b 1c ce-81 fd 46 ea fa 6d 86 b2   .Ik..+....F..m..
0070 - a1 83 d1 89 81 db 40 c4-58 2f df 87 32 33 68 71   ......@.X/..23hq
0080 - 3b 83 24 d9 a8 38 0b 8e-2a 3a c6 c6 64 79 09 c0   ;.$..8..*:..dy..
0090 - 41 ce 02 04 54 99 f4 e8-b9 48 6d 82 56 f5 92 6b   A...T....Hm.V..k
00a0 - 8a 27 2e 66 94 51 e7 1e-38 3b a9 c0 4c 89 74 5f   .'.f.Q..8;..L.t_
00b0 - b9 26 04 13 33 42 fe d4-6f 74 1f b4 3f 9f 27 33   .&..3B..ot..?.'3
00c0 - 7c 53 a8 85 dc 2c 71 ee-45 1a 0b 31 5e 11 c8 1a   |S...,q.E..1^...
00d0 - 64 28 93 f1 0a ee b7 f9-96 ed ff 60 21 12 b0 6e   d(.........`!..n
00e0 - 7b fd 37 25 eb ef a5 44-f9 ea                     {.7%...D..
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_CCM_SHA256
    Session-ID: D172B60595D70CBF1407B7CB1AEBD867015653A85733C16F74EC8D6650AEF807
    Session-ID-ctx:
    Resumption PSK: 7DE2EC215F70E1AD61EB0D50B17C4EF1110300CF9FDC066BFCBDE64DE7344F89
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 44 0f 07 10 7c 87 23 b2-b6 e9 3f 1f 75 99 d4 5a   D...|.#...?.u..Z
    0010 - 29 fe f7 57 9a 1b 61 46-cf 4a 5e 5f 88 5b 52 6d   )..W..aF.J^_.[Rm
    0020 - bd b3 19 55 6b fd d3 93-5c 3c b5 ba 3f 22 02 94   ...Uk...\<..?"..
    0030 - 17 a6 bc 1a 75 44 2b 6b-29 6c 4b 21 35 b7 c9 fd   ....uD+k)lK!5...
    0040 - 4f 96 39 9b 93 39 bd 90-0c 86 15 b1 3b 4f 23 16   O.9..9......;O#.
    0050 - 72 d4 cd 28 48 31 01 b5-7e 47 c4 67 0d 9f 0d af   r..(H1..~G.g....
    0060 - 19 a3 a5 41 49 06 a2 bb-8f 4e 21 92 8c ed 5a 10   ...AI....N!...Z.
    0070 - fb 95 bb 65 77 81 b8 f3-47 d4 38 68 b0 05 58 04   ...ew...G.8h..X.
    0080 - 03 87 c8 1a 6b c7 7f b3-62 05 24 9d 6a 8c 49 4b   ....k...b.$.j.IK
    0090 - be 11 e9 17 ea a8 a0 03-a6 69 f5 8c b6 16 7f 16   .........i......
    00a0 - c8 3e 19 98 93 00 6a 8e-ad 1b 58 eb 64 1e 29 5c   .>....j...X.d.)\
    00b0 - 57 31 cf 74 1b 66 79 6b-c2 ec c9 b3 8f dc 77 49   W1.t.fyk......wI

    Start Time: 1760179577
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
test
write to 0x2c1a40c6490 [0x2c1a44b6bc3] (28 bytes => 28 (0x1C))
0000 - 17 03 03 00 17 d6 d2 74-14 67 d3 33 58 84 95 d5   .......t.g.3X...
0010 - 2a 4e be 45 04 fc ff 5e-19 89 53 0e               *N.E...^..S.
Q
DONE
write to 0x2c1a40c6490 [0x2c1a44b6bc3] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 25 99 80-57 51 f1 c8 53 e4 8d 2a   .....%..WQ..S..*
0010 - 2c 89 c3 54 58 f5 15 10-                          ,..TX...
SSL3 alert write:warning:close notify
read from 0x2c1a40c6490 [0x2c1a3feffa0] (16384 bytes => 24 (0x18))
0000 - 17 03 03 00 13 da e5 e6-24 00 15 f4 67 30 a3 ec   ........$...g0..
0010 - aa 10 56 28 1b e3 c9 10-                          ..V(....
read from 0x2c1a40c6490 [0x2c1a3feffa0] (16384 bytes => 0)
````

[TOC](README.md)
