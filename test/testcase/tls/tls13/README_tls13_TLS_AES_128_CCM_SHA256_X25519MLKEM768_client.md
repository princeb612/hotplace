#### client

````
$ openssl s_client -connect localhost:9000 -state -debug -keylogfile sslkeylog -tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256 -groups X25519MLKEM768
Connecting to ::1
CONNECTED(000001E8)
SSL_connect:before SSL initialization
write to 0x1b4d65d67f0 [0x1b4d82e2b60] (1396 bytes => 1396 (0x574))
0000 - 16 03 01 05 6f 01 00 05-6b 03 03 ee ff 3b 12 b2   ....o...k....;..
0010 - 84 e6 4c 59 ee 3e b7 1e-ad 21 4c 28 e5 52 96 49   ..LY.>...!L(.R.I
0020 - 39 fd da cd 5c bb 7b 61-d5 fb b2 20 7f 67 6c cb   9...\.{a... .gl.
0030 - 3a a8 5a 60 a8 38 d9 9c-4b 4a 00 76 e1 97 35 61   :.Z`.8..KJ.v..5a
0040 - 2a f3 df b7 6c d0 7b 04-51 0d f8 47 00 02 13 04   *...l.{.Q..G....
0050 - 01 00 05 20 00 0a 00 04-00 02 11 ec 00 23 00 00   ... .........#..
0060 - 00 16 00 00 00 17 00 00-00 0d 00 2a 00 28 09 05   ...........*.(..
0070 - 09 06 09 04 04 03 05 03-06 03 08 07 08 08 08 1a   ................
0080 - 08 1b 08 1c 08 09 08 0a-08 0b 08 04 08 05 08 06   ................
0090 - 04 01 05 01 06 01 00 2b-00 03 02 03 04 00 2d 00   .......+......-.
00a0 - 02 01 01 00 33 04 c6 04-c4 11 ec 04 c0 cd d4 ac   ....3...........
00b0 - 03 21 59 a3 cc c9 56 ea-89 cb 1c 03 90 66 1c 50   .!Y...V......f.P
00c0 - 98 a7 ef 21 2b bd cb 39-11 85 8c 80 d4 8d 77 2b   ...!+..9......w+
00d0 - 3e 49 13 b7 94 73 07 67-ec ab e4 44 50 d5 29 3d   >I...s.g...DP.)=
00e0 - 60 03 72 97 77 a7 e2 2c-7a 3c b9 28 70 90 77 08   `.r.w..,z<.(p.w.
00f0 - 7c aa 79 a8 6c a8 17 c9-68 5c 1f ae 29 28 51 14   |.y.l...h\..)(Q.
0100 - 5b c7 c9 0f 1c 51 4d f7-65 ce 70 6b c6 95 b7 1b   [....QM.e.pk....
0110 - 9f 0b 6f 67 da c9 55 a2-80 9c 6b 7f 2e 42 96 a9   ..og..U...k..B..
0120 - 20 1d 96 66 cd ec c2 af-21 69 5d c5 09 16 93 d8    ..f....!i].....
0130 - 48 9e d5 bc bb 72 18 aa-ba 76 e3 94 5d 97 c8 cc   H....r...v..]...
0140 - b6 91 6d 29 00 71 2f e4-b8 56 62 74 e2 7b 5e 7c   ..m).q/..Vbt.{^|
0150 - 9a 3f 36 26 a1 a5 70 b1-b0 27 7e 09 b5 1d 86 59   .?6&..p..'~....Y
0160 - 96 36 24 54 2c 6b b0 c1-c5 83 52 ab 31 43 28 2c   .6$T,k....R.1C(,
0170 - a5 99 27 69 2c c9 ac 87-9d a9 27 b2 2a 1a 19 41   ..'i,.....'.*..A
0180 - 37 3c 4a ca 7c cf 49 9f-e3 b3 36 a8 78 82 01 42   7<J.|.I...6.x..B
0190 - 2d f9 b3 0c 20 e4 03 43-01 5b 4a cc 7e 8a c9 18   -... ..C.[J.~...
01a0 - 94 47 0d 89 27 b9 10 5a-00 2f f5 aa e6 a3 6b b3   .G..'..Z./....k.
01b0 - 9c 90 3b 56 3b 6a 1a 6d-03 5c 5f eb 20 85 e5 e4   ..;V;j.m.\_. ...
01c0 - 6e 81 13 7f 97 c7 40 88-30 b8 0d d7 7c 37 45 11   n.....@.0...|7E.
01d0 - ce d5 95 03 9a 51 e0 c9-a2 4e 65 3d 88 3c 02 e4   .....Q...Ne=.<..
01e0 - d6 6a f4 19 76 48 49 42-90 a8 23 a8 c1 64 e5 55   .j..vHIB..#..d.U
01f0 - cc db 72 50 0f 87 3f 95-13 41 f9 d9 c2 53 65 89   ..rP..?..A...Se.
0200 - d7 b0 1f ec 67 57 18 00-20 82 4a 0f 19 bb 6f f7   ....gW.. .J...o.
0210 - 40 a4 db c3 bc e3 71 af-60 75 b1 2b 16 8e 9d f4   @.....q.`u.+....
0220 - 68 bc d0 49 b6 a0 21 40-85 0f 57 17 66 bb 6a 71   h..I..!@..W.f.jq
0230 - 07 f4 94 3a d1 31 4c d8-47 a3 ac 27 60 14 9d b0   ...:.1L.G..'`...
0240 - 9a a6 06 24 a7 60 9a 1b-2b d2 5c 6f 41 c5 28 35   ...$.`..+.\oA.(5
0250 - cb a6 14 1d b9 9a 71 94-0c 0d 95 bb 2a a6 e9 5b   ......q.....*..[
0260 - a2 e7 33 cb 82 5e 4b 4a-33 28 f3 01 03 06 bd ee   ..3..^KJ3(......
0270 - 54 40 1b c6 9b 7e 40 a1-6b b1 bc 74 d4 a1 64 f0   T@...~@.k..t..d.
0280 - c9 a9 d0 0c f0 7b c5 cf-e1 64 cd 6b bc bb 9c 5c   .....{...d.k...\
0290 - c0 5a 75 c1 fb 9e c9 9c-05 74 c8 c5 7b 17 19 a4   .Zu......t..{...
02a0 - 85 98 c7 bb 2a 42 48 b6-93 23 32 df 49 53 9f ca   ....*BH..#2.IS..
02b0 - 90 eb ab 2d 98 64 a1 da-8b b4 d8 15 04 37 13 bf   ...-.d.......7..
02c0 - e3 39 1f a7 36 a0 45 79-6b e6 f1 30 46 55 71 fd   .9..6.Eyk..0FUq.
02d0 - 72 77 ee fa ac fd a4 20-1f 94 8a 91 78 3f 8e 35   rw..... ....x?.5
02e0 - 7b a0 ea 0b 6d 17 81 7f-07 5a 42 69 51 6a 79 24   {...m....ZBiQjy$
02f0 - e7 13 13 fd 61 7e 1b f2-a6 86 13 8b 1c 46 5f 07   ....a~.......F_.
0300 - 55 36 df 91 2d da a4 95-46 c3 5a e5 e8 5f 51 b3   U6..-...F.Z.._Q.
0310 - 1b 1d b0 12 09 93 2b 42-80 09 e5 d4 39 3d fb 3b   ......+B....9=.;
0320 - d2 95 9c 9d 9c 2d 50 eb-79 e8 27 9d 48 55 63 b8   .....-P.y.'.HUc.
0330 - 6c b7 86 9b ba 18 58 06-45 01 8b 0b 02 2b 55 c0   l.....X.E....+U.
0340 - 51 1c 90 86 6b 1a c9 a8-bb 04 c9 80 b1 b7 0a 75   Q...k..........u
0350 - a7 60 c5 13 f9 08 2b 74-c8 58 8a 6a 15 53 81 2a   .`....+t.X.j.S.*
0360 - eb 01 22 0b a7 2b 3b 97-56 93 11 46 79 1f 38 aa   .."..+;.V..Fy.8.
0370 - 48 d7 fb 5c 46 08 42 9e-8a 81 80 41 ad c9 6c 80   H..\F.B....A..l.
0380 - 68 65 a9 9b 41 59 a9 b6-49 a4 99 9d ed 16 6d 6f   he..AY..I.....mo
0390 - 15 1c 72 e3 64 bd 50 af-ec db 96 68 c8 84 9d 86   ..r.d.P....h....
03a0 - 6d 5a d8 3e 75 81 8d cb-2c be 99 d2 7e 13 0b 2d   mZ.>u...,...~..-
03b0 - a9 0b 5a 27 e6 cd a5 87-c7 bc 10 8c b9 0a be 09   ..Z'............
03c0 - 33 0b 13 eb 63 72 62 4f-1c d4 cb be bc b4 fd d8   3...crbO........
03d0 - 9e 57 14 2e 91 85 bc a1-03 87 8b 6c a8 25 75 2a   .W.........l.%u*
03e0 - 60 05 73 92 89 93 ec 87-c7 98 98 36 30 72 8a d8   `.s........60r..
03f0 - e2 33 de f3 44 ed db 74-82 a7 ba 49 62 39 23 f9   .3..D..t...Ib9#.
0400 - 80 47 89 2c 90 e5 4f 00-5b 4c d6 cb 52 cf a8 b9   .G.,..O.[L..R...
0410 - a2 d6 78 af 51 cb 70 2a-97 90 a2 02 b6 4a bd 23   ..x.Q.p*.....J.#
0420 - 1a ce 01 04 38 d1 d8 75-bc e4 18 21 23 b4 b4 f0   ....8..u...!#...
0430 - 53 0a 34 bb 30 7c 10 7c-a7 cf ef a8 44 b1 82 50   S.4.0|.|....D..P
0440 - e3 84 9e 57 01 56 89 a2-87 ce a8 a2 ab 4a 9e 8d   ...W.V.......J..
0450 - e3 36 50 54 90 f9 48 b4-14 dc 4a 39 c7 95 d7 94   .6PT..H...J9....
0460 - 55 b4 ba 02 41 d0 7f 79-9b 94 66 1b a7 60 45 aa   U...A..y..f..`E.
0470 - dd 8a 55 76 94 02 23 6c-a7 a2 38 c1 20 36 bc 0d   ..Uv..#l..8. 6..
0480 - c2 43 b8 f2 58 ff dc 25-10 26 61 b0 44 70 bb ac   .C..X..%.&a.Dp..
0490 - 01 2c b9 70 e5 b6 7d 23-cc 25 b6 f8 af 40 82 b7   .,.p..}#.%...@..
04a0 - a4 bb 27 de f6 26 40 76-17 77 31 8b 6d 3b 95 42   ..'..&@v.w1.m;.B
04b0 - 43 18 56 d3 a2 89 09 1a-5e 55 55 32 86 17 ad 4b   C.V.....^UU2...K
04c0 - 6b e4 d7 7f b9 2b 01 76-8b 39 eb b0 c5 48 43 ac   k....+.v.9...HC.
04d0 - 6a 6b 32 53 47 b5 21 e5-80 e4 00 57 4a 51 63 e9   jk2SG.!....WJQc.
04e0 - 60 a0 ea 92 80 0b 28 01-73 46 52 a9 c5 0b 19 f2   `.....(.sFR.....
04f0 - 01 92 b0 07 44 fa c3 de-d4 58 15 84 70 74 62 48   ....D....X..ptbH
0500 - c4 a4 51 2d a1 67 48 70-a3 d7 ea 0b c9 f0 8e 6c   ..Q-.gHp.......l
0510 - 02 60 dc 38 49 44 c9 27-f2 85 3f b5 21 45 77 29   .`.8ID.'..?.!Ew)
0520 - 40 9a 73 99 e3 bc 96 f0-0c 86 62 c3 a9 98 1a e9   @.s.......b.....
0530 - ab 55 da 06 a3 59 28 bb-5f 09 3f 77 94 5e f4 7f   .U...Y(._.?w.^..
0540 - 1e 49 11 39 7f ba 73 1c-a2 b6 7d 69 35 07 6b eb   .I.9..s...}i5.k.
0550 - a9 06 c5 a3 56 78 55 5c-6c 35 3a fe ec a8 a2 01   ....VxU\l5:.....
0560 - 50 b3 42 60 c4 58 00 74-29 a9 43 05 1e 00 1b 00   P.B`.X.t).C.....
0570 - 03 02 00 01                                       ....
SSL_connect:SSLv3/TLS write client hello
read from 0x1b4d65d67f0 [0x1b4d82ea1d3] (5 bytes => 5 (0x5))
0000 - 16 03 03 04 ba                                    .....
read from 0x1b4d65d67f0 [0x1b4d82ea1d8] (1210 bytes => 1210 (0x4BA))
0000 - 02 00 04 b6 03 03 90 13-4c 32 a0 be e7 20 15 9a   ........L2... ..
0010 - 74 fd 6c 3c d7 c1 23 2a-fa b3 de ce 18 e2 e0 12   t.l<..#*........
0020 - 06 d6 ef 33 a0 a7 20 7f-67 6c cb 3a a8 5a 60 a8   ...3.. .gl.:.Z`.
0030 - 38 d9 9c 4b 4a 00 76 e1-97 35 61 2a f3 df b7 6c   8..KJ.v..5a*...l
0040 - d0 7b 04 51 0d f8 47 13-04 00 04 6e 00 2b 00 02   .{.Q..G....n.+..
0050 - 03 04 00 33 04 64 11 ec-04 60 6f 14 ee 33 76 ef   ...3.d...`o..3v.
0060 - 65 b8 88 d5 e9 5b b9 5d-b0 1e 70 7d 62 ea 64 73   e....[.]..p}b.ds
0070 - 9f b5 1a be 20 31 e4 20-97 81 5b 78 3c ae 5c 0c   .... 1. ..[x<.\.
0080 - 66 78 f1 cd 84 ff dc d5-48 70 fd 2e af 98 66 ef   fx......Hp....f.
0090 - bc c4 fd cd 2f 80 60 3a-4e f1 97 31 12 9c 62 19   ..../.`:N..1..b.
00a0 - 2b 87 f4 0e 58 27 e7 54-72 9f 06 d1 16 0a 51 93   +...X'.Tr.....Q.
00b0 - f3 44 a2 69 df e2 51 f5-88 de f9 47 77 33 89 0a   .D.i..Q....Gw3..
00c0 - a8 b9 d2 c9 e6 49 1b cc-7f 93 db 7b e6 6b 77 02   .....I.....{.kw.
00d0 - 80 d2 0c 66 b9 50 df e6-4c 2e 19 34 d7 cd 55 f9   ...f.P..L..4..U.
00e0 - a4 e7 97 a8 1d 01 7b 6d-2c 29 da 37 7a 4b 9f 94   ......{m,).7zK..
00f0 - 05 02 b0 7c ba 58 6e 1a-7c ec d8 ed 8d 02 07 48   ...|.Xn.|......H
0100 - 84 9a d8 89 41 d0 5b 69-ed 8f 87 d5 a8 fc 5f aa   ....A.[i......_.
0110 - 88 59 a5 87 c7 6a c4 f3-37 7c c7 15 45 8c 3e 98   .Y...j..7|..E.>.
0120 - e7 b6 32 d0 0d 5e b8 81-c5 af 80 d1 a9 e3 46 a4   ..2..^........F.
0130 - 7b 19 73 9a 41 8b 17 3b-84 42 3e 5b b0 7b 1a 8f   {.s.A..;.B>[.{..
0140 - 06 83 85 05 68 35 d9 4d-58 1a 80 ee 69 8f a8 6c   ....h5.MX...i..l
0150 - a9 0d aa 0d 33 e9 fb ea-6a 5c 99 2d ee 27 36 a4   ....3...j\.-.'6.
0160 - a8 ee 2d 44 6f 2a 78 b9-13 ce e7 e6 c2 92 8b 1b   ..-Do*x.........
0170 - 65 7e 18 10 42 f1 4f 9e-5f 65 61 38 15 3f bb 6b   e~..B.O._ea8.?.k
0180 - ad a9 b6 46 4d 84 b4 82-4b 50 c7 a6 46 b2 93 db   ...FM...KP..F...
0190 - 17 1f 80 d2 38 a1 3a 79-00 75 54 1e d2 6e ae 0c   ....8.:y.uT..n..
01a0 - f2 fe b9 18 f4 d1 67 b8-4f c9 2d d2 6e 47 4e e6   ......g.O.-.nGN.
01b0 - a9 77 b2 d9 df 85 31 19-56 d4 6d 87 73 db a8 8a   .w....1.V.m.s...
01c0 - 4b 53 df 64 a6 7d 35 e4-36 95 42 0a a4 be 42 b0   KS.d.}5.6.B...B.
01d0 - cb d9 48 23 83 f1 00 7a-f6 dc c5 3c b5 d1 bc e3   ..H#...z...<....
01e0 - ae 25 9f f0 ec 6f 93 e8-4e 9b 78 87 72 27 fa 91   .%...o..N.x.r'..
01f0 - c5 83 9a 23 cd d3 62 99-08 00 7f 28 43 52 65 75   ...#..b....(CReu
0200 - 22 95 5a a1 96 23 4c 63-d6 80 5f 93 81 90 4b ab   ".Z..#Lc.._...K.
0210 - 25 03 c3 ca 67 f9 27 b1-ac 1d bc 46 d5 bb 7a 22   %...g.'....F..z"
0220 - 57 81 42 f8 32 28 8b 99-13 53 56 e4 6c 80 18 75   W.B.2(...SV.l..u
0230 - 49 ce 4f 0a 6c 23 d9 19-4e b0 e9 fd bc 3c 90 26   I.O.l#..N....<.&
0240 - c0 17 db 8f 33 eb 81 18-df fa cb 60 83 1a 4d 57   ....3......`..MW
0250 - 38 f5 1a f8 8a f3 65 d5-d8 0c 49 6a b3 7b 20 bc   8.....e...Ij.{ .
0260 - 69 eb e2 87 64 aa de cb-6d 76 72 48 3d 29 96 51   i...d...mvrH=).Q
0270 - a2 41 60 b7 a4 ad 67 7b-ff bf 57 e2 64 c8 82 fa   .A`...g{..W.d...
0280 - 28 ce cf 69 aa 1d b2 12-3a 23 6a 60 41 66 b6 94   (..i....:#j`Af..
0290 - 69 5d 27 0b f1 90 1a 15-a9 ba 45 9a aa 7e 01 94   i]'.......E..~..
02a0 - 10 85 fe e0 60 01 ba 6e-31 7e fc 53 be b8 b8 9d   ....`..n1~.S....
02b0 - 0d a1 2d 38 87 98 91 de-a7 29 fc e4 0d 1e 0a d2   ..-8.....)......
02c0 - 67 8e 4c 9a fa 03 35 d8-ea 35 d6 b8 e5 fa 71 c1   g.L...5..5....q.
02d0 - b9 51 38 f1 cb 02 e9 54-61 f4 3e 0d 3d 4a 03 42   .Q8....Ta.>.=J.B
02e0 - 6e e3 8e 00 aa 76 e6 9c-3a dd 7d ad 07 05 30 0e   n....v..:.}...0.
02f0 - 76 6c ca 2e 5a 20 dc f5-79 7d df 9b 45 a5 f9 08   vl..Z ..y}..E...
0300 - ef b1 b3 39 9f 77 34 c1-b8 83 47 7b bc 97 6f fd   ...9.w4...G{..o.
0310 - 36 e8 c4 b1 9d 7b d7 8e-fc 5d 45 01 81 08 c2 c3   6....{...]E.....
0320 - ef 38 57 f3 cc f1 54 b2-34 08 69 12 a5 1e 63 e4   .8W...T.4.i...c.
0330 - 33 7f 4d 2e a4 07 54 95-55 63 01 81 9b a0 92 19   3.M...T.Uc......
0340 - 8b 03 8b da fa dd ce 13-93 e4 3f c1 ce 5e f2 88   ..........?..^..
0350 - 63 0e ca 42 23 06 e0 1a-48 66 9b 20 4c c5 0a 22   c..B#...Hf. L.."
0360 - 83 dc b9 7d d6 1f dc 3b-06 ac 3f ed 90 fa 68 e5   ...}...;..?...h.
0370 - 6e 8c f9 dc d9 d8 e3 19-3e 2d 63 13 e2 27 59 fc   n.......>-c..'Y.
0380 - c5 84 c7 72 a0 c4 04 a2-4d e0 35 a4 5e 0a dc 7d   ...r....M.5.^..}
0390 - 7f 02 54 5f a0 d9 72 93-44 30 5f 1e 31 80 d9 f4   ..T_..r.D0_.1...
03a0 - 1c 5e 85 58 70 79 84 46-22 c9 4a 8f e8 cc dd d3   .^.Xpy.F".J.....
03b0 - 6e 64 6a 4e 51 fb fe b8-a7 6b 96 d8 b2 9e 1e 8c   ndjNQ....k......
03c0 - 76 4c 38 1e 93 03 44 04-13 70 bc 3a 30 ae 4b c0   vL8...D..p.:0.K.
03d0 - 7a fa f3 94 0c d6 57 43-7d de 21 46 04 e8 bf 3c   z.....WC}.!F...<
03e0 - b8 87 b7 1e 4d 31 7f de-04 ae 1e 47 2e 5f 2b 16   ....M1.....G._+.
03f0 - 4c 1c 23 ff 3e a1 40 06-68 60 bb 55 df 6b 92 02   L.#.>.@.h`.U.k..
0400 - 17 17 fd 4d e3 f9 d1 60-a8 b0 6e 35 01 66 8e 32   ...M...`..n5.f.2
0410 - b4 99 6a 16 86 52 8f d2-7c 7e bf f5 23 88 3f 33   ..j..R..|~..#.?3
0420 - 6d bb 3b 80 a0 82 21 a7-ba 3b b1 cd c6 7f e8 ac   m.;...!..;......
0430 - 35 76 b9 51 43 ad 1d ce-84 c6 55 a5 92 27 45 7f   5v.QC.....U..'E.
0440 - 99 fd 85 06 e1 81 fb 38-bb f5 a8 ff bd c2 15 3f   .......8.......?
0450 - 2a ef c2 6a df e1 e6 d7-b4 02 36 00 57 4d 96 6b   *..j......6.WM.k
0460 - e4 e4 46 27 db b3 6a ee-f8 0f 11 90 4d ff 1c a5   ..F'..j.....M...
0470 - 34 ca b2 4d 0e fa 70 86-79 af 76 c0 23 21 14 ff   4..M..p.y.v.#!..
0480 - 7f 3e 5c 6d ca d0 13 dd-d3 08 70 61 a6 f2 04 de   .>\m......pa....
0490 - 81 e0 95 e5 0c 23 87 6e-d6 bc d6 67 6c 54 d9 65   .....#.n...glT.e
04a0 - 55 06 4e a7 90 e4 38 f4-98 1a b7 fe be fc 6c 74   U.N...8.......lt
04b0 - f3 75 bb 25 c6 95 3b c8-4a 24                     .u.%..;.J$
SSL_connect:SSLv3/TLS write client hello
read from 0x1b4d65d67f0 [0x1b4d82e9a83] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x1b4d65d67f0 [0x1b4d82e9a88] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x1b4d65d67f0 [0x1b4d82e9a83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x1b4d65d67f0 [0x1b4d82e9a88] (23 bytes => 23 (0x17))
0000 - 5d 57 a7 0a fb 56 0c 84-7b 47 2e 31 c1 a2 77 3e   ]W...V..{G.1..w>
0010 - dc c7 54 e7 3e 81 80                              ..T.>..
SSL_connect:SSLv3/TLS read server hello
Can't use SSL_get_servername
read from 0x1b4d65d67f0 [0x1b4d82e9a83] (5 bytes => 5 (0x5))
0000 - 17 03 03 02 2a                                    ....*
read from 0x1b4d65d67f0 [0x1b4d82e9a88] (554 bytes => 554 (0x22A))
0000 - 7c 7b bc d7 71 24 0e de-f6 33 1d 7e 32 be 81 c6   |{..q$...3.~2...
0010 - a8 8c 58 80 87 ee 6d fa-da ce ff 97 bd 0b 3f 0c   ..X...m.......?.
0020 - fd 1e ba 1a d1 4d 72 62-dd a2 05 a5 d9 e6 e7 d6   .....Mrb........
0030 - bb b7 04 8c 79 b4 b5 64-66 ef a5 e2 c0 0c e2 80   ....y..df.......
0040 - af e3 a3 f3 c6 f3 64 c1-61 46 c7 a0 b3 01 ed 39   ......d.aF.....9
0050 - 72 2d 52 b7 0a 9d 66 0e-2e 4b f0 dd 37 98 42 6c   r-R...f..K..7.Bl
0060 - d1 18 8f ce d7 eb 9c 63-11 c5 91 fb 72 d5 8d 6e   .......c....r..n
0070 - 90 c1 a8 32 a2 f0 a6 88-da 33 d0 89 61 b5 5c bb   ...2.....3..a.\.
0080 - cb ea b8 c3 32 ec 24 26-9c 88 16 c1 56 d5 37 a7   ....2.$&....V.7.
0090 - 00 89 24 15 57 b8 de 8e-47 07 92 aa 14 63 63 fa   ..$.W...G....cc.
00a0 - 3b c1 cc c8 9c f7 e7 7a-90 3a d6 97 29 43 8c 6d   ;......z.:..)C.m
00b0 - c4 d4 7e 26 18 ce c1 22-36 63 39 65 cc f4 1e 3e   ..~&..."6c9e...>
00c0 - 82 8d 56 bd 3e c0 71 74-f8 67 08 9f bd b3 ce 9e   ..V.>.qt.g......
00d0 - 9a dd e1 6e 71 b6 b2 09-60 84 ad 76 38 58 e2 c0   ...nq...`..v8X..
00e0 - b9 f9 95 97 be 1d 94 1c-c5 7d 62 bd 83 7d eb bc   .........}b..}..
00f0 - f7 69 5a fc 1a 40 cc f5-62 b9 17 af f7 f2 42 ad   .iZ..@..b.....B.
0100 - c1 d2 e2 92 fc 36 87 04-a8 1c bf 31 d8 c1 19 b9   .....6.....1....
0110 - f4 19 a6 bc 17 03 d0 11-9c b3 9e d6 1e 5e 43 d4   .............^C.
0120 - e0 31 dd c5 ce a0 1a c3-18 a0 d4 8e 95 88 d2 c8   .1..............
0130 - 8f a6 0b cc ba a4 f8 a1-eb 80 b6 5c d5 5a c7 2e   ...........\.Z..
0140 - 14 e3 ae 10 bd 64 b9 71-4b de 44 6b eb 5c e4 f0   .....d.qK.Dk.\..
0150 - 1c dd 44 ff b6 55 08 f1-8c 75 06 30 8d 43 ac 9b   ..D..U...u.0.C..
0160 - e4 88 a4 0f 9c 1d ec 8e-d8 a2 c0 83 24 5e 23 c4   ............$^#.
0170 - fc 71 2a 64 6a cc 20 b4-c3 80 b1 7e ef 94 85 7a   .q*dj. ....~...z
0180 - 17 a0 d0 d2 77 c6 4c dc-32 94 cc 3d ad 2b b7 87   ....w.L.2..=.+..
0190 - da db 1e b2 96 8e 29 0f-28 26 70 8c 8d ed e1 1a   ......).(&p.....
01a0 - 8a 0d 1b 56 88 15 81 89-10 51 09 8d d3 b6 a7 4b   ...V.....Q.....K
01b0 - 33 af 4d bc 64 27 46 4b-df 4e b9 98 5e 2f e9 01   3.M.d'FK.N..^/..
01c0 - 42 9e 88 8e 5d 2c fd 40-73 b6 7c 62 56 90 7b 22   B...],.@s.|bV.{"
01d0 - 9a aa ed 57 7d 1f 69 14-db 90 a1 16 83 9d a0 32   ...W}.i........2
01e0 - 08 1e ab 82 86 d6 ea 38-47 b7 16 f0 26 02 e8 5d   .......8G...&..]
01f0 - 67 a9 a6 7e 1e 8f 18 2d-84 66 50 b9 1d 3f 79 ca   g..~...-.fP..?y.
0200 - ed 87 c8 9b b1 26 8e 16-3f 3b d4 18 ef 5e e2 8f   .....&..?;...^..
0210 - 88 d6 cd e3 4a c4 40 d2-75 3f 53 72 52 4b 33 26   ....J.@.u?SrRK3&
0220 - a3 b2 12 3e 2a f2 8c ba-db 75                     ...>*....u
SSL_connect:TLSv1.3 read encrypted extensions
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
verify error:num=18:self-signed certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
verify return:1
read from 0x1b4d65d67f0 [0x1b4d82e9a83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 61                                    ....a
read from 0x1b4d65d67f0 [0x1b4d82e9a88] (97 bytes => 97 (0x61))
0000 - 30 c4 a6 11 d0 99 20 9b-03 ac 43 70 83 f0 b4 47   0..... ...Cp...G
0010 - ee 42 29 f0 68 1b a3 85-1c 9c eb 0d 45 30 40 84   .B).h.......E0@.
0020 - 3d e0 3d 29 ec 7a 17 8c-d7 ca 36 01 b7 4a 7d 62   =.=).z....6..J}b
0030 - a0 1d 1d 4a 15 9f c7 a5-7d 83 fd 04 5b af e6 b3   ...J....}...[...
0040 - f0 fc 9c 8a 6e ef e0 d2-e4 9b 78 68 6a 13 b6 77   ....n.....xhj..w
0050 - 46 e0 1c 5e 04 fe a9 bc-7b f6 d9 1d c3 e2 bf 00   F..^....{.......
0060 - 13                                                .
SSL_connect:SSLv3/TLS read server certificate
read from 0x1b4d65d67f0 [0x1b4d82e9a83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
read from 0x1b4d65d67f0 [0x1b4d82e9a88] (53 bytes => 53 (0x35))
0000 - 4a 3a 81 27 eb 38 c2 16-f1 e1 57 f9 08 d9 e0 cf   J:.'.8....W.....
0010 - 69 1a de 82 aa f8 0c fb-0c cc 9f 29 f4 cd 71 ca   i..........)..q.
0020 - 19 b3 55 4a 45 29 c5 fa-3f bb 76 74 e6 2f 77 56   ..UJE)..?.vt./wV
0030 - 39 00 2d 44 71                                    9.-Dq
SSL_connect:TLSv1.3 read server certificate verify
SSL_connect:SSLv3/TLS read finished
SSL_connect:SSLv3/TLS write change cipher spec
write to 0x1b4d65d67f0 [0x1b4d82e2b60] (64 bytes => 64 (0x40))
0000 - 14 03 03 00 01 01 17 03-03 00 35 65 3a 69 66 09   ..........5e:if.
0010 - c4 8c 76 9f 92 89 08 a6-79 b9 2d f1 5f 26 e4 49   ..v.....y.-._&.I
0020 - 2c 0f 07 48 ae ca 78 3d-a8 da f0 e0 64 cf 8b 63   ,..H..x=....d..c
0030 - 2f db 88 39 75 73 c1 c6-37 87 2f c3 a3 51 c3 2a   /..9us..7./..Q.*
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
Negotiated TLS1.3 group: X25519MLKEM768
---
SSL handshake has read 1968 bytes and written 1460 bytes
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
read from 0x1b4d65d67f0 [0x1b4d82dc5f3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
read from 0x1b4d65d67f0 [0x1b4d82dc5f8] (234 bytes => 234 (0xEA))
0000 - ed 4f 7c 43 4a 0c a2 ca-ea d1 6d 8c fb b7 27 a7   .O|CJ.....m...'.
0010 - 06 90 f6 69 69 ee 4f 50-a0 7c 60 da a9 c3 2c e9   ...ii.OP.|`...,.
0020 - 34 6f b3 20 d0 4a 9e 67-79 87 40 3a 86 39 f0 85   4o. .J.gy.@:.9..
0030 - 99 2c a0 5a 86 47 dc b4-7c bb fc 04 91 b4 06 1c   .,.Z.G..|.......
0040 - 9a 94 7a 34 0a 81 66 4d-9d 95 d7 75 76 33 39 81   ..z4..fM...uv39.
0050 - 4e 83 89 80 b9 de cb cc-a3 88 83 67 8e 9f 60 c0   N..........g..`.
0060 - 31 40 7a d1 69 40 01 5b-8a 48 7d c2 70 7b d3 cf   1@z.i@.[.H}.p{..
0070 - 13 62 c2 3f 89 5a de a2-2b ab 4b f6 6d 33 6b 5f   .b.?.Z..+.K.m3k_
0080 - 9f ff 8c f3 76 73 10 cc-af 08 ea f3 f2 71 44 61   ....vs.......qDa
0090 - 43 f5 d2 cf 6f 22 67 90-e3 1d b7 e1 0e 7a e4 94   C...o"g......z..
00a0 - b7 be 70 6e 33 6b a3 40-e3 7d 2a 37 8d 6d 75 6f   ..pn3k.@.}*7.muo
00b0 - ae 9c ca c7 c1 35 b1 3a-d2 6e 25 74 9b 06 85 a4   .....5.:.n%t....
00c0 - bd f2 72 03 ab 62 56 07-b4 6c 5f 6d e4 a2 66 41   ..r..bV..l_m..fA
00d0 - a3 1e bc b1 9f 37 38 01-02 ee ec ca c7 00 0a 0f   .....78.........
00e0 - 55 5d e2 65 97 f8 7b c0-c9 e2                     U].e..{...
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_CCM_SHA256
    Session-ID: B0C94AD3DB36AEDBFC99C3B09839AFC28FE43E367B7544AAF5444CD91A247ECA
    Session-ID-ctx:
    Resumption PSK: 7B4177440AFF989B10F800056C57FBCEFBDAE5CD92AFE027903BD60A593F8B67
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 43 29 ca 7e f9 0f fd 18-62 cb 20 c6 5f 78 9d 0b   C).~....b. ._x..
    0010 - dd 45 9e 6d 72 99 84 8d-16 57 98 0c 59 c4 b1 48   .E.mr....W..Y..H
    0020 - 3f 1f 9d 4c d5 93 35 0a-e2 1d 5b 3c 8a 6f 2a c2   ?..L..5...[<.o*.
    0030 - 52 02 17 a0 3b 66 fd 0e-79 65 81 df 8a ff 88 5e   R...;f..ye.....^
    0040 - ba 33 5e 28 83 cf 60 77-a5 bf 5c 55 2e cc af 0e   .3^(..`w..\U....
    0050 - 53 40 48 13 70 09 71 69-23 2a 29 14 83 16 6e 41   S@H.p.qi#*)...nA
    0060 - a4 6a 77 57 f8 fa 22 f3-ce b0 7c b3 3d fd 1a 9c   .jwW.."...|.=...
    0070 - a9 72 c8 34 34 9e 4c 57-6e aa 5c a8 6c 00 d6 f2   .r.44.LWn.\.l...
    0080 - 05 54 5e 16 e5 b7 65 90-8c d4 12 34 3c 99 02 be   .T^...e....4<...
    0090 - 44 fa 20 24 89 3a 99 b6-80 45 59 d9 46 6d 94 84   D. $.:...EY.Fm..
    00a0 - f9 12 9a 07 c4 e7 de 42-1f 7e cb d9 9c e5 c0 c5   .......B.~......
    00b0 - 4e 4a db ad ab 59 cd b1-e1 8e 83 75 ee 42 44 46   NJ...Y.....u.BDF

    Start Time: 1760177152
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
read from 0x1b4d65d67f0 [0x1b4d82dc5f3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
read from 0x1b4d65d67f0 [0x1b4d82dc5f8] (234 bytes => 234 (0xEA))
0000 - 5f 5d 14 7a 18 f4 67 f8-6f 54 54 7d 1b 00 a7 85   _].z..g.oTT}....
0010 - 7c 25 1c ef 8f 74 bd 60-e3 db f3 fe c2 8b d0 f3   |%...t.`........
0020 - c0 b8 b0 5f d9 5e f9 0d-da 3c 2a 70 86 e7 87 75   ..._.^...<*p...u
0030 - 91 60 bd 94 64 bf 49 b2-68 75 0f d6 f4 27 9c 44   .`..d.I.hu...'.D
0040 - 7b b1 7a bc 84 f7 6b 7e-1d 55 c6 e5 07 f3 9e a4   {.z...k~.U......
0050 - ff d4 5a 35 bb aa d4 e0-e0 e4 cd 66 e9 5d c1 a6   ..Z5.......f.]..
0060 - 03 73 c3 16 51 88 35 e9-7c ff 73 1b 82 72 f1 69   .s..Q.5.|.s..r.i
0070 - f0 2e d3 b0 b6 fa 70 5c-97 3e 36 77 d4 5c 51 90   ......p\.>6w.\Q.
0080 - c5 b7 71 39 f4 22 00 dd-c7 2b ca cd e9 08 14 67   ..q9."...+.....g
0090 - 27 f7 4a ee bf 93 73 d0-90 3e 58 23 30 03 a6 73   '.J...s..>X#0..s
00a0 - 16 88 f7 1c a9 e4 64 13-5a 26 84 10 cf b9 52 df   ......d.Z&....R.
00b0 - 41 f1 eb f9 28 0e bb 5f-52 c8 24 c5 c9 e4 f4 68   A...(.._R.$....h
00c0 - 68 9b a9 fd ec 05 cb 48-78 d4 00 c2 6a 9a d1 be   h......Hx...j...
00d0 - b8 cd 6b 22 c4 48 68 7b-7d 7a de 63 bd bf 11 0f   ..k".Hh{}z.c....
00e0 - 59 33 92 10 b2 c0 5c 84-79 9b                     Y3....\.y.
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_CCM_SHA256
    Session-ID: 1E5809062044D507BE6866BAB45862F1283D857BAB2C2672DA8D9A1452732079
    Session-ID-ctx:
    Resumption PSK: 4F1CDB402E73A30154EB473738BFC905F7E9975475E4C2E9CDF2BB0832B4CED7
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 43 29 ca 7e f9 0f fd 18-62 cb 20 c6 5f 78 9d 0b   C).~....b. ._x..
    0010 - ef 5a b2 5c 92 99 7a c6-95 66 6b eb 3a 5f c0 a6   .Z.\..z..fk.:_..
    0020 - 90 97 df e5 ed 09 10 b5-23 c0 b0 7b 36 c0 f0 a3   ........#..{6...
    0030 - 9c d4 f4 4c aa ea 28 6c-83 42 be 09 23 71 5c 06   ...L..(l.B..#q\.
    0040 - ac 7f 88 cc c6 dd a4 7a-5d d6 b0 2a 9e 5e 2e f8   .......z]..*.^..
    0050 - 9f 4a 46 26 f5 77 1f 63-1a 57 2b b0 39 9b 3b d6   .JF&.w.c.W+.9.;.
    0060 - 2a 15 27 17 12 68 0f f9-e2 8a e1 68 18 fe 1f b6   *.'..h.....h....
    0070 - 8a 77 df 0a 0c 7c 1b 72-78 c8 f0 4d 6b 29 14 d2   .w...|.rx..Mk)..
    0080 - 75 2e 50 e1 9c 5c 03 7a-03 f1 57 d8 a6 59 05 11   u.P..\.z..W..Y..
    0090 - 90 94 33 03 0b 93 70 e7-de f4 04 62 99 e2 43 a8   ..3...p....b..C.
    00a0 - 9d 20 ec 3f 5a 36 9c b7-6c 1a 08 75 76 d0 2a 57   . .?Z6..l..uv.*W
    00b0 - ba ce 02 37 d6 c6 80 ee-94 b4 c5 8f b1 eb 81 df   ...7............

    Start Time: 1760177152
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
test
write to 0x1b4d65d67f0 [0x1b4d82e59c3] (28 bytes => 28 (0x1C))
0000 - 17 03 03 00 17 01 a7 f4-b3 6f 25 fe 82 a1 c6 8c   .........o%.....
0010 - a5 d7 a9 de f7 0c 82 28-6c e9 c2 d4               .......(l...
Q
DONE
write to 0x1b4d65d67f0 [0x1b4d82e59c3] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 f9 d1 d1-2e fa 3a 03 9a 0c 25 a6   ..........:...%.
0010 - 0b f1 fb fc 1a 3c ab 7d-                          .....<.}
SSL3 alert write:warning:close notify
read from 0x1b4d65d67f0 [0x1b4d64fffa0] (16384 bytes => 24 (0x18))
0000 - 17 03 03 00 13 14 15 ba-cc cc 38 85 63 b8 e6 c2   ..........8.c...
0010 - f8 f8 2f 8b ca e2 d9 9a-                          ../.....
read from 0x1b4d65d67f0 [0x1b4d64fffa0] (16384 bytes => 0)
````

[TOC](README.md)
