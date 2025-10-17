#### server

````
openssl s_server -accept 9000 -cert ecdsa.crt -key ecdsa.key -state -debug -status_verbose -keylogfile sslkeylog -tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256 -groups X25519MLKEM768
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x264d548a8e0 [0x264d7063503] (5 bytes => 5 (0x5))
0000 - 16 03 01 05 6f                                    ....o
read from 0x264d548a8e0 [0x264d7063508] (1391 bytes => 1391 (0x56F))
0000 - 01 00 05 6b 03 03 ee ff-3b 12 b2 84 e6 4c 59 ee   ...k....;....LY.
0010 - 3e b7 1e ad 21 4c 28 e5-52 96 49 39 fd da cd 5c   >...!L(.R.I9...\
0020 - bb 7b 61 d5 fb b2 20 7f-67 6c cb 3a a8 5a 60 a8   .{a... .gl.:.Z`.
0030 - 38 d9 9c 4b 4a 00 76 e1-97 35 61 2a f3 df b7 6c   8..KJ.v..5a*...l
0040 - d0 7b 04 51 0d f8 47 00-02 13 04 01 00 05 20 00   .{.Q..G....... .
0050 - 0a 00 04 00 02 11 ec 00-23 00 00 00 16 00 00 00   ........#.......
0060 - 17 00 00 00 0d 00 2a 00-28 09 05 09 06 09 04 04   ......*.(.......
0070 - 03 05 03 06 03 08 07 08-08 08 1a 08 1b 08 1c 08   ................
0080 - 09 08 0a 08 0b 08 04 08-05 08 06 04 01 05 01 06   ................
0090 - 01 00 2b 00 03 02 03 04-00 2d 00 02 01 01 00 33   ..+......-.....3
00a0 - 04 c6 04 c4 11 ec 04 c0-cd d4 ac 03 21 59 a3 cc   ............!Y..
00b0 - c9 56 ea 89 cb 1c 03 90-66 1c 50 98 a7 ef 21 2b   .V......f.P...!+
00c0 - bd cb 39 11 85 8c 80 d4-8d 77 2b 3e 49 13 b7 94   ..9......w+>I...
00d0 - 73 07 67 ec ab e4 44 50-d5 29 3d 60 03 72 97 77   s.g...DP.)=`.r.w
00e0 - a7 e2 2c 7a 3c b9 28 70-90 77 08 7c aa 79 a8 6c   ..,z<.(p.w.|.y.l
00f0 - a8 17 c9 68 5c 1f ae 29-28 51 14 5b c7 c9 0f 1c   ...h\..)(Q.[....
0100 - 51 4d f7 65 ce 70 6b c6-95 b7 1b 9f 0b 6f 67 da   QM.e.pk......og.
0110 - c9 55 a2 80 9c 6b 7f 2e-42 96 a9 20 1d 96 66 cd   .U...k..B.. ..f.
0120 - ec c2 af 21 69 5d c5 09-16 93 d8 48 9e d5 bc bb   ...!i].....H....
0130 - 72 18 aa ba 76 e3 94 5d-97 c8 cc b6 91 6d 29 00   r...v..].....m).
0140 - 71 2f e4 b8 56 62 74 e2-7b 5e 7c 9a 3f 36 26 a1   q/..Vbt.{^|.?6&.
0150 - a5 70 b1 b0 27 7e 09 b5-1d 86 59 96 36 24 54 2c   .p..'~....Y.6$T,
0160 - 6b b0 c1 c5 83 52 ab 31-43 28 2c a5 99 27 69 2c   k....R.1C(,..'i,
0170 - c9 ac 87 9d a9 27 b2 2a-1a 19 41 37 3c 4a ca 7c   .....'.*..A7<J.|
0180 - cf 49 9f e3 b3 36 a8 78-82 01 42 2d f9 b3 0c 20   .I...6.x..B-...
0190 - e4 03 43 01 5b 4a cc 7e-8a c9 18 94 47 0d 89 27   ..C.[J.~....G..'
01a0 - b9 10 5a 00 2f f5 aa e6-a3 6b b3 9c 90 3b 56 3b   ..Z./....k...;V;
01b0 - 6a 1a 6d 03 5c 5f eb 20-85 e5 e4 6e 81 13 7f 97   j.m.\_. ...n....
01c0 - c7 40 88 30 b8 0d d7 7c-37 45 11 ce d5 95 03 9a   .@.0...|7E......
01d0 - 51 e0 c9 a2 4e 65 3d 88-3c 02 e4 d6 6a f4 19 76   Q...Ne=.<...j..v
01e0 - 48 49 42 90 a8 23 a8 c1-64 e5 55 cc db 72 50 0f   HIB..#..d.U..rP.
01f0 - 87 3f 95 13 41 f9 d9 c2-53 65 89 d7 b0 1f ec 67   .?..A...Se.....g
0200 - 57 18 00 20 82 4a 0f 19-bb 6f f7 40 a4 db c3 bc   W.. .J...o.@....
0210 - e3 71 af 60 75 b1 2b 16-8e 9d f4 68 bc d0 49 b6   .q.`u.+....h..I.
0220 - a0 21 40 85 0f 57 17 66-bb 6a 71 07 f4 94 3a d1   .!@..W.f.jq...:.
0230 - 31 4c d8 47 a3 ac 27 60-14 9d b0 9a a6 06 24 a7   1L.G..'`......$.
0240 - 60 9a 1b 2b d2 5c 6f 41-c5 28 35 cb a6 14 1d b9   `..+.\oA.(5.....
0250 - 9a 71 94 0c 0d 95 bb 2a-a6 e9 5b a2 e7 33 cb 82   .q.....*..[..3..
0260 - 5e 4b 4a 33 28 f3 01 03-06 bd ee 54 40 1b c6 9b   ^KJ3(......T@...
0270 - 7e 40 a1 6b b1 bc 74 d4-a1 64 f0 c9 a9 d0 0c f0   ~@.k..t..d......
0280 - 7b c5 cf e1 64 cd 6b bc-bb 9c 5c c0 5a 75 c1 fb   {...d.k...\.Zu..
0290 - 9e c9 9c 05 74 c8 c5 7b-17 19 a4 85 98 c7 bb 2a   ....t..{.......*
02a0 - 42 48 b6 93 23 32 df 49-53 9f ca 90 eb ab 2d 98   BH..#2.IS.....-.
02b0 - 64 a1 da 8b b4 d8 15 04-37 13 bf e3 39 1f a7 36   d.......7...9..6
02c0 - a0 45 79 6b e6 f1 30 46-55 71 fd 72 77 ee fa ac   .Eyk..0FUq.rw...
02d0 - fd a4 20 1f 94 8a 91 78-3f 8e 35 7b a0 ea 0b 6d   .. ....x?.5{...m
02e0 - 17 81 7f 07 5a 42 69 51-6a 79 24 e7 13 13 fd 61   ....ZBiQjy$....a
02f0 - 7e 1b f2 a6 86 13 8b 1c-46 5f 07 55 36 df 91 2d   ~.......F_.U6..-
0300 - da a4 95 46 c3 5a e5 e8-5f 51 b3 1b 1d b0 12 09   ...F.Z.._Q......
0310 - 93 2b 42 80 09 e5 d4 39-3d fb 3b d2 95 9c 9d 9c   .+B....9=.;.....
0320 - 2d 50 eb 79 e8 27 9d 48-55 63 b8 6c b7 86 9b ba   -P.y.'.HUc.l....
0330 - 18 58 06 45 01 8b 0b 02-2b 55 c0 51 1c 90 86 6b   .X.E....+U.Q...k
0340 - 1a c9 a8 bb 04 c9 80 b1-b7 0a 75 a7 60 c5 13 f9   ..........u.`...
0350 - 08 2b 74 c8 58 8a 6a 15-53 81 2a eb 01 22 0b a7   .+t.X.j.S.*.."..
0360 - 2b 3b 97 56 93 11 46 79-1f 38 aa 48 d7 fb 5c 46   +;.V..Fy.8.H..\F
0370 - 08 42 9e 8a 81 80 41 ad-c9 6c 80 68 65 a9 9b 41   .B....A..l.he..A
0380 - 59 a9 b6 49 a4 99 9d ed-16 6d 6f 15 1c 72 e3 64   Y..I.....mo..r.d
0390 - bd 50 af ec db 96 68 c8-84 9d 86 6d 5a d8 3e 75   .P....h....mZ.>u
03a0 - 81 8d cb 2c be 99 d2 7e-13 0b 2d a9 0b 5a 27 e6   ...,...~..-..Z'.
03b0 - cd a5 87 c7 bc 10 8c b9-0a be 09 33 0b 13 eb 63   ...........3...c
03c0 - 72 62 4f 1c d4 cb be bc-b4 fd d8 9e 57 14 2e 91   rbO.........W...
03d0 - 85 bc a1 03 87 8b 6c a8-25 75 2a 60 05 73 92 89   ......l.%u*`.s..
03e0 - 93 ec 87 c7 98 98 36 30-72 8a d8 e2 33 de f3 44   ......60r...3..D
03f0 - ed db 74 82 a7 ba 49 62-39 23 f9 80 47 89 2c 90   ..t...Ib9#..G.,.
0400 - e5 4f 00 5b 4c d6 cb 52-cf a8 b9 a2 d6 78 af 51   .O.[L..R.....x.Q
0410 - cb 70 2a 97 90 a2 02 b6-4a bd 23 1a ce 01 04 38   .p*.....J.#....8
0420 - d1 d8 75 bc e4 18 21 23-b4 b4 f0 53 0a 34 bb 30   ..u...!#...S.4.0
0430 - 7c 10 7c a7 cf ef a8 44-b1 82 50 e3 84 9e 57 01   |.|....D..P...W.
0440 - 56 89 a2 87 ce a8 a2 ab-4a 9e 8d e3 36 50 54 90   V.......J...6PT.
0450 - f9 48 b4 14 dc 4a 39 c7-95 d7 94 55 b4 ba 02 41   .H...J9....U...A
0460 - d0 7f 79 9b 94 66 1b a7-60 45 aa dd 8a 55 76 94   ..y..f..`E...Uv.
0470 - 02 23 6c a7 a2 38 c1 20-36 bc 0d c2 43 b8 f2 58   .#l..8. 6...C..X
0480 - ff dc 25 10 26 61 b0 44-70 bb ac 01 2c b9 70 e5   ..%.&a.Dp...,.p.
0490 - b6 7d 23 cc 25 b6 f8 af-40 82 b7 a4 bb 27 de f6   .}#.%...@....'..
04a0 - 26 40 76 17 77 31 8b 6d-3b 95 42 43 18 56 d3 a2   &@v.w1.m;.BC.V..
04b0 - 89 09 1a 5e 55 55 32 86-17 ad 4b 6b e4 d7 7f b9   ...^UU2...Kk....
04c0 - 2b 01 76 8b 39 eb b0 c5-48 43 ac 6a 6b 32 53 47   +.v.9...HC.jk2SG
04d0 - b5 21 e5 80 e4 00 57 4a-51 63 e9 60 a0 ea 92 80   .!....WJQc.`....
04e0 - 0b 28 01 73 46 52 a9 c5-0b 19 f2 01 92 b0 07 44   .(.sFR.........D
04f0 - fa c3 de d4 58 15 84 70-74 62 48 c4 a4 51 2d a1   ....X..ptbH..Q-.
0500 - 67 48 70 a3 d7 ea 0b c9-f0 8e 6c 02 60 dc 38 49   gHp.......l.`.8I
0510 - 44 c9 27 f2 85 3f b5 21-45 77 29 40 9a 73 99 e3   D.'..?.!Ew)@.s..
0520 - bc 96 f0 0c 86 62 c3 a9-98 1a e9 ab 55 da 06 a3   .....b......U...
0530 - 59 28 bb 5f 09 3f 77 94-5e f4 7f 1e 49 11 39 7f   Y(._.?w.^...I.9.
0540 - ba 73 1c a2 b6 7d 69 35-07 6b eb a9 06 c5 a3 56   .s...}i5.k.....V
0550 - 78 55 5c 6c 35 3a fe ec-a8 a2 01 50 b3 42 60 c4   xU\l5:.....P.B`.
0560 - 58 00 74 29 a9 43 05 1e-00 1b 00 03 02 00 01      X.t).C.........
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write change cipher spec
SSL_accept:TLSv1.3 write encrypted extensions
SSL_accept:SSLv3/TLS write certificate
SSL_accept:TLSv1.3 write server certificate verify
write to 0x264d548a8e0 [0x264d70624f0] (1968 bytes => 1968 (0x7B0))
0000 - 16 03 03 04 ba 02 00 04-b6 03 03 90 13 4c 32 a0   .............L2.
0010 - be e7 20 15 9a 74 fd 6c-3c d7 c1 23 2a fa b3 de   .. ..t.l<..#*...
0020 - ce 18 e2 e0 12 06 d6 ef-33 a0 a7 20 7f 67 6c cb   ........3.. .gl.
0030 - 3a a8 5a 60 a8 38 d9 9c-4b 4a 00 76 e1 97 35 61   :.Z`.8..KJ.v..5a
0040 - 2a f3 df b7 6c d0 7b 04-51 0d f8 47 13 04 00 04   *...l.{.Q..G....
0050 - 6e 00 2b 00 02 03 04 00-33 04 64 11 ec 04 60 6f   n.+.....3.d...`o
0060 - 14 ee 33 76 ef 65 b8 88-d5 e9 5b b9 5d b0 1e 70   ..3v.e....[.]..p
0070 - 7d 62 ea 64 73 9f b5 1a-be 20 31 e4 20 97 81 5b   }b.ds.... 1. ..[
0080 - 78 3c ae 5c 0c 66 78 f1-cd 84 ff dc d5 48 70 fd   x<.\.fx......Hp.
0090 - 2e af 98 66 ef bc c4 fd-cd 2f 80 60 3a 4e f1 97   ...f...../.`:N..
00a0 - 31 12 9c 62 19 2b 87 f4-0e 58 27 e7 54 72 9f 06   1..b.+...X'.Tr..
00b0 - d1 16 0a 51 93 f3 44 a2-69 df e2 51 f5 88 de f9   ...Q..D.i..Q....
00c0 - 47 77 33 89 0a a8 b9 d2-c9 e6 49 1b cc 7f 93 db   Gw3.......I.....
00d0 - 7b e6 6b 77 02 80 d2 0c-66 b9 50 df e6 4c 2e 19   {.kw....f.P..L..
00e0 - 34 d7 cd 55 f9 a4 e7 97-a8 1d 01 7b 6d 2c 29 da   4..U.......{m,).
00f0 - 37 7a 4b 9f 94 05 02 b0-7c ba 58 6e 1a 7c ec d8   7zK.....|.Xn.|..
0100 - ed 8d 02 07 48 84 9a d8-89 41 d0 5b 69 ed 8f 87   ....H....A.[i...
0110 - d5 a8 fc 5f aa 88 59 a5-87 c7 6a c4 f3 37 7c c7   ..._..Y...j..7|.
0120 - 15 45 8c 3e 98 e7 b6 32-d0 0d 5e b8 81 c5 af 80   .E.>...2..^.....
0130 - d1 a9 e3 46 a4 7b 19 73-9a 41 8b 17 3b 84 42 3e   ...F.{.s.A..;.B>
0140 - 5b b0 7b 1a 8f 06 83 85-05 68 35 d9 4d 58 1a 80   [.{......h5.MX..
0150 - ee 69 8f a8 6c a9 0d aa-0d 33 e9 fb ea 6a 5c 99   .i..l....3...j\.
0160 - 2d ee 27 36 a4 a8 ee 2d-44 6f 2a 78 b9 13 ce e7   -.'6...-Do*x....
0170 - e6 c2 92 8b 1b 65 7e 18-10 42 f1 4f 9e 5f 65 61   .....e~..B.O._ea
0180 - 38 15 3f bb 6b ad a9 b6-46 4d 84 b4 82 4b 50 c7   8.?.k...FM...KP.
0190 - a6 46 b2 93 db 17 1f 80-d2 38 a1 3a 79 00 75 54   .F.......8.:y.uT
01a0 - 1e d2 6e ae 0c f2 fe b9-18 f4 d1 67 b8 4f c9 2d   ..n........g.O.-
01b0 - d2 6e 47 4e e6 a9 77 b2-d9 df 85 31 19 56 d4 6d   .nGN..w....1.V.m
01c0 - 87 73 db a8 8a 4b 53 df-64 a6 7d 35 e4 36 95 42   .s...KS.d.}5.6.B
01d0 - 0a a4 be 42 b0 cb d9 48-23 83 f1 00 7a f6 dc c5   ...B...H#...z...
01e0 - 3c b5 d1 bc e3 ae 25 9f-f0 ec 6f 93 e8 4e 9b 78   <.....%...o..N.x
01f0 - 87 72 27 fa 91 c5 83 9a-23 cd d3 62 99 08 00 7f   .r'.....#..b....
0200 - 28 43 52 65 75 22 95 5a-a1 96 23 4c 63 d6 80 5f   (CReu".Z..#Lc.._
0210 - 93 81 90 4b ab 25 03 c3-ca 67 f9 27 b1 ac 1d bc   ...K.%...g.'....
0220 - 46 d5 bb 7a 22 57 81 42-f8 32 28 8b 99 13 53 56   F..z"W.B.2(...SV
0230 - e4 6c 80 18 75 49 ce 4f-0a 6c 23 d9 19 4e b0 e9   .l..uI.O.l#..N..
0240 - fd bc 3c 90 26 c0 17 db-8f 33 eb 81 18 df fa cb   ..<.&....3......
0250 - 60 83 1a 4d 57 38 f5 1a-f8 8a f3 65 d5 d8 0c 49   `..MW8.....e...I
0260 - 6a b3 7b 20 bc 69 eb e2-87 64 aa de cb 6d 76 72   j.{ .i...d...mvr
0270 - 48 3d 29 96 51 a2 41 60-b7 a4 ad 67 7b ff bf 57   H=).Q.A`...g{..W
0280 - e2 64 c8 82 fa 28 ce cf-69 aa 1d b2 12 3a 23 6a   .d...(..i....:#j
0290 - 60 41 66 b6 94 69 5d 27-0b f1 90 1a 15 a9 ba 45   `Af..i]'.......E
02a0 - 9a aa 7e 01 94 10 85 fe-e0 60 01 ba 6e 31 7e fc   ..~......`..n1~.
02b0 - 53 be b8 b8 9d 0d a1 2d-38 87 98 91 de a7 29 fc   S......-8.....).
02c0 - e4 0d 1e 0a d2 67 8e 4c-9a fa 03 35 d8 ea 35 d6   .....g.L...5..5.
02d0 - b8 e5 fa 71 c1 b9 51 38-f1 cb 02 e9 54 61 f4 3e   ...q..Q8....Ta.>
02e0 - 0d 3d 4a 03 42 6e e3 8e-00 aa 76 e6 9c 3a dd 7d   .=J.Bn....v..:.}
02f0 - ad 07 05 30 0e 76 6c ca-2e 5a 20 dc f5 79 7d df   ...0.vl..Z ..y}.
0300 - 9b 45 a5 f9 08 ef b1 b3-39 9f 77 34 c1 b8 83 47   .E......9.w4...G
0310 - 7b bc 97 6f fd 36 e8 c4-b1 9d 7b d7 8e fc 5d 45   {..o.6....{...]E
0320 - 01 81 08 c2 c3 ef 38 57-f3 cc f1 54 b2 34 08 69   ......8W...T.4.i
0330 - 12 a5 1e 63 e4 33 7f 4d-2e a4 07 54 95 55 63 01   ...c.3.M...T.Uc.
0340 - 81 9b a0 92 19 8b 03 8b-da fa dd ce 13 93 e4 3f   ...............?
0350 - c1 ce 5e f2 88 63 0e ca-42 23 06 e0 1a 48 66 9b   ..^..c..B#...Hf.
0360 - 20 4c c5 0a 22 83 dc b9-7d d6 1f dc 3b 06 ac 3f    L.."...}...;..?
0370 - ed 90 fa 68 e5 6e 8c f9-dc d9 d8 e3 19 3e 2d 63   ...h.n.......>-c
0380 - 13 e2 27 59 fc c5 84 c7-72 a0 c4 04 a2 4d e0 35   ..'Y....r....M.5
0390 - a4 5e 0a dc 7d 7f 02 54-5f a0 d9 72 93 44 30 5f   .^..}..T_..r.D0_
03a0 - 1e 31 80 d9 f4 1c 5e 85-58 70 79 84 46 22 c9 4a   .1....^.Xpy.F".J
03b0 - 8f e8 cc dd d3 6e 64 6a-4e 51 fb fe b8 a7 6b 96   .....ndjNQ....k.
03c0 - d8 b2 9e 1e 8c 76 4c 38-1e 93 03 44 04 13 70 bc   .....vL8...D..p.
03d0 - 3a 30 ae 4b c0 7a fa f3-94 0c d6 57 43 7d de 21   :0.K.z.....WC}.!
03e0 - 46 04 e8 bf 3c b8 87 b7-1e 4d 31 7f de 04 ae 1e   F...<....M1.....
03f0 - 47 2e 5f 2b 16 4c 1c 23-ff 3e a1 40 06 68 60 bb   G._+.L.#.>.@.h`.
0400 - 55 df 6b 92 02 17 17 fd-4d e3 f9 d1 60 a8 b0 6e   U.k.....M...`..n
0410 - 35 01 66 8e 32 b4 99 6a-16 86 52 8f d2 7c 7e bf   5.f.2..j..R..|~.
0420 - f5 23 88 3f 33 6d bb 3b-80 a0 82 21 a7 ba 3b b1   .#.?3m.;...!..;.
0430 - cd c6 7f e8 ac 35 76 b9-51 43 ad 1d ce 84 c6 55   .....5v.QC.....U
0440 - a5 92 27 45 7f 99 fd 85-06 e1 81 fb 38 bb f5 a8   ..'E........8...
0450 - ff bd c2 15 3f 2a ef c2-6a df e1 e6 d7 b4 02 36   ....?*..j......6
0460 - 00 57 4d 96 6b e4 e4 46-27 db b3 6a ee f8 0f 11   .WM.k..F'..j....
0470 - 90 4d ff 1c a5 34 ca b2-4d 0e fa 70 86 79 af 76   .M...4..M..p.y.v
0480 - c0 23 21 14 ff 7f 3e 5c-6d ca d0 13 dd d3 08 70   .#!...>\m......p
0490 - 61 a6 f2 04 de 81 e0 95-e5 0c 23 87 6e d6 bc d6   a.........#.n...
04a0 - 67 6c 54 d9 65 55 06 4e-a7 90 e4 38 f4 98 1a b7   glT.eU.N...8....
04b0 - fe be fc 6c 74 f3 75 bb-25 c6 95 3b c8 4a 24 14   ...lt.u.%..;.J$.
04c0 - 03 03 00 01 01 17 03 03-00 17 5d 57 a7 0a fb 56   ..........]W...V
04d0 - 0c 84 7b 47 2e 31 c1 a2-77 3e dc c7 54 e7 3e 81   ..{G.1..w>..T.>.
04e0 - 80 17 03 03 02 2a 7c 7b-bc d7 71 24 0e de f6 33   .....*|{..q$...3
04f0 - 1d 7e 32 be 81 c6 a8 8c-58 80 87 ee 6d fa da ce   .~2.....X...m...
0500 - ff 97 bd 0b 3f 0c fd 1e-ba 1a d1 4d 72 62 dd a2   ....?......Mrb..
0510 - 05 a5 d9 e6 e7 d6 bb b7-04 8c 79 b4 b5 64 66 ef   ..........y..df.
0520 - a5 e2 c0 0c e2 80 af e3-a3 f3 c6 f3 64 c1 61 46   ............d.aF
0530 - c7 a0 b3 01 ed 39 72 2d-52 b7 0a 9d 66 0e 2e 4b   .....9r-R...f..K
0540 - f0 dd 37 98 42 6c d1 18-8f ce d7 eb 9c 63 11 c5   ..7.Bl.......c..
0550 - 91 fb 72 d5 8d 6e 90 c1-a8 32 a2 f0 a6 88 da 33   ..r..n...2.....3
0560 - d0 89 61 b5 5c bb cb ea-b8 c3 32 ec 24 26 9c 88   ..a.\.....2.$&..
0570 - 16 c1 56 d5 37 a7 00 89-24 15 57 b8 de 8e 47 07   ..V.7...$.W...G.
0580 - 92 aa 14 63 63 fa 3b c1-cc c8 9c f7 e7 7a 90 3a   ...cc.;......z.:
0590 - d6 97 29 43 8c 6d c4 d4-7e 26 18 ce c1 22 36 63   ..)C.m..~&..."6c
05a0 - 39 65 cc f4 1e 3e 82 8d-56 bd 3e c0 71 74 f8 67   9e...>..V.>.qt.g
05b0 - 08 9f bd b3 ce 9e 9a dd-e1 6e 71 b6 b2 09 60 84   .........nq...`.
05c0 - ad 76 38 58 e2 c0 b9 f9-95 97 be 1d 94 1c c5 7d   .v8X...........}
05d0 - 62 bd 83 7d eb bc f7 69-5a fc 1a 40 cc f5 62 b9   b..}...iZ..@..b.
05e0 - 17 af f7 f2 42 ad c1 d2-e2 92 fc 36 87 04 a8 1c   ....B......6....
05f0 - bf 31 d8 c1 19 b9 f4 19-a6 bc 17 03 d0 11 9c b3   .1..............
0600 - 9e d6 1e 5e 43 d4 e0 31-dd c5 ce a0 1a c3 18 a0   ...^C..1........
0610 - d4 8e 95 88 d2 c8 8f a6-0b cc ba a4 f8 a1 eb 80   ................
0620 - b6 5c d5 5a c7 2e 14 e3-ae 10 bd 64 b9 71 4b de   .\.Z.......d.qK.
0630 - 44 6b eb 5c e4 f0 1c dd-44 ff b6 55 08 f1 8c 75   Dk.\....D..U...u
0640 - 06 30 8d 43 ac 9b e4 88-a4 0f 9c 1d ec 8e d8 a2   .0.C............
0650 - c0 83 24 5e 23 c4 fc 71-2a 64 6a cc 20 b4 c3 80   ..$^#..q*dj. ...
0660 - b1 7e ef 94 85 7a 17 a0-d0 d2 77 c6 4c dc 32 94   .~...z....w.L.2.
0670 - cc 3d ad 2b b7 87 da db-1e b2 96 8e 29 0f 28 26   .=.+........).(&
0680 - 70 8c 8d ed e1 1a 8a 0d-1b 56 88 15 81 89 10 51   p........V.....Q
0690 - 09 8d d3 b6 a7 4b 33 af-4d bc 64 27 46 4b df 4e   .....K3.M.d'FK.N
06a0 - b9 98 5e 2f e9 01 42 9e-88 8e 5d 2c fd 40 73 b6   ..^/..B...],.@s.
06b0 - 7c 62 56 90 7b 22 9a aa-ed 57 7d 1f 69 14 db 90   |bV.{"...W}.i...
06c0 - a1 16 83 9d a0 32 08 1e-ab 82 86 d6 ea 38 47 b7   .....2.......8G.
06d0 - 16 f0 26 02 e8 5d 67 a9-a6 7e 1e 8f 18 2d 84 66   ..&..]g..~...-.f
06e0 - 50 b9 1d 3f 79 ca ed 87-c8 9b b1 26 8e 16 3f 3b   P..?y......&..?;
06f0 - d4 18 ef 5e e2 8f 88 d6-cd e3 4a c4 40 d2 75 3f   ...^......J.@.u?
0700 - 53 72 52 4b 33 26 a3 b2-12 3e 2a f2 8c ba db 75   SrRK3&...>*....u
0710 - 17 03 03 00 61 30 c4 a6-11 d0 99 20 9b 03 ac 43   ....a0..... ...C
0720 - 70 83 f0 b4 47 ee 42 29-f0 68 1b a3 85 1c 9c eb   p...G.B).h......
0730 - 0d 45 30 40 84 3d e0 3d-29 ec 7a 17 8c d7 ca 36   .E0@.=.=).z....6
0740 - 01 b7 4a 7d 62 a0 1d 1d-4a 15 9f c7 a5 7d 83 fd   ..J}b...J....}..
0750 - 04 5b af e6 b3 f0 fc 9c-8a 6e ef e0 d2 e4 9b 78   .[.......n.....x
0760 - 68 6a 13 b6 77 46 e0 1c-5e 04 fe a9 bc 7b f6 d9   hj..wF..^....{..
0770 - 1d c3 e2 bf 00 13 17 03-03 00 35 4a 3a 81 27 eb   ..........5J:.'.
0780 - 38 c2 16 f1 e1 57 f9 08-d9 e0 cf 69 1a de 82 aa   8....W.....i....
0790 - f8 0c fb 0c cc 9f 29 f4-cd 71 ca 19 b3 55 4a 45   ......)..q...UJE
07a0 - 29 c5 fa 3f bb 76 74 e6-2f 77 56 39 00 2d 44 71   )..?.vt./wV9.-Dq
SSL_accept:SSLv3/TLS write finished
SSL_accept:TLSv1.3 early data
read from 0x264d548a8e0 [0x264d7063503] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x264d548a8e0 [0x264d7063508] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x264d548a8e0 [0x264d7063503] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
read from 0x264d548a8e0 [0x264d7063508] (53 bytes => 53 (0x35))
0000 - 65 3a 69 66 09 c4 8c 76-9f 92 89 08 a6 79 b9 2d   e:if...v.....y.-
0010 - f1 5f 26 e4 49 2c 0f 07-48 ae ca 78 3d a8 da f0   ._&.I,..H..x=...
0020 - e0 64 cf 8b 63 2f db 88-39 75 73 c1 c6 37 87 2f   .d..c/..9us..7./
0030 - c3 a3 51 c3 2a                                    ..Q.*
SSL_accept:TLSv1.3 early data
SSL_accept:SSLv3/TLS read finished
write to 0x264d548a8e0 [0x264d70624f0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea ed 4f 7c-43 4a 0c a2 ca ea d1 6d   ......O|CJ.....m
0010 - 8c fb b7 27 a7 06 90 f6-69 69 ee 4f 50 a0 7c 60   ...'....ii.OP.|`
0020 - da a9 c3 2c e9 34 6f b3-20 d0 4a 9e 67 79 87 40   ...,.4o. .J.gy.@
0030 - 3a 86 39 f0 85 99 2c a0-5a 86 47 dc b4 7c bb fc   :.9...,.Z.G..|..
0040 - 04 91 b4 06 1c 9a 94 7a-34 0a 81 66 4d 9d 95 d7   .......z4..fM...
0050 - 75 76 33 39 81 4e 83 89-80 b9 de cb cc a3 88 83   uv39.N..........
0060 - 67 8e 9f 60 c0 31 40 7a-d1 69 40 01 5b 8a 48 7d   g..`.1@z.i@.[.H}
0070 - c2 70 7b d3 cf 13 62 c2-3f 89 5a de a2 2b ab 4b   .p{...b.?.Z..+.K
0080 - f6 6d 33 6b 5f 9f ff 8c-f3 76 73 10 cc af 08 ea   .m3k_....vs.....
0090 - f3 f2 71 44 61 43 f5 d2-cf 6f 22 67 90 e3 1d b7   ..qDaC...o"g....
00a0 - e1 0e 7a e4 94 b7 be 70-6e 33 6b a3 40 e3 7d 2a   ..z....pn3k.@.}*
00b0 - 37 8d 6d 75 6f ae 9c ca-c7 c1 35 b1 3a d2 6e 25   7.muo.....5.:.n%
00c0 - 74 9b 06 85 a4 bd f2 72-03 ab 62 56 07 b4 6c 5f   t......r..bV..l_
00d0 - 6d e4 a2 66 41 a3 1e bc-b1 9f 37 38 01 02 ee ec   m..fA.....78....
00e0 - ca c7 00 0a 0f 55 5d e2-65 97 f8 7b c0 c9 e2      .....U].e..{...
SSL_accept:SSLv3/TLS write session ticket
write to 0x264d548a8e0 [0x264d70624f0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea 5f 5d 14-7a 18 f4 67 f8 6f 54 54   ....._].z..g.oTT
0010 - 7d 1b 00 a7 85 7c 25 1c-ef 8f 74 bd 60 e3 db f3   }....|%...t.`...
0020 - fe c2 8b d0 f3 c0 b8 b0-5f d9 5e f9 0d da 3c 2a   ........_.^...<*
0030 - 70 86 e7 87 75 91 60 bd-94 64 bf 49 b2 68 75 0f   p...u.`..d.I.hu.
0040 - d6 f4 27 9c 44 7b b1 7a-bc 84 f7 6b 7e 1d 55 c6   ..'.D{.z...k~.U.
0050 - e5 07 f3 9e a4 ff d4 5a-35 bb aa d4 e0 e0 e4 cd   .......Z5.......
0060 - 66 e9 5d c1 a6 03 73 c3-16 51 88 35 e9 7c ff 73   f.]...s..Q.5.|.s
0070 - 1b 82 72 f1 69 f0 2e d3-b0 b6 fa 70 5c 97 3e 36   ..r.i......p\.>6
0080 - 77 d4 5c 51 90 c5 b7 71-39 f4 22 00 dd c7 2b ca   w.\Q...q9."...+.
0090 - cd e9 08 14 67 27 f7 4a-ee bf 93 73 d0 90 3e 58   ....g'.J...s..>X
00a0 - 23 30 03 a6 73 16 88 f7-1c a9 e4 64 13 5a 26 84   #0..s......d.Z&.
00b0 - 10 cf b9 52 df 41 f1 eb-f9 28 0e bb 5f 52 c8 24   ...R.A...(.._R.$
00c0 - c5 c9 e4 f4 68 68 9b a9-fd ec 05 cb 48 78 d4 00   ....hh......Hx..
00d0 - c2 6a 9a d1 be b8 cd 6b-22 c4 48 68 7b 7d 7a de   .j.....k".Hh{}z.
00e0 - 63 bd bf 11 0f 59 33 92-10 b2 c0 5c 84 79 9b      c....Y3....\.y.
SSL_accept:SSLv3/TLS write session ticket
-----BEGIN SSL SESSION PARAMETERS-----
MHQCAQECAgMEBAITBAQg7J7/5b9jnK60k2hJxw5SAN+tH66NfRbFJDoe51T/bQgE
IE8c20Auc6MBVOtHNzi/yQX36ZdUdeTC6c3yuwgytM7XoQYCBGjqLACiBAICHCCk
BgQEAQAAAK4HAgUAl5F7G7MEAgIR7A==
-----END SSL SESSION PARAMETERS-----
Shared ciphers:TLS_AES_128_CCM_SHA256
Signature Algorithms: id-ml-dsa-65:id-ml-dsa-87:id-ml-dsa-44:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:ed448:ecdsa_brainpoolP256r1_sha256:ecdsa_brainpoolP384r1_sha384:ecdsa_brainpoolP512r1_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Shared Signature Algorithms: id-ml-dsa-65:id-ml-dsa-87:id-ml-dsa-44:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:ed448:ecdsa_brainpoolP256r1_sha256:ecdsa_brainpoolP384r1_sha384:ecdsa_brainpoolP512r1_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Supported groups: X25519MLKEM768
Shared groups: X25519MLKEM768
CIPHER is TLS_AES_128_CCM_SHA256
This TLS version forbids renegotiation.
read from 0x264d548a8e0 [0x264d7072ab3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x264d548a8e0 [0x264d7072ab8] (23 bytes => 23 (0x17))
0000 - 01 a7 f4 b3 6f 25 fe 82-a1 c6 8c a5 d7 a9 de f7   ....o%..........
0010 - 0c 82 28 6c e9 c2 d4                              ..(l...
test
read from 0x264d548a8e0 [0x264d7072ab3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 13                                    .....
read from 0x264d548a8e0 [0x264d7072ab8] (19 bytes => 19 (0x13))
0000 - f9 d1 d1 2e fa 3a 03 9a-0c 25 a6 0b f1 fb fc 1a   .....:...%......
0010 - 3c ab 7d                                          <.}
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x264d548a8e0 [0x264d7063503] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 14 15 ba-cc cc 38 85 63 b8 e6 c2   ..........8.c...
0010 - f8 f8 2f 8b ca e2 d9 9a-                          ../.....
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
