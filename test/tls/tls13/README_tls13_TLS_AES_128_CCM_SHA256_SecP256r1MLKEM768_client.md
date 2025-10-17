#### client

````
$ openssl s_client -connect localhost:9000 -state -debug -keylogfile sslkeylog -tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256 -groups SecP256r1MLKEM768
Connecting to ::1
CONNECTED(0000017C)
SSL_connect:before SSL initialization
write to 0x27953e97b10 [0x27954282b60] (1429 bytes => 1429 (0x595))
0000 - 16 03 01 05 90 01 00 05-8c 03 03 a7 71 77 2c d5   ............qw,.
0010 - 02 4b 8b db eb ed 45 7a-e2 b6 48 df 0e 7a 27 fb   .K....Ez..H..z'.
0020 - 10 c0 a1 39 f2 5d 54 be-8e 36 f7 20 50 48 d7 e3   ...9.]T..6. PH..
0030 - b0 03 b7 0c 1b ae 6e f8-c2 b0 15 65 cc c2 6c ac   ......n....e..l.
0040 - fb 33 67 8a 16 53 dd a3-d8 36 cf 7d 00 02 13 04   .3g..S...6.}....
0050 - 01 00 05 41 00 0a 00 04-00 02 11 eb 00 23 00 00   ...A.........#..
0060 - 00 16 00 00 00 17 00 00-00 0d 00 2a 00 28 09 05   ...........*.(..
0070 - 09 06 09 04 04 03 05 03-06 03 08 07 08 08 08 1a   ................
0080 - 08 1b 08 1c 08 09 08 0a-08 0b 08 04 08 05 08 06   ................
0090 - 04 01 05 01 06 01 00 2b-00 03 02 03 04 00 2d 00   .......+......-.
00a0 - 02 01 01 00 33 04 e7 04-e5 11 eb 04 e1 04 b8 b9   ....3...........
00b0 - c3 1e 54 c1 f3 03 f0 5c-f0 a2 72 74 ad ae c2 18   ..T....\..rt....
00c0 - 47 04 64 dd bf 18 cd b2-a7 90 9a 04 da a6 59 ff   G.d...........Y.
00d0 - 9e 8d e6 0c d6 e1 16 6f-b3 f9 7b 21 83 21 85 2b   .......o..{!.!.+
00e0 - 5f 19 79 f1 be f2 f3 28-82 2a 3e 1e 0f 02 e1 57   _.y....(.*>....W
00f0 - 6f 1a f1 0a 71 07 27 4f-a1 66 3c f5 81 5c d5 8d   o...q.'O.f<..\..
0100 - f1 6a 7d 13 19 a7 49 36-42 aa 55 c4 5e eb ba 2b   .j}...I6B.U.^..+
0110 - e7 97 dc 71 b7 d0 7c 13-3e a7 98 d8 53 9d 71 b5   ...q..|.>...S.q.
0120 - a9 d6 54 3c b8 52 5f 95-01 2c 31 12 60 f1 22 90   ..T<.R_..,1.`.".
0130 - d4 f3 74 8f a8 33 33 f6-1b 96 a8 81 5e 06 42 6a   ..t..33.....^.Bj
0140 - 52 cc e6 a0 c4 21 06 39-79 03 55 ee b6 1c ed da   R....!.9y.U.....
0150 - 6b 11 eb 42 1e eb 34 28-0a c7 6f 21 b1 c2 63 ad   k..B..4(..o!..c.
0160 - 00 a2 07 69 e7 6b 8f 0c-17 f3 71 46 f1 38 51 48   ...i.k....qF.8QH
0170 - e7 95 5e 00 7a 74 00 59-97 c4 9f 6c 61 9e 38 60   ..^.zt.Y...la.8`
0180 - 45 10 28 60 bd 23 cf 48-f8 1f 4f 87 99 9c 61 81   E.(`.#.H..O...a.
0190 - 81 c5 47 41 da 22 18 62-40 75 d1 b1 f8 41 87 c0   ..GA.".b@u...A..
01a0 - 38 90 b5 99 89 17 35 3c-d3 a9 9f 52 c6 7a 14 33   8.....5<...R.z.3
01b0 - 1d b5 d9 6e 4e 61 8e 84-74 94 18 44 5d e6 46 00   ...nNa..t..D].F.
01c0 - 2d 00 34 a7 cc 18 37 3a-6e 58 a1 b0 0f 33 00 f2   -.4...7:nX...3..
01d0 - c4 5f f5 d3 b6 06 0b a2-6f c3 9d e5 b5 91 46 0c   ._......o.....F.
01e0 - ad 70 e6 a2 35 09 b3 6b-77 4a 70 86 bc e6 e2 c9   .p..5..kwJp.....
01f0 - 60 07 3f ba 51 28 43 d5-7f 60 96 2f eb 59 af dd   `.?.Q(C..`./.Y..
0200 - 01 96 30 58 12 e0 47 b3-7d 47 90 95 d2 c5 9f 40   ..0X..G.}G.....@
0210 - 12 41 60 02 71 f0 37 52-e2 00 ac e7 0d d0 6c 72   .A`.q.7R......lr
0220 - 8b 53 8d 9c 1a 41 fa f4-27 5e 9a cf 67 a9 19 48   .S...A..'^..g..H
0230 - 8b 7e 92 79 c9 5a a0 16-fa c2 8e b4 66 c8 cf 96   .~.y.Z......f...
0240 - cc 3a c9 c5 25 a0 8a 1e-80 b3 47 e4 42 45 86 a7   .:..%.....G.BE..
0250 - 30 3c 75 53 83 c9 3d 70-2b b0 c3 23 df e0 c0 93   0<uS..=p+..#....
0260 - b2 9e b9 40 c4 68 09 6a-21 80 77 43 27 93 36 a8   ...@.h.j!.wC'.6.
0270 - 9b a3 da 20 ca d9 90 1c-e8 8a d2 06 45 29 0a b3   ... ........E)..
0280 - 80 0a 04 d5 4a be 73 aa-93 25 55 3c 92 8a 69 f9   ....J.s..%U<..i.
0290 - ba 35 a5 fb 74 49 96 3c-c8 82 74 b7 4a 03 9e 3b   .5..tI.<..t.J..;
02a0 - c6 a8 e0 a7 96 bb b4 15-21 5c 3c 93 c1 b4 96 65   ........!\<....e
02b0 - ec 11 72 17 a1 7c d9 b5-bf 8f e3 47 4a a3 54 eb   ..r..|.....GJ.T.
02c0 - 5c a1 fc 07 61 19 06 a6-b6 0a 5d 0b 83 39 e4 3c   \...a.....]..9.<
02d0 - 85 89 c5 95 e2 2b b8 d3-20 99 4c d0 a7 49 51 0e   .....+.. .L..IQ.
02e0 - 43 67 9a f9 88 35 f5 5a-60 8a c6 c7 fa cc cc 7c   Cg...5.Z`......|
02f0 - 46 bb 90 57 c0 f8 83 18-52 53 12 a8 bc 41 50 a3   F..W....RS...AP.
0300 - 23 ca 18 7c ef 2c 18 48-cc ba 65 91 95 be 66 b7   #..|.,.H..e...f.
0310 - e0 97 4b b8 45 36 7f 84-82 46 86 23 05 59 5b e1   ..K.E6...F.#.Y[.
0320 - cb 68 ea 32 52 ae 0a 50-d8 66 a6 1c 42 c5 c6 4c   .h.2R..P.f..B..L
0330 - b4 e5 d9 0a 67 35 7c c7-d4 6f dc f1 8b df 1b 83   ....g5|..o......
0340 - a7 17 b4 45 07 8e 11 98-18 9b c5 a3 ad 0b 45 15   ...E..........E.
0350 - a3 4d c2 26 36 bd 0b 67-4c 52 1c ec 31 03 07 32   .M.&6..gLR..1..2
0360 - ba 73 56 55 78 35 06 f2-a0 1f 43 48 97 dc 76 88   .sVUx5....CH..v.
0370 - 66 0b b5 60 c0 40 5d 41-7c 5f 59 44 d9 25 91 15   f..`.@]A|_YD.%..
0380 - e3 3c ab 60 47 60 b0 71-99 c1 01 29 64 17 a2 a3   .<.`G`.q...)d...
0390 - 52 3c ac 78 33 64 06 cc-c2 83 bc 78 c4 a7 6b 76   R<.x3d.....x..kv
03a0 - 5a b2 c7 2f a2 00 4c a8-b7 eb 52 59 dd 90 ac 49   Z../..L...RY...I
03b0 - 53 3d 40 77 9d b7 d4 08-c2 63 a1 4e 7c 8c 04 27   S=@w.....c.N|..'
03c0 - 91 98 08 41 65 50 6d 57-c9 c1 47 29 c8 7a 72 87   ...AePmW..G).zr.
03d0 - af d1 85 28 a8 c6 1f 37-30 fa 9c 0c 04 40 a6 09   ...(...70....@..
03e0 - 7c 89 df bc 27 55 16 09-5a 67 c1 60 6b 33 cf fa   |...'U..Zg.`k3..
03f0 - 30 9c 03 3d dd e2 23 7c-52 1a 88 b3 61 97 2a 1e   0..=..#|R...a.*.
0400 - d7 64 6b 96 93 68 9b 44-62 7f 14 7e 45 3b 14 60   .dk..h.Db..~E;.`
0410 - a1 a5 c4 44 53 2b eb 79-82 a2 74 b3 19 56 37 2a   ...DS+.y..t..V7*
0420 - 17 5e 26 73 1c c4 bd 82-d5 0f d3 b4 2a 6c 93 47   .^&s........*l.G
0430 - 15 36 85 75 39 6c 7a 9a-7d a8 99 55 39 96 1f f7   .6.u9lz.}..U9...
0440 - 5c cd f8 22 be b4 75 0a-19 d0 35 9d 50 2e bc 61   \.."..u...5.P..a
0450 - 9e c0 b1 94 26 74 a3 f2-80 8e 3e 52 50 9b 50 61   ....&t....>RP.Pa
0460 - 7f c2 6b a0 c6 c6 5c dc-4d ff 68 1d 59 09 87 85   ..k...\.M.h.Y...
0470 - c6 71 6a 63 2f 1a 50 77-fa 04 56 bd 08 69 78 72   .qjc/.Pw..V..ixr
0480 - 54 04 39 7c 52 dc 85 63-19 a7 61 95 51 ba 26 83   T.9|R..c..a.Q.&.
0490 - e8 14 59 ce 84 6d e0 12-14 07 d4 9d 39 23 a2 ff   ..Y..m......9#..
04a0 - bb 0c dd e4 3b cc 54 2f-bb 57 0e e5 c8 57 91 00   ....;.T/.W...W..
04b0 - 70 3e f2 5d 12 c7 bf 14-81 2d b0 f7 bf da 71 60   p>.].....-....q`
04c0 - c4 cc 19 b1 01 5b 15 19-81 c1 01 40 80 78 65 ef   .....[.....@.xe.
04d0 - 3b 6a d6 cc 11 a0 da 80-ea d5 b3 f0 4c c1 06 e6   ;j..........L...
04e0 - 42 48 88 07 f4 e2 ba 3e-67 39 79 83 c7 f3 d8 8e   BH.....>g9y.....
04f0 - 54 c5 1d da 94 66 81 c5-a4 7f 13 ad d8 8b 2f 3a   T....f......../:
0500 - 22 43 bd 36 02 c7 67 49-11 f9 cd da 88 a6 39 b7   "C.6..gI......9.
0510 - 9d a6 5a 19 14 84 a2 18-7b 46 b0 7a 7b ae 8c 1c   ..Z.....{F.z{...
0520 - b7 e7 6a c4 3c 38 bb 42-03 8b f9 80 96 7a ab 54   ..j.<8.B.....z.T
0530 - 91 8c 4d 8b 08 92 a5 58-8a 36 10 16 1c 2d ec 81   ..M....X.6...-..
0540 - 2b 18 d9 aa f2 b9 71 ee-d8 9c a5 70 be b4 38 7c   +.....q....p..8|
0550 - d1 28 31 f7 82 1f e8 cc-94 a4 62 a9 bf f1 39 2a   .(1.......b...9*
0560 - 67 8c 2a d3 33 85 04 b9-a3 38 92 94 5c 15 61 d3   g.*.3....8..\.a.
0570 - f1 aa 38 7f a2 70 26 46-54 dc 3c fe 6b ac 8c 49   ..8..p&FT.<.k..I
0580 - b0 16 fa 23 36 98 9a f2-83 92 1f a8 9b a8 00 1b   ...#6...........
0590 - 00 03 02 00 01                                    .....
SSL_connect:SSLv3/TLS write client hello
read from 0x27953e97b10 [0x2795428a203] (5 bytes => 5 (0x5))
0000 - 16 03 03 04 db                                    .....
read from 0x27953e97b10 [0x2795428a208] (1243 bytes => 1243 (0x4DB))
0000 - 02 00 04 d7 03 03 47 10-8d e4 b4 b7 87 5b fc 41   ......G......[.A
0010 - cd 22 3c 5a 1e 58 cd f5-41 78 c6 4d 9b a5 42 f9   ."<Z.X..Ax.M..B.
0020 - c7 78 c0 13 ea 86 20 50-48 d7 e3 b0 03 b7 0c 1b   .x.... PH.......
0030 - ae 6e f8 c2 b0 15 65 cc-c2 6c ac fb 33 67 8a 16   .n....e..l..3g..
0040 - 53 dd a3 d8 36 cf 7d 13-04 00 04 8f 00 2b 00 02   S...6.}......+..
0050 - 03 04 00 33 04 85 11 eb-04 81 04 3e b9 21 32 62   ...3.......>.!2b
0060 - fc fc 80 d4 63 a6 9c f2-1c 6d 6e 7c 2a 68 b4 35   ....c....mn|*h.5
0070 - cc 6d c1 b0 40 81 a6 9e-c2 bc 2e 7f f1 3b c3 e9   .m..@........;..
0080 - 9c 89 df 8b e2 61 14 6a-dc 3d 73 87 3b 08 fc ea   .....a.j.=s.;...
0090 - 16 ee b4 22 3b ac 66 62-37 6a 2d ed ec 78 a0 19   ...";.fb7j-..x..
00a0 - 11 b3 d8 9e 90 f3 28 12-0f 37 0a 53 91 c1 6c b8   ......(..7.S..l.
00b0 - e1 99 57 cb 5d b9 50 03-6b 1d 0e 30 98 1c a6 4f   ..W.].P.k..0...O
00c0 - 0d c5 02 46 87 45 d1 86-d8 5f 73 ae 33 79 53 48   ...F.E..._s.3ySH
00d0 - 9e 96 8e 20 5e e7 37 72-e9 e6 40 95 e0 a6 0b e0   ... ^.7r..@.....
00e0 - 61 c9 6a ae d9 59 0c d6-ce ab a8 b4 bd 7b f3 f7   a.j..Y.......{..
00f0 - ef 62 44 d8 89 93 b0 11-6f cf 41 0e d2 37 12 8a   .bD.....o.A..7..
0100 - 48 c3 72 aa 3c 9b 88 0e-e8 9a bf 59 ea 52 ea 12   H.r.<......Y.R..
0110 - 08 db ed 41 25 d2 ff 50-b8 86 af 71 e7 57 24 2e   ...A%..P...q.W$.
0120 - 60 d9 df 47 f9 8c e9 12-bf ef 3b 66 39 c4 0f 19   `..G......;f9...
0130 - d7 d8 2a 59 55 8f 59 70-ec 94 e5 84 ef 7b 83 20   ..*YU.Yp.....{.
0140 - a9 3e 7b dc a4 ad fb 75-36 04 30 56 b4 81 e1 cf   .>{....u6.0V....
0150 - 6d 6b 81 55 65 97 f7 73-c2 1c 5f 91 a2 18 bf ac   mk.Ue..s.._.....
0160 - ff 48 d3 31 9b 46 93 7c-a3 e6 6a 89 52 f8 6c f7   .H.1.F.|..j.R.l.
0170 - f7 dd 78 fd 7a 73 f7 ea-26 6a bd 73 a5 0d 07 72   ..x.zs..&j.s...r
0180 - 62 8a fe ac c0 8a 8a 2e-91 9c b5 6a 11 b9 83 70   b..........j...p
0190 - 04 4d c3 8c 91 67 d8 91-21 82 35 2d 91 cc 2a e5   .M...g..!.5-..*.
01a0 - 7f 21 c3 b8 69 c7 e9 a7-d0 cb c5 4b 87 68 0b a0   .!..i......K.h..
01b0 - 5d 53 48 f7 5d dc b7 56-a0 f1 97 e5 6b 49 ba 64   ]SH.]..V....kI.d
01c0 - 86 09 8d 20 ac a9 68 b7-4f 4e 38 c5 eb cb 9c 8a   ... ..h.ON8.....
01d0 - 4a d4 79 69 d7 23 58 b7-88 53 9c c1 73 b3 1a 0f   J.yi.#X..S..s...
01e0 - b9 b7 5e f6 9c 8e b8 0a-c5 db c3 16 fe ca ee 94   ..^.............
01f0 - 7f 37 8b 62 c6 a7 33 08-93 49 d0 43 5f 67 1f 18   .7.b..3..I.C_g..
0200 - 39 6a a7 e1 5f 1e a7 05-62 b8 77 a7 53 91 ee fb   9j.._...b.w.S...
0210 - 10 21 a8 45 fd 06 12 3a-8c 59 0c df 5b 5a b3 cc   .!.E...:.Y..[Z..
0220 - b9 8c 22 67 b1 6f 82 0c-e3 ed 0c ee 21 9d dc 60   .."g.o......!..`
0230 - bf 69 1a 6b dd f1 51 c1-53 71 5c b3 0b c6 43 cf   .i.k..Q.Sq\...C.
0240 - dd 50 16 23 21 5b 52 d3-b0 f5 0f 16 f3 b0 18 f8   .P.#![R.........
0250 - 07 31 f4 d3 72 bf e3 96-ee 6c f7 be ae e6 ce 30   .1..r....l.....0
0260 - e9 99 3e 67 2c 83 87 0e-90 52 ae 57 f7 c2 61 f8   ..>g,....R.W..a.
0270 - 4b 42 8b 3a af 58 e9 f7-7f 2b 01 11 9c 0f 03 64   KB.:.X...+.....d
0280 - 7c 1b e9 2c d2 63 d2 76-d5 74 5d eb a5 16 d5 53   |..,.c.v.t]....S
0290 - cf c5 c7 f5 99 b7 a9 60-e4 6b e2 bf 10 98 51 ac   .......`.k....Q.
02a0 - 6e 33 8e 56 be f3 29 6b-c1 a9 46 cc c5 29 ec 7e   n3.V..)k..F..).~
02b0 - 9c 38 45 4e ac 41 d9 b9-e4 56 19 07 8e 31 46 14   .8EN.A...V...1F.
02c0 - 6d 05 99 67 90 3c 60 2d-0c d5 dc a0 4c 42 66 2e   m..g.<`-....LBf.
02d0 - fe af 6c c5 c8 b9 62 aa-93 84 ce 55 6d 1a 0d f8   ..l...b....Um...
02e0 - eb f3 55 4e ae c1 d3 31-a3 19 5a 86 34 99 08 b8   ..UN...1..Z.4...
02f0 - aa 40 9e 90 d7 04 86 56-ba 82 82 37 8c c0 e0 20   .@.....V...7...
0300 - 26 9e a2 87 b2 a2 67 91-00 45 eb b2 00 2d a2 80   &.....g..E...-..
0310 - 29 d3 d0 a7 90 0d f1 70-aa 87 71 e9 c4 64 80 d8   )......p..q..d..
0320 - bb bd 93 d5 2f 76 de 1d-89 be c5 36 53 96 f9 b1   ..../v.....6S...
0330 - 74 94 eb 47 3a b5 16 44-e1 e3 ed eb 5f 16 11 7a   t..G:..D...._..z
0340 - c6 51 8e 8c 66 43 1f e4-3c 53 55 f8 a4 11 bd b5   .Q..fC..<SU.....
0350 - d1 73 07 7f 67 5d 16 b6-b2 f7 2a 92 07 bc ab 3e   .s..g]....*....>
0360 - 0d 5b 77 29 9b f4 d7 1f-ef 9f 5b 9c 84 4a 97 2e   .[w)......[..J..
0370 - d3 42 82 72 4c 2c 68 af-ae 04 c6 79 92 93 d6 8d   .B.rL,h....y....
0380 - b4 3e 31 be 8f 50 98 b5-09 f6 df 54 96 5b 89 9e   .>1..P.....T.[..
0390 - 44 09 b6 bd 72 ca 33 44-e4 c1 2b 68 c0 f5 3c 30   D...r.3D..+h..<0
03a0 - ec d2 2c 25 b2 01 fb 14-69 ba c1 b8 56 7c 84 ae   ..,%....i...V|..
03b0 - 76 b6 2a 50 72 3a 6f d9-9d 24 03 1b 8e 21 65 fc   v.*Pr:o..$...!e.
03c0 - 4d 49 14 9a bd 7f 2c 0d-5b 96 d1 fe 4c 97 49 11   MI....,.[...L.I.
03d0 - 07 68 de 7d 4f 8d 1e cd-ce bf 8f cf 4e a1 cb 44   .h.}O.......N..D
03e0 - 9f 8e ef b2 96 00 f3 88-f8 d1 49 08 9b 60 7c fb   ..........I..`|.
03f0 - 17 71 77 80 ab a0 e9 54-69 24 7f 6f 1a 91 c0 06   .qw....Ti$.o....
0400 - 25 a4 22 a4 e6 01 d4 de-73 18 0e 52 be 49 e0 b9   %.".....s..R.I..
0410 - 7d a2 be 63 d5 84 20 21-96 57 14 40 43 5c dc 0e   }..c.. !.W.@C\..
0420 - dd 02 d0 c6 ba 8b fe 1b-73 ad b4 73 10 c7 76 00   ........s..s..v.
0430 - 50 e9 9a e3 92 8a 8c 5e-a9 ec d8 f0 c1 79 2a 20   P......^.....y*
0440 - 60 72 ef 7a b0 6e 7f 73-ef 9e 96 f0 fe 8d d9 00   `r.z.n.s........
0450 - eb 49 36 27 54 ab fe 9a-57 9f 28 b7 e0 cb 8a 9b   .I6'T...W.(.....
0460 - 15 90 1e c5 fb a1 b3 b8-41 65 63 d9 4a 21 86 65   ........Aec.J!.e
0470 - f2 26 b7 97 ba 0e f0 ab-4b 97 2c 7d be 56 4e 96   .&......K.,}.VN.
0480 - a5 91 69 fa c0 c9 f2 2c-0e 3c 44 23 df 24 36 ac   ..i....,.<D#.$6.
0490 - 9e c6 c8 68 ec 91 61 80-80 52 46 34 10 28 bc 9e   ...h..a..RF4.(..
04a0 - 5d 14 7e 3e 65 56 bb 22-ae c6 38 fb 88 d0 4b b6   ].~>eV."..8...K.
04b0 - 24 5f 92 54 27 7d db c6-0a 94 af 2d 97 88 ec 1d   $_.T'}.....-....
04c0 - 5c 22 8d af 99 5b bf 85-93 8f 3d 48 53 98 fe 39   \"...[....=HS..9
04d0 - 4e 5e 5a a7 84 56 29 60-e7 35 99                  N^Z..V)`.5.
SSL_connect:SSLv3/TLS write client hello
read from 0x27953e97b10 [0x27954289a83] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x27953e97b10 [0x27954289a88] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x27953e97b10 [0x27954289a83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x27953e97b10 [0x27954289a88] (23 bytes => 23 (0x17))
0000 - aa ca 6d bb 24 83 f0 87-ac f0 e9 43 6e 83 fe f3   ..m.$......Cn...
0010 - f0 f1 c9 d8 7e b3 e9                              ....~..
SSL_connect:SSLv3/TLS read server hello
Can't use SSL_get_servername
read from 0x27953e97b10 [0x27954289a83] (5 bytes => 5 (0x5))
0000 - 17 03 03 02 2a                                    ....*
read from 0x27953e97b10 [0x27954289a88] (554 bytes => 554 (0x22A))
0000 - ab f6 2c 10 8b aa d9 86-58 de 79 ba 14 9d a8 6c   ..,.....X.y....l
0010 - af 5b 6b c8 4e a3 9c 39-d2 74 1c f2 46 76 77 6e   .[k.N..9.t..Fvwn
0020 - 84 0e 14 81 b0 f4 c2 ce-2d e4 34 fd 19 d8 3d 61   ........-.4...=a
0030 - f5 59 30 6d 12 63 c4 2e-46 08 90 8c e5 31 c0 74   .Y0m.c..F....1.t
0040 - b8 78 4e 3b 51 54 3b 53-63 54 dd d5 34 c9 0d f9   .xN;QT;ScT..4...
0050 - 2f fa 1d 25 34 e7 ac 6a-aa 1c 6c 41 13 3c 0c ac   /..%4..j..lA.<..
0060 - 78 e4 e2 a7 8c bd 00 af-3d 46 01 74 5b f3 a4 37   x.......=F.t[..7
0070 - 76 af c5 73 af c0 17 8f-eb 51 9f 12 32 73 74 58   v..s.....Q..2stX
0080 - be 8a be 97 96 7a 47 ed-f7 6e 9a 5a ac 2e 12 fb   .....zG..n.Z....
0090 - 67 5f 4c ef f8 0f 88 b6-71 06 be be 5b 9b f7 29   g_L.....q...[..)
00a0 - 2c b1 52 ea 2f aa c8 a1-29 68 82 49 ad 8d 11 bf   ,.R./...)h.I....
00b0 - f7 18 5b 25 5c 86 c5 b7-83 33 6f a5 23 4e cb fc   ..[%\....3o.#N..
00c0 - d3 91 85 fb fc 75 31 19-83 da a9 59 75 c7 11 ac   .....u1....Yu...
00d0 - a6 48 1f bc 49 48 60 33-7c bc 08 d2 f1 43 bc 1b   .H..IH`3|....C..
00e0 - bc 1c a4 45 7b 51 6d c3-29 ae f4 10 52 94 d6 f1   ...E{Qm.)...R...
00f0 - ea 00 33 5c 03 55 2a be-c0 e8 f5 00 48 c3 35 ca   ..3\.U*.....H.5.
0100 - b8 2e e1 ed 41 8e 35 62-a3 10 23 a1 d5 8f df af   ....A.5b..#.....
0110 - f1 7e 1e 6e c4 9d 16 e5-3c 7c 56 60 4b 1f 41 97   .~.n....<|V`K.A.
0120 - 5c ec 11 74 6e dd 52 bc-35 25 90 a4 f0 f4 36 9c   \..tn.R.5%....6.
0130 - b2 7b 89 07 d3 8e 6f 9d-2f ce b9 82 d2 55 f3 cf   .{....o./....U..
0140 - 16 17 c9 9b 7e 90 90 bc-08 45 32 2f 89 74 94 f9   ....~....E2/.t..
0150 - 44 c7 fc 95 5f bb f9 79-2a 3e 5e e5 4f bc 2a 5b   D..._..y*>^.O.*[
0160 - 10 15 00 48 9b 94 16 d1-cd 9c 7a 85 f8 50 44 5f   ...H......z..PD_
0170 - f8 2f 8b 7f 45 4f d2 d6-32 c7 fd ba a1 20 e6 86   ./..EO..2.... ..
0180 - 9c b8 c5 5b 94 31 fa a1-2d 89 fc 68 1b 52 97 ff   ...[.1..-..h.R..
0190 - f8 fc 9d 0d c8 5e c4 44-a6 7a 6f f0 b2 a8 7f 18   .....^.D.zo.....
01a0 - 0c 5a 93 3b bd 1b 3f a9-ae 54 ec 0f 4c 76 80 e8   .Z.;..?..T..Lv..
01b0 - f4 db 33 b4 40 01 57 d3-2d 53 04 f9 72 53 d9 50   ..3.@.W.-S..rS.P
01c0 - 33 8b d8 d9 f5 6c de e8-2a ed b8 94 17 e6 28 bc   3....l..*.....(.
01d0 - ff a4 11 e1 2a ea 09 3f-3f 59 22 4c 09 f8 16 fa   ....*..??Y"L....
01e0 - 2d 2f 38 57 2d 00 89 46-f4 2a 30 9f 01 f2 3d 12   -/8W-..F.*0...=.
01f0 - e4 c6 ba 86 d0 96 12 14-4f ae fd cc bc b3 0b cf   ........O.......
0200 - 13 a5 24 9b 92 8e 85 84-83 e9 4e e3 fe 2b 0a 13   ..$.......N..+..
0210 - ec ec 59 f0 5e 71 a6 c6-79 fc b7 1f 92 a6 63 fd   ..Y.^q..y.....c.
0220 - be 7f 0e a9 2a 98 2c 63-24 2a                     ....*.,c$*
SSL_connect:TLSv1.3 read encrypted extensions
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
verify error:num=18:self-signed certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
verify return:1
read from 0x27953e97b10 [0x27954289a83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 60                                    ....`
read from 0x27953e97b10 [0x27954289a88] (96 bytes => 96 (0x60))
0000 - a5 b2 88 69 e1 35 66 ea-c7 87 66 16 21 8b ab 98   ...i.5f...f.!...
0010 - 2f dc 7d 0a f7 67 56 78-1c b8 9a 5b 53 be 9d 4f   /.}..gVx...[S..O
0020 - fd 42 7b 25 88 ad 14 3a-f5 f4 c8 a1 57 dc 76 18   .B{%...:....W.v.
0030 - 05 3d f8 ec cf d1 99 09-d9 e5 16 9e a7 7f e9 c5   .=..............
0040 - 85 6d 1c 6b ef 01 bb 8c-09 0b 9d c7 fa 94 9f b1   .m.k............
0050 - 3e 50 8e 3b 76 88 78 c4-fe 22 2f 68 56 2b c0 95   >P.;v.x.."/hV+..
SSL_connect:SSLv3/TLS read server certificate
read from 0x27953e97b10 [0x27954289a83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
read from 0x27953e97b10 [0x27954289a88] (53 bytes => 53 (0x35))
0000 - 7a 58 7d a6 6f 88 92 3c-82 2e f7 0c 98 b0 92 5b   zX}.o..<.......[
0010 - d9 61 30 21 31 e9 9a 13-9e 51 66 39 50 9a 70 cc   .a0!1....Qf9P.p.
0020 - 20 56 bc f9 ea d3 92 af-b7 e6 72 6f 69 5a 27 b5    V........roiZ'.
0030 - 3d 54 4d e5 4d                                    =TM.M
SSL_connect:TLSv1.3 read server certificate verify
SSL_connect:SSLv3/TLS read finished
SSL_connect:SSLv3/TLS write change cipher spec
write to 0x27953e97b10 [0x27954282b60] (64 bytes => 64 (0x40))
0000 - 14 03 03 00 01 01 17 03-03 00 35 01 cc d9 d2 8c   ..........5.....
0010 - c2 f6 8c 04 99 a9 23 72-07 00 31 2b 88 fc fa 40   ......#r..1+...@
0020 - 67 4f c2 db de 58 20 19-e8 5a 72 d7 b2 c3 c7 2a   gO...X ..Zr....*
0030 - 86 f1 52 a1 cf c3 66 50-ce 6e 0b d7 fe fd 71 ab   ..R...fP.n....q.
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
Negotiated TLS1.3 group: SecP256r1MLKEM768
---
SSL handshake has read 2000 bytes and written 1493 bytes
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
read from 0x27953e97b10 [0x2795427c5f3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
read from 0x27953e97b10 [0x2795427c5f8] (234 bytes => 234 (0xEA))
0000 - c9 d4 99 1f b8 84 8b d0-5b 37 2f fc 96 33 20 18   ........[7/..3 .
0010 - 14 3c f5 0e b2 e5 28 f3-d1 9b 48 bc 5c e5 f2 74   .<....(...H.\..t
0020 - b1 2b e2 14 f0 dd a5 46-d7 3c 40 6a c9 cd 73 d0   .+.....F.<@j..s.
0030 - b1 ea e5 b9 67 80 1a 66-68 ac a9 db 12 60 76 0c   ....g..fh....`v.
0040 - 43 db 6d 57 d4 83 5e ca-98 4b 21 61 2f 17 e9 6f   C.mW..^..K!a/..o
0050 - 1b d0 a4 e0 16 bd a8 6f-61 24 ad 29 ee e0 58 91   .......oa$.)..X.
0060 - 59 9e bf da 2a 53 1f e5-79 18 b4 4c 04 45 a9 94   Y...*S..y..L.E..
0070 - b7 29 a9 b1 88 5d 2f 26-60 6f 70 f3 16 1f 44 f3   .)...]/&`op...D.
0080 - d8 de 0d a6 c8 43 9c 6f-db 09 a9 31 68 aa c9 24   .....C.o...1h..$
0090 - 8b ed a1 77 fc f1 91 f0-1e 9e df 83 97 01 21 d1   ...w..........!.
00a0 - a3 5b a2 fa c6 06 19 8f-71 3b 22 09 fc 55 f7 64   .[......q;"..U.d
00b0 - a2 8f ef 61 63 79 b3 2c-3c 11 d4 83 82 6e 8d b9   ...acy.,<....n..
00c0 - 77 ff 3c 5c 1a db 30 b2-2e a5 88 d4 af c1 5f d4   w.<\..0......._.
00d0 - 79 29 84 d8 18 ff 14 af-aa a3 92 74 8c d5 c8 d7   y).........t....
00e0 - fd 6b 33 7b fa af a6 d6-34 22                     .k3{....4"
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_CCM_SHA256
    Session-ID: CAB7FC3D453B59058C53DB98451C8D50EE6F7A8E00027F3FB8ABB4C3D9FDA02C
    Session-ID-ctx:
    Resumption PSK: 1991EC4E45224FD4C08DD79B6D58059D341863D9408DFE331FEDEF74FBBE1BC2
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 9a 1c 2d 72 21 52 6e 90-91 41 55 fb 8b 09 41 6f   ..-r!Rn..AU...Ao
    0010 - e3 ae 0a bb 9b 14 4d 2f-80 74 d5 81 58 86 7c e7   ......M/.t..X.|.
    0020 - 6b a3 1f 67 f3 70 00 a8-a7 d0 10 11 81 2d a5 9a   k..g.p.......-..
    0030 - 3b 85 6b b5 59 5a 8c cb-6b 59 ed e9 b3 96 1f be   ;.k.YZ..kY......
    0040 - 30 fe 92 97 6f 8b 57 d8-6b 89 a5 c5 ed 84 e4 a8   0...o.W.k.......
    0050 - 3b 1d ef 8a 33 25 94 2e-3c 70 1a 7a 59 f4 e9 c7   ;...3%..<p.zY...
    0060 - ed 7e 5b 3d 20 78 4d dd-d9 20 e7 22 62 17 07 29   .~[= xM.. ."b..)
    0070 - ca b7 0b e0 f0 86 2c 23-53 f0 5d f9 89 d6 65 97   ......,#S.]...e.
    0080 - e9 9a 5d 95 df 29 05 ff-6f 8b 52 6e 23 8c 43 56   ..]..)..o.Rn#.CV
    0090 - 58 a1 bc 42 0c c9 bb c0-e4 a4 19 90 ed 80 dd 24   X..B...........$
    00a0 - a4 e8 54 52 07 25 a1 cc-49 ec f0 44 07 74 b3 19   ..TR.%..I..D.t..
    00b0 - 77 d9 92 30 ee b6 87 4b-16 26 96 7e c9 13 d5 06   w..0...K.&.~....

    Start Time: 1760176174
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
read from 0x27953e97b10 [0x2795427c5f3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
read from 0x27953e97b10 [0x2795427c5f8] (234 bytes => 234 (0xEA))
0000 - 1f ef 74 1a 08 29 79 2d-8f 02 81 e9 de 48 77 0c   ..t..)y-.....Hw.
0010 - ef 3e d0 df 14 e2 35 79-6f 35 4b f5 34 21 12 54   .>....5yo5K.4!.T
0020 - ec 92 b7 d8 f3 0f 5c 3c-90 84 67 d6 9b 5d 8b cb   ......\<..g..]..
0030 - d2 54 97 b3 3f e2 14 b4-60 21 5f 42 a4 b7 41 98   .T..?...`!_B..A.
0040 - 0a 0c ac bb 8a 43 d9 69-fe d9 13 d8 49 96 3e 5d   .....C.i....I.>]
0050 - 53 17 0e 01 b5 76 2a ad-1b a1 c7 20 8a 48 a4 1d   S....v*.... .H..
0060 - 91 f4 f9 a1 4b d5 ba e7-2b 38 d7 d7 fd 9d d1 4b   ....K...+8.....K
0070 - 45 d7 72 6c ee 4d 0a 73-ed 7d 88 5f 07 35 f5 db   E.rl.M.s.}._.5..
0080 - 8b d8 2d 91 47 46 6b cc-d5 b0 82 49 27 95 90 13   ..-.GFk....I'...
0090 - cc 22 40 49 96 4a 1d da-55 37 8f 14 20 29 8e cb   ."@I.J..U7.. )..
00a0 - 4a d1 5e 77 cc 5d 18 b9-aa 5c af 50 0b 43 a1 5e   J.^w.]...\.P.C.^
00b0 - 6d a8 ff a9 23 2e 2d 7c-f4 73 aa 17 a0 f8 a0 db   m...#.-|.s......
00c0 - ce 58 ff b4 74 fc 1d de-92 41 e9 eb 63 9d 5e 39   .X..t....A..c.^9
00d0 - 44 39 7f a8 4f cf 79 f6-78 2b 2c 12 27 f1 dc 0f   D9..O.y.x+,.'...
00e0 - 21 1d 6b 1c 95 d3 72 c6-00 75                     !.k...r..u
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_CCM_SHA256
    Session-ID: C098312A157708DBA12929EBB97FA8F5E1D4C04A8C8A3C5B04985FE062668C5F
    Session-ID-ctx:
    Resumption PSK: 7103FC6C17A010E4A1F7C349120B6B1C0397F829E8C271D2370EE209A0FB5244
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 9a 1c 2d 72 21 52 6e 90-91 41 55 fb 8b 09 41 6f   ..-r!Rn..AU...Ao
    0010 - 47 2b 40 87 a9 7b f7 cb-f7 9c ca de 7f 6c a0 70   G+@..{.......l.p
    0020 - d4 44 fd c9 6f 65 1f 93-29 f4 12 d4 23 60 5a 98   .D..oe..)...#`Z.
    0030 - d0 f2 c0 9d 8b 49 70 97-b4 8f ac d5 a8 18 26 52   .....Ip.......&R
    0040 - 25 6c 79 57 32 80 ee 70-a4 4d d6 74 16 0f 37 6c   %lyW2..p.M.t..7l
    0050 - 1a df ab d9 68 a1 50 43-f5 87 0d 4f 25 cc 89 f2   ....h.PC...O%...
    0060 - 21 41 9b dc 61 57 11 66-08 f1 0b 73 72 20 69 02   !A..aW.f...sr i.
    0070 - 94 4a 8e 0c 15 fb a2 16-55 15 40 02 2c da f4 f2   .J......U.@.,...
    0080 - 4e 61 3b 33 30 a9 7b 88-99 83 78 28 32 d6 47 4c   Na;30.{...x(2.GL
    0090 - 16 d6 9c 4d 66 ea 9b 9a-4b 86 4b bd 83 c3 56 4b   ...Mf...K.K...VK
    00a0 - aa 82 76 af 81 04 d8 8a-14 aa 9c f8 d6 5d 5c ae   ..v..........]\.
    00b0 - ba 1c f3 aa f7 c1 98 d4-d5 c0 df 2b 63 b7 09 9a   ...........+c...

    Start Time: 1760176174
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
test
write to 0x27953e97b10 [0x279542859c3] (28 bytes => 28 (0x1C))
0000 - 17 03 03 00 17 a3 89 af-38 26 9d ad 64 de fa f8   ........8&..d...
0010 - a0 9f 38 85 d1 53 9a 02-fd 42 c8 ee               ..8..S...B..
Q
DONE
write to 0x27953e97b10 [0x279542859c3] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 c2 96 a3-e2 8f 94 e9 90 e6 3d 10   ..............=.
0010 - 81 81 01 39 47 e7 d5 2a-                          ...9G..*
SSL3 alert write:warning:close notify
read from 0x27953e97b10 [0x27953dbffa0] (16384 bytes => 24 (0x18))
0000 - 17 03 03 00 13 d0 81 05-50 38 01 7e 38 ed 10 b3   ........P8.~8...
0010 - 34 c5 72 38 64 7f 34 4a-                          4.r8d.4J
read from 0x27953e97b10 [0x27953dbffa0] (16384 bytes => 0)
````

[TOC](README.md)
