#### server

````
$ openssl s_server -accept 9000 -cert ecdsa.crt -key ecdsa.key -state -debug -status_verbose -keylogfile sslkeylog -tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256 -groups SecP256r1MLKEM768
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x16b828ba730 [0x16b844a3503] (5 bytes => 5 (0x5))
0000 - 16 03 01 05 90                                    .....
read from 0x16b828ba730 [0x16b844a3508] (1424 bytes => 1424 (0x590))
0000 - 01 00 05 8c 03 03 a7 71-77 2c d5 02 4b 8b db eb   .......qw,..K...
0010 - ed 45 7a e2 b6 48 df 0e-7a 27 fb 10 c0 a1 39 f2   .Ez..H..z'....9.
0020 - 5d 54 be 8e 36 f7 20 50-48 d7 e3 b0 03 b7 0c 1b   ]T..6. PH.......
0030 - ae 6e f8 c2 b0 15 65 cc-c2 6c ac fb 33 67 8a 16   .n....e..l..3g..
0040 - 53 dd a3 d8 36 cf 7d 00-02 13 04 01 00 05 41 00   S...6.}.......A.
0050 - 0a 00 04 00 02 11 eb 00-23 00 00 00 16 00 00 00   ........#.......
0060 - 17 00 00 00 0d 00 2a 00-28 09 05 09 06 09 04 04   ......*.(.......
0070 - 03 05 03 06 03 08 07 08-08 08 1a 08 1b 08 1c 08   ................
0080 - 09 08 0a 08 0b 08 04 08-05 08 06 04 01 05 01 06   ................
0090 - 01 00 2b 00 03 02 03 04-00 2d 00 02 01 01 00 33   ..+......-.....3
00a0 - 04 e7 04 e5 11 eb 04 e1-04 b8 b9 c3 1e 54 c1 f3   .............T..
00b0 - 03 f0 5c f0 a2 72 74 ad-ae c2 18 47 04 64 dd bf   ..\..rt....G.d..
00c0 - 18 cd b2 a7 90 9a 04 da-a6 59 ff 9e 8d e6 0c d6   .........Y......
00d0 - e1 16 6f b3 f9 7b 21 83-21 85 2b 5f 19 79 f1 be   ..o..{!.!.+_.y..
00e0 - f2 f3 28 82 2a 3e 1e 0f-02 e1 57 6f 1a f1 0a 71   ..(.*>....Wo...q
00f0 - 07 27 4f a1 66 3c f5 81-5c d5 8d f1 6a 7d 13 19   .'O.f<..\...j}..
0100 - a7 49 36 42 aa 55 c4 5e-eb ba 2b e7 97 dc 71 b7   .I6B.U.^..+...q.
0110 - d0 7c 13 3e a7 98 d8 53-9d 71 b5 a9 d6 54 3c b8   .|.>...S.q...T<.
0120 - 52 5f 95 01 2c 31 12 60-f1 22 90 d4 f3 74 8f a8   R_..,1.`."...t..
0130 - 33 33 f6 1b 96 a8 81 5e-06 42 6a 52 cc e6 a0 c4   33.....^.BjR....
0140 - 21 06 39 79 03 55 ee b6-1c ed da 6b 11 eb 42 1e   !.9y.U.....k..B.
0150 - eb 34 28 0a c7 6f 21 b1-c2 63 ad 00 a2 07 69 e7   .4(..o!..c....i.
0160 - 6b 8f 0c 17 f3 71 46 f1-38 51 48 e7 95 5e 00 7a   k....qF.8QH..^.z
0170 - 74 00 59 97 c4 9f 6c 61-9e 38 60 45 10 28 60 bd   t.Y...la.8`E.(`.
0180 - 23 cf 48 f8 1f 4f 87 99-9c 61 81 81 c5 47 41 da   #.H..O...a...GA.
0190 - 22 18 62 40 75 d1 b1 f8-41 87 c0 38 90 b5 99 89   ".b@u...A..8....
01a0 - 17 35 3c d3 a9 9f 52 c6-7a 14 33 1d b5 d9 6e 4e   .5<...R.z.3...nN
01b0 - 61 8e 84 74 94 18 44 5d-e6 46 00 2d 00 34 a7 cc   a..t..D].F.-.4..
01c0 - 18 37 3a 6e 58 a1 b0 0f-33 00 f2 c4 5f f5 d3 b6   .7:nX...3..._...
01d0 - 06 0b a2 6f c3 9d e5 b5-91 46 0c ad 70 e6 a2 35   ...o.....F..p..5
01e0 - 09 b3 6b 77 4a 70 86 bc-e6 e2 c9 60 07 3f ba 51   ..kwJp.....`.?.Q
01f0 - 28 43 d5 7f 60 96 2f eb-59 af dd 01 96 30 58 12   (C..`./.Y....0X.
0200 - e0 47 b3 7d 47 90 95 d2-c5 9f 40 12 41 60 02 71   .G.}G.....@.A`.q
0210 - f0 37 52 e2 00 ac e7 0d-d0 6c 72 8b 53 8d 9c 1a   .7R......lr.S...
0220 - 41 fa f4 27 5e 9a cf 67-a9 19 48 8b 7e 92 79 c9   A..'^..g..H.~.y.
0230 - 5a a0 16 fa c2 8e b4 66-c8 cf 96 cc 3a c9 c5 25   Z......f....:..%
0240 - a0 8a 1e 80 b3 47 e4 42-45 86 a7 30 3c 75 53 83   .....G.BE..0<uS.
0250 - c9 3d 70 2b b0 c3 23 df-e0 c0 93 b2 9e b9 40 c4   .=p+..#.......@.
0260 - 68 09 6a 21 80 77 43 27-93 36 a8 9b a3 da 20 ca   h.j!.wC'.6.... .
0270 - d9 90 1c e8 8a d2 06 45-29 0a b3 80 0a 04 d5 4a   .......E)......J
0280 - be 73 aa 93 25 55 3c 92-8a 69 f9 ba 35 a5 fb 74   .s..%U<..i..5..t
0290 - 49 96 3c c8 82 74 b7 4a-03 9e 3b c6 a8 e0 a7 96   I.<..t.J..;.....
02a0 - bb b4 15 21 5c 3c 93 c1-b4 96 65 ec 11 72 17 a1   ...!\<....e..r..
02b0 - 7c d9 b5 bf 8f e3 47 4a-a3 54 eb 5c a1 fc 07 61   |.....GJ.T.\...a
02c0 - 19 06 a6 b6 0a 5d 0b 83-39 e4 3c 85 89 c5 95 e2   .....]..9.<.....
02d0 - 2b b8 d3 20 99 4c d0 a7-49 51 0e 43 67 9a f9 88   +.. .L..IQ.Cg...
02e0 - 35 f5 5a 60 8a c6 c7 fa-cc cc 7c 46 bb 90 57 c0   5.Z`......|F..W.
02f0 - f8 83 18 52 53 12 a8 bc-41 50 a3 23 ca 18 7c ef   ...RS...AP.#..|.
0300 - 2c 18 48 cc ba 65 91 95-be 66 b7 e0 97 4b b8 45   ,.H..e...f...K.E
0310 - 36 7f 84 82 46 86 23 05-59 5b e1 cb 68 ea 32 52   6...F.#.Y[..h.2R
0320 - ae 0a 50 d8 66 a6 1c 42-c5 c6 4c b4 e5 d9 0a 67   ..P.f..B..L....g
0330 - 35 7c c7 d4 6f dc f1 8b-df 1b 83 a7 17 b4 45 07   5|..o.........E.
0340 - 8e 11 98 18 9b c5 a3 ad-0b 45 15 a3 4d c2 26 36   .........E..M.&6
0350 - bd 0b 67 4c 52 1c ec 31-03 07 32 ba 73 56 55 78   ..gLR..1..2.sVUx
0360 - 35 06 f2 a0 1f 43 48 97-dc 76 88 66 0b b5 60 c0   5....CH..v.f..`.
0370 - 40 5d 41 7c 5f 59 44 d9-25 91 15 e3 3c ab 60 47   @]A|_YD.%...<.`G
0380 - 60 b0 71 99 c1 01 29 64-17 a2 a3 52 3c ac 78 33   `.q...)d...R<.x3
0390 - 64 06 cc c2 83 bc 78 c4-a7 6b 76 5a b2 c7 2f a2   d.....x..kvZ../.
03a0 - 00 4c a8 b7 eb 52 59 dd-90 ac 49 53 3d 40 77 9d   .L...RY...IS=@w.
03b0 - b7 d4 08 c2 63 a1 4e 7c-8c 04 27 91 98 08 41 65   ....c.N|..'...Ae
03c0 - 50 6d 57 c9 c1 47 29 c8-7a 72 87 af d1 85 28 a8   PmW..G).zr....(.
03d0 - c6 1f 37 30 fa 9c 0c 04-40 a6 09 7c 89 df bc 27   ..70....@..|...'
03e0 - 55 16 09 5a 67 c1 60 6b-33 cf fa 30 9c 03 3d dd   U..Zg.`k3..0..=.
03f0 - e2 23 7c 52 1a 88 b3 61-97 2a 1e d7 64 6b 96 93   .#|R...a.*..dk..
0400 - 68 9b 44 62 7f 14 7e 45-3b 14 60 a1 a5 c4 44 53   h.Db..~E;.`...DS
0410 - 2b eb 79 82 a2 74 b3 19-56 37 2a 17 5e 26 73 1c   +.y..t..V7*.^&s.
0420 - c4 bd 82 d5 0f d3 b4 2a-6c 93 47 15 36 85 75 39   .......*l.G.6.u9
0430 - 6c 7a 9a 7d a8 99 55 39-96 1f f7 5c cd f8 22 be   lz.}..U9...\..".
0440 - b4 75 0a 19 d0 35 9d 50-2e bc 61 9e c0 b1 94 26   .u...5.P..a....&
0450 - 74 a3 f2 80 8e 3e 52 50-9b 50 61 7f c2 6b a0 c6   t....>RP.Pa..k..
0460 - c6 5c dc 4d ff 68 1d 59-09 87 85 c6 71 6a 63 2f   .\.M.h.Y....qjc/
0470 - 1a 50 77 fa 04 56 bd 08-69 78 72 54 04 39 7c 52   .Pw..V..ixrT.9|R
0480 - dc 85 63 19 a7 61 95 51-ba 26 83 e8 14 59 ce 84   ..c..a.Q.&...Y..
0490 - 6d e0 12 14 07 d4 9d 39-23 a2 ff bb 0c dd e4 3b   m......9#......;
04a0 - cc 54 2f bb 57 0e e5 c8-57 91 00 70 3e f2 5d 12   .T/.W...W..p>.].
04b0 - c7 bf 14 81 2d b0 f7 bf-da 71 60 c4 cc 19 b1 01   ....-....q`.....
04c0 - 5b 15 19 81 c1 01 40 80-78 65 ef 3b 6a d6 cc 11   [.....@.xe.;j...
04d0 - a0 da 80 ea d5 b3 f0 4c-c1 06 e6 42 48 88 07 f4   .......L...BH...
04e0 - e2 ba 3e 67 39 79 83 c7-f3 d8 8e 54 c5 1d da 94   ..>g9y.....T....
04f0 - 66 81 c5 a4 7f 13 ad d8-8b 2f 3a 22 43 bd 36 02   f......../:"C.6.
0500 - c7 67 49 11 f9 cd da 88-a6 39 b7 9d a6 5a 19 14   .gI......9...Z..
0510 - 84 a2 18 7b 46 b0 7a 7b-ae 8c 1c b7 e7 6a c4 3c   ...{F.z{.....j.<
0520 - 38 bb 42 03 8b f9 80 96-7a ab 54 91 8c 4d 8b 08   8.B.....z.T..M..
0530 - 92 a5 58 8a 36 10 16 1c-2d ec 81 2b 18 d9 aa f2   ..X.6...-..+....
0540 - b9 71 ee d8 9c a5 70 be-b4 38 7c d1 28 31 f7 82   .q....p..8|.(1..
0550 - 1f e8 cc 94 a4 62 a9 bf-f1 39 2a 67 8c 2a d3 33   .....b...9*g.*.3
0560 - 85 04 b9 a3 38 92 94 5c-15 61 d3 f1 aa 38 7f a2   ....8..\.a...8..
0570 - 70 26 46 54 dc 3c fe 6b-ac 8c 49 b0 16 fa 23 36   p&FT.<.k..I...#6
0580 - 98 9a f2 83 92 1f a8 9b-a8 00 1b 00 03 02 00 01   ................
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write change cipher spec
SSL_accept:TLSv1.3 write encrypted extensions
SSL_accept:SSLv3/TLS write certificate
SSL_accept:TLSv1.3 write server certificate verify
write to 0x16b828ba730 [0x16b844a24f0] (2000 bytes => 2000 (0x7D0))
0000 - 16 03 03 04 db 02 00 04-d7 03 03 47 10 8d e4 b4   ...........G....
0010 - b7 87 5b fc 41 cd 22 3c-5a 1e 58 cd f5 41 78 c6   ..[.A."<Z.X..Ax.
0020 - 4d 9b a5 42 f9 c7 78 c0-13 ea 86 20 50 48 d7 e3   M..B..x.... PH..
0030 - b0 03 b7 0c 1b ae 6e f8-c2 b0 15 65 cc c2 6c ac   ......n....e..l.
0040 - fb 33 67 8a 16 53 dd a3-d8 36 cf 7d 13 04 00 04   .3g..S...6.}....
0050 - 8f 00 2b 00 02 03 04 00-33 04 85 11 eb 04 81 04   ..+.....3.......
0060 - 3e b9 21 32 62 fc fc 80-d4 63 a6 9c f2 1c 6d 6e   >.!2b....c....mn
0070 - 7c 2a 68 b4 35 cc 6d c1-b0 40 81 a6 9e c2 bc 2e   |*h.5.m..@......
0080 - 7f f1 3b c3 e9 9c 89 df-8b e2 61 14 6a dc 3d 73   ..;.......a.j.=s
0090 - 87 3b 08 fc ea 16 ee b4-22 3b ac 66 62 37 6a 2d   .;......";.fb7j-
00a0 - ed ec 78 a0 19 11 b3 d8-9e 90 f3 28 12 0f 37 0a   ..x........(..7.
00b0 - 53 91 c1 6c b8 e1 99 57-cb 5d b9 50 03 6b 1d 0e   S..l...W.].P.k..
00c0 - 30 98 1c a6 4f 0d c5 02-46 87 45 d1 86 d8 5f 73   0...O...F.E..._s
00d0 - ae 33 79 53 48 9e 96 8e-20 5e e7 37 72 e9 e6 40   .3ySH... ^.7r..@
00e0 - 95 e0 a6 0b e0 61 c9 6a-ae d9 59 0c d6 ce ab a8   .....a.j..Y.....
00f0 - b4 bd 7b f3 f7 ef 62 44-d8 89 93 b0 11 6f cf 41   ..{...bD.....o.A
0100 - 0e d2 37 12 8a 48 c3 72-aa 3c 9b 88 0e e8 9a bf   ..7..H.r.<......
0110 - 59 ea 52 ea 12 08 db ed-41 25 d2 ff 50 b8 86 af   Y.R.....A%..P...
0120 - 71 e7 57 24 2e 60 d9 df-47 f9 8c e9 12 bf ef 3b   q.W$.`..G......;
0130 - 66 39 c4 0f 19 d7 d8 2a-59 55 8f 59 70 ec 94 e5   f9.....*YU.Yp...
0140 - 84 ef 7b 83 20 a9 3e 7b-dc a4 ad fb 75 36 04 30   ..{. .>{....u6.0
0150 - 56 b4 81 e1 cf 6d 6b 81-55 65 97 f7 73 c2 1c 5f   V....mk.Ue..s.._
0160 - 91 a2 18 bf ac ff 48 d3-31 9b 46 93 7c a3 e6 6a   ......H.1.F.|..j
0170 - 89 52 f8 6c f7 f7 dd 78-fd 7a 73 f7 ea 26 6a bd   .R.l...x.zs..&j.
0180 - 73 a5 0d 07 72 62 8a fe-ac c0 8a 8a 2e 91 9c b5   s...rb..........
0190 - 6a 11 b9 83 70 04 4d c3-8c 91 67 d8 91 21 82 35   j...p.M...g..!.5
01a0 - 2d 91 cc 2a e5 7f 21 c3-b8 69 c7 e9 a7 d0 cb c5   -..*..!..i......
01b0 - 4b 87 68 0b a0 5d 53 48-f7 5d dc b7 56 a0 f1 97   K.h..]SH.]..V...
01c0 - e5 6b 49 ba 64 86 09 8d-20 ac a9 68 b7 4f 4e 38   .kI.d... ..h.ON8
01d0 - c5 eb cb 9c 8a 4a d4 79-69 d7 23 58 b7 88 53 9c   .....J.yi.#X..S.
01e0 - c1 73 b3 1a 0f b9 b7 5e-f6 9c 8e b8 0a c5 db c3   .s.....^........
01f0 - 16 fe ca ee 94 7f 37 8b-62 c6 a7 33 08 93 49 d0   ......7.b..3..I.
0200 - 43 5f 67 1f 18 39 6a a7-e1 5f 1e a7 05 62 b8 77   C_g..9j.._...b.w
0210 - a7 53 91 ee fb 10 21 a8-45 fd 06 12 3a 8c 59 0c   .S....!.E...:.Y.
0220 - df 5b 5a b3 cc b9 8c 22-67 b1 6f 82 0c e3 ed 0c   .[Z...."g.o.....
0230 - ee 21 9d dc 60 bf 69 1a-6b dd f1 51 c1 53 71 5c   .!..`.i.k..Q.Sq\
0240 - b3 0b c6 43 cf dd 50 16-23 21 5b 52 d3 b0 f5 0f   ...C..P.#![R....
0250 - 16 f3 b0 18 f8 07 31 f4-d3 72 bf e3 96 ee 6c f7   ......1..r....l.
0260 - be ae e6 ce 30 e9 99 3e-67 2c 83 87 0e 90 52 ae   ....0..>g,....R.
0270 - 57 f7 c2 61 f8 4b 42 8b-3a af 58 e9 f7 7f 2b 01   W..a.KB.:.X...+.
0280 - 11 9c 0f 03 64 7c 1b e9-2c d2 63 d2 76 d5 74 5d   ....d|..,.c.v.t]
0290 - eb a5 16 d5 53 cf c5 c7-f5 99 b7 a9 60 e4 6b e2   ....S.......`.k.
02a0 - bf 10 98 51 ac 6e 33 8e-56 be f3 29 6b c1 a9 46   ...Q.n3.V..)k..F
02b0 - cc c5 29 ec 7e 9c 38 45-4e ac 41 d9 b9 e4 56 19   ..).~.8EN.A...V.
02c0 - 07 8e 31 46 14 6d 05 99-67 90 3c 60 2d 0c d5 dc   ..1F.m..g.<`-...
02d0 - a0 4c 42 66 2e fe af 6c-c5 c8 b9 62 aa 93 84 ce   .LBf...l...b....
02e0 - 55 6d 1a 0d f8 eb f3 55-4e ae c1 d3 31 a3 19 5a   Um.....UN...1..Z
02f0 - 86 34 99 08 b8 aa 40 9e-90 d7 04 86 56 ba 82 82   .4....@.....V...
0300 - 37 8c c0 e0 20 26 9e a2-87 b2 a2 67 91 00 45 eb   7... &.....g..E.
0310 - b2 00 2d a2 80 29 d3 d0-a7 90 0d f1 70 aa 87 71   ..-..)......p..q
0320 - e9 c4 64 80 d8 bb bd 93-d5 2f 76 de 1d 89 be c5   ..d....../v.....
0330 - 36 53 96 f9 b1 74 94 eb-47 3a b5 16 44 e1 e3 ed   6S...t..G:..D...
0340 - eb 5f 16 11 7a c6 51 8e-8c 66 43 1f e4 3c 53 55   ._..z.Q..fC..<SU
0350 - f8 a4 11 bd b5 d1 73 07-7f 67 5d 16 b6 b2 f7 2a   ......s..g]....*
0360 - 92 07 bc ab 3e 0d 5b 77-29 9b f4 d7 1f ef 9f 5b   ....>.[w)......[
0370 - 9c 84 4a 97 2e d3 42 82-72 4c 2c 68 af ae 04 c6   ..J...B.rL,h....
0380 - 79 92 93 d6 8d b4 3e 31-be 8f 50 98 b5 09 f6 df   y.....>1..P.....
0390 - 54 96 5b 89 9e 44 09 b6-bd 72 ca 33 44 e4 c1 2b   T.[..D...r.3D..+
03a0 - 68 c0 f5 3c 30 ec d2 2c-25 b2 01 fb 14 69 ba c1   h..<0..,%....i..
03b0 - b8 56 7c 84 ae 76 b6 2a-50 72 3a 6f d9 9d 24 03   .V|..v.*Pr:o..$.
03c0 - 1b 8e 21 65 fc 4d 49 14-9a bd 7f 2c 0d 5b 96 d1   ..!e.MI....,.[..
03d0 - fe 4c 97 49 11 07 68 de-7d 4f 8d 1e cd ce bf 8f   .L.I..h.}O......
03e0 - cf 4e a1 cb 44 9f 8e ef-b2 96 00 f3 88 f8 d1 49   .N..D..........I
03f0 - 08 9b 60 7c fb 17 71 77-80 ab a0 e9 54 69 24 7f   ..`|..qw....Ti$.
0400 - 6f 1a 91 c0 06 25 a4 22-a4 e6 01 d4 de 73 18 0e   o....%.".....s..
0410 - 52 be 49 e0 b9 7d a2 be-63 d5 84 20 21 96 57 14   R.I..}..c.. !.W.
0420 - 40 43 5c dc 0e dd 02 d0-c6 ba 8b fe 1b 73 ad b4   @C\..........s..
0430 - 73 10 c7 76 00 50 e9 9a-e3 92 8a 8c 5e a9 ec d8   s..v.P......^...
0440 - f0 c1 79 2a 20 60 72 ef-7a b0 6e 7f 73 ef 9e 96   ..y* `r.z.n.s...
0450 - f0 fe 8d d9 00 eb 49 36-27 54 ab fe 9a 57 9f 28   ......I6'T...W.(
0460 - b7 e0 cb 8a 9b 15 90 1e-c5 fb a1 b3 b8 41 65 63   .............Aec
0470 - d9 4a 21 86 65 f2 26 b7-97 ba 0e f0 ab 4b 97 2c   .J!.e.&......K.,
0480 - 7d be 56 4e 96 a5 91 69-fa c0 c9 f2 2c 0e 3c 44   }.VN...i....,.<D
0490 - 23 df 24 36 ac 9e c6 c8-68 ec 91 61 80 80 52 46   #.$6....h..a..RF
04a0 - 34 10 28 bc 9e 5d 14 7e-3e 65 56 bb 22 ae c6 38   4.(..].~>eV."..8
04b0 - fb 88 d0 4b b6 24 5f 92-54 27 7d db c6 0a 94 af   ...K.$_.T'}.....
04c0 - 2d 97 88 ec 1d 5c 22 8d-af 99 5b bf 85 93 8f 3d   -....\"...[....=
04d0 - 48 53 98 fe 39 4e 5e 5a-a7 84 56 29 60 e7 35 99   HS..9N^Z..V)`.5.
04e0 - 14 03 03 00 01 01 17 03-03 00 17 aa ca 6d bb 24   .............m.$
04f0 - 83 f0 87 ac f0 e9 43 6e-83 fe f3 f0 f1 c9 d8 7e   ......Cn.......~
0500 - b3 e9 17 03 03 02 2a ab-f6 2c 10 8b aa d9 86 58   ......*..,.....X
0510 - de 79 ba 14 9d a8 6c af-5b 6b c8 4e a3 9c 39 d2   .y....l.[k.N..9.
0520 - 74 1c f2 46 76 77 6e 84-0e 14 81 b0 f4 c2 ce 2d   t..Fvwn........-
0530 - e4 34 fd 19 d8 3d 61 f5-59 30 6d 12 63 c4 2e 46   .4...=a.Y0m.c..F
0540 - 08 90 8c e5 31 c0 74 b8-78 4e 3b 51 54 3b 53 63   ....1.t.xN;QT;Sc
0550 - 54 dd d5 34 c9 0d f9 2f-fa 1d 25 34 e7 ac 6a aa   T..4.../..%4..j.
0560 - 1c 6c 41 13 3c 0c ac 78-e4 e2 a7 8c bd 00 af 3d   .lA.<..x.......=
0570 - 46 01 74 5b f3 a4 37 76-af c5 73 af c0 17 8f eb   F.t[..7v..s.....
0580 - 51 9f 12 32 73 74 58 be-8a be 97 96 7a 47 ed f7   Q..2stX.....zG..
0590 - 6e 9a 5a ac 2e 12 fb 67-5f 4c ef f8 0f 88 b6 71   n.Z....g_L.....q
05a0 - 06 be be 5b 9b f7 29 2c-b1 52 ea 2f aa c8 a1 29   ...[..),.R./...)
05b0 - 68 82 49 ad 8d 11 bf f7-18 5b 25 5c 86 c5 b7 83   h.I......[%\....
05c0 - 33 6f a5 23 4e cb fc d3-91 85 fb fc 75 31 19 83   3o.#N.......u1..
05d0 - da a9 59 75 c7 11 ac a6-48 1f bc 49 48 60 33 7c   ..Yu....H..IH`3|
05e0 - bc 08 d2 f1 43 bc 1b bc-1c a4 45 7b 51 6d c3 29   ....C.....E{Qm.)
05f0 - ae f4 10 52 94 d6 f1 ea-00 33 5c 03 55 2a be c0   ...R.....3\.U*..
0600 - e8 f5 00 48 c3 35 ca b8-2e e1 ed 41 8e 35 62 a3   ...H.5.....A.5b.
0610 - 10 23 a1 d5 8f df af f1-7e 1e 6e c4 9d 16 e5 3c   .#......~.n....<
0620 - 7c 56 60 4b 1f 41 97 5c-ec 11 74 6e dd 52 bc 35   |V`K.A.\..tn.R.5
0630 - 25 90 a4 f0 f4 36 9c b2-7b 89 07 d3 8e 6f 9d 2f   %....6..{....o./
0640 - ce b9 82 d2 55 f3 cf 16-17 c9 9b 7e 90 90 bc 08   ....U......~....
0650 - 45 32 2f 89 74 94 f9 44-c7 fc 95 5f bb f9 79 2a   E2/.t..D..._..y*
0660 - 3e 5e e5 4f bc 2a 5b 10-15 00 48 9b 94 16 d1 cd   >^.O.*[...H.....
0670 - 9c 7a 85 f8 50 44 5f f8-2f 8b 7f 45 4f d2 d6 32   .z..PD_./..EO..2
0680 - c7 fd ba a1 20 e6 86 9c-b8 c5 5b 94 31 fa a1 2d   .... .....[.1..-
0690 - 89 fc 68 1b 52 97 ff f8-fc 9d 0d c8 5e c4 44 a6   ..h.R.......^.D.
06a0 - 7a 6f f0 b2 a8 7f 18 0c-5a 93 3b bd 1b 3f a9 ae   zo......Z.;..?..
06b0 - 54 ec 0f 4c 76 80 e8 f4-db 33 b4 40 01 57 d3 2d   T..Lv....3.@.W.-
06c0 - 53 04 f9 72 53 d9 50 33-8b d8 d9 f5 6c de e8 2a   S..rS.P3....l..*
06d0 - ed b8 94 17 e6 28 bc ff-a4 11 e1 2a ea 09 3f 3f   .....(.....*..??
06e0 - 59 22 4c 09 f8 16 fa 2d-2f 38 57 2d 00 89 46 f4   Y"L....-/8W-..F.
06f0 - 2a 30 9f 01 f2 3d 12 e4-c6 ba 86 d0 96 12 14 4f   *0...=.........O
0700 - ae fd cc bc b3 0b cf 13-a5 24 9b 92 8e 85 84 83   .........$......
0710 - e9 4e e3 fe 2b 0a 13 ec-ec 59 f0 5e 71 a6 c6 79   .N..+....Y.^q..y
0720 - fc b7 1f 92 a6 63 fd be-7f 0e a9 2a 98 2c 63 24   .....c.....*.,c$
0730 - 2a 17 03 03 00 60 a5 b2-88 69 e1 35 66 ea c7 87   *....`...i.5f...
0740 - 66 16 21 8b ab 98 2f dc-7d 0a f7 67 56 78 1c b8   f.!.../.}..gVx..
0750 - 9a 5b 53 be 9d 4f fd 42-7b 25 88 ad 14 3a f5 f4   .[S..O.B{%...:..
0760 - c8 a1 57 dc 76 18 05 3d-f8 ec cf d1 99 09 d9 e5   ..W.v..=........
0770 - 16 9e a7 7f e9 c5 85 6d-1c 6b ef 01 bb 8c 09 0b   .......m.k......
0780 - 9d c7 fa 94 9f b1 3e 50-8e 3b 76 88 78 c4 fe 22   ......>P.;v.x.."
0790 - 2f 68 56 2b c0 95 17 03-03 00 35 7a 58 7d a6 6f   /hV+......5zX}.o
07a0 - 88 92 3c 82 2e f7 0c 98-b0 92 5b d9 61 30 21 31   ..<.......[.a0!1
07b0 - e9 9a 13 9e 51 66 39 50-9a 70 cc 20 56 bc f9 ea   ....Qf9P.p. V...
07c0 - d3 92 af b7 e6 72 6f 69-5a 27 b5 3d 54 4d e5 4d   .....roiZ'.=TM.M
SSL_accept:SSLv3/TLS write finished
SSL_accept:TLSv1.3 early data
read from 0x16b828ba730 [0x16b844a3503] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x16b828ba730 [0x16b844a3508] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x16b828ba730 [0x16b844a3503] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
read from 0x16b828ba730 [0x16b844a3508] (53 bytes => 53 (0x35))
0000 - 01 cc d9 d2 8c c2 f6 8c-04 99 a9 23 72 07 00 31   ...........#r..1
0010 - 2b 88 fc fa 40 67 4f c2-db de 58 20 19 e8 5a 72   +...@gO...X ..Zr
0020 - d7 b2 c3 c7 2a 86 f1 52-a1 cf c3 66 50 ce 6e 0b   ....*..R...fP.n.
0030 - d7 fe fd 71 ab                                    ...q.
SSL_accept:TLSv1.3 early data
SSL_accept:SSLv3/TLS read finished
write to 0x16b828ba730 [0x16b844a24f0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea c9 d4 99-1f b8 84 8b d0 5b 37 2f   .............[7/
0010 - fc 96 33 20 18 14 3c f5-0e b2 e5 28 f3 d1 9b 48   ..3 ..<....(...H
0020 - bc 5c e5 f2 74 b1 2b e2-14 f0 dd a5 46 d7 3c 40   .\..t.+.....F.<@
0030 - 6a c9 cd 73 d0 b1 ea e5-b9 67 80 1a 66 68 ac a9   j..s.....g..fh..
0040 - db 12 60 76 0c 43 db 6d-57 d4 83 5e ca 98 4b 21   ..`v.C.mW..^..K!
0050 - 61 2f 17 e9 6f 1b d0 a4-e0 16 bd a8 6f 61 24 ad   a/..o.......oa$.
0060 - 29 ee e0 58 91 59 9e bf-da 2a 53 1f e5 79 18 b4   )..X.Y...*S..y..
0070 - 4c 04 45 a9 94 b7 29 a9-b1 88 5d 2f 26 60 6f 70   L.E...)...]/&`op
0080 - f3 16 1f 44 f3 d8 de 0d-a6 c8 43 9c 6f db 09 a9   ...D......C.o...
0090 - 31 68 aa c9 24 8b ed a1-77 fc f1 91 f0 1e 9e df   1h..$...w.......
00a0 - 83 97 01 21 d1 a3 5b a2-fa c6 06 19 8f 71 3b 22   ...!..[......q;"
00b0 - 09 fc 55 f7 64 a2 8f ef-61 63 79 b3 2c 3c 11 d4   ..U.d...acy.,<..
00c0 - 83 82 6e 8d b9 77 ff 3c-5c 1a db 30 b2 2e a5 88   ..n..w.<\..0....
00d0 - d4 af c1 5f d4 79 29 84-d8 18 ff 14 af aa a3 92   ..._.y).........
00e0 - 74 8c d5 c8 d7 fd 6b 33-7b fa af a6 d6 34 22      t.....k3{....4"
SSL_accept:SSLv3/TLS write session ticket
write to 0x16b828ba730 [0x16b844a24f0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea 1f ef 74-1a 08 29 79 2d 8f 02 81   .......t..)y-...
0010 - e9 de 48 77 0c ef 3e d0-df 14 e2 35 79 6f 35 4b   ..Hw..>....5yo5K
0020 - f5 34 21 12 54 ec 92 b7-d8 f3 0f 5c 3c 90 84 67   .4!.T......\<..g
0030 - d6 9b 5d 8b cb d2 54 97-b3 3f e2 14 b4 60 21 5f   ..]...T..?...`!_
0040 - 42 a4 b7 41 98 0a 0c ac-bb 8a 43 d9 69 fe d9 13   B..A......C.i...
0050 - d8 49 96 3e 5d 53 17 0e-01 b5 76 2a ad 1b a1 c7   .I.>]S....v*....
0060 - 20 8a 48 a4 1d 91 f4 f9-a1 4b d5 ba e7 2b 38 d7    .H......K...+8.
0070 - d7 fd 9d d1 4b 45 d7 72-6c ee 4d 0a 73 ed 7d 88   ....KE.rl.M.s.}.
0080 - 5f 07 35 f5 db 8b d8 2d-91 47 46 6b cc d5 b0 82   _.5....-.GFk....
0090 - 49 27 95 90 13 cc 22 40-49 96 4a 1d da 55 37 8f   I'...."@I.J..U7.
00a0 - 14 20 29 8e cb 4a d1 5e-77 cc 5d 18 b9 aa 5c af   . )..J.^w.]...\.
00b0 - 50 0b 43 a1 5e 6d a8 ff-a9 23 2e 2d 7c f4 73 aa   P.C.^m...#.-|.s.
00c0 - 17 a0 f8 a0 db ce 58 ff-b4 74 fc 1d de 92 41 e9   ......X..t....A.
00d0 - eb 63 9d 5e 39 44 39 7f-a8 4f cf 79 f6 78 2b 2c   .c.^9D9..O.y.x+,
00e0 - 12 27 f1 dc 0f 21 1d 6b-1c 95 d3 72 c6 00 75      .'...!.k...r..u
SSL_accept:SSLv3/TLS write session ticket
-----BEGIN SSL SESSION PARAMETERS-----
MHQCAQECAgMEBAITBAQghc/mFkvYUQ2ocUBPUDQjzyRLfxsfnHBXtaaiK7mjS3YE
IHED/GwXoBDkoffDSRILaxwDl/gp6MJx0jcO4gmg+1JEoQYCBGjqKC6iBAICHCCk
BgQEAQAAAK4HAgUAjW1+drMEAgIR6w==
-----END SSL SESSION PARAMETERS-----
Shared ciphers:TLS_AES_128_CCM_SHA256
Signature Algorithms: id-ml-dsa-65:id-ml-dsa-87:id-ml-dsa-44:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:ed448:ecdsa_brainpoolP256r1_sha256:ecdsa_brainpoolP384r1_sha384:ecdsa_brainpoolP512r1_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Shared Signature Algorithms: id-ml-dsa-65:id-ml-dsa-87:id-ml-dsa-44:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:ed448:ecdsa_brainpoolP256r1_sha256:ecdsa_brainpoolP384r1_sha384:ecdsa_brainpoolP512r1_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Supported groups: SecP256r1MLKEM768
Shared groups: SecP256r1MLKEM768
CIPHER is TLS_AES_128_CCM_SHA256
This TLS version forbids renegotiation.
read from 0x16b828ba730 [0x16b844b2ab3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x16b828ba730 [0x16b844b2ab8] (23 bytes => 23 (0x17))
0000 - a3 89 af 38 26 9d ad 64-de fa f8 a0 9f 38 85 d1   ...8&..d.....8..
0010 - 53 9a 02 fd 42 c8 ee                              S...B..
test
read from 0x16b828ba730 [0x16b844b2ab3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 13                                    .....
read from 0x16b828ba730 [0x16b844b2ab8] (19 bytes => 19 (0x13))
0000 - c2 96 a3 e2 8f 94 e9 90-e6 3d 10 81 81 01 39 47   .........=....9G
0010 - e7 d5 2a                                          ..*
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x16b828ba730 [0x16b844a3503] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 d0 81 05-50 38 01 7e 38 ed 10 b3   ........P8.~8...
0010 - 34 c5 72 38 64 7f 34 4a-                          4.r8d.4J
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
