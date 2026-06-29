#### client

````
$ openssl s_client -connect localhost:9000 -state -debug -keylogfile sslkeylog -tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256 -groups MLKEM768
Connecting to ::1
CONNECTED(000001F0)
SSL_connect:before SSL initialization
write to 0x184b47c7a80 [0x184b4bb2b60] (1364 bytes => 1364 (0x554))
0000 - 16 03 01 05 4f 01 00 05-4b 03 03 72 f4 fd 67 02   ....O...K..r..g.
0010 - bd 47 5a 94 e1 e8 0a 91-c9 a8 a2 d7 ed 16 0f 34   .GZ............4
0020 - 45 d3 0e e9 95 9d 96 21-f4 ba 2c 20 60 2e af a4   E......!.., `...
0030 - 43 02 b4 47 4c 2d 8d b5-1e 69 79 0f 4e cb e1 88   C..GL-...iy.N...
0040 - 04 be 83 a5 3b 82 7f 87-d6 e9 2d 8a 00 02 13 04   ....;.....-.....
0050 - 01 00 05 00 00 0a 00 04-00 02 02 01 00 23 00 00   .............#..
0060 - 00 16 00 00 00 17 00 00-00 0d 00 2a 00 28 09 05   ...........*.(..
0070 - 09 06 09 04 04 03 05 03-06 03 08 07 08 08 08 1a   ................
0080 - 08 1b 08 1c 08 09 08 0a-08 0b 08 04 08 05 08 06   ................
0090 - 04 01 05 01 06 01 00 2b-00 03 02 03 04 00 2d 00   .......+......-.
00a0 - 02 01 01 00 33 04 a6 04-a4 02 01 04 a0 ed 5b 6a   ....3.........[j
00b0 - b4 9b 1d a4 a4 66 11 d3-60 73 48 b4 80 42 61 be   .....f..`sH..Ba.
00c0 - d5 3d f9 ab 75 71 72 49-b3 59 05 31 1c 7e 9d da   .=..uqrI.Y.1.~..
00d0 - b5 6f 31 91 f0 ca 39 60-e3 b6 ab 30 01 96 b9 90   .o1...9`...0....
00e0 - bf 1a 06 ed b1 4d f2 87-55 1a 26 37 11 6b 76 32   .....M..U.&7.kv2
00f0 - 68 3e d4 91 b3 60 8a 1c-b8 90 49 38 10 94 47 58   h>...`....I8..GX
0100 - 5c df e9 62 5f fb 5b d8-7b 16 12 76 93 fe 53 66   \..b_.[.{..v..Sf
0110 - 30 40 4b 6a d2 85 7c 30-59 70 18 5d 00 2d 6c f8   0@Kj..|0Yp.].-l.
0120 - c7 54 39 76 09 0a 5a 2b-84 72 ab b5 9b 97 6a a8   .T9v..Z+.r....j.
0130 - 0d 6a 2c a4 b0 a8 b6 94-b8 0e e3 73 11 84 fb 62   .j,........s...b
0140 - 08 e9 a4 7a 10 88 00 4d-54 e4 ac 2a b0 c6 cb 07   ...z...MT..*....
0150 - a1 2c e3 da 4f a2 cb 69-0d b6 7a 35 d1 35 bc 42   .,..O..i..z5.5.B
0160 - 3c db 9c 10 34 18 bc f4-f5 10 f7 5b c9 8c ea 5f   <...4......[..._
0170 - 81 27 38 d8 e2 3b dc b9-6b 75 49 23 15 05 a8 29   .'8..;..kuI#...)
0180 - 4b 8e 25 a2 8d 3e 97 2c-73 33 a4 e0 d8 74 ac 36   K.%..>.,s3...t.6
0190 - 02 d2 94 80 6d 29 24 dd-c3 3f a2 25 58 49 e2 53   ....m)$..?.%XI.S
01a0 - 3b db b7 7f a1 b8 2f a2-55 71 9b c5 97 f5 b7 5d   ;...../.Uq.....]
01b0 - e2 61 17 31 19 5a f5 48-d5 47 47 95 c7 43 ff e5   .a.1.Z.H.GG..C..
01c0 - 0d 33 1c 71 e1 a7 b6 d0-76 a0 03 b8 30 20 92 75   .3.q....v...0 .u
01d0 - 6e 2a 97 7f 08 61 9a 61-5f bd 92 3d c6 93 9d 06   n*...a.a_..=....
01e0 - 79 95 71 a6 10 bd a3 39-95 d9 0b 26 8a 48 d3 4a   y.q....9...&.H.J
01f0 - 54 67 18 39 c2 4a ce bc-f8 cf cc 79 26 05 9c cd   Tg.9.J.....y&...
0200 - 59 6b 00 80 e3 7c d6 38-b4 e3 65 6e ab dc 54 29   Yk...|.8..en..T)
0210 - 37 44 14 44 47 d0 03 3d-fd dc 4d 81 2b 17 3a 06   7D.DG..=..M.+.:.
0220 - 7e d4 eb 4e 25 d3 35 e9-f3 c9 b6 20 40 51 68 46   ~..N%.5.... @QhF
0230 - c2 11 08 08 da bf ea f4-62 61 fa 82 0a 63 b1 5a   ........ba...c.Z
0240 - bb 08 e9 70 91 b1 78 07-8b 5a 70 23 72 c1 aa 12   ...p..x..Zp#r...
0250 - 78 7b 17 4b 5e 93 78 80-f5 1b c1 03 04 2f a2 75   x{.K^.x....../.u
0260 - 05 ec c8 23 ea 02 9e 80-5c 13 95 00 f7 c3 19 ea   ...#....\.......
0270 - 2c 45 4c ca 63 e9 71 2e-48 b2 72 99 45 7c 3a 54   ,EL.c.q.H.r.E|:T
0280 - a1 69 7b bc 02 f6 b4 f9-a0 64 a9 f5 8b f5 f0 09   .i{......d......
0290 - de 52 47 7d 25 2a 51 62-74 97 17 67 8e 36 6b eb   .RG}%*Qbt..g.6k.
02a0 - cc 32 f7 73 9a 69 49 cc-f7 60 8b cd 6c 59 4c ec   .2.s.iI..`..lYL.
02b0 - 05 6c c7 50 46 b7 0d 70-56 3e 60 85 6c 19 9a a1   .l.PF..pV>`.l...
02c0 - c5 b4 75 d4 27 65 f8 5c-73 c4 25 07 5a 15 05 32   ..u.'e.\s.%.Z..2
02d0 - 17 a0 a0 b7 87 dd d5 ca-09 39 47 d4 0a 0a 75 fa   .........9G...u.
02e0 - 1d e7 27 ac 65 36 4f 7c-07 7c 3d 94 bc 3f b1 3d   ..'.e6O|.|=..?.=
02f0 - 7f e6 25 c2 77 22 da 52-2e a3 e7 01 d9 c0 07 5d   ..%.w".R.......]
0300 - 57 06 96 2a 31 cd 37 6b-a2 27 39 16 f8 aa be 76   W..*1.7k.'9....v
0310 - b3 45 80 36 5b 92 c3 be-60 0e 21 67 60 2f 54 4a   .E.6[...`.!g`/TJ
0320 - b3 75 0a 76 98 3a fd d4-79 90 97 22 ec 50 c5 fe   .u.v.:..y..".P..
0330 - b7 93 82 02 87 8f d4 cd-66 92 75 17 6c b8 a7 6c   ........f.u.l..l
0340 - 43 ef c8 10 14 78 b3 2d-86 72 0d 6a 08 03 e1 4f   C....x.-.r.j...O
0350 - 62 3a cc 82 52 c0 b2 77-5b c8 c5 4a 58 b4 4e 50   b:..R..w[..JX.NP
0360 - d8 9b 4a a1 bc 73 94 cf-c7 58 b0 3d c4 bb 6b d1   ..J..s...X.=..k.
0370 - 3e f5 7b 03 e0 0c 5d 2f-ac 7b 96 0a 04 a4 e7 a2   >.{...]/.{......
0380 - 52 62 9d b3 d4 c6 22 d2-c4 eb c9 20 a2 94 ca fa   Rb....".... ....
0390 - ec b9 42 2a 3d 2a 50 72-a8 f2 5c 4c 3b 8a c7 e9   ..B*=*Pr..\L;...
03a0 - 1a 32 e5 31 a9 81 a6 5e-e9 5a c4 e3 18 bd 83 ae   .2.1...^.Z......
03b0 - d4 54 04 81 a3 c5 ae e5-4c 89 cb 7d 78 14 c2 77   .T......L..}x..w
03c0 - 40 c1 86 5a 99 0e f7 73-78 b8 3d 68 04 c0 c8 b5   @..Z...sx.=h....
03d0 - 52 16 fa 10 90 66 34 de-1b 48 1b 84 b5 dc 71 a5   R....f4..H....q.
03e0 - 05 f7 b1 4e b0 20 84 97-69 a5 46 09 af 1c 33 87   ...N. ..i.F...3.
03f0 - 65 88 86 c7 3b 0f 1a 23-1e 61 4a e5 e4 22 d6 c7   e...;..#.aJ.."..
0400 - 61 b5 b6 bb 87 c1 0a 8d-8a 53 d1 f3 05 ae 60 23   a........S....`#
0410 - fb f5 65 3e 0a 13 d3 1b-c5 d5 74 be 87 58 85 58   ..e>......t..X.X
0420 - 29 cc fe c3 37 a1 91 42-89 39 ca 7f f9 02 10 72   )...7..B.9.....r
0430 - 04 7b e8 95 cf 04 77 1b-4c 1b 31 bc ba a2 d9 86   .{....w.L.1.....
0440 - c0 a8 44 08 64 a1 3a 41-85 df da 7c ca 57 26 72   ..D.d.:A...|.W&r
0450 - 71 44 0d 24 6b 0d 56 49-77 54 a1 12 03 8c 32 f2   qD.$k.VIwT....2.
0460 - 3f 0c b7 15 e5 f6 5d 59-87 1a f5 d3 56 7e e8 38   ?.....]Y....V~.8
0470 - 22 16 b4 3f 62 62 38 5b-93 de 52 45 a3 bc 59 b0   "..?bb8[..RE..Y.
0480 - b2 0f 5a 17 b0 fc ca 01-d0 dc 56 8c c1 1c c0 88   ..Z.......V.....
0490 - 25 12 a6 04 34 a7 5f a2-59 a2 86 33 07 78 da 35   %...4._.Y..3.x.5
04a0 - 94 e5 27 9b d6 56 6c b8-a4 81 f2 b9 8f cb 61 c9   ..'..Vl.......a.
04b0 - 56 99 bb 9a a6 72 50 7e-04 8b 4c 6a 59 9d 01 63   V....rP~..LjY..c
04c0 - 1c c4 d1 9e 48 32 8a 96-78 ce 10 8b 56 a2 78 59   ....H2..x...V.xY
04d0 - fc 6c 58 6b 92 67 46 35-16 86 28 8b 0e 02 ad 3c   .lXk.gF5..(....<
04e0 - ab ab 11 72 19 37 06 57-c2 f0 a9 2e 92 3b 9e 39   ...r.7.W.....;.9
04f0 - bd ce c0 2a 6a b8 bb 86-93 ac 17 72 22 5d 07 b8   ...*j......r"]..
0500 - 1d 10 a3 fe 4a 88 ef a3-04 07 57 cf 2c 95 45 51   ....J.....W.,.EQ
0510 - bb 28 87 db 88 b5 e9 27-d1 7c 25 d4 30 4e 30 8b   .(.....'.|%.0N0.
0520 - 9c e2 f6 38 87 d9 95 62-06 a1 bf 36 bd 11 40 21   ...8...b...6..@!
0530 - 77 38 c6 b4 98 3a ab 42-0b ae a9 90 20 0a c8 05   w8...:.B.... ...
0540 - 35 77 b5 00 21 16 f5 00-d1 45 82 9b ea 00 1b 00   5w..!....E......
0550 - 03 02 00 01                                       ....
SSL_connect:SSLv3/TLS write client hello
read from 0x184b47c7a80 [0x184b4bb9a83] (5 bytes => 5 (0x5))
0000 - 16 03 03 04 9a                                    .....
read from 0x184b47c7a80 [0x184b4bb9a88] (1178 bytes => 1178 (0x49A))
0000 - 02 00 04 96 03 03 6a 69-9e 35 aa 5d 94 65 01 ca   ......ji.5.].e..
0010 - ca e9 34 3d a1 2f eb 04-30 af 3f 0a 69 18 14 91   ..4=./..0.?.i...
0020 - f7 90 09 53 69 29 20 60-2e af a4 43 02 b4 47 4c   ...Si) `...C..GL
0030 - 2d 8d b5 1e 69 79 0f 4e-cb e1 88 04 be 83 a5 3b   -...iy.N.......;
0040 - 82 7f 87 d6 e9 2d 8a 13-04 00 04 4e 00 2b 00 02   .....-.....N.+..
0050 - 03 04 00 33 04 44 02 01-04 40 41 37 fc af 19 68   ...3.D...@A7...h
0060 - aa 75 90 62 a8 2b e7 4c-3a 1c 51 eb d8 34 98 46   .u.b.+.L:.Q..4.F
0070 - 7f aa 62 48 2e 5b 31 97-0a a8 f4 95 30 d4 37 1e   ..bH.[1.....0.7.
0080 - ce 95 2f d6 61 a3 f7 2e-c4 1c 39 94 5c fc 43 00   ../.a.....9.\.C.
0090 - 34 e9 de e9 dd 92 22 59-35 17 36 f1 5c 6b 93 62   4....."Y5.6.\k.b
00a0 - 7e 20 7c 5d 18 35 8d d6-d1 46 e9 e9 68 b9 37 5c   ~ |].5...F..h.7\
00b0 - 31 ba f0 70 4f 66 cd e2-53 ba 4f 16 cf 8e 1b 37   1..pOf..S.O....7
00c0 - 40 20 eb 36 1f 3d 1a 8c-f7 e4 81 1d 2d 56 73 33   @ .6.=......-Vs3
00d0 - 8e 52 0f 9e 79 69 7d 1c-05 e4 6c de 1b b3 a8 8f   .R..yi}...l.....
00e0 - 08 be 4b a8 9b e4 11 c7-b2 2e ce bb 3f 6d f9 41   ..K.........?m.A
00f0 - fd d6 a6 51 c3 d4 f0 57-0d 1b 6b 7e 60 ea 30 8c   ...Q...W..k~`.0.
0100 - 55 93 67 21 2a ac de ca-a7 a1 80 af b3 b6 fe 74   U.g!*..........t
0110 - 85 e7 39 96 eb f5 68 70-f0 19 44 13 d4 ac f0 4f   ..9...hp..D....O
0120 - c8 a2 32 12 0c 9b 0b 49-88 2b 1d 48 4b 1b 1c c6   ..2....I.+.HK...
0130 - 8c aa 0c c1 85 7a 48 3f-eb b5 18 63 65 c5 fa 5f   .....zH?...ce.._
0140 - e5 97 e8 df 6a 36 68 51-9c 65 84 f7 62 5a 2d 44   ....j6hQ.e..bZ-D
0150 - 95 40 31 a8 ea a3 6d 46-8d 63 a1 bb 6d 4d 64 4f   .@1...mF.c..mMdO
0160 - 8d 06 7f 99 04 70 5e 0b-88 70 07 4a dd 76 b5 a4   .....p^..p.J.v..
0170 - 0d 04 88 c5 19 47 98 e1-30 78 7d c2 a4 11 c9 a9   .....G..0x}.....
0180 - f8 5b 7b 8b 03 c4 d5 38-d2 77 f2 76 5d 86 35 d8   .[{....8.w.v].5.
0190 - e9 27 54 fa 1f 1e 7e 9c-a0 d8 37 88 8a 20 28 5b   .'T...~...7.. ([
01a0 - 62 c0 be 01 47 3b ac c4-8f 91 36 97 b0 58 23 6d   b...G;....6..X#m
01b0 - ec 39 50 71 5c 66 7b f6-58 ee 22 37 ac ac 34 62   .9Pq\f{.X."7..4b
01c0 - cf e6 d4 98 87 fe cf 22-f8 e1 50 95 0c ba 35 88   ......."..P...5.
01d0 - 59 dd 24 97 96 35 c1 39-a6 de 7c 5f 46 31 b6 76   Y.$..5.9..|_F1.v
01e0 - 1a 47 ea 26 15 3c dd 34-77 11 f9 e8 9e 50 72 4a   .G.&.<.4w....PrJ
01f0 - 6d c8 d4 02 6f be e8 7c-5f b5 96 de c4 09 cc 21   m...o..|_......!
0200 - 26 62 b6 fc e7 55 76 bc-a0 e2 27 6c 8b f1 c9 e5   &b...Uv...'l....
0210 - ee 02 07 7d 41 6c 0b 41-9d ce 76 94 5f c4 da 3c   ...}Al.A..v._..<
0220 - 83 57 ac d3 d1 7e c3 8f-1c 1f 51 3c f5 93 41 0e   .W...~....Q<..A.
0230 - 35 5f 0f c1 ec 54 d5 84-28 90 34 5d 28 33 0d c1   5_...T..(.4](3..
0240 - 48 93 97 cd 0e 90 a3 f9-b1 a0 cd 22 86 ee 92 bd   H.........."....
0250 - 5d 82 38 c1 74 59 b4 80-57 11 fb 02 5e 14 3a be   ].8.tY..W...^.:.
0260 - 8d ed 44 79 07 af d0 13-c7 b5 85 5f 8a 4d 32 75   ..Dy......._.M2u
0270 - 4e 03 ba 93 6f 92 9c 01-1b 14 cf 46 e0 38 e9 65   N...o......F.8.e
0280 - 16 88 65 d8 01 15 49 de-51 c9 e7 c1 f7 b5 c3 fd   ..e...I.Q.......
0290 - a8 f3 6d 7b 5c f8 38 1c-ee d9 29 45 56 c3 1d 03   ..m{\.8...)EV...
02a0 - d2 73 bc 38 f2 c6 10 b5-d8 ba f5 67 48 4b b2 77   .s.8.......gHK.w
02b0 - 5f 70 2e 9c ac a4 26 f9-43 03 7c e0 ab 36 ef 34   _p....&.C.|..6.4
02c0 - 85 e0 05 84 9d 87 84 34-48 e5 50 e8 b4 9b ae d1   .......4H.P.....
02d0 - 0f 77 05 f7 cb 24 61 bc-04 85 19 93 d2 ba 12 23   .w...$a........#
02e0 - 77 b3 7b 4e d2 41 7d d5-35 62 ca 40 e9 28 57 05   w.{N.A}.5b.@.(W.
02f0 - a8 54 70 16 86 f9 7e 81-b8 71 44 f5 dd d0 27 b8   .Tp...~..qD...'.
0300 - 7e 73 c3 fd e4 ca cc 01-a1 dc 77 dd e8 2a 86 31   ~s........w..*.1
0310 - de 24 20 c1 93 92 a8 4d-a3 0d ca aa 2c 1e 98 45   .$ ....M....,..E
0320 - 67 36 a6 2e 54 bb f5 dc-ad e6 70 f0 25 15 3b ee   g6..T.....p.%.;.
0330 - 00 88 d5 17 72 c0 79 91-0e 52 20 68 c1 9f cb 18   ....r.y..R h....
0340 - e9 3a f7 8b 55 85 96 e5-75 44 31 ea b7 b6 12 0a   .:..U...uD1.....
0350 - f6 4a d3 45 e3 42 61 63-8c 5c 98 58 63 88 51 32   .J.E.Bac.\.Xc.Q2
0360 - 81 c0 87 c4 58 2a 15 f6-2b 0a 09 8e 53 fc 83 bd   ....X*..+...S...
0370 - 3f 65 55 7b 53 52 05 04-35 dd f2 cb 71 4f 49 99   ?eU{SR..5...qOI.
0380 - bc b6 54 47 ae d6 dd 5d-c4 d9 9e a1 52 67 2c c5   ..TG...]....Rg,.
0390 - e9 e3 e3 15 fb 20 f8 e5-17 eb 93 52 02 df 1e 94   ..... .....R....
03a0 - e6 0f 82 9a a0 56 5b 24-70 c0 02 c2 03 47 1d 74   .....V[$p....G.t
03b0 - 58 a5 4a 31 72 27 18 e4-ad 2b b8 1a 86 59 12 56   X.J1r'...+...Y.V
03c0 - b3 0d 7b 2f 0c 63 1d fb-4b f4 d2 07 53 b0 3b 5b   ..{/.c..K...S.;[
03d0 - 86 d5 93 e2 f1 76 89 a5-4e 3b 7c 47 cc be d5 82   .....v..N;|G....
03e0 - 44 5d 40 79 da 4d cf a9-1e 58 3b a0 64 ee ad eb   D]@y.M...X;.d...
03f0 - c1 ad 1e a8 bb fa 9b 4c-b9 29 6e 2d 8d a2 17 4f   .......L.)n-...O
0400 - b2 e3 76 8f d0 8b 30 2b-2b 07 46 51 a7 9d dc 34   ..v...0++.FQ...4
0410 - cc b4 87 a9 50 eb fd db-86 fb f4 84 f7 f0 04 79   ....P..........y
0420 - d6 30 7c 1b d9 15 0b 65-7f 64 46 fd 9f ca 09 71   .0|....e.dF....q
0430 - c6 68 ed da 82 aa f5 a8-72 ec 7b aa eb 15 6e f7   .h......r.{...n.
0440 - 36 ba 6d 63 1c 57 05 e8-7b 8b 6d 96 40 b7 af ce   6.mc.W..{.m.@...
0450 - 47 10 98 48 77 da 18 80-8b e8 5e 03 97 ae 6e 04   G..Hw.....^...n.
0460 - c7 32 2d 08 ff f7 15 17-ff 50 91 4c 5f 22 69 06   .2-......P.L_"i.
0470 - bd 5f 47 1f 0a e5 6f f6-04 f5 32 37 6c 25 49 a1   ._G...o...27l%I.
0480 - 64 18 dd e7 c5 0d 99 c0-88 28 f0 85 02 a4 e8 ea   d........(......
0490 - 82 01 b9 0c 3b c5 ae 38-d7 be                     ....;..8..
SSL_connect:SSLv3/TLS write client hello
read from 0x184b47c7a80 [0x184b4bb9a83] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x184b47c7a80 [0x184b4bb9a88] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x184b47c7a80 [0x184b4bb9a83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x184b47c7a80 [0x184b4bb9a88] (23 bytes => 23 (0x17))
0000 - 16 d8 b6 ca 85 56 2d 1e-4e 5b 9d 5a f0 15 bc 52   .....V-.N[.Z...R
0010 - 94 65 ed 83 36 f6 0c                              .e..6..
SSL_connect:SSLv3/TLS read server hello
Can't use SSL_get_servername
read from 0x184b47c7a80 [0x184b4bb9a83] (5 bytes => 5 (0x5))
0000 - 17 03 03 02 2a                                    ....*
read from 0x184b47c7a80 [0x184b4bb9a88] (554 bytes => 554 (0x22A))
0000 - 5f 16 03 81 2b 81 d8 ec-bc e5 ed 77 67 08 66 e2   _...+......wg.f.
0010 - f1 87 27 aa 97 89 e7 0c-cd ae c7 04 d5 a3 a6 cf   ..'.............
0020 - ec 9c 7f 28 a4 39 37 73-c0 98 40 d2 6d a5 d3 ab   ...(.97s..@.m...
0030 - 46 75 d0 52 f7 2a fd 8c-5f 29 99 59 ae 76 b6 36   Fu.R.*.._).Y.v.6
0040 - e3 ae 2a 48 76 d3 49 31-e3 8d fd 4b ab e7 ab ee   ..*Hv.I1...K....
0050 - f9 23 13 19 7e 00 1b ca-da eb a0 aa 47 fe ec 21   .#..~.......G..!
0060 - df 32 ba f2 96 54 2a d4-b2 60 bb a4 db 32 71 10   .2...T*..`...2q.
0070 - 13 50 3e 3d 86 49 03 2f-7a a4 b7 d4 60 be db 1a   .P>=.I./z...`...
0080 - eb d9 0a 4b 30 a5 e4 e2-ae 63 d4 03 b6 d9 34 bc   ...K0....c....4.
0090 - ee af ed 08 f1 07 3e fd-10 12 f1 48 53 c4 64 6f   ......>....HS.do
00a0 - 7e 90 f3 ff a0 b8 ee e4-6b a0 be 54 54 75 41 41   ~.......k..TTuAA
00b0 - a5 65 a0 c1 bf 71 d9 63-ca d7 94 5b 80 ca 98 f9   .e...q.c...[....
00c0 - fa ef 4f 8e d0 9e f3 02-6c 97 24 f0 49 5d 74 e1   ..O.....l.$.I]t.
00d0 - 03 66 5e 5a 61 bf ee 79-2d f7 8c ae 53 20 9d aa   .f^Za..y-...S ..
00e0 - 8e 24 86 60 c3 6a aa 17-a0 d3 ad d6 b6 d0 fc d8   .$.`.j..........
00f0 - 0c ac b4 2b 34 2f f1 f5-6d 7f f9 37 2b 34 b4 a4   ...+4/..m..7+4..
0100 - 4d bc 79 41 94 03 1d 2f-ca ad 91 42 11 40 7f fb   M.yA.../...B.@..
0110 - 40 cd 0e 68 bb 2a 86 eb-94 10 0e 76 60 28 57 ee   @..h.*.....v`(W.
0120 - db 92 a8 e1 49 73 41 46-88 67 2d c7 f4 1c 47 00   ....IsAF.g-...G.
0130 - 61 bf 4e 5b 3e 64 18 6a-6b 2d 80 a2 38 c9 5b b6   a.N[>d.jk-..8.[.
0140 - b9 80 a2 12 69 3d 82 a8-6b 2b 90 10 2f 29 6e c8   ....i=..k+../)n.
0150 - 1a 44 f6 bf 39 37 19 17-b7 2d 9e 9c c7 4e f7 e0   .D..97...-...N..
0160 - 22 69 50 08 0c 2d 03 e6-0d 7a 3d f9 ec 91 84 a3   "iP..-...z=.....
0170 - f5 af e7 9c d1 bf 71 4d-79 90 97 d4 d0 47 78 d3   ......qMy....Gx.
0180 - ef 10 f1 a8 e0 69 67 5c-a5 8d b7 c8 58 8a ea 10   .....ig\....X...
0190 - 1d 7d 48 6f 09 4c d0 9a-9b 78 48 4f d1 3b ec 17   .}Ho.L...xHO.;..
01a0 - c6 9e e9 f5 bc cb fb 81-1e db 9d 97 fb a5 64 78   ..............dx
01b0 - de 6b 47 25 bb f0 ba a0-5f 26 38 b5 97 3a 1a 5d   .kG%...._&8..:.]
01c0 - 54 d5 4f 4f 86 13 10 fe-ef a7 88 a4 b2 f9 5f 76   T.OO.........._v
01d0 - f7 52 fa 3b ec 12 96 02-bd 79 23 88 04 2f 2c 42   .R.;.....y#../,B
01e0 - d6 ec b9 fc c0 2a 0e 96-11 a5 58 97 0f 2f dd f2   .....*....X../..
01f0 - 02 34 39 8e 2b 10 4a ad-92 81 e9 bf 78 6a 01 79   .49.+.J.....xj.y
0200 - 69 f9 81 a7 c8 ad 7d 11-aa 3f 75 e8 62 cd 2c ab   i.....}..?u.b.,.
0210 - 7a a5 96 f5 86 40 6d af-11 e8 66 fc 93 e4 5a 6d   z....@m...f...Zm
0220 - d1 e9 7f 9b 4e f8 01 34-ad 0b                     ....N..4..
SSL_connect:TLSv1.3 read encrypted extensions
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
verify error:num=18:self-signed certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
verify return:1
read from 0x184b47c7a80 [0x184b4bb9a83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 60                                    ....`
read from 0x184b47c7a80 [0x184b4bb9a88] (96 bytes => 96 (0x60))
0000 - a9 35 f9 6f 84 a3 bb 92-be e3 e7 64 19 34 d3 04   .5.o.......d.4..
0010 - bc 25 1d dd a4 61 aa 51-66 46 c9 6a 64 89 73 88   .%...a.QfF.jd.s.
0020 - 1e bc de 29 d8 e1 94 03-36 40 8d 42 1a 8d cc 7d   ...)....6@.B...}
0030 - e0 2f c3 15 b7 93 2c f7-1e d7 a7 5a 75 f3 04 47   ./....,....Zu..G
0040 - ae fc ff 5b 15 48 75 31-90 69 15 8a d1 01 51 fc   ...[.Hu1.i....Q.
0050 - 1e 88 01 88 b9 5f 2a 42-46 6f ed e2 d5 f1 16 f9   ....._*BFo......
SSL_connect:SSLv3/TLS read server certificate
read from 0x184b47c7a80 [0x184b4bb9a83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
read from 0x184b47c7a80 [0x184b4bb9a88] (53 bytes => 53 (0x35))
0000 - 6b ca 3f df 42 73 a0 7e-42 ee a7 5c f9 89 de 65   k.?.Bs.~B..\...e
0010 - c6 93 f2 f9 33 a9 e5 51-b8 8e 8a 56 39 7a 26 f5   ....3..Q...V9z&.
0020 - f8 dd 6f a6 ad 7a 70 f4-c2 ac 8e 28 af 7a ce c7   ..o..zp....(.z..
0030 - 91 16 15 f1 d1                                    .....
SSL_connect:TLSv1.3 read server certificate verify
SSL_connect:SSLv3/TLS read finished
SSL_connect:SSLv3/TLS write change cipher spec
write to 0x184b47c7a80 [0x184b4bb2b60] (64 bytes => 64 (0x40))
0000 - 14 03 03 00 01 01 17 03-03 00 35 dd c6 1d c7 38   ..........5....8
0010 - e1 67 5a 93 5f 09 df 16-8d 45 3c bb 60 5c e6 f7   .gZ._....E<.`\..
0020 - 00 9d d0 1d 09 95 2c 58-46 8c 1c ee 31 e4 5f ef   ......,XF...1._.
0030 - 98 a8 3e 4a 3e 38 15 4c-28 d8 6c 72 b8 19 fe e1   ..>J>8.L(.lr....
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
Negotiated TLS1.3 group: MLKEM768
---
SSL handshake has read 1935 bytes and written 1428 bytes
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
read from 0x184b47c7a80 [0x184b4bac5f3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
read from 0x184b47c7a80 [0x184b4bac5f8] (234 bytes => 234 (0xEA))
0000 - bf 5c 3b 38 c6 6b 58 fa-39 7c 92 27 4a 21 56 ae   .\;8.kX.9|.'J!V.
0010 - 02 f5 0f e6 2d 18 f4 2b-88 37 08 d0 f8 b6 39 57   ....-..+.7....9W
0020 - af 1f a1 d8 cc 8a fb c5-5f c8 e6 48 4f fb d0 86   ........_..HO...
0030 - ae 1f ec 9c 7d c8 16 17-65 01 1f 32 d9 76 5f 28   ....}...e..2.v_(
0040 - cd b5 52 82 32 6f fd 10-d3 6a 97 e1 84 a7 b3 21   ..R.2o...j.....!
0050 - ee 54 fe f6 37 02 cf 4c-1b da 5e d3 84 10 fc 8b   .T..7..L..^.....
0060 - 79 93 18 5c 0d a8 52 f9-2b c1 0d ea 35 b0 4c ac   y..\..R.+...5.L.
0070 - 5f d2 33 52 5c 59 bc ca-d6 1f a9 b8 ea a1 02 7a   _.3R\Y.........z
0080 - f6 fa d8 38 7a 36 4a 48-41 df 50 3b dc cb c5 cc   ...8z6JHA.P;....
0090 - 7e 65 70 50 6c d9 30 3b-9d 43 7c fa 67 10 14 4a   ~epPl.0;.C|.g..J
00a0 - ab 76 73 0d b1 7b 4f 91-8c 18 6e a3 b1 74 0d 28   .vs..{O...n..t.(
00b0 - 7f 7a ba 31 00 70 73 ea-a8 35 5f ae 51 19 03 fa   .z.1.ps..5_.Q...
00c0 - 46 54 79 db fa dc cc 0c-83 3b f6 8d 71 96 45 90   FTy......;..q.E.
00d0 - c0 c0 33 2f dc 79 1f 20-58 6e e6 c9 3b 6b 68 39   ..3/.y. Xn..;kh9
00e0 - 8a 6f 2c cd 45 96 dd 02-6d 4d                     .o,.E...mM
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_CCM_SHA256
    Session-ID: 04A7A2B65B3FCD98E484C313E1E67E1623319EFCEF83C257D4B6E75205C095F8
    Session-ID-ctx:
    Resumption PSK: 28F1618795EE0060241F5877908FD383AF48D13D58869CB61D80BB2F34E5379F
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - bf 77 eb fc fe 3c 8c 66-9b e7 4b ee 35 ea a6 4f   .w...<.f..K.5..O
    0010 - 4d a3 86 d8 a6 f7 20 91-b5 21 fc cf 6d 65 74 0b   M..... ..!..met.
    0020 - f2 5f d4 0a d0 30 9e 01-d7 5d a2 68 ff f0 6d a3   ._...0...].h..m.
    0030 - 49 22 e1 1b 15 30 44 88-3b ab 53 08 b9 08 d8 8e   I"...0D.;.S.....
    0040 - f6 aa 8e 76 cb fd 62 bb-f2 1f ec 3f 8b 1d a4 24   ...v..b....?...$
    0050 - b4 02 f1 f5 84 bf de 36-8c fe 47 bb d5 40 e0 33   .......6..G..@.3
    0060 - e9 61 60 c7 3a 7d 73 bb-b8 bc b9 02 e8 fe 92 55   .a`.:}s........U
    0070 - d4 7b 02 9e 13 02 ea f8-27 13 25 53 c7 c1 85 eb   .{......'.%S....
    0080 - 0a 62 3a 4f c5 7f c8 5d-fd c2 c7 7d 93 73 41 34   .b:O...]...}.sA4
    0090 - 63 1c 59 fa e7 af 5d 80-b9 be b1 73 24 4c e4 ed   c.Y...]....s$L..
    00a0 - 55 2c 53 21 f4 84 3f 53-5c 7c 0c cd b6 bf 14 ca   U,S!..?S\|......
    00b0 - 7a 31 6d 3d f6 96 d3 e6-1c fb 2d 01 ce 8b eb 3f   z1m=......-....?

    Start Time: 1760179357
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
read from 0x184b47c7a80 [0x184b4bac5f3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
read from 0x184b47c7a80 [0x184b4bac5f8] (234 bytes => 234 (0xEA))
0000 - 44 1c 4d 1f 20 34 07 9a-33 9f 96 e3 65 f5 38 31   D.M. 4..3...e.81
0010 - 90 b3 67 f0 69 7e 28 eb-a9 e9 e2 07 f5 37 b2 68   ..g.i~(......7.h
0020 - 9a 9c bd 44 f9 a5 d0 48-b0 8d 27 ef ec ec d9 c8   ...D...H..'.....
0030 - a9 f3 d5 fb 3d 2a 46 79-b4 30 be b6 38 60 20 be   ....=*Fy.0..8` .
0040 - 90 ce bc a9 a2 0f 90 f7-74 30 48 be 2e a5 b0 d0   ........t0H.....
0050 - cf c0 11 93 8a 33 54 38-24 ba 16 df b5 7f a6 52   .....3T8$......R
0060 - 29 53 c7 88 76 a5 9a 1e-e1 f4 f0 18 32 ab a6 ca   )S..v.......2...
0070 - ff 2c 9d ca 7e 02 0e 15-7c 06 81 9b c5 6c e9 d7   .,..~...|....l..
0080 - 20 3b de 41 97 d2 bc fe-86 54 02 d0 d5 d2 cd 94    ;.A.....T......
0090 - 55 29 09 b9 fe c3 72 72-00 22 37 31 72 b2 88 89   U)....rr."71r...
00a0 - 39 a0 f5 b1 4e 58 3e b7-91 50 26 17 dc 8d 0b 05   9...NX>..P&.....
00b0 - 46 a8 06 f5 06 15 03 ea-e4 64 2c 5e 42 df fa c1   F........d,^B...
00c0 - 3a 2c 06 6d b8 68 3a 42-2b 3b 33 3a 2b bc fd 43   :,.m.h:B+;3:+..C
00d0 - 96 68 c3 40 4a 3f eb 19-11 e1 c9 03 bd 0f 20 0a   .h.@J?........ .
00e0 - d3 73 3f 06 5e 2a 17 72-b1 d9                     .s?.^*.r..
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_CCM_SHA256
    Session-ID: 1809C12A3E424348848A39D64A6F2C4DA4512C3CB23C7F876DAB4C679D9D9352
    Session-ID-ctx:
    Resumption PSK: 8120A13571F3196B37EAF1530B7989E48B7162D56EC083EF372BA2EC641264F7
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - bf 77 eb fc fe 3c 8c 66-9b e7 4b ee 35 ea a6 4f   .w...<.f..K.5..O
    0010 - 8e 24 03 6b f3 02 f5 c6-b1 0f 56 cb 8a 7b 90 f2   .$.k......V..{..
    0020 - 9b fb fc e7 8d 85 a1 70-f8 e0 66 6d 03 e6 ce 18   .......p..fm....
    0030 - c5 ba 61 08 11 13 4b b5-b2 e9 62 29 b5 a1 69 2c   ..a...K...b)..i,
    0040 - ba 68 a9 a9 9e 8b 05 05-83 38 dd b0 79 04 d3 9e   .h.......8..y...
    0050 - 52 34 e2 2d 71 79 72 59-33 01 5a 54 1e 02 d1 fb   R4.-qyrY3.ZT....
    0060 - fa ac c5 8e 66 ab 20 c0-ac 59 4a ec fb 5d 08 b2   ....f. ..YJ..]..
    0070 - 8d bf 1d 13 65 c8 12 d2-df 73 94 1c 9b 74 48 57   ....e....s...tHW
    0080 - ba be fb 07 84 98 57 b2-4d ee 04 0f c8 44 94 56   ......W.M....D.V
    0090 - d4 1a 1e 69 c5 be eb b6-f1 ce 64 de d7 84 bb 10   ...i......d.....
    00a0 - c3 85 78 b5 b1 3a 3d 1f-c1 32 99 a9 c4 b5 57 83   ..x..:=..2....W.
    00b0 - 4c 9f 49 b5 b5 13 ff 72-8e 34 f9 6f 73 34 60 d6   L.I....r.4.os4`.

    Start Time: 1760179357
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
test
write to 0x184b47c7a80 [0x184b4bb59c3] (28 bytes => 28 (0x1C))
0000 - 17 03 03 00 17 cc fc be-4a 56 06 98 cc 6b 8c 57   ........JV...k.W
0010 - cc a2 3e 8a 3d 39 a8 be-fa e9 99 1a               ..>.=9......
Q
DONE
write to 0x184b47c7a80 [0x184b4bb59c3] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 b7 5b a1-2c 47 2c 62 31 ef 26 20   ......[.,G,b1.&
0010 - 90 36 2d 2c 60 76 13 aa-                          .6-,`v..
SSL3 alert write:warning:close notify
read from 0x184b47c7a80 [0x184b46effa0] (16384 bytes => 24 (0x18))
0000 - 17 03 03 00 13 88 af 26-dd 5a 0b 51 6c c1 6e b2   .......&.Z.Ql.n.
0010 - 76 71 16 83 29 7c ba e0-                          vq..)|..
read from 0x184b47c7a80 [0x184b46effa0] (16384 bytes => 0)
````

[TOC](README.md)
