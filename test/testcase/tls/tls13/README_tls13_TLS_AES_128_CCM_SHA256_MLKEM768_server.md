#### server

````
$ openssl s_server -accept 9000 -cert ecdsa.crt -key ecdsa.key -state -debug -status_verbose -keylogfile sslkeylog -tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256 -groups MLKEM768
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x26fdef9b300 [0x26fdf394be3] (5 bytes => 5 (0x5))
0000 - 16 03 01 05 4f                                    ....O
read from 0x26fdef9b300 [0x26fdf394be8] (1359 bytes => 1359 (0x54F))
0000 - 01 00 05 4b 03 03 72 f4-fd 67 02 bd 47 5a 94 e1   ...K..r..g..GZ..
0010 - e8 0a 91 c9 a8 a2 d7 ed-16 0f 34 45 d3 0e e9 95   ..........4E....
0020 - 9d 96 21 f4 ba 2c 20 60-2e af a4 43 02 b4 47 4c   ..!.., `...C..GL
0030 - 2d 8d b5 1e 69 79 0f 4e-cb e1 88 04 be 83 a5 3b   -...iy.N.......;
0040 - 82 7f 87 d6 e9 2d 8a 00-02 13 04 01 00 05 00 00   .....-..........
0050 - 0a 00 04 00 02 02 01 00-23 00 00 00 16 00 00 00   ........#.......
0060 - 17 00 00 00 0d 00 2a 00-28 09 05 09 06 09 04 04   ......*.(.......
0070 - 03 05 03 06 03 08 07 08-08 08 1a 08 1b 08 1c 08   ................
0080 - 09 08 0a 08 0b 08 04 08-05 08 06 04 01 05 01 06   ................
0090 - 01 00 2b 00 03 02 03 04-00 2d 00 02 01 01 00 33   ..+......-.....3
00a0 - 04 a6 04 a4 02 01 04 a0-ed 5b 6a b4 9b 1d a4 a4   .........[j.....
00b0 - 66 11 d3 60 73 48 b4 80-42 61 be d5 3d f9 ab 75   f..`sH..Ba..=..u
00c0 - 71 72 49 b3 59 05 31 1c-7e 9d da b5 6f 31 91 f0   qrI.Y.1.~...o1..
00d0 - ca 39 60 e3 b6 ab 30 01-96 b9 90 bf 1a 06 ed b1   .9`...0.........
00e0 - 4d f2 87 55 1a 26 37 11-6b 76 32 68 3e d4 91 b3   M..U.&7.kv2h>...
00f0 - 60 8a 1c b8 90 49 38 10-94 47 58 5c df e9 62 5f   `....I8..GX\..b_
0100 - fb 5b d8 7b 16 12 76 93-fe 53 66 30 40 4b 6a d2   .[.{..v..Sf0@Kj.
0110 - 85 7c 30 59 70 18 5d 00-2d 6c f8 c7 54 39 76 09   .|0Yp.].-l..T9v.
0120 - 0a 5a 2b 84 72 ab b5 9b-97 6a a8 0d 6a 2c a4 b0   .Z+.r....j..j,..
0130 - a8 b6 94 b8 0e e3 73 11-84 fb 62 08 e9 a4 7a 10   ......s...b...z.
0140 - 88 00 4d 54 e4 ac 2a b0-c6 cb 07 a1 2c e3 da 4f   ..MT..*.....,..O
0150 - a2 cb 69 0d b6 7a 35 d1-35 bc 42 3c db 9c 10 34   ..i..z5.5.B<...4
0160 - 18 bc f4 f5 10 f7 5b c9-8c ea 5f 81 27 38 d8 e2   ......[..._.'8..
0170 - 3b dc b9 6b 75 49 23 15-05 a8 29 4b 8e 25 a2 8d   ;..kuI#...)K.%..
0180 - 3e 97 2c 73 33 a4 e0 d8-74 ac 36 02 d2 94 80 6d   >.,s3...t.6....m
0190 - 29 24 dd c3 3f a2 25 58-49 e2 53 3b db b7 7f a1   )$..?.%XI.S;....
01a0 - b8 2f a2 55 71 9b c5 97-f5 b7 5d e2 61 17 31 19   ./.Uq.....].a.1.
01b0 - 5a f5 48 d5 47 47 95 c7-43 ff e5 0d 33 1c 71 e1   Z.H.GG..C...3.q.
01c0 - a7 b6 d0 76 a0 03 b8 30-20 92 75 6e 2a 97 7f 08   ...v...0 .un*...
01d0 - 61 9a 61 5f bd 92 3d c6-93 9d 06 79 95 71 a6 10   a.a_..=....y.q..
01e0 - bd a3 39 95 d9 0b 26 8a-48 d3 4a 54 67 18 39 c2   ..9...&.H.JTg.9.
01f0 - 4a ce bc f8 cf cc 79 26-05 9c cd 59 6b 00 80 e3   J.....y&...Yk...
0200 - 7c d6 38 b4 e3 65 6e ab-dc 54 29 37 44 14 44 47   |.8..en..T)7D.DG
0210 - d0 03 3d fd dc 4d 81 2b-17 3a 06 7e d4 eb 4e 25   ..=..M.+.:.~..N%
0220 - d3 35 e9 f3 c9 b6 20 40-51 68 46 c2 11 08 08 da   .5.... @QhF.....
0230 - bf ea f4 62 61 fa 82 0a-63 b1 5a bb 08 e9 70 91   ...ba...c.Z...p.
0240 - b1 78 07 8b 5a 70 23 72-c1 aa 12 78 7b 17 4b 5e   .x..Zp#r...x{.K^
0250 - 93 78 80 f5 1b c1 03 04-2f a2 75 05 ec c8 23 ea   .x....../.u...#.
0260 - 02 9e 80 5c 13 95 00 f7-c3 19 ea 2c 45 4c ca 63   ...\.......,EL.c
0270 - e9 71 2e 48 b2 72 99 45-7c 3a 54 a1 69 7b bc 02   .q.H.r.E|:T.i{..
0280 - f6 b4 f9 a0 64 a9 f5 8b-f5 f0 09 de 52 47 7d 25   ....d.......RG}%
0290 - 2a 51 62 74 97 17 67 8e-36 6b eb cc 32 f7 73 9a   *Qbt..g.6k..2.s.
02a0 - 69 49 cc f7 60 8b cd 6c-59 4c ec 05 6c c7 50 46   iI..`..lYL..l.PF
02b0 - b7 0d 70 56 3e 60 85 6c-19 9a a1 c5 b4 75 d4 27   ..pV>`.l.....u.'
02c0 - 65 f8 5c 73 c4 25 07 5a-15 05 32 17 a0 a0 b7 87   e.\s.%.Z..2.....
02d0 - dd d5 ca 09 39 47 d4 0a-0a 75 fa 1d e7 27 ac 65   ....9G...u...'.e
02e0 - 36 4f 7c 07 7c 3d 94 bc-3f b1 3d 7f e6 25 c2 77   6O|.|=..?.=..%.w
02f0 - 22 da 52 2e a3 e7 01 d9-c0 07 5d 57 06 96 2a 31   ".R.......]W..*1
0300 - cd 37 6b a2 27 39 16 f8-aa be 76 b3 45 80 36 5b   .7k.'9....v.E.6[
0310 - 92 c3 be 60 0e 21 67 60-2f 54 4a b3 75 0a 76 98   ...`.!g`/TJ.u.v.
0320 - 3a fd d4 79 90 97 22 ec-50 c5 fe b7 93 82 02 87   :..y..".P.......
0330 - 8f d4 cd 66 92 75 17 6c-b8 a7 6c 43 ef c8 10 14   ...f.u.l..lC....
0340 - 78 b3 2d 86 72 0d 6a 08-03 e1 4f 62 3a cc 82 52   x.-.r.j...Ob:..R
0350 - c0 b2 77 5b c8 c5 4a 58-b4 4e 50 d8 9b 4a a1 bc   ..w[..JX.NP..J..
0360 - 73 94 cf c7 58 b0 3d c4-bb 6b d1 3e f5 7b 03 e0   s...X.=..k.>.{..
0370 - 0c 5d 2f ac 7b 96 0a 04-a4 e7 a2 52 62 9d b3 d4   .]/.{......Rb...
0380 - c6 22 d2 c4 eb c9 20 a2-94 ca fa ec b9 42 2a 3d   .".... ......B*=
0390 - 2a 50 72 a8 f2 5c 4c 3b-8a c7 e9 1a 32 e5 31 a9   *Pr..\L;....2.1.
03a0 - 81 a6 5e e9 5a c4 e3 18-bd 83 ae d4 54 04 81 a3   ..^.Z.......T...
03b0 - c5 ae e5 4c 89 cb 7d 78-14 c2 77 40 c1 86 5a 99   ...L..}x..w@..Z.
03c0 - 0e f7 73 78 b8 3d 68 04-c0 c8 b5 52 16 fa 10 90   ..sx.=h....R....
03d0 - 66 34 de 1b 48 1b 84 b5-dc 71 a5 05 f7 b1 4e b0   f4..H....q....N.
03e0 - 20 84 97 69 a5 46 09 af-1c 33 87 65 88 86 c7 3b    ..i.F...3.e...;
03f0 - 0f 1a 23 1e 61 4a e5 e4-22 d6 c7 61 b5 b6 bb 87   ..#.aJ.."..a....
0400 - c1 0a 8d 8a 53 d1 f3 05-ae 60 23 fb f5 65 3e 0a   ....S....`#..e>.
0410 - 13 d3 1b c5 d5 74 be 87-58 85 58 29 cc fe c3 37   .....t..X.X)...7
0420 - a1 91 42 89 39 ca 7f f9-02 10 72 04 7b e8 95 cf   ..B.9.....r.{...
0430 - 04 77 1b 4c 1b 31 bc ba-a2 d9 86 c0 a8 44 08 64   .w.L.1.......D.d
0440 - a1 3a 41 85 df da 7c ca-57 26 72 71 44 0d 24 6b   .:A...|.W&rqD.$k
0450 - 0d 56 49 77 54 a1 12 03-8c 32 f2 3f 0c b7 15 e5   .VIwT....2.?....
0460 - f6 5d 59 87 1a f5 d3 56-7e e8 38 22 16 b4 3f 62   .]Y....V~.8"..?b
0470 - 62 38 5b 93 de 52 45 a3-bc 59 b0 b2 0f 5a 17 b0   b8[..RE..Y...Z..
0480 - fc ca 01 d0 dc 56 8c c1-1c c0 88 25 12 a6 04 34   .....V.....%...4
0490 - a7 5f a2 59 a2 86 33 07-78 da 35 94 e5 27 9b d6   ._.Y..3.x.5..'..
04a0 - 56 6c b8 a4 81 f2 b9 8f-cb 61 c9 56 99 bb 9a a6   Vl.......a.V....
04b0 - 72 50 7e 04 8b 4c 6a 59-9d 01 63 1c c4 d1 9e 48   rP~..LjY..c....H
04c0 - 32 8a 96 78 ce 10 8b 56-a2 78 59 fc 6c 58 6b 92   2..x...V.xY.lXk.
04d0 - 67 46 35 16 86 28 8b 0e-02 ad 3c ab ab 11 72 19   gF5..(....<...r.
04e0 - 37 06 57 c2 f0 a9 2e 92-3b 9e 39 bd ce c0 2a 6a   7.W.....;.9...*j
04f0 - b8 bb 86 93 ac 17 72 22-5d 07 b8 1d 10 a3 fe 4a   ......r"]......J
0500 - 88 ef a3 04 07 57 cf 2c-95 45 51 bb 28 87 db 88   .....W.,.EQ.(...
0510 - b5 e9 27 d1 7c 25 d4 30-4e 30 8b 9c e2 f6 38 87   ..'.|%.0N0....8.
0520 - d9 95 62 06 a1 bf 36 bd-11 40 21 77 38 c6 b4 98   ..b...6..@!w8...
0530 - 3a ab 42 0b ae a9 90 20-0a c8 05 35 77 b5 00 21   :.B.... ...5w..!
0540 - 16 f5 00 d1 45 82 9b ea-00 1b 00 03 02 00 01      ....E..........
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write change cipher spec
SSL_accept:TLSv1.3 write encrypted extensions
SSL_accept:SSLv3/TLS write certificate
SSL_accept:TLSv1.3 write server certificate verify
write to 0x26fdef9b300 [0x26fdf393bd0] (1935 bytes => 1935 (0x78F))
0000 - 16 03 03 04 9a 02 00 04-96 03 03 6a 69 9e 35 aa   ...........ji.5.
0010 - 5d 94 65 01 ca ca e9 34-3d a1 2f eb 04 30 af 3f   ].e....4=./..0.?
0020 - 0a 69 18 14 91 f7 90 09-53 69 29 20 60 2e af a4   .i......Si) `...
0030 - 43 02 b4 47 4c 2d 8d b5-1e 69 79 0f 4e cb e1 88   C..GL-...iy.N...
0040 - 04 be 83 a5 3b 82 7f 87-d6 e9 2d 8a 13 04 00 04   ....;.....-.....
0050 - 4e 00 2b 00 02 03 04 00-33 04 44 02 01 04 40 41   N.+.....3.D...@A
0060 - 37 fc af 19 68 aa 75 90-62 a8 2b e7 4c 3a 1c 51   7...h.u.b.+.L:.Q
0070 - eb d8 34 98 46 7f aa 62-48 2e 5b 31 97 0a a8 f4   ..4.F..bH.[1....
0080 - 95 30 d4 37 1e ce 95 2f-d6 61 a3 f7 2e c4 1c 39   .0.7.../.a.....9
0090 - 94 5c fc 43 00 34 e9 de-e9 dd 92 22 59 35 17 36   .\.C.4....."Y5.6
00a0 - f1 5c 6b 93 62 7e 20 7c-5d 18 35 8d d6 d1 46 e9   .\k.b~ |].5...F.
00b0 - e9 68 b9 37 5c 31 ba f0-70 4f 66 cd e2 53 ba 4f   .h.7\1..pOf..S.O
00c0 - 16 cf 8e 1b 37 40 20 eb-36 1f 3d 1a 8c f7 e4 81   ....7@ .6.=.....
00d0 - 1d 2d 56 73 33 8e 52 0f-9e 79 69 7d 1c 05 e4 6c   .-Vs3.R..yi}...l
00e0 - de 1b b3 a8 8f 08 be 4b-a8 9b e4 11 c7 b2 2e ce   .......K........
00f0 - bb 3f 6d f9 41 fd d6 a6-51 c3 d4 f0 57 0d 1b 6b   .?m.A...Q...W..k
0100 - 7e 60 ea 30 8c 55 93 67-21 2a ac de ca a7 a1 80   ~`.0.U.g!*......
0110 - af b3 b6 fe 74 85 e7 39-96 eb f5 68 70 f0 19 44   ....t..9...hp..D
0120 - 13 d4 ac f0 4f c8 a2 32-12 0c 9b 0b 49 88 2b 1d   ....O..2....I.+.
0130 - 48 4b 1b 1c c6 8c aa 0c-c1 85 7a 48 3f eb b5 18   HK........zH?...
0140 - 63 65 c5 fa 5f e5 97 e8-df 6a 36 68 51 9c 65 84   ce.._....j6hQ.e.
0150 - f7 62 5a 2d 44 95 40 31-a8 ea a3 6d 46 8d 63 a1   .bZ-D.@1...mF.c.
0160 - bb 6d 4d 64 4f 8d 06 7f-99 04 70 5e 0b 88 70 07   .mMdO.....p^..p.
0170 - 4a dd 76 b5 a4 0d 04 88-c5 19 47 98 e1 30 78 7d   J.v.......G..0x}
0180 - c2 a4 11 c9 a9 f8 5b 7b-8b 03 c4 d5 38 d2 77 f2   ......[{....8.w.
0190 - 76 5d 86 35 d8 e9 27 54-fa 1f 1e 7e 9c a0 d8 37   v].5..'T...~...7
01a0 - 88 8a 20 28 5b 62 c0 be-01 47 3b ac c4 8f 91 36   .. ([b...G;....6
01b0 - 97 b0 58 23 6d ec 39 50-71 5c 66 7b f6 58 ee 22   ..X#m.9Pq\f{.X."
01c0 - 37 ac ac 34 62 cf e6 d4-98 87 fe cf 22 f8 e1 50   7..4b......."..P
01d0 - 95 0c ba 35 88 59 dd 24-97 96 35 c1 39 a6 de 7c   ...5.Y.$..5.9..|
01e0 - 5f 46 31 b6 76 1a 47 ea-26 15 3c dd 34 77 11 f9   _F1.v.G.&.<.4w..
01f0 - e8 9e 50 72 4a 6d c8 d4-02 6f be e8 7c 5f b5 96   ..PrJm...o..|_..
0200 - de c4 09 cc 21 26 62 b6-fc e7 55 76 bc a0 e2 27   ....!&b...Uv...'
0210 - 6c 8b f1 c9 e5 ee 02 07-7d 41 6c 0b 41 9d ce 76   l.......}Al.A..v
0220 - 94 5f c4 da 3c 83 57 ac-d3 d1 7e c3 8f 1c 1f 51   ._..<.W...~....Q
0230 - 3c f5 93 41 0e 35 5f 0f-c1 ec 54 d5 84 28 90 34   <..A.5_...T..(.4
0240 - 5d 28 33 0d c1 48 93 97-cd 0e 90 a3 f9 b1 a0 cd   ](3..H..........
0250 - 22 86 ee 92 bd 5d 82 38-c1 74 59 b4 80 57 11 fb   "....].8.tY..W..
0260 - 02 5e 14 3a be 8d ed 44-79 07 af d0 13 c7 b5 85   .^.:...Dy.......
0270 - 5f 8a 4d 32 75 4e 03 ba-93 6f 92 9c 01 1b 14 cf   _.M2uN...o......
0280 - 46 e0 38 e9 65 16 88 65-d8 01 15 49 de 51 c9 e7   F.8.e..e...I.Q..
0290 - c1 f7 b5 c3 fd a8 f3 6d-7b 5c f8 38 1c ee d9 29   .......m{\.8...)
02a0 - 45 56 c3 1d 03 d2 73 bc-38 f2 c6 10 b5 d8 ba f5   EV....s.8.......
02b0 - 67 48 4b b2 77 5f 70 2e-9c ac a4 26 f9 43 03 7c   gHK.w_p....&.C.|
02c0 - e0 ab 36 ef 34 85 e0 05-84 9d 87 84 34 48 e5 50   ..6.4.......4H.P
02d0 - e8 b4 9b ae d1 0f 77 05-f7 cb 24 61 bc 04 85 19   ......w...$a....
02e0 - 93 d2 ba 12 23 77 b3 7b-4e d2 41 7d d5 35 62 ca   ....#w.{N.A}.5b.
02f0 - 40 e9 28 57 05 a8 54 70-16 86 f9 7e 81 b8 71 44   @.(W..Tp...~..qD
0300 - f5 dd d0 27 b8 7e 73 c3-fd e4 ca cc 01 a1 dc 77   ...'.~s........w
0310 - dd e8 2a 86 31 de 24 20-c1 93 92 a8 4d a3 0d ca   ..*.1.$ ....M...
0320 - aa 2c 1e 98 45 67 36 a6-2e 54 bb f5 dc ad e6 70   .,..Eg6..T.....p
0330 - f0 25 15 3b ee 00 88 d5-17 72 c0 79 91 0e 52 20   .%.;.....r.y..R
0340 - 68 c1 9f cb 18 e9 3a f7-8b 55 85 96 e5 75 44 31   h.....:..U...uD1
0350 - ea b7 b6 12 0a f6 4a d3-45 e3 42 61 63 8c 5c 98   ......J.E.Bac.\.
0360 - 58 63 88 51 32 81 c0 87-c4 58 2a 15 f6 2b 0a 09   Xc.Q2....X*..+..
0370 - 8e 53 fc 83 bd 3f 65 55-7b 53 52 05 04 35 dd f2   .S...?eU{SR..5..
0380 - cb 71 4f 49 99 bc b6 54-47 ae d6 dd 5d c4 d9 9e   .qOI...TG...]...
0390 - a1 52 67 2c c5 e9 e3 e3-15 fb 20 f8 e5 17 eb 93   .Rg,...... .....
03a0 - 52 02 df 1e 94 e6 0f 82-9a a0 56 5b 24 70 c0 02   R.........V[$p..
03b0 - c2 03 47 1d 74 58 a5 4a-31 72 27 18 e4 ad 2b b8   ..G.tX.J1r'...+.
03c0 - 1a 86 59 12 56 b3 0d 7b-2f 0c 63 1d fb 4b f4 d2   ..Y.V..{/.c..K..
03d0 - 07 53 b0 3b 5b 86 d5 93-e2 f1 76 89 a5 4e 3b 7c   .S.;[.....v..N;|
03e0 - 47 cc be d5 82 44 5d 40-79 da 4d cf a9 1e 58 3b   G....D]@y.M...X;
03f0 - a0 64 ee ad eb c1 ad 1e-a8 bb fa 9b 4c b9 29 6e   .d..........L.)n
0400 - 2d 8d a2 17 4f b2 e3 76-8f d0 8b 30 2b 2b 07 46   -...O..v...0++.F
0410 - 51 a7 9d dc 34 cc b4 87-a9 50 eb fd db 86 fb f4   Q...4....P......
0420 - 84 f7 f0 04 79 d6 30 7c-1b d9 15 0b 65 7f 64 46   ....y.0|....e.dF
0430 - fd 9f ca 09 71 c6 68 ed-da 82 aa f5 a8 72 ec 7b   ....q.h......r.{
0440 - aa eb 15 6e f7 36 ba 6d-63 1c 57 05 e8 7b 8b 6d   ...n.6.mc.W..{.m
0450 - 96 40 b7 af ce 47 10 98-48 77 da 18 80 8b e8 5e   .@...G..Hw.....^
0460 - 03 97 ae 6e 04 c7 32 2d-08 ff f7 15 17 ff 50 91   ...n..2-......P.
0470 - 4c 5f 22 69 06 bd 5f 47-1f 0a e5 6f f6 04 f5 32   L_"i.._G...o...2
0480 - 37 6c 25 49 a1 64 18 dd-e7 c5 0d 99 c0 88 28 f0   7l%I.d........(.
0490 - 85 02 a4 e8 ea 82 01 b9-0c 3b c5 ae 38 d7 be 14   .........;..8...
04a0 - 03 03 00 01 01 17 03 03-00 17 16 d8 b6 ca 85 56   ...............V
04b0 - 2d 1e 4e 5b 9d 5a f0 15-bc 52 94 65 ed 83 36 f6   -.N[.Z...R.e..6.
04c0 - 0c 17 03 03 02 2a 5f 16-03 81 2b 81 d8 ec bc e5   .....*_...+.....
04d0 - ed 77 67 08 66 e2 f1 87-27 aa 97 89 e7 0c cd ae   .wg.f...'.......
04e0 - c7 04 d5 a3 a6 cf ec 9c-7f 28 a4 39 37 73 c0 98   .........(.97s..
04f0 - 40 d2 6d a5 d3 ab 46 75-d0 52 f7 2a fd 8c 5f 29   @.m...Fu.R.*.._)
0500 - 99 59 ae 76 b6 36 e3 ae-2a 48 76 d3 49 31 e3 8d   .Y.v.6..*Hv.I1..
0510 - fd 4b ab e7 ab ee f9 23-13 19 7e 00 1b ca da eb   .K.....#..~.....
0520 - a0 aa 47 fe ec 21 df 32-ba f2 96 54 2a d4 b2 60   ..G..!.2...T*..`
0530 - bb a4 db 32 71 10 13 50-3e 3d 86 49 03 2f 7a a4   ...2q..P>=.I./z.
0540 - b7 d4 60 be db 1a eb d9-0a 4b 30 a5 e4 e2 ae 63   ..`......K0....c
0550 - d4 03 b6 d9 34 bc ee af-ed 08 f1 07 3e fd 10 12   ....4.......>...
0560 - f1 48 53 c4 64 6f 7e 90-f3 ff a0 b8 ee e4 6b a0   .HS.do~.......k.
0570 - be 54 54 75 41 41 a5 65-a0 c1 bf 71 d9 63 ca d7   .TTuAA.e...q.c..
0580 - 94 5b 80 ca 98 f9 fa ef-4f 8e d0 9e f3 02 6c 97   .[......O.....l.
0590 - 24 f0 49 5d 74 e1 03 66-5e 5a 61 bf ee 79 2d f7   $.I]t..f^Za..y-.
05a0 - 8c ae 53 20 9d aa 8e 24-86 60 c3 6a aa 17 a0 d3   ..S ...$.`.j....
05b0 - ad d6 b6 d0 fc d8 0c ac-b4 2b 34 2f f1 f5 6d 7f   .........+4/..m.
05c0 - f9 37 2b 34 b4 a4 4d bc-79 41 94 03 1d 2f ca ad   .7+4..M.yA.../..
05d0 - 91 42 11 40 7f fb 40 cd-0e 68 bb 2a 86 eb 94 10   .B.@..@..h.*....
05e0 - 0e 76 60 28 57 ee db 92-a8 e1 49 73 41 46 88 67   .v`(W.....IsAF.g
05f0 - 2d c7 f4 1c 47 00 61 bf-4e 5b 3e 64 18 6a 6b 2d   -...G.a.N[>d.jk-
0600 - 80 a2 38 c9 5b b6 b9 80-a2 12 69 3d 82 a8 6b 2b   ..8.[.....i=..k+
0610 - 90 10 2f 29 6e c8 1a 44-f6 bf 39 37 19 17 b7 2d   ../)n..D..97...-
0620 - 9e 9c c7 4e f7 e0 22 69-50 08 0c 2d 03 e6 0d 7a   ...N.."iP..-...z
0630 - 3d f9 ec 91 84 a3 f5 af-e7 9c d1 bf 71 4d 79 90   =...........qMy.
0640 - 97 d4 d0 47 78 d3 ef 10-f1 a8 e0 69 67 5c a5 8d   ...Gx......ig\..
0650 - b7 c8 58 8a ea 10 1d 7d-48 6f 09 4c d0 9a 9b 78   ..X....}Ho.L...x
0660 - 48 4f d1 3b ec 17 c6 9e-e9 f5 bc cb fb 81 1e db   HO.;............
0670 - 9d 97 fb a5 64 78 de 6b-47 25 bb f0 ba a0 5f 26   ....dx.kG%...._&
0680 - 38 b5 97 3a 1a 5d 54 d5-4f 4f 86 13 10 fe ef a7   8..:.]T.OO......
0690 - 88 a4 b2 f9 5f 76 f7 52-fa 3b ec 12 96 02 bd 79   ...._v.R.;.....y
06a0 - 23 88 04 2f 2c 42 d6 ec-b9 fc c0 2a 0e 96 11 a5   #../,B.....*....
06b0 - 58 97 0f 2f dd f2 02 34-39 8e 2b 10 4a ad 92 81   X../...49.+.J...
06c0 - e9 bf 78 6a 01 79 69 f9-81 a7 c8 ad 7d 11 aa 3f   ..xj.yi.....}..?
06d0 - 75 e8 62 cd 2c ab 7a a5-96 f5 86 40 6d af 11 e8   u.b.,.z....@m...
06e0 - 66 fc 93 e4 5a 6d d1 e9-7f 9b 4e f8 01 34 ad 0b   f...Zm....N..4..
06f0 - 17 03 03 00 60 a9 35 f9-6f 84 a3 bb 92 be e3 e7   ....`.5.o.......
0700 - 64 19 34 d3 04 bc 25 1d-dd a4 61 aa 51 66 46 c9   d.4...%...a.QfF.
0710 - 6a 64 89 73 88 1e bc de-29 d8 e1 94 03 36 40 8d   jd.s....)....6@.
0720 - 42 1a 8d cc 7d e0 2f c3-15 b7 93 2c f7 1e d7 a7   B...}./....,....
0730 - 5a 75 f3 04 47 ae fc ff-5b 15 48 75 31 90 69 15   Zu..G...[.Hu1.i.
0740 - 8a d1 01 51 fc 1e 88 01-88 b9 5f 2a 42 46 6f ed   ...Q......_*BFo.
0750 - e2 d5 f1 16 f9 17 03 03-00 35 6b ca 3f df 42 73   .........5k.?.Bs
0760 - a0 7e 42 ee a7 5c f9 89-de 65 c6 93 f2 f9 33 a9   .~B..\...e....3.
0770 - e5 51 b8 8e 8a 56 39 7a-26 f5 f8 dd 6f a6 ad 7a   .Q...V9z&...o..z
0780 - 70 f4 c2 ac 8e 28 af 7a-ce c7 91 16 15 f1 d1      p....(.z.......
SSL_accept:SSLv3/TLS write finished
SSL_accept:TLSv1.3 early data
read from 0x26fdef9b300 [0x26fdf394be3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x26fdef9b300 [0x26fdf394be8] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x26fdef9b300 [0x26fdf394be3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
read from 0x26fdef9b300 [0x26fdf394be8] (53 bytes => 53 (0x35))
0000 - dd c6 1d c7 38 e1 67 5a-93 5f 09 df 16 8d 45 3c   ....8.gZ._....E<
0010 - bb 60 5c e6 f7 00 9d d0-1d 09 95 2c 58 46 8c 1c   .`\........,XF..
0020 - ee 31 e4 5f ef 98 a8 3e-4a 3e 38 15 4c 28 d8 6c   .1._...>J>8.L(.l
0030 - 72 b8 19 fe e1                                    r....
SSL_accept:TLSv1.3 early data
SSL_accept:SSLv3/TLS read finished
write to 0x26fdef9b300 [0x26fdf393bd0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea bf 5c 3b-38 c6 6b 58 fa 39 7c 92   ......\;8.kX.9|.
0010 - 27 4a 21 56 ae 02 f5 0f-e6 2d 18 f4 2b 88 37 08   'J!V.....-..+.7.
0020 - d0 f8 b6 39 57 af 1f a1-d8 cc 8a fb c5 5f c8 e6   ...9W........_..
0030 - 48 4f fb d0 86 ae 1f ec-9c 7d c8 16 17 65 01 1f   HO.......}...e..
0040 - 32 d9 76 5f 28 cd b5 52-82 32 6f fd 10 d3 6a 97   2.v_(..R.2o...j.
0050 - e1 84 a7 b3 21 ee 54 fe-f6 37 02 cf 4c 1b da 5e   ....!.T..7..L..^
0060 - d3 84 10 fc 8b 79 93 18-5c 0d a8 52 f9 2b c1 0d   .....y..\..R.+..
0070 - ea 35 b0 4c ac 5f d2 33-52 5c 59 bc ca d6 1f a9   .5.L._.3R\Y.....
0080 - b8 ea a1 02 7a f6 fa d8-38 7a 36 4a 48 41 df 50   ....z...8z6JHA.P
0090 - 3b dc cb c5 cc 7e 65 70-50 6c d9 30 3b 9d 43 7c   ;....~epPl.0;.C|
00a0 - fa 67 10 14 4a ab 76 73-0d b1 7b 4f 91 8c 18 6e   .g..J.vs..{O...n
00b0 - a3 b1 74 0d 28 7f 7a ba-31 00 70 73 ea a8 35 5f   ..t.(.z.1.ps..5_
00c0 - ae 51 19 03 fa 46 54 79-db fa dc cc 0c 83 3b f6   .Q...FTy......;.
00d0 - 8d 71 96 45 90 c0 c0 33-2f dc 79 1f 20 58 6e e6   .q.E...3/.y. Xn.
00e0 - c9 3b 6b 68 39 8a 6f 2c-cd 45 96 dd 02 6d 4d      .;kh9.o,.E...mM
SSL_accept:SSLv3/TLS write session ticket
write to 0x26fdef9b300 [0x26fdf393bd0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea 44 1c 4d-1f 20 34 07 9a 33 9f 96   .....D.M. 4..3..
0010 - e3 65 f5 38 31 90 b3 67-f0 69 7e 28 eb a9 e9 e2   .e.81..g.i~(....
0020 - 07 f5 37 b2 68 9a 9c bd-44 f9 a5 d0 48 b0 8d 27   ..7.h...D...H..'
0030 - ef ec ec d9 c8 a9 f3 d5-fb 3d 2a 46 79 b4 30 be   .........=*Fy.0.
0040 - b6 38 60 20 be 90 ce bc-a9 a2 0f 90 f7 74 30 48   .8` .........t0H
0050 - be 2e a5 b0 d0 cf c0 11-93 8a 33 54 38 24 ba 16   ..........3T8$..
0060 - df b5 7f a6 52 29 53 c7-88 76 a5 9a 1e e1 f4 f0   ....R)S..v......
0070 - 18 32 ab a6 ca ff 2c 9d-ca 7e 02 0e 15 7c 06 81   .2....,..~...|..
0080 - 9b c5 6c e9 d7 20 3b de-41 97 d2 bc fe 86 54 02   ..l.. ;.A.....T.
0090 - d0 d5 d2 cd 94 55 29 09-b9 fe c3 72 72 00 22 37   .....U)....rr."7
00a0 - 31 72 b2 88 89 39 a0 f5-b1 4e 58 3e b7 91 50 26   1r...9...NX>..P&
00b0 - 17 dc 8d 0b 05 46 a8 06-f5 06 15 03 ea e4 64 2c   .....F........d,
00c0 - 5e 42 df fa c1 3a 2c 06-6d b8 68 3a 42 2b 3b 33   ^B...:,.m.h:B+;3
00d0 - 3a 2b bc fd 43 96 68 c3-40 4a 3f eb 19 11 e1 c9   :+..C.h.@J?.....
00e0 - 03 bd 0f 20 0a d3 73 3f-06 5e 2a 17 72 b1 d9      ... ..s?.^*.r..
SSL_accept:SSLv3/TLS write session ticket
-----BEGIN SSL SESSION PARAMETERS-----
MHQCAQECAgMEBAITBAQgY4KBkOpBCVC6ubDx0cWem5ajz8b1eMzO5tOpyddF6YEE
IIEgoTVx8xlrN+rxUwt5ieSLcWLVbsCD7zcrouxkEmT3oQYCBGjqNJ2iBAICHCCk
BgQEAQAAAK4HAgUAySkYVLMEAgICAQ==
-----END SSL SESSION PARAMETERS-----
Shared ciphers:TLS_AES_128_CCM_SHA256
Signature Algorithms: id-ml-dsa-65:id-ml-dsa-87:id-ml-dsa-44:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:ed448:ecdsa_brainpoolP256r1_sha256:ecdsa_brainpoolP384r1_sha384:ecdsa_brainpoolP512r1_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Shared Signature Algorithms: id-ml-dsa-65:id-ml-dsa-87:id-ml-dsa-44:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:ed448:ecdsa_brainpoolP256r1_sha256:ecdsa_brainpoolP384r1_sha384:ecdsa_brainpoolP512r1_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Supported groups: MLKEM768
Shared groups: MLKEM768
CIPHER is TLS_AES_128_CCM_SHA256
This TLS version forbids renegotiation.
read from 0x26fdef9b300 [0x26fdf3a3113] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x26fdef9b300 [0x26fdf3a3118] (23 bytes => 23 (0x17))
0000 - cc fc be 4a 56 06 98 cc-6b 8c 57 cc a2 3e 8a 3d   ...JV...k.W..>.=
0010 - 39 a8 be fa e9 99 1a                              9......
test
read from 0x26fdef9b300 [0x26fdf3a3113] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 13                                    .....
read from 0x26fdef9b300 [0x26fdf3a3118] (19 bytes => 19 (0x13))
0000 - b7 5b a1 2c 47 2c 62 31-ef 26 20 90 36 2d 2c 60   .[.,G,b1.& .6-,`
0010 - 76 13 aa                                          v..
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x26fdef9b300 [0x26fdf394be3] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 88 af 26-dd 5a 0b 51 6c c1 6e b2   .......&.Z.Ql.n.
0010 - 76 71 16 83 29 7c ba e0-                          vq..)|..
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
