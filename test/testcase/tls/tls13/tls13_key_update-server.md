#### server

````
$ openssl s_server -accept 9000 -cert server-ecdsa.crt -key server-ecdsa.key -state -debug -status_verbose -keylogfile sslkeylog -tls1_3
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x248b45f57b0 [0x248b4616c83] (5 bytes => 5 (0x5))
0000 - 16 03 01 05 ab                                    .....
read from 0x248b45f57b0 [0x248b4616c88] (1451 bytes => 1451 (0x5AB))
0000 - 01 00 05 a7 03 03 1e f0-c3 f2 64 99 56 10 80 3e   ..........d.V..>
0010 - b0 a1 d1 40 d7 0a 80 52-e9 50 cc 9b 0c 5a 71 63   ...@...R.P...Zqc
0020 - 18 af 6b d2 ef 88 20 c9-67 9c b3 07 c2 d3 5b ff   ..k... .g.....[.
0030 - 34 15 fa d3 13 1c 4c 6e-e1 86 cc 2b f7 c9 87 96   4.....Ln...+....
0040 - fc ef 4e 5d 7c 5c 2f 00-06 13 02 13 03 13 01 01   ..N]|\/.........
0050 - 00 05 58 00 0b 00 02 01-00 00 0a 00 12 00 10 11   ..X.............
0060 - ec 00 1d 00 17 00 1e 00-18 00 19 01 00 01 01 00   ................
0070 - 23 00 00 00 16 00 00 00-17 00 00 00 0d 00 2a 00   #.............*.
0080 - 28 09 05 09 06 09 04 04-03 05 03 06 03 08 07 08   (...............
0090 - 08 08 1a 08 1b 08 1c 08-09 08 0a 08 0b 08 04 08   ................
00a0 - 05 08 06 04 01 05 01 06-01 00 2b 00 03 02 03 04   ..........+.....
00b0 - 00 2d 00 02 01 01 00 33-04 ea 04 e8 11 ec 04 c0   .-.....3........
00c0 - 92 62 c1 34 73 32 5e 47-cc cc 36 48 2d d2 29 dc   .b.4s2^G..6H-.).
00d0 - b2 2a 79 4c 43 91 ba ca-be a6 1e e3 35 bf 4c 1b   .*yLC.......5.L.
00e0 - 20 e0 9b 8e 6d 00 cd 17-c5 c2 97 ec be 47 06 29    ...m........G.)
00f0 - 5a a4 50 9b 58 85 25 44-cc 97 20 37 51 71 42 ff   Z.P.X.%D.. 7QqB.
0100 - 51 43 c6 60 ad 32 95 65-57 07 94 af 4a 6a 5a 98   QC.`.2.eW...JjZ.
0110 - b3 f2 7a 83 b2 e4 5b be-36 94 57 d3 a8 11 39 3d   ..z...[.6.W...9=
0120 - 1e 20 71 d7 b1 8d e1 0b-be f3 f6 64 e4 78 a9 da   . q........d.x..
0130 - f5 24 32 00 09 77 88 65-54 05 a0 a3 95 26 46 4c   .$2..w.eT....&FL
0140 - 7a 97 51 3d c5 1c c3 04-d1 c9 f6 d6 88 84 33 64   z.Q=..........3d
0150 - 9a 6c 22 a9 26 6e 1f ab-a6 35 78 2e 8b c7 0f 09   .l".&n...5x.....
0160 - 92 3b 7b 38 b8 e2 19 b0-2c 34 3d 0b e9 24 3c 6b   .;{8....,4=..$<k
0170 - 1c 41 f8 5c fb 09 86 c1-26 58 16 c2 00 02 3c c5   .A.\....&X....<.
0180 - e0 25 78 1b bb 68 7a e2-44 6d 39 41 e1 fc 0d f6   .%x..hz.Dm9A....
0190 - 81 3d d5 50 50 e2 ba 97-b3 f6 b3 c0 a9 2d 3f 0c   .=.PP........-?.
01a0 - 4d ff 29 48 70 52 31 b6-2a 75 56 21 17 f0 99 6d   M.)HpR1.*uV!...m
01b0 - 17 c0 17 23 49 41 71 35-3b 50 d0 53 c9 93 9d c5   ...#IAq5;P.S....
01c0 - 79 b2 50 38 2d f6 4c 68-96 a5 a0 9e bb 2d 99 68   y.P8-.Lh.....-.h
01d0 - 55 75 fc 35 96 86 94 d9-f0 69 6f d0 cb 3b 6b a0   Uu.5.....io..;k.
01e0 - bd ac 87 1e 92 98 de ac-74 67 c0 42 76 b8 5e 29   ........tg.Bv.^)
01f0 - 03 74 61 49 35 04 87 68-4c 37 a7 67 b3 6a 8e cb   .taI5..hL7.g.j..
0200 - 2b b5 56 cd 7f 92 bf 1b-aa ca 91 68 6f 3a c2 61   +.V........ho:.a
0210 - d7 a6 83 93 15 7b 1a 7c-c3 4c 2b 06 a7 c2 3a 6c   .....{.|.L+...:l
0220 - 1a a8 01 00 7f 6c 50 28-c4 e2 74 88 2a 47 8a 36   .....lP(..t.*G.6
0230 - 2f ea 71 7e 8b 2a 74 89-9c 3e 8c b3 08 36 8b cd   /.q~.*t..>...6..
0240 - 80 b2 06 a9 fc 13 8e 78-b3 b0 10 a0 ec c9 7c 98   .......x......|.
0250 - ba 4b ba c4 ce 08 a7 85-2a 90 a5 75 d8 30 15 e4   .K......*..u.0..
0260 - a2 af 04 af 13 7c 2d 63-52 24 5f 05 ab b5 23 52   .....|-cR$_...#R
0270 - 44 fb 68 f6 44 2f b6 27-c7 92 4a 5e f2 7a 92 a7   D.h.D/.'..J^.z..
0280 - 16 c1 77 cb c7 56 8b bc-bb 93 49 6e 37 81 6e 56   ..w..V....In7.nV
0290 - 08 83 18 35 7d 54 ad 48-b2 34 5a 29 16 99 30 3f   ...5}T.H.4Z)..0?
02a0 - 50 4a 48 80 e6 5d 9f 95-38 88 5b ba 13 27 83 62   PJH..]..8.[..'.b
02b0 - a1 1c ab 39 11 70 f3 76-a4 b3 94 40 20 1c 7f 91   ...9.p.v...@ ...
02c0 - c6 5c c7 12 cd 17 64 9b-c3 44 d9 c6 0e 14 2b c1   .\....d..D....+.
02d0 - 11 41 0a 94 6b 7d 1c b4-56 bd b3 67 90 06 8d 12   .A..k}..V..g....
02e0 - e6 14 26 7b 80 6d c4 7a-8c 6a 89 7e 70 91 2e b7   ..&{.m.z.j.~p...
02f0 - c2 97 e8 85 b6 07 0e 87-1b 26 30 12 9e 87 27 43   .........&0...'C
0300 - f4 83 04 16 0c 66 49 39-19 e9 32 5e 06 90 07 36   .....fI9..2^...6
0310 - b1 84 a1 78 0b c6 89 52-0e f6 3e 14 f2 80 68 f3   ...x...R..>...h.
0320 - 67 af 2b a5 b8 75 9c 02-f3 35 37 27 9b 87 74 12   g.+..u...57'..t.
0330 - 6f b1 4f bc 55 72 4f e7-72 e7 a9 a1 93 43 5f 1e   o.O.UrO.r....C_.
0340 - a8 97 b9 73 bf 48 8c 59-5b e3 54 f3 2b 4e de 62   ...s.H.Y[.T.+N.b
0350 - 89 a2 99 1d 11 95 c4 22-24 c7 a5 f7 2b 16 88 52   ......."$...+..R
0360 - 22 39 97 f7 77 92 c3 c1-65 3b 5c 7c 3b cc 71 94   "9..w...e;\|;.q.
0370 - c1 68 2d 79 74 76 6c a0-f1 45 a0 06 5c 93 14 bb   .h-ytvl..E..\...
0380 - 6e f5 58 98 0c a9 7f c5-f6 7d e6 31 03 b5 76 b3   n.X......}.1..v.
0390 - 70 e1 11 44 cb 5b e5 3b-8d ee 01 a6 48 7b 6c d2   p..D.[.;....H{l.
03a0 - 78 a4 43 c1 bc 5b da 46-97 68 18 4d 77 2f c3 16   x.C..[.F.h.Mw/..
03b0 - 8f 75 d9 6b a5 fc 2b af-e1 0c 1d c0 50 71 67 c0   .u.k..+.....Pqg.
03c0 - 72 90 6f 31 56 b8 7d 84-6c cb 11 b5 f3 db cc 56   r.o1V.}.l......V
03d0 - f6 ba 6d 12 38 a5 2c 41-34 11 9e 3f 94 bf 8d e8   ..m.8.,A4..?....
03e0 - 27 ae d5 30 fd 23 66 29-12 38 c0 e3 b2 45 13 5f   '..0.#f).8...E._
03f0 - aa c4 0f 4c 2b 22 54 dc-27 00 ec 95 36 ab 23 cf   ...L+"T.'...6.#.
0400 - 89 ce a7 a2 8a 7e 10 cc-78 91 4e 30 d9 39 1d d9   .....~..x.N0.9..
0410 - 6c a5 90 04 cb a7 a2 0b-d9 98 03 19 9f e5 47 c7   l.............G.
0420 - b9 55 1d f8 d8 0d c0 b0-8a f6 1a 94 6e 68 2c 4f   .U..........nh,O
0430 - 57 53 fb f2 60 3d 88 c5-1f 82 68 39 a5 15 14 20   WS..`=....h9...
0440 - bd d4 00 63 61 8a 70 c3-8c 20 7c 20 b7 98 e3 37   ...ca.p.. | ...7
0450 - 54 e9 80 75 14 ae 14 1b-33 91 a0 c1 28 95 c9 89   T..u....3...(...
0460 - 90 5e cb ec 74 09 56 15-d9 c9 96 37 0c bd 4a 2a   .^..t.V....7..J*
0470 - ce 61 b4 a3 c9 24 6d fe-7b 6a d8 69 b9 60 05 46   .a...$m.{j.i.`.F
0480 - 2e d8 cf fe 48 1e a2 a8-c1 3b 71 01 13 54 96 52   ....H....;q..T.R
0490 - 2a 27 f6 c6 11 62 db 7c-7e 7c 24 5b 00 ac 0e d7   *'...b.|~|$[....
04a0 - b6 89 fc 40 07 06 71 96-d0 b9 8a 60 21 0c 12 a3   ...@..q....`!...
04b0 - 91 57 aa 68 30 c6 bf f0-93 e3 b8 50 70 1c b1 fa   .W.h0......Pp...
04c0 - d2 cc 5e bb c6 9f bb a5-aa 14 09 11 30 b8 a4 2c   ..^.........0..,
04d0 - a2 9d 74 22 34 b8 a6 7a-c4 2b 34 00 5d 82 90 03   ..t"4..z.+4.]...
04e0 - 44 f9 ac d7 55 95 e4 bc-c8 50 73 b9 c1 38 4f 81   D...U....Ps..8O.
04f0 - a6 bb a3 a7 9d e8 c6 38-b8 7a 80 0d 9a 7f aa d5   .......8.z......
0500 - 96 ce 01 73 90 c1 0e c6-38 ad 9c e7 17 87 0a 34   ...s....8......4
0510 - 4c c0 61 49 c6 30 78 47-3d c3 e2 7b 5c e2 27 78   L.aI.0xG=..{\.'x
0520 - 17 c1 dc a0 a0 08 05 20-15 c3 38 cf 1c ba 57 65   ....... ..8...We
0530 - b7 e9 17 0a 82 7a 34 94-07 6f d3 31 95 35 b9 64   .....z4..o.1.5.d
0540 - ec 59 d6 84 4d d9 4b 09-52 2b 4b c2 d9 1d 20 54   .Y..M.K.R+K... T
0550 - 42 16 f9 5c b7 46 13 df-24 87 bb f6 cb 8a b3 16   B..\.F..$.......
0560 - 12 59 37 99 f5 09 e2 42-28 ff 6c 81 18 fa d2 dd   .Y7....B(.l.....
0570 - fe 0f 4d 42 41 11 13 0d-b8 f5 91 b6 85 dd 79 7a   ..MBA.........yz
0580 - 00 1d 00 20 84 7e 2f ab-de ed 01 a5 16 50 d2 d1   ... .~/......P..
0590 - 2c 28 09 6a 8a 5b ae 5b-b1 ae 73 a0 34 94 13 33   ,(.j.[.[..s.4..3
05a0 - ab 7d df 77 00 1b 00 03-02 00 01                  .}.w.......
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write change cipher spec
SSL_accept:TLSv1.3 write encrypted extensions
SSL_accept:SSLv3/TLS write certificate
SSL_accept:TLSv1.3 write server certificate verify
write to 0x248b45f57b0 [0x248b4615c70] (2143 bytes => 2143 (0x85F))
0000 - 16 03 03 04 ba 02 00 04-b6 03 03 6a 4c a7 d2 76   ...........jL..v
0010 - c3 08 cd 77 41 13 57 44-31 92 7b 59 fa 1e c7 cc   ...wA.WD1.{Y....
0020 - 70 a9 4a bb aa ed 7b 53-7a d3 c9 20 c9 67 9c b3   p.J...{Sz.. .g..
0030 - 07 c2 d3 5b ff 34 15 fa-d3 13 1c 4c 6e e1 86 cc   ...[.4.....Ln...
0040 - 2b f7 c9 87 96 fc ef 4e-5d 7c 5c 2f 13 02 00 04   +......N]|\/....
0050 - 6e 00 2b 00 02 03 04 00-33 04 64 11 ec 04 60 3a   n.+.....3.d...`:
0060 - 55 ed 7d c0 9c eb 11 b5-a5 4e a9 9f 77 52 f1 d2   U.}......N..wR..
0070 - 54 3d 69 df 76 e4 9d 96-c5 52 b2 80 b5 9a a6 88   T=i.v....R......
0080 - fd 25 69 f9 aa 4c e0 57-30 7b 96 fe 4b bd af 42   .%i..L.W0{..K..B
0090 - 79 28 ee d0 31 a7 5b dd-51 60 61 d3 f6 01 fa 7c   y(..1.[.Q`a....|
00a0 - 0c 3a b6 90 27 bb 9a d1-bb 73 85 f7 8c 59 a7 72   .:..'....s...Y.r
00b0 - b5 e8 38 e6 46 0a c1 4e-b1 90 f6 75 01 d3 67 ad   ..8.F..N...u..g.
00c0 - 62 50 50 f1 7c be 29 9e-9e 9d 8b 53 a4 d3 3a 58   bPP.|.)....S..:X
00d0 - e6 db 16 93 29 8a 0a e4-53 c4 66 f5 4b 30 25 d2   ....)...S.f.K0%.
00e0 - b8 4c c9 83 a7 13 26 eb-5f ca cd 98 cf e1 98 4c   .L....&._......L
00f0 - ef db aa 63 5f fe bd 82-5d 6e 82 cb 49 a0 36 4c   ...c_...]n..I.6L
0100 - bb 1b e2 de 9d 86 c3 96-db 2b 9b fe ae 44 16 d0   .........+...D..
0110 - a3 76 48 90 4a 54 f1 0b-8c 29 37 51 b8 3c 9a c8   .vH.JT...)7Q.<..
0120 - 11 a9 67 ac 02 94 c2 d7-cd 63 23 9f 99 b9 b7 c4   ..g......c#.....
0130 - ab b4 d0 53 d8 e9 73 9b-e1 ad 14 e0 f3 28 7c 57   ...S..s......(|W
0140 - ab be e4 f5 43 d7 0b 47-ce 67 d5 53 fc b3 4b ad   ....C..G.g.S..K.
0150 - 05 8e c2 67 4f 1a d2 26-c0 02 70 b8 0c 3d b5 5d   ...gO..&..p..=.]
0160 - 0b a1 a7 dd a2 67 09 9f-8b 7a 29 cb bf e1 81 3c   .....g...z)....<
0170 - 2b b9 87 36 f9 7e 34 46-3a 3b c6 71 5a c8 2b 85   +..6.~4F:;.qZ.+.
0180 - 87 5d a8 a7 2d 30 0f 6f-97 f3 a6 7b ab a7 6c c5   .]..-0.o...{..l.
0190 - d2 e5 dd b2 c2 44 70 a4-0b 75 9f c8 fe bc 27 d8   .....Dp..u....'.
01a0 - 60 97 10 9e 36 d6 c2 2c-d8 0f ec 48 e6 b3 c7 52   `...6..,...H...R
01b0 - 69 cf 22 8a cd 6c fb 8e-41 ca 11 e8 66 0e e8 38   i."..l..A...f..8
01c0 - 17 81 cd 7a f2 74 a9 48-0b f1 03 b6 00 ec 0a cd   ...z.t.H........
01d0 - c9 e8 25 e6 06 db c5 61-68 67 35 11 fa b8 2f 81   ..%....ahg5.../.
01e0 - 42 69 61 4c 27 5c 23 ad-42 c9 f7 ac 4e a9 0d 27   BiaL'\#.B...N..'
01f0 - 75 87 c6 0c bd 5c 03 ef-2b 71 66 53 68 4c 47 bf   u....\..+qfShLG.
0200 - cf b5 c9 23 2c 13 bf 13-34 e9 3e 4e b4 de 84 29   ...#,...4.>N...)
0210 - d3 b9 59 fa 82 37 01 4d-00 a6 88 ad 56 9d 8d 9b   ..Y..7.M....V...
0220 - 19 7d 78 2b 01 e3 d8 bb-13 30 65 e4 b8 9d d0 57   .}x+.....0e....W
0230 - 6f 92 10 e0 88 29 01 fb-a6 a9 5f 79 0d f8 a9 e5   o....)...._y....
0240 - 7a 5e e8 a5 3a 7a f0 37-26 91 41 9d 5e ad c6 e5   z^..:z.7&.A.^...
0250 - 4a 4e 36 3e 13 65 67 fb-c4 74 9b 62 ce 9b aa 42   JN6>.eg..t.b...B
0260 - b8 a1 5a b8 90 09 f8 57-20 60 2f 3e 57 fd 87 99   ..Z....W `/>W...
0270 - b5 00 cb c2 0c 2c 1f 59-3f 36 f0 3b 57 67 9c 57   .....,.Y?6.;Wg.W
0280 - ba 65 0c c9 03 df c7 39-8f 38 c1 40 12 35 e5 b0   .e.....9.8.@.5..
0290 - 30 fc 20 98 5b 3a d9 d7-b7 f1 72 17 86 ae b7 d3   0. .[:....r.....
02a0 - ae 3e 63 fc 9a ac ba c6-00 a4 a1 a0 ab 89 a9 71   .>c............q
02b0 - 4d fa 2f 3a 71 6f 37 ec-49 1a ee 91 c2 52 b5 bc   M./:qo7.I....R..
02c0 - 94 5c fd 4d 69 92 94 8b-15 ea b3 aa 1f 90 08 78   .\.Mi..........x
02d0 - d1 30 f7 cc ff 42 ec 6b-12 ba c3 bc fa ce 50 14   .0...B.k......P.
02e0 - d5 7f da d2 58 ea 8e 60-69 96 01 a4 79 a8 b1 08   ....X..`i...y...
02f0 - 7e c1 1c 58 d7 55 e5 52-44 33 dc c3 97 1a 6e df   ~..X.U.RD3....n.
0300 - fd 2d c8 79 5f 78 8e 29-de 9e 36 b9 77 08 a8 be   .-.y_x.)..6.w...
0310 - 25 57 44 97 63 5b 99 2c-17 fa 4b d0 75 bc 7f 77   %WD.c[.,..K.u..w
0320 - 1a 68 4c 67 86 17 19 6c-01 5b 94 f5 e4 23 7f 1c   .hLg...l.[...#..
0330 - 68 06 27 ec 83 f9 80 ac-8f d9 5b ff 3f dd 40 fa   h.'.......[.?.@.
0340 - 30 35 8d 16 73 86 0a 33-22 ca 8c 93 f7 dd 50 ae   05..s..3".....P.
0350 - 1f 47 9a 07 21 cb ce 39-8d f4 77 4b 8d 0a 7d a7   .G..!..9..wK..}.
0360 - 68 ad 48 de c8 a0 93 53-c1 56 1c bf e8 d8 39 4b   h.H....S.V....9K
0370 - 5c b5 8b c9 bb 1f f7 c3-58 72 5b db 6b 47 1c 08   \.......Xr[.kG..
0380 - 16 62 04 c9 f5 50 f4 a6-d1 36 67 d9 9c 01 17 45   .b...P...6g....E
0390 - 84 19 83 21 25 fa b7 f1-32 06 15 2e 25 07 38 c3   ...!%...2...%.8.
03a0 - 5d 4c 01 35 c5 8d e1 83-53 73 51 b1 e0 05 1b 1f   ]L.5....SsQ.....
03b0 - 2a 9c b4 c3 47 4c a3 2a-d9 84 65 34 8a d6 d6 e2   *...GL.*..e4....
03c0 - 59 4c e1 e8 cb 98 35 14-5f c4 af fa 12 c6 6f f3   YL....5._.....o.
03d0 - 32 66 23 0f 10 f6 b8 93-5f a2 fc b5 d3 68 89 68   2f#....._....h.h
03e0 - 20 b0 15 b0 f0 49 95 db-ab 1d a4 13 c2 76 bb c0    ....I.......v..
03f0 - 33 e7 eb fa bf c6 a1 b6-10 47 7f 10 b2 7e 2f 5e   3........G...~/^
0400 - 45 cc fe ff d9 dc e5 d9-31 06 0b 7f 93 9f 12 03   E.......1.......
0410 - f8 a9 65 0b 58 90 6c e8-4e b4 65 29 e9 ea de 85   ..e.X.l.N.e)....
0420 - 37 fc 35 68 89 e3 9a 10-f9 5d cb 37 e3 46 c2 d9   7.5h.....].7.F..
0430 - 28 c3 9e 88 4f 0a 1d 05-63 e5 a8 53 d1 3c c1 72   (...O...c..S.<.r
0440 - 4d df 1c 64 18 c1 cf 5a-c7 42 76 23 52 c2 26 9d   M..d...Z.Bv#R.&.
0450 - d6 9a ed 0d c0 ef 4e 1b-ba 91 16 1c 11 c1 84 de   ......N.........
0460 - e6 c7 16 8f bb 46 32 b0-a0 62 95 d8 40 d1 4f 35   .....F2..b..@.O5
0470 - 20 c9 48 fe e0 8b e2 16-d2 0c 31 07 4a 72 5f ce    .H.......1.Jr_.
0480 - eb 4f a8 6c e0 4a 1c 01-84 d6 6d d4 32 10 a3 9b   .O.l.J....m.2...
0490 - ec e1 8d a7 8a ae b3 d6-30 2e 63 6b 3c 4f ee d0   ........0.ck<O..
04a0 - db a7 77 f4 5a 7d e5 6e-52 86 11 d0 82 13 de 9e   ..w.Z}.nR.......
04b0 - fd 2a 46 b6 4b 97 cc d6-e6 42 e3 43 3c 12 3e 14   .*F.K....B.C<.>.
04c0 - 03 03 00 01 01 17 03 03-00 17 4c 3f 60 6d 34 e1   ..........L?`m4.
04d0 - a6 bc 78 94 87 31 3f 07-89 6b c8 b0 90 87 4e 19   ..x..1?..k....N.
04e0 - 74 17 03 03 02 a9 88 d8-9b 30 90 87 da 60 17 3f   t........0...`.?
04f0 - 1f 7a 79 68 2b 8f 60 6f-40 07 20 82 48 0f eb 8f   .zyh+.`o@. .H...
0500 - 32 74 4f 3c 85 6d 40 29-47 bc ce 95 43 18 f0 4e   2tO<.m@)G...C..N
0510 - 36 86 2f 16 ca ba 9f db-95 36 40 5a 8b c5 3c b9   6./......6@Z..<.
0520 - 99 5d 55 0d a2 24 a4 31-19 c9 7a 71 d6 9f 49 a9   .]U..$.1..zq..I.
0530 - e0 cb 2f a3 bc db b2 e9-27 55 dd 44 23 42 f8 44   ../.....'U.D#B.D
0540 - c2 76 50 1a a2 a5 a0 a7-23 02 fe 44 4e 95 48 7d   .vP.....#..DN.H}
0550 - 0e fe 7b 65 c1 d4 9a a3-eb f0 c9 07 2f 05 7a 44   ..{e......../.zD
0560 - fc 0f a0 27 7e 9e 65 3b-25 22 c1 60 e2 35 3e 61   ...'~.e;%".`.5>a
0570 - f3 d1 73 9c 62 b9 e6 7b-b8 c5 48 d3 49 99 a2 d5   ..s.b..{..H.I...
0580 - 17 04 2a b2 29 5d 8a c5-dc 42 60 1f 8f b6 15 b8   ..*.)]...B`.....
0590 - cc 9f 0c 4c 23 2b 8f 47-0b 91 e5 4a 50 44 33 aa   ...L#+.G...JPD3.
05a0 - 28 03 c9 56 f3 10 3c 9e-ac cb b0 c3 ff ae 2d f2   (..V..<.......-.
05b0 - 19 0d e0 87 47 42 4c d7-b3 ef 1a a1 fa d9 5d 55   ....GBL.......]U
05c0 - 92 4e 46 96 23 eb cf be-62 62 e6 e9 c3 bb b1 e1   .NF.#...bb......
05d0 - c7 7e 07 5b f9 bb 4c 3e-37 b2 a5 05 3e 92 09 a1   .~.[..L>7...>...
05e0 - b7 74 9e 96 ad 2c ee 3f-d4 b6 37 e6 ee ad cf 2e   .t...,.?..7.....
05f0 - 00 0f c4 ac f8 63 27 89-e4 f1 4c 5c 99 7b ce b5   .....c'...L\.{..
0600 - ea 98 bd 81 69 cc 16 d7-e9 59 38 65 79 bf ec 7b   ....i....Y8ey..{
0610 - dd b5 6e 03 17 ac b8 d4-df 9c ff f7 b7 62 86 d0   ..n..........b..
0620 - d7 91 55 1c 0d a0 1d 17-4d 4e 99 29 54 f9 34 f5   ..U.....MN.)T.4.
0630 - 14 65 45 97 c5 5e 96 fe-d0 9c dd 44 1d e2 d7 96   .eE..^.....D....
0640 - 3f a5 7e 4d 0a eb 90 da-b6 5e 5d 2f a6 4b c9 6a   ?.~M.....^]/.K.j
0650 - 24 82 95 4e f0 c3 7c f4-51 b3 da a1 5e 39 04 e2   $..N..|.Q...^9..
0660 - b4 83 14 73 2e 5b 4f b7-aa 2d 49 de da 5d bd 03   ...s.[O..-I..]..
0670 - b2 4f e1 2b 3e 84 a0 53-65 2f 4f a1 c1 b0 49 20   .O.+>..Se/O...I
0680 - 50 0e 36 ac b8 16 51 37-fd 38 8c 8f 3d f8 a3 6e   P.6...Q7.8..=..n
0690 - 1f bf d1 db bd 4c af aa-b7 44 2b 3d 5c 78 13 db   .....L...D+=\x..
06a0 - 82 7e 88 97 27 59 55 5a-f1 1d c7 7e 9f 82 b3 cd   .~..'YUZ...~....
06b0 - 49 8a d7 8d 28 bb 4e a7-25 8c d3 0f 17 82 bc 34   I...(.N.%......4
06c0 - 8a 20 dc 77 7a e9 a4 11-ca 2d 05 db ea 2b c4 14   . .wz....-...+..
06d0 - 4f 07 54 99 b9 e7 3e 95-db 62 27 46 30 41 5c a1   O.T...>..b'F0A\.
06e0 - 10 76 61 f8 48 0c d4 05-85 fc 3a 86 c8 9c 34 d7   .va.H.....:...4.
06f0 - c2 c4 65 78 a0 71 66 b5-2e 77 15 8b ec 8f b6 ae   ..ex.qf..w......
0700 - a4 a1 26 4a f3 21 f3 2b-89 2e 90 f6 9e 3b 32 a0   ..&J.!.+.....;2.
0710 - bd fc 2a 46 f7 5d 1d 8e-5a b4 da b2 be 3c 5c 63   ..*F.]..Z....<\c
0720 - 2b 5f ba 74 f7 11 1a 20-3f fd 97 43 08 95 04 9c   +_.t... ?..C....
0730 - 41 bf 51 cf ab 5b d2 bc-e9 cf 69 41 60 23 47 b7   A.Q..[....iA`#G.
0740 - ca 6f 63 91 48 59 9d d1-71 0f bd f3 0d 62 75 99   .oc.HY..q....bu.
0750 - fe 82 d6 63 63 52 24 c7-95 89 43 f2 26 8e 28 43   ...ccR$...C.&.(C
0760 - 1d eb 40 0d b5 3d dd 02-28 e1 59 e2 bb 6f b0 d7   ..@..=..(.Y..o..
0770 - 59 65 8f fb e8 c8 d2 f1-86 5b d2 6c 90 c9 16 b8   Ye.......[.l....
0780 - 68 40 39 4f 69 71 42 9b-d0 10 f1 dd 5a 7a 4f 17   h@9OiqB.....ZzO.
0790 - 03 03 00 81 1d c2 25 1a-f9 2b bb d0 56 83 d5 7c   ......%..+..V..|
07a0 - 8c 5d 78 95 a9 fe 63 93-04 cc d4 22 ae 5d b7 b2   .]x...c....".]..
07b0 - de dd 15 b4 07 6d 68 41-d9 60 28 da b8 98 6f 9d   .....mhA.`(...o.
07c0 - 03 ec 2e db a9 e1 bf 13-75 26 8c 65 82 20 8f 00   ........u&.e. ..
07d0 - f9 d3 17 40 3f a3 98 a1-00 a4 c3 66 fc e7 74 82   ...@?......f..t.
07e0 - 04 10 ec 3d 84 7d 95 d0-40 a9 69 7c 62 62 cd f2   ...=.}..@.i|bb..
07f0 - 74 cb f7 cb ef e4 b2 86-57 f6 59 a1 33 03 2a 97   t.......W.Y.3.*.
0800 - c3 8c 8b 63 bb 1b 90 69-44 31 5b ef 56 34 37 84   ...c...iD1[.V47.
0810 - 57 d8 a7 e2 ff 17 03 03-00 45 23 dc 18 16 45 03   W........E#...E.
0820 - 3c a0 e6 fd 91 cb 87 e6-75 54 ec 74 63 da 15 38   <.......uT.tc..8
0830 - c1 33 3a 96 2d 2f 43 9f-8d d1 7c ea 00 ca 38 57   .3:.-/C...|...8W
0840 - 4a e3 5c e9 68 44 89 31-a9 1f 8a 02 6d 69 ea af   J.\.hD.1....mi..
0850 - 29 ae 7d dd 52 3b b9 70-e4 ac 11 c9 0a 9f 5f      ).}.R;.p......_
SSL_accept:SSLv3/TLS write finished
SSL_accept:TLSv1.3 early data
read from 0x248b45f57b0 [0x248b4626aa3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x248b45f57b0 [0x248b4626aa8] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x248b45f57b0 [0x248b4626aa3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 45                                    ....E
read from 0x248b45f57b0 [0x248b4626aa8] (69 bytes => 69 (0x45))
0000 - b6 41 aa 8e 58 22 41 c5-ef 08 bf 02 19 22 25 29   .A..X"A......"%)
0010 - c0 7c c7 ef 7d 5e d6 14-29 49 13 b9 6f 0d bb 9b   .|..}^..)I..o...
0020 - aa cd b3 f5 8f 4d 12 fb-e6 03 e2 f7 a9 ce a4 76   .....M.........v
0030 - 7f 5f a6 4b 0d ce 9a 4e-c0 24 cd 94 ca 95 75 f9   ._.K...N.$....u.
0040 - 0d 6b f6 a4 fc                                    .k...
SSL_accept:TLSv1.3 early data
SSL_accept:SSLv3/TLS read finished
write to 0x248b45f57b0 [0x248b4615c70] (255 bytes => 255 (0xFF))
0000 - 17 03 03 00 fa 25 5f da-09 71 21 5d d0 f5 4c 93   .....%_..q!]..L.
0010 - 2f 52 f6 23 12 73 11 41-31 09 dc 9a 26 fe 33 bd   /R.#.s.A1...&.3.
0020 - 9a 18 af bd 3a 05 9f 50-c4 6d c1 41 46 ac e7 9c   ....:..P.m.AF...
0030 - 59 d1 aa 8f c9 c6 98 fa-3e 4d 03 b2 d6 23 16 b2   Y.......>M...#..
0040 - 95 b5 bb fb fc 7c 14 84-89 1b ac f9 08 fa b8 15   .....|..........
0050 - af c5 0d 5b 63 29 78 ca-1f a4 0c f7 cb 4e 87 71   ...[c)x......N.q
0060 - 87 6b 47 13 88 39 59 95-9a 75 57 42 bf 8d 7a 48   .kG..9Y..uWB..zH
0070 - 01 08 83 39 f0 a7 74 4e-7d 64 0c 48 01 0b 85 8a   ...9..tN}d.H....
0080 - f0 ff 22 6c c7 17 c2 cf-57 76 cc 31 d1 61 02 59   .."l....Wv.1.a.Y
0090 - 8c 08 2d 25 d1 47 52 67-23 0d 8f c3 a8 b9 b2 35   ..-%.GRg#......5
00a0 - 64 51 e1 8f c1 c1 e8 90-d8 18 d0 0d 61 47 36 f1   dQ..........aG6.
00b0 - 0d ae d2 49 d9 d2 42 69-f1 f1 22 01 18 59 86 45   ...I..Bi.."..Y.E
00c0 - 75 b0 ac 2e 89 6c c7 3e-8a 4f 3b 8d 70 3e a4 5c   u....l.>.O;.p>.\
00d0 - de af fb 3c 98 ef 4b 1f-3a b1 32 7a e4 ba b9 10   ...<..K.:.2z....
00e0 - 31 07 f3 2e 6f 3a ab 3d-7c d0 7e bc 18 33 1b cb   1...o:.=|.~..3..
00f0 - be 74 a7 cf d9 5c f3 b7-5d e2 2a ba 25 f2 ea      .t...\..].*.%..
SSL_accept:SSLv3/TLS write session ticket
write to 0x248b45f57b0 [0x248b4615c70] (255 bytes => 255 (0xFF))
0000 - 17 03 03 00 fa e9 46 67-01 30 bf e4 a0 43 3a 2a   ......Fg.0...C:*
0010 - 6f 18 ec 60 d9 61 79 14-9f f5 5a a5 8b e2 b3 6e   o..`.ay...Z....n
0020 - 28 d6 c9 f2 64 ca 1b 56-d6 f1 f6 43 d9 d9 2a 88   (...d..V...C..*.
0030 - 1e 10 88 6d 90 66 75 77-83 92 80 77 43 2d 4e af   ...m.fuw...wC-N.
0040 - 01 ed 56 87 2c c0 5b dd-6a ec d8 5a a3 bf d0 80   ..V.,.[.j..Z....
0050 - 8f a4 db 25 89 f7 ad bb-c8 99 07 c4 8d b9 13 ed   ...%............
0060 - 03 c8 e9 92 54 e2 77 40-4e da e3 a0 f2 a6 fe 85   ....T.w@N.......
0070 - 0f ef 3b d0 1b d3 8c f1-45 93 e7 88 6a 0b 75 db   ..;.....E...j.u.
0080 - 49 ca 81 41 18 e7 a6 0c-11 dd f2 a4 f3 43 6e d0   I..A.........Cn.
0090 - 82 a2 75 fc 69 e0 a8 3c-98 2e 77 20 d5 39 4c 11   ..u.i..<..w .9L.
00a0 - fb a2 b0 83 dc 4e 1a 55-ea b0 4e 8f b9 53 6b cd   .....N.U..N..Sk.
00b0 - 40 33 64 18 c2 57 07 49-64 22 63 c7 ca e7 0a b4   @3d..W.Id"c.....
00c0 - 71 45 9c e6 11 be a3 a9-c5 64 98 1c 5b 51 10 89   qE.......d..[Q..
00d0 - 02 cb ba 3e 1e 8b 18 fa-ad c5 e5 57 dc 89 58 c6   ...>.......W..X.
00e0 - 6d bd 51 00 c7 b5 c8 59-d4 b8 ad cb d5 d3 b9 a0   m.Q....Y........
00f0 - 81 ae 19 e9 2c 42 c2 a5-68 27 ff f4 cb ae 19      ....,B..h'.....
SSL_accept:SSLv3/TLS write session ticket
-----BEGIN SSL SESSION PARAMETERS-----
MIGDAgEBAgIDBAQCEwIEII2aD6jasWczO0lYBcO3K4plLu2HaJVveX4zdq+FOGdE
BDA25PALJr1QQQtniB5HOPpZ5XLpX0jrIOBFDswRTP7xUEV4eVvctduMlMWO1y+k
O0ChBgIEavo0QaIEAgIcIKQGBAQBAAAArgYCBCopTiSzBAICEew=
-----END SSL SESSION PARAMETERS-----
Shared ciphers:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
Signature Algorithms: id-ml-dsa-65:id-ml-dsa-87:id-ml-dsa-44:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:ed448:ecdsa_brainpoolP256r1_sha256:ecdsa_brainpoolP384r1_sha384:ecdsa_brainpoolP512r1_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Shared Signature Algorithms: id-ml-dsa-65:id-ml-dsa-87:id-ml-dsa-44:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:ed448:ecdsa_brainpoolP256r1_sha256:ecdsa_brainpoolP384r1_sha384:ecdsa_brainpoolP512r1_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Supported groups: X25519MLKEM768:x25519:secp256r1:x448:secp384r1:secp521r1:ffdhe2048:ffdhe3072
Shared groups: X25519MLKEM768:x25519:secp256r1:x448:secp384r1:secp521r1:ffdhe2048:ffdhe3072
CIPHER is TLS_AES_256_GCM_SHA384
This TLS version forbids renegotiation.
read from 0x248b45f57b0 [0x248b460e5b3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x248b45f57b0 [0x248b460e5b8] (23 bytes => 23 (0x17))
0000 - 0b 15 ee 3f 57 21 29 e6-f3 30 d8 6e 06 25 97 52   ...?W!)..0.n.%.R
0010 - bd 58 29 17 8d f7 a3                              .X)....
test
read from 0x248b45f57b0 [0x248b460e5b3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 16                                    .....
read from 0x248b45f57b0 [0x248b460e5b8] (22 bytes => 22 (0x16))
0000 - 3e ba 81 fd 2d e7 5f df-5e b7 7b b5 ef 13 a3 c8   >...-._.^.{.....
0010 - 96 40 16 3b d2 bf                                 .@.;..
SSL_accept:SSL negotiation finished successfully
SSL_accept:SSL negotiation finished successfully
SSL_accept:TLSv1.3 read client key update
Read BLOCK
read from 0x248b45f57b0 [0x248b463d3e3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x248b45f57b0 [0x248b463d3e8] (23 bytes => 23 (0x17))
0000 - d5 29 bf bf 2f 6c a5 f0-40 61 fc 64 70 a4 5b 7c   .)../l..@a.dp.[|
0010 - ad 7e f3 bf 55 24 53                              .~..U$S
test
read from 0x248b45f57b0 [0x248b463d3e3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 16                                    .....
read from 0x248b45f57b0 [0x248b463d3e8] (22 bytes => 22 (0x16))
0000 - 35 d0 a7 df 56 0a 96 7e-e2 ce e6 04 71 c8 1b 3a   5...V..~....q..:
0010 - c8 30 5b 64 8e 67                                 .0[d.g
SSL_accept:SSL negotiation finished successfully
SSL_accept:SSL negotiation finished successfully
SSL_accept:TLSv1.3 read client key update
Read BLOCK
read from 0x248b45f57b0 [0x248b463d3e3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x248b45f57b0 [0x248b463d3e8] (23 bytes => 23 (0x17))
0000 - 4d 6e 18 28 e8 a4 64 0a-03 1d 56 c3 d5 cf a7 7a   Mn.(..d...V....z
0010 - a9 da 02 38 c0 7d 5a                              ...8.}Z
test
read from 0x248b45f57b0 [0x248b463d3e3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 13                                    .....
read from 0x248b45f57b0 [0x248b463d3e8] (19 bytes => 19 (0x13))
0000 - 98 3a 84 04 33 08 6a 46-09 67 da 5c eb 10 e3 20   .:..3.jF.g.\...
0010 - 61 ad 73                                          a.s
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x248b45f57b0 [0x248b4626aa3] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 1b b3 4d-64 f3 8f 2e 76 b3 e7 a8   .......Md...v...
0010 - 93 2c 04 b5 bd cc 76 41-                          .,....vA
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
