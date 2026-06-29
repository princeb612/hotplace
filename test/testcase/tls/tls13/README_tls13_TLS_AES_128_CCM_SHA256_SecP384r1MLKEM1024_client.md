#### client

````
$ openssl s_client -connect localhost:9000 -state -debug -keylogfile sslkeylog -tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256 -groups SecP384r1MLKEM1024
Connecting to ::1
CONNECTED(000001F0)
SSL_connect:before SSL initialization
write to 0x21cf79c6910 [0x21cf9382b60] (1845 bytes => 1845 (0x735))
0000 - 16 03 01 07 30 01 00 07-2c 03 03 48 d6 db 37 65   ....0...,..H..7e
0010 - 38 94 8c 9e e6 4d ad ed-5f fe 77 e0 f7 a8 a5 0c   8....M.._.w.....
0020 - c1 7c d8 45 6b 9b 71 20-93 6e ae 20 30 71 04 27   .|.Ek.q .n. 0q.'
0030 - 1d bb 40 43 fe 2b c2 2c-f0 d2 4e f8 d7 cb 38 43   ..@C.+.,..N...8C
0040 - 3d 66 ef 06 4d 2b e3 36-b2 89 e2 73 00 02 13 04   =f..M+.6...s....
0050 - 01 00 06 e1 00 0a 00 04-00 02 11 ed 00 23 00 00   .............#..
0060 - 00 16 00 00 00 17 00 00-00 0d 00 2a 00 28 09 05   ...........*.(..
0070 - 09 06 09 04 04 03 05 03-06 03 08 07 08 08 08 1a   ................
0080 - 08 1b 08 1c 08 09 08 0a-08 0b 08 04 08 05 08 06   ................
0090 - 04 01 05 01 06 01 00 2b-00 03 02 03 04 00 2d 00   .......+......-.
00a0 - 02 01 01 00 33 06 87 06-85 11 ed 06 81 04 d7 f9   ....3...........
00b0 - 0d 34 bc 11 4e 53 4a 53-65 75 74 dc 4a b1 f5 e3   .4..NSJSeut.J...
00c0 - bf 77 2b e6 05 78 49 c2-00 93 db 63 8d 17 f1 3e   .w+..xI....c...>
00d0 - d0 b1 cd 73 38 1e 76 33-e0 c7 b7 71 1b e7 39 5d   ...s8.v3...q..9]
00e0 - 32 0d c3 34 6d fc 3b 04-49 34 7c 2c 35 7a 98 f9   2..4m.;.I4|,5z..
00f0 - 02 37 1d a6 f8 2f 80 97-3b 9a cd 72 5b 2b c1 3a   .7.../..;..r[+.:
0100 - 3d 26 26 db b8 74 85 b4-60 6c 07 da 10 c9 f4 a4   =&&..t..`l......
0110 - 74 73 08 54 91 f3 2f b8-02 40 43 b7 b4 eb 38 5a   ts.T../..@C...8Z
0120 - 33 94 0f e6 83 8c 2d 45-b2 9e b5 0a 60 c1 3d 8e   3.....-E....`.=.
0130 - fc 86 48 f6 b8 09 c8 82-f0 11 a0 e2 86 71 85 63   ..H..........q.c
0140 - c4 af 3b 51 12 f2 49 0d-00 6b 50 51 9f 97 b1 ab   ..;Q..I..kPQ....
0150 - b3 77 99 9a 0c c6 70 81-b9 d1 65 8a 86 ec 42 43   .w....p...e...BC
0160 - cb 71 96 f5 37 81 e7 7b-f7 75 29 44 57 b1 f9 b1   .q..7..{.u)DW...
0170 - 65 50 f9 ca a1 72 4b b6-10 9c f9 c6 00 16 fc 01   eP...rK.........
0180 - d3 a7 58 88 56 b3 f7 10-54 c0 4c 63 ce 67 93 26   ..X.V...T.Lc.g.&
0190 - ca 2d 25 98 63 f3 68 6d-aa 20 6c a3 c8 0d 25 d6   .-%.c.hm. l...%.
01a0 - 5f fc 6b 39 3b e3 55 3f-d7 8d 84 a5 60 f2 c3 3c   _.k9;.U?....`..<
01b0 - e9 46 63 b9 56 33 4e e5-bb be 75 03 58 d9 67 90   .Fc.V3N...u.X.g.
01c0 - c4 6d ac 43 26 26 25 7b-09 6a 28 b9 54 4d 15 17   .m.C&&%{.j(.TM..
01d0 - 62 ef 9c a0 7e 81 41 5a-9a 9c 22 42 12 85 ca 06   b...~.AZ.."B....
01e0 - ed f7 c3 c2 f0 15 58 0b-1c aa a7 89 63 d7 9d ac   ......X.....c...
01f0 - 15 48 de f6 17 ff c6 8f-55 14 36 ac 46 82 67 20   .H......U.6.F.g
0200 - c5 f9 47 55 4f 41 be 48-1c 32 63 1b bb 0c 1a 05   ..GUOA.H.2c.....
0210 - 87 c1 6e cf 52 b3 34 fb-a5 2b 83 5e 7e 3c 4d f8   ..n.R.4..+.^~<M.
0220 - 76 71 bb 56 cf 67 73 02-7b bb 27 fe eb cf 62 84   vq.V.gs.{.'...b.
0230 - 25 a2 87 b6 44 f4 31 2c-73 71 c0 06 af e0 cb 4a   %...D.1,sq.....J
0240 - 36 15 c9 c0 60 4f 30 7a-02 ac 44 c0 a0 d5 78 2a   6...`O0z..D...x*
0250 - cb 4a 35 88 b5 4e d0 62-37 53 23 ce 30 87 c7 f1   .J5..N.b7S#.0...
0260 - 1e 49 16 ae ef d5 40 b5-eb 2c 8e 29 1b 1e f9 4d   .I....@..,.)...M
0270 - 26 c8 7c 31 e0 19 70 58-9a 49 c1 74 8d bb 06 9a   &.|1..pX.I.t....
0280 - 17 bb 01 16 6e 34 4a 69-cc 79 2c 0c 61 72 51 e4   ....n4Ji.y,.arQ.
0290 - 90 25 81 69 0d 88 9f 9f-43 73 db 46 0d 84 cc 34   .%.i....Cs.F...4
02a0 - 04 7c bb 2c 65 7c 5b 9c-89 58 ba c2 82 ca 75 48   .|.,e|[..X....uH
02b0 - c6 c0 72 15 9d 55 aa b3-62 45 c1 74 30 bb 5f 42   ..r..U..bE.t0._B
02c0 - 51 09 c3 0f 8f 27 ac ba-b5 6d d5 08 61 4f a1 01   Q....'...m..aO..
02d0 - de 82 a9 e3 e4 92 20 c1-8c c1 0c 01 d0 fc 0f 05   ...... .........
02e0 - d1 95 d6 b2 46 2f 39 a4-b2 7b 7f 5c c4 cb 02 d1   ....F/9..{.\....
02f0 - 3a 66 23 0b fc 0a 49 c9-a9 aa 2b c8 34 1e c0 b7   :f#...I...+.4...
0300 - da 34 51 cb f7 7d e0 97-50 bf 2a 26 e0 bb 13 95   .4Q..}..P.*&....
0310 - 49 bb 0e db c1 5a fa 07-13 17 83 d5 37 b3 00 1a   I....Z......7...
0320 - 3b 6e f5 98 57 d9 9d 08-b7 c0 5d 0b 18 29 e4 35   ;n..W.....]..).5
0330 - 51 db 82 29 87 83 d3 d0-41 5b cc 45 a9 61 06 20   Q..)....A[.E.a.
0340 - bb cc d9 ba 44 6d c1 56-2e ba 0c 80 05 49 3c b8   ....Dm.V.....I<.
0350 - 75 8d 3c 95 74 c4 81 18-50 4e 84 e3 66 26 67 47   u.<.t...PN..f&gG
0360 - 68 87 9d b5 81 83 74 63-4f 27 46 55 b7 ac 4d a9   h.....tcO'FU..M.
0370 - 54 26 1c 56 63 06 54 36-3c 07 b6 ad fa 44 fe 3c   T&.Vc.T6<....D.<
0380 - 68 0f fa a3 22 a4 7d 95-45 74 8d 57 ae b7 cc a4   h...".}.Et.W....
0390 - 89 a8 c0 3f 24 9f 9b eb-ab bf 4a 87 6a 31 6e 9b   ...?$.....J.j1n.
03a0 - 80 11 24 e3 90 73 ab 61-05 15 7b 86 f9 2b 90 9a   ..$..s.a..{..+..
03b0 - 74 63 38 10 14 bb 31 2b-da 83 6d d0 41 d2 a1 c5   tc8...1+..m.A...
03c0 - ca ec 0e d0 8c 63 3d 66-1a e2 65 a6 d7 f3 52 8e   .....c=f..e...R.
03d0 - 1c 5a 2e 90 64 a6 2c 46-93 6b 4f 56 53 c9 17 63   .Z..d.,F.kOVS..c
03e0 - 2f 39 74 c4 71 b5 c5 f7-08 b8 1f b2 12 71 e2 0b   /9t.q........q..
03f0 - 76 d1 55 fc 56 3c 61 1a-8c 88 e8 68 46 54 34 52   v.U.V<a....hFT4R
0400 - c8 10 6e 45 68 c6 01 86-9b 20 b5 82 a8 b6 12 c4   ..nEh.... ......
0410 - 78 5a ba a8 e2 20 10 49-28 05 28 5c 63 74 1a 7f   xZ... .I(.(\ct..
0420 - ae 5c 2c dd 79 14 83 76-66 d7 60 6c a3 a7 3b 00   .\,.y..vf.`l..;.
0430 - 92 1d 91 e1 0e cc b5 ba-ff e7 c0 3f 3a 6e ed d2   ...........?:n..
0440 - 32 9f 59 78 10 13 64 16-d2 15 c9 a1 66 aa 1a 4d   2.Yx..d.....f..M
0450 - 4a 1b b7 10 7a 7a 19 94-a5 1c 30 92 cf 63 0b aa   J...zz....0..c..
0460 - a6 8b 6c b8 c1 e6 e4 1c-d7 07 26 06 70 a6 51 96   ..l.......&.p.Q.
0470 - 3c 7a 4c 23 47 e3 b8 b2-0c 46 5d 2b aa c6 2b 55   <zL#G....F]+..+U
0480 - aa d5 c4 88 65 7e bb b2-30 6e d8 09 af f5 0f 6c   ....e~..0n.....l
0490 - e5 1e 0a b1 54 ba c1 b2-99 55 90 d9 c8 1c 20 c8   ....T....U.... .
04a0 - 98 fa 26 b1 5f 5a 66 42-d0 18 fb d2 5e 6b 7b b3   ..&._ZfB....^k{.
04b0 - 58 15 78 b8 e2 94 f3 0b-a0 87 aa ce f6 22 65 f5   X.x.........."e.
04c0 - a9 94 b2 16 73 22 45 36-f9 48 89 ff c4 21 ab c3   ....s"E6.H...!..
04d0 - c7 87 12 57 55 7b 8b b8-57 87 dc 78 54 b0 a1 9e   ...WU{..W..xT...
04e0 - ff 4b ac d9 e9 36 e6 2c-8e 29 35 8f 76 c1 2e 8c   .K...6.,.)5.v...
04f0 - 2b cf 3f 18 62 24 55 5b-db a3 c3 fd e3 7a bc bb   +.?.b$U[.....z..
0500 - 1d 4c e9 c2 a5 53 b1 48-93 10 66 ec 12 de c0 22   .L...S.H..f...."
0510 - e7 f9 b5 b5 a9 8a 28 6a-b0 1e 58 25 79 2c 34 bc   ......(j..X%y,4.
0520 - 5a 13 34 87 a6 e7 98 03-04 37 6d 0a e9 b6 68 f0   Z.4......7m...h.
0530 - 08 be e6 29 82 94 04 24-70 ca 67 b9 a8 b2 6a c6   ...)...$p.g...j.
0540 - a9 da 3f 93 82 13 9a c9-b0 a3 f7 3a bd ea 0d 44   ..?........:...D
0550 - c5 06 5f 41 bf cc 45 8d-86 92 9c d1 db 3a 6f b3   .._A..E......:o.
0560 - 77 cf 70 35 0d 77 32 29-51 8f 6a 06 48 0c c2 00   w.p5.w2)Q.j.H...
0570 - ef fa 68 0f d3 95 f2 5b-02 1f d6 92 e8 1c c0 e0   ..h....[........
0580 - 36 53 11 24 3d 52 88 53-25 d0 cc fd 10 ce 4a 43   6S.$=R.S%.....JC
0590 - 29 cd e0 5c 29 b2 9f 78-23 53 0e 82 ca 29 bb 6e   )..\)..x#S...).n
05a0 - 83 e8 01 a7 ab a4 b5 b6-66 67 f4 87 8e 60 b6 57   ........fg...`.W
05b0 - 51 ac 61 c9 78 07 08 1f-ab 74 0c 2b 02 b8 20 d0   Q.a.x....t.+.. .
05c0 - 1a a9 6a bb 9d d4 7d 48-eb 91 fd d4 87 34 69 98   ..j...}H.....4i.
05d0 - 40 47 2e 90 18 10 70 17-0e 3c d9 13 59 93 c2 b9   @G....p..<..Y...
05e0 - c1 4d a5 0b a7 df 56 57-99 ec b8 0b 8a 78 7d ba   .M....VW.....x}.
05f0 - bd 3a a8 b8 86 f3 87 e0-59 7d c4 13 09 44 ba 43   .:......Y}...D.C
0600 - 21 08 c3 e0 34 03 3f 34-1e 09 5b 52 bf 5c 17 a7   !...4.?4..[R.\..
0610 - 29 60 10 08 b4 49 c1 be-58 05 14 8c 8c c1 5f 50   )`...I..X....._P
0620 - 9d 89 0b 92 82 ac bf a7-c4 20 45 82 9f 7a 15 53   ......... E..z.S
0630 - c9 9b 42 08 b6 c7 db 18-ca 21 3b 8f dd 08 5c 01   ..B......!;...\.
0640 - 33 7f ef da be 4f 77 b8-a5 66 47 e5 6a 65 5b c0   3....Ow..fG.je[.
0650 - 08 88 78 ce d2 c3 8f af-a8 7d d3 91 8a e0 f5 b2   ..x......}......
0660 - 71 56 ae af ac bc 2b 1a-6a 62 a6 38 ee d2 58 e0   qV....+.jb.8..X.
0670 - 65 2c 69 54 ce 7f 91 cd-9b 17 92 70 e0 71 ee 6c   e,iT.......p.q.l
0680 - 5a 0f 38 b0 89 b1 8d 78-d1 81 90 44 4e d4 76 6d   Z.8....x...DN.vm
0690 - aa 65 9d 0a 75 36 59 ca-64 54 71 05 3c 7c be 5e   .e..u6Y.dTq.<|.^
06a0 - 1a 10 8d d4 80 f9 49 3e-3c 80 7e 37 e7 66 7e 27   ......I><.~7.f~'
06b0 - 7a dc f1 7d 9a aa b8 f0-d8 bc e3 20 23 9f 91 ce   z..}....... #...
06c0 - 35 fb 04 94 a7 ce 24 aa-4f 1e e7 5e 43 fb 98 11   5.....$.O..^C...
06d0 - f8 5f 21 72 11 81 74 4c-ce 0a 66 ec b8 16 6f 22   ._!r..tL..f...o"
06e0 - c4 dd f5 0a 22 cc b4 6f-08 11 be 35 ad 7b 8c a3   ...."..o...5.{..
06f0 - 55 ac 9c a8 01 a4 73 d3-7b c3 d1 41 94 aa cb 56   U.....s.{..A...V
0700 - 42 24 23 1c 26 fb 04 68-43 82 75 d1 51 4c f0 4b   B$#.&..hC.u.QL.K
0710 - 28 0a 17 b2 ef fc 3b 32-58 ae ed 80 2a 1c ed 49   (.....;2X...*..I
0720 - 30 0c 72 c6 35 4b eb 68-43 73 36 14 5b cf 00 1b   0.r.5K.hCs6.[...
0730 - 00 03 02 00 01                                    .....
SSL_connect:SSLv3/TLS write client hello
read from 0x21cf79c6910 [0x21cf938b623] (5 bytes => 5 (0x5))
0000 - 16 03 03 06 db                                    .....
read from 0x21cf79c6910 [0x21cf938b628] (1755 bytes => 1755 (0x6DB))
0000 - 02 00 06 d7 03 03 07 5e-70 1e e4 1f 03 b7 e5 4d   .......^p......M
0010 - de 05 9b a2 52 00 81 d4-af 75 3f de 57 25 e4 45   ....R....u?.W%.E
0020 - ed f2 30 82 d2 50 20 30-71 04 27 1d bb 40 43 fe   ..0..P 0q.'..@C.
0030 - 2b c2 2c f0 d2 4e f8 d7-cb 38 43 3d 66 ef 06 4d   +.,..N...8C=f..M
0040 - 2b e3 36 b2 89 e2 73 13-04 00 06 8f 00 2b 00 02   +.6...s......+..
0050 - 03 04 00 33 06 85 11 ed-06 81 04 09 2f 68 d6 f4   ...3......../h..
0060 - bb 4f 31 04 20 f4 99 d8-21 bf 95 d9 3d 2c 2d e4   .O1. ...!...=,-.
0070 - 96 f8 ce 36 43 c3 dc a4-d3 98 ea fe bc 23 3f 8e   ...6C........#?.
0080 - 11 70 24 e3 36 85 8f bf-7f e6 97 96 04 c1 30 82   .p$.6.........0.
0090 - 7e 68 6e 03 b2 c5 bb af-b5 b9 ca ef 52 49 63 c1   ~hn.........RIc.
00a0 - 3c 03 16 ab 82 dc 6b d7-58 c8 3b 79 87 1a 13 a6   <.....k.X.;y....
00b0 - a1 33 d6 28 15 5d 68 df-70 43 14 cc 46 1d d6 8a   .3.(.]h.pC..F...
00c0 - f8 04 a5 69 66 e6 5b 52-85 5f 6f 14 55 62 15 4f   ...if.[R._o.Ub.O
00d0 - 93 2f c1 a2 bc b7 18 f7-96 f2 fa 35 69 83 dd fa   ./.........5i...
00e0 - 0e dd 8d 6c 20 47 29 50-98 28 2b e6 68 09 2b 93   ...l G)P.(+.h.+.
00f0 - 37 2e d4 68 5e 38 35 96-da 9e 0a f2 bc 72 e8 11   7..h^85......r..
0100 - 12 1b d7 f8 7a e9 c7 fc-1e dc af 86 bb 18 e7 44   ....z..........D
0110 - ec e2 43 88 e9 b8 ca 98-f6 6d 79 78 fa 77 37 82   ..C......myx.w7.
0120 - 52 74 b7 ab eb 5b ab 6b-98 f5 1b eb de 62 0f dd   Rt...[.k.....b..
0130 - 28 08 75 79 f1 7c 0d 86-40 f7 35 e9 7c 72 99 81   (.uy.|..@.5.|r..
0140 - a8 2d ab 71 61 2c e0 fe-83 e6 1a 2a 35 36 20 ad   .-.qa,.....*56 .
0150 - 18 33 50 b5 97 26 1f 44-a4 e2 aa 1e 04 08 8a 31   .3P..&.D.......1
0160 - 3b 9c 64 b8 84 84 67 8a-4c ab ed 61 59 d5 65 c9   ;.d...g.L..aY.e.
0170 - 0d 3f 25 1e 0c 86 23 ce-ee 7e f5 d1 23 46 ed e9   .?%...#..~..#F..
0180 - da 51 0f f5 82 b3 66 07-e5 a8 c3 72 52 62 fd b3   .Q....f....rRb..
0190 - f8 2b 71 3f 12 1f 60 d3-64 49 0a 95 f0 c4 5c 53   .+q?..`.dI....\S
01a0 - 9b 60 96 1a a5 a9 b3 1b-8c d9 5e 88 d2 2a 69 eb   .`........^..*i.
01b0 - 92 52 1f de 8d 51 70 1b-50 01 b3 01 87 a8 1a b1   .R...Qp.P.......
01c0 - 2a 4e 20 a9 d5 46 6f 55-22 96 22 66 fc 1b 09 d8   *N ..FoU"."f....
01d0 - 69 fb 5a 4e ac 92 d8 9c-50 34 99 aa a0 08 19 53   i.ZN....P4.....S
01e0 - 2f 95 73 51 03 62 c1 8d-9e fa ab 9a 6b 2a 2a 2e   /.sQ.b......k**.
01f0 - 3d 94 e5 d1 8b a1 90 fe-2a 52 e5 a2 37 9c 54 84   =.......*R..7.T.
0200 - 1e e0 f9 b6 50 a3 4b 7c-e8 13 71 a2 23 d8 64 52   ....P.K|..q.#.dR
0210 - e2 0c f2 a6 5a 67 79 f5-fb 15 31 dc 23 6f b8 9e   ....Zgy...1.#o..
0220 - 37 39 cb 13 d7 b0 18 0b-74 c3 d4 d5 2b 68 9c 78   79......t...+h.x
0230 - e4 92 4b 6c e8 b7 75 ec-b5 3c 72 3d 00 dc 84 7c   ..Kl..u..<r=...|
0240 - fe b8 97 95 fe 96 43 b0-d1 5b b6 9c 96 0b 14 ed   ......C..[......
0250 - ce 83 11 4a c3 bc 5a 72-1f 86 74 2a 14 9c 6c d8   ...J..Zr..t*..l.
0260 - 14 2d 8f de 87 94 7e c5-c1 6f d2 b2 54 bf 9f 0b   .-....~..o..T...
0270 - 7c 98 c7 0a 94 80 1f 08-2b f3 75 a1 4b dc ba 24   |.......+.u.K..$
0280 - a5 b8 24 d3 9c 64 8c 3a-dd ec ff ce de cd a5 0c   ..$..d.:........
0290 - 15 3a ee f4 48 23 66 f5-7e fe 4f 04 f9 03 4a 5c   .:..H#f.~.O...J\
02a0 - 04 56 d9 ce fa 84 cd 20-14 6c 37 eb 9c af ad 5c   .V..... .l7....\
02b0 - c7 f7 c0 db d5 7b 8f a7-9c cb c1 12 3a 89 89 7a   .....{......:..z
02c0 - 86 07 ac fd 09 c4 a3 0a-75 1c b5 7f 6a 89 c3 06   ........u...j...
02d0 - 8b 88 f5 a7 11 f2 2f 1a-f1 19 25 7e 28 50 23 c9   ....../...%~(P#.
02e0 - a4 4d 66 f9 a0 b6 ff 8b-71 bc bd 83 a7 0f 41 49   .Mf.....q.....AI
02f0 - 60 14 f6 b2 21 77 c4 7b-95 83 07 79 27 32 2d 70   `...!w.{...y'2-p
0300 - 83 37 b0 8a 00 bb 92 6a-f0 35 32 6b cf 3e 51 6f   .7.....j.52k.>Qo
0310 - b7 d4 b6 ed a5 3f 69 c8-12 f9 45 b2 76 28 51 e5   .....?i...E.v(Q.
0320 - 70 8e 9e be 44 bd 7d b9-33 22 29 70 26 1e 52 00   p...D.}.3")p&.R.
0330 - 4e ba 8b ca 71 8f 80 3b-b2 f3 ec b1 e2 b2 94 4f   N...q..;.......O
0340 - 22 22 dd 7b 3f be 15 67-0e a1 21 01 ce c8 8a a8   "".{?..g..!.....
0350 - 2b 0e 50 fb 58 b0 0d ed-0b bf dc fa 29 8f 24 ed   +.P.X.......).$.
0360 - f4 7a 60 ba 57 57 81 2a-7e e0 69 fa b3 56 6e 87   .z`.WW.*~.i..Vn.
0370 - c3 f1 cc 15 6e f3 24 41-61 4d de f0 e2 c4 aa dc   ....n.$AaM......
0380 - 88 be eb b7 1d 78 91 4d-f8 0a 18 1c 18 34 2f a9   .....x.M.....4/.
0390 - 25 e5 43 91 b4 68 39 67-3c ae 98 3c 96 0e a7 26   %.C..h9g<..<...&
03a0 - e4 c4 6e e7 a7 ad 01 d0-c4 4e 5f 37 fb 77 4f 35   ..n......N_7.wO5
03b0 - 70 76 36 11 15 c8 3c 1f-7d a5 49 85 3f df 31 fb   pv6...<.}.I.?.1.
03c0 - 7c 36 69 5a 22 38 c6 d6-30 d2 02 76 94 f7 c2 45   |6iZ"8..0..v...E
03d0 - 9b 01 21 96 df 33 ad d2-29 3e 93 43 7f e5 dd 1c   ..!..3..)>.C....
03e0 - 86 07 82 2d c5 84 08 10-98 d0 d7 40 0b 2d 2f b8   ...-.......@.-/.
03f0 - b1 82 f9 4f da ef e4 d2-7d 38 b1 8a a9 e9 ff c8   ...O....}8......
0400 - 7c 69 2b b7 ee 2a 4d d5-e8 d6 8b fc b8 d1 b3 30   |i+..*M........0
0410 - c0 01 94 85 17 e7 3b b5-62 f8 d0 e5 9a b2 7a 7d   ......;.b.....z}
0420 - a6 43 55 2f 4c e7 59 c8-5f 01 34 e6 6c 6f 37 76   .CU/L.Y._.4.lo7v
0430 - 5e 9f fe ac 4a fa 46 98-6e 9a 7b 15 51 b7 7f 3f   ^...J.F.n.{.Q..?
0440 - 28 c8 9c bd e6 27 4e dc-1a 93 90 f9 17 6d 00 ad   (....'N......m..
0450 - a7 5b 2b a9 d1 1a ed cf-76 63 63 42 d1 d9 a0 10   .[+.....vccB....
0460 - 76 e6 d3 db 1e a7 b9 8f-32 6c ba 76 47 38 a9 3b   v.......2l.vG8.;
0470 - 5a ef 7e bb 85 e3 68 4b-fe de ee 95 54 95 f1 ea   Z.~...hK....T...
0480 - 8b 64 25 52 f8 7e b1 e6-59 f7 39 b0 11 9f 34 4e   .d%R.~..Y.9...4N
0490 - 2b 0f 08 5f a2 b8 27 03-b7 fc 8e 48 87 be 04 78   +.._..'....H...x
04a0 - d2 4e 14 58 49 35 1d 7d-fe 94 31 d4 9a c2 e1 d2   .N.XI5.}..1.....
04b0 - 0e 2c 91 8b 55 b5 b8 7b-35 3d da b1 04 84 be 7d   .,..U..{5=.....}
04c0 - 78 7e 5b 3e 60 5d b4 c2-df ba 32 bb 2a 35 86 cd   x~[>`]....2.*5..
04d0 - ab 9c 59 20 dd 7a e6 b6-a0 6a 85 e8 fb 73 f5 41   ..Y .z...j...s.A
04e0 - f4 0f 78 73 aa 7a 47 35-e5 d8 10 64 cc aa 36 41   ..xs.zG5...d..6A
04f0 - b1 f3 8b 22 66 d4 95 ca-4b 39 91 32 cc 20 f9 81   ..."f...K9.2. ..
0500 - d7 4d 13 09 96 4f df 2d-61 89 b8 a2 d6 92 fc 66   .M...O.-a......f
0510 - 34 3f b9 36 29 1d 42 81-ce 8c 77 57 80 de 46 e3   4?.6).B...wW..F.
0520 - 04 ef 5f 54 af e3 87 05-b4 3f 71 d6 1a ce 27 58   .._T.....?q...'X
0530 - f6 0b d2 f9 f4 3a a1 25-ce f6 b6 d1 8e 79 e4 dd   .....:.%.....y..
0540 - 36 bf f5 23 a2 36 66 e5-71 3f c9 2c b7 77 b7 a8   6..#.6f.q?.,.w..
0550 - 50 90 88 27 4c c1 14 fb-d5 b5 47 be 5e f7 1e c8   P..'L.....G.^...
0560 - 45 88 92 76 77 76 11 1a-81 ce b0 75 c0 d9 c2 63   E..vwv.....u...c
0570 - cb 94 90 80 43 68 5a 74-7a 72 bd 54 4d 9a ba 54   ....ChZtzr.TM..T
0580 - 93 aa 5d a4 b1 1e 87 9f-e1 d1 84 18 b1 e3 74 f1   ..]...........t.
0590 - c3 01 61 68 e6 41 7e a0-59 03 a2 2a 30 41 ce df   ..ah.A~.Y..*0A..
05a0 - 22 54 38 d7 d2 51 d3 d6-16 de 2e 17 c7 92 88 a6   "T8..Q..........
05b0 - 34 3d b8 6d d2 48 7a fc-9b b6 94 b4 14 4a e7 c6   4=.m.Hz......J..
05c0 - a2 8b 47 43 a6 1f 2d d8-c1 d7 30 32 c4 25 03 e0   ..GC..-...02.%..
05d0 - e6 4e 92 d8 90 a3 d4 0e-41 39 f1 42 dd ed 6e b4   .N......A9.B..n.
05e0 - 58 d4 cc bc d8 13 62 e5-13 88 26 aa 97 c7 5c 08   X.....b...&...\.
05f0 - f9 c4 1a 31 2b 42 f2 88-fc d8 f5 9d 9d 11 39 4f   ...1+B........9O
0600 - b1 e5 d9 7b 9e 83 56 36-fb 5a 17 a0 bf c6 a3 3b   ...{..V6.Z.....;
0610 - e8 4d b2 fb 08 58 95 06-30 21 99 7b f9 c4 95 47   .M...X..0!.{...G
0620 - a2 f7 a8 e7 d0 bd 13 82-23 59 8f a1 2a 31 5d 0b   ........#Y..*1].
0630 - 1d f4 df 63 c1 82 9d 25-44 df 93 09 98 bb 11 7a   ...c...%D......z
0640 - ad 23 93 62 7d 31 3c 7a-49 75 04 a1 f5 45 6a a2   .#.b}1<zIu...Ej.
0650 - f7 7b d2 e4 9e 75 ca d9-16 0c 54 2a 42 14 bd 13   .{...u....T*B...
0660 - 7f 54 aa 7b 6a 97 e9 5d-9a 3d 59 c7 0c 8d e8 01   .T.{j..].=Y.....
0670 - e2 ef 35 58 cd a4 92 d2-83 14 81 00 67 9f e1 27   ..5X........g..'
0680 - 91 26 ed e4 e5 80 b3 05-32 c4 21 04 a0 fb c6 ee   .&......2.!.....
0690 - 8e c5 5d c2 67 b9 3f e1-0d c9 d5 5f 16 21 13 ff   ..].g.?...._.!..
06a0 - 6a a5 c5 9f dd 70 15 18-5a 73 95 d7 a7 7e d3 97   j....p..Zs...~..
06b0 - f4 48 83 e7 4f f2 41 34-d1 0d 02 8c b4 82 6b c8   .H..O.A4......k.
06c0 - d8 5e 50 ae 68 e3 e5 9e-50 62 95 11 87 95 db e1   .^P.h...Pb......
06d0 - 84 94 f1 23 ed 94 cd d8-a6 51 0d                  ...#.....Q.
SSL_connect:SSLv3/TLS write client hello
read from 0x21cf79c6910 [0x21cf938ac83] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x21cf79c6910 [0x21cf938ac88] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x21cf79c6910 [0x21cf938ac83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x21cf79c6910 [0x21cf938ac88] (23 bytes => 23 (0x17))
0000 - a9 39 58 ef cb 05 01 3d-0f 32 b6 ef 01 90 87 bf   .9X....=.2......
0010 - 37 30 ea 79 81 a6 d4                              70.y...
SSL_connect:SSLv3/TLS read server hello
Can't use SSL_get_servername
read from 0x21cf79c6910 [0x21cf938ac83] (5 bytes => 5 (0x5))
0000 - 17 03 03 02 2a                                    ....*
read from 0x21cf79c6910 [0x21cf938ac88] (554 bytes => 554 (0x22A))
0000 - a3 90 d3 2d 08 8a 27 2e-9c c4 bb 76 b3 15 f3 44   ...-..'....v...D
0010 - a8 9d 23 93 28 47 8d 4c-a4 47 bc 1b 9a b9 1a 13   ..#.(G.L.G......
0020 - 52 e0 3a ac 63 a7 b8 19-ae 0f 9e 85 ba 58 de 98   R.:.c........X..
0030 - 27 a9 ae 7e c9 92 50 b5-f2 65 0e e2 3e cd 9f fa   '..~..P..e..>...
0040 - 33 f1 1f 10 ca c7 75 bf-cd 10 c0 9b 80 a5 b1 13   3.....u.........
0050 - 20 b3 f0 0a 94 10 30 f2-a4 7b cc 94 5d f3 b9 c1    .....0..{..]...
0060 - f7 41 78 c5 86 04 d5 d3-96 98 bb 3e de 3c 2c c6   .Ax........>.<,.
0070 - 33 b7 08 75 0f d5 61 82-bf ca 6a aa 6e 45 53 c2   3..u..a...j.nES.
0080 - 62 62 06 aa ea 00 e0 a6-ae ea 55 b3 3a 07 a3 db   bb........U.:...
0090 - 58 7f 0a 85 df e8 f3 e6-a3 e6 de 5c e9 16 d9 15   X..........\....
00a0 - 0e 7a 2a 61 1e e5 1b f8-c9 58 7b 46 5c 46 47 90   .z*a.....X{F\FG.
00b0 - bf b8 e8 2f e0 7e 0e 37-f3 ab 2e ed 5c 9c cd 73   .../.~.7....\..s
00c0 - 3f 83 86 51 42 da 61 e2-da 38 ec a6 d2 ab f6 f6   ?..QB.a..8......
00d0 - 02 2a 88 39 98 74 90 c6-26 45 dc 26 0e 64 dc 26   .*.9.t..&E.&.d.&
00e0 - 71 8d fa 2f 48 6e 15 98-03 59 90 95 65 34 95 79   q../Hn...Y..e4.y
00f0 - da f8 a6 cc ee 52 55 2e-1c 15 6c 48 c9 1e df 9a   .....RU...lH....
0100 - 83 ad 91 04 28 7c c1 82-be 3f 5a ff 43 c8 f7 83   ....(|...?Z.C...
0110 - 13 a8 b0 46 76 47 c6 17-2f 03 13 51 e3 99 1b 42   ...FvG../..Q...B
0120 - 39 01 0b 17 ce 2a d3 b2-9d 8a 04 67 a9 70 90 3d   9....*.....g.p.=
0130 - d7 dd 94 23 f2 78 05 5f-a0 30 9a b6 00 a7 0e b7   ...#.x._.0......
0140 - a5 70 12 d3 fd 08 a8 87-1c 9f 75 b0 4f 84 05 bc   .p........u.O...
0150 - f6 47 83 f1 75 2f 26 a4-af 6a 0d 0c 2a df 1a 18   .G..u/&..j..*...
0160 - bd 30 19 26 77 7d b7 21-db c7 76 62 e7 d8 61 e5   .0.&w}.!..vb..a.
0170 - 50 52 06 95 31 93 38 bc-8b 4b 2d 1b e2 7c ae 2c   PR..1.8..K-..|.,
0180 - fa f9 fa 0d b0 bd 89 59-55 1c d5 ed 19 a0 4a e4   .......YU.....J.
0190 - 67 71 86 45 b8 b5 fc 41-d9 92 47 46 74 5e 93 25   gq.E...A..GFt^.%
01a0 - 15 44 06 52 1e e9 00 25-54 8d d5 82 89 4a 5e 3f   .D.R...%T....J^?
01b0 - 0a fe c1 e8 ac 5e 40 47-ac 51 ed 95 4d 19 9b 8f   .....^@G.Q..M...
01c0 - 09 ae 41 ad 53 34 a0 ba-9e a0 48 95 cd 93 d2 0d   ..A.S4....H.....
01d0 - 6c c9 22 63 a6 b8 41 b8-a7 37 29 de ba fb 2d 7d   l."c..A..7)...-}
01e0 - 5e 38 c6 39 8b 80 e8 4e-e5 05 be 8b 85 0b bd 17   ^8.9...N........
01f0 - fd 5e 3d 35 ee 54 15 41-80 16 e4 ea 37 1a 63 af   .^=5.T.A....7.c.
0200 - 94 6c be c9 5b f9 41 bc-f3 cb 13 25 0b ed 04 26   .l..[.A....%...&
0210 - 83 48 00 58 da c5 b6 f0-72 9e 0d 66 d7 b6 b7 88   .H.X....r..f....
0220 - e3 59 9f c2 67 df 71 e5-ff 71                     .Y..g.q..q
SSL_connect:TLSv1.3 read encrypted extensions
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
verify error:num=18:self-signed certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
verify return:1
read from 0x21cf79c6910 [0x21cf938ac83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 60                                    ....`
read from 0x21cf79c6910 [0x21cf938ac88] (96 bytes => 96 (0x60))
0000 - eb 96 ef 84 f6 dc 54 86-e0 9e 7d e6 c8 e3 6f f5   ......T...}...o.
0010 - 69 06 0b 02 2f 2f 08 41-e6 1f 83 c5 45 8d dd 49   i...//.A....E..I
0020 - e9 33 af 7c 67 09 51 fd-9b c1 1d 13 3d 8c 7c 40   .3.|g.Q.....=.|@
0030 - e9 4b ea 88 d9 a5 da 7f-d4 8c 51 90 86 2d 4f 03   .K........Q..-O.
0040 - 8a 41 c8 dc 7f 72 2f d3-8a cc b9 91 10 83 06 86   .A...r/.........
0050 - 95 cc b5 33 e7 73 15 65-49 ed 40 ef 9a 5b 02 4d   ...3.s.eI.@..[.M
SSL_connect:SSLv3/TLS read server certificate
read from 0x21cf79c6910 [0x21cf938ac83] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
read from 0x21cf79c6910 [0x21cf938ac88] (53 bytes => 53 (0x35))
0000 - 89 6b 60 37 3c 63 08 35-bf 80 87 ef 64 de 8c f7   .k`7<c.5....d...
0010 - 70 60 a2 d9 01 42 2e 4d-7a d8 7c e7 09 68 47 25   p`...B.Mz.|..hG%
0020 - e4 8f 2c 52 a0 f5 76 84-9b d8 ce 85 14 53 52 cc   ..,R..v......SR.
0030 - 5d 24 10 3c 0a                                    ]$.<.
SSL_connect:TLSv1.3 read server certificate verify
SSL_connect:SSLv3/TLS read finished
SSL_connect:SSLv3/TLS write change cipher spec
write to 0x21cf79c6910 [0x21cf9382b60] (64 bytes => 64 (0x40))
0000 - 14 03 03 00 01 01 17 03-03 00 35 76 45 de fc 30   ..........5vE..0
0010 - 2d 37 45 a6 eb c7 3e 0d-2b 88 95 e1 57 9a 6f ec   -7E...>.+...W.o.
0020 - 99 2e e0 21 19 74 68 5e-af 5b c4 bb 73 15 b4 64   ...!.th^.[..s..d
0030 - d8 2d 93 08 f7 dc 69 56-b6 c7 0c 23 d1 84 f5 ae   .-....iV...#....
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
Negotiated TLS1.3 group: SecP384r1MLKEM1024
---
SSL handshake has read 2512 bytes and written 1909 bytes
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
read from 0x21cf79c6910 [0x21cf937c5f3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
read from 0x21cf79c6910 [0x21cf937c5f8] (234 bytes => 234 (0xEA))
0000 - 49 76 b1 82 5e b1 96 11-2b 30 9d 3b 5c 5e c2 ee   Iv..^...+0.;\^..
0010 - 1c 57 0b 4e 39 9f 1a f6-b9 11 fd 81 8e 38 8e 27   .W.N9........8.'
0020 - 56 5e 65 b5 92 18 39 36-3d 2b c5 51 0b 87 94 44   V^e...96=+.Q...D
0030 - 43 ba b8 0b 05 5b e1 39-46 47 15 a0 e1 1a c2 2e   C....[.9FG......
0040 - bd 64 58 7a 04 c4 b3 15-9c 97 76 5d ac 1c 23 48   .dXz......v]..#H
0050 - 3b b5 6e 8c e3 b1 7b 20-dc 8a c2 61 6c 9f 0b 9d   ;.n...{ ...al...
0060 - c0 e9 7c fc 6e 9f cc f4-a1 66 c7 ec e7 0b f5 d4   ..|.n....f......
0070 - 5d c8 19 fe b7 5d 0b ac-b6 7c 09 c2 c0 96 67 a6   ]....]...|....g.
0080 - 4c a0 6d 2b e1 ae ef 81-3c 92 52 3f 70 84 b1 d5   L.m+....<.R?p...
0090 - d2 c9 8c b8 20 b5 64 1c-d3 14 d2 81 26 97 74 1b   .... .d.....&.t.
00a0 - fb 6d ed b5 90 3d 3b f6-f4 20 4c 75 82 e7 41 c5   .m...=;.. Lu..A.
00b0 - 0d d1 56 0e 73 a6 60 ad-a8 5c ef 9b 59 d1 f9 9d   ..V.s.`..\..Y...
00c0 - 00 83 2b 30 d7 e3 d7 fe-3a f2 95 45 29 65 d0 c1   ..+0....:..E)e..
00d0 - f0 6d ef f0 ed d0 36 35-d2 a0 6e f4 22 59 8d 20   .m....65..n."Y.
00e0 - cb 09 37 41 6d c8 04 86-89 bd                     ..7Am.....
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_CCM_SHA256
    Session-ID: C9DE5338D10ADA811B0A504CC5F6291EBCA1BF62531565D10B4EB6691A8D9B6D
    Session-ID-ctx:
    Resumption PSK: 7F144EF75E8C25B127FA0BDE5695BF46FE6C1125EC168508ACD0CD0210CAADA1
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 66 83 89 03 21 d4 2c a5-49 78 c6 22 05 5c 94 47   f...!.,.Ix.".\.G
    0010 - b8 64 9a 18 7a a4 f5 67-ac 19 c5 6c dc 7f 54 24   .d..z..g...l..T$
    0020 - 76 55 11 be c0 a7 49 03-61 f3 2e ea c4 20 c8 4c   vU....I.a.... .L
    0030 - 36 10 69 b2 61 c9 d0 10-8f de 26 5e 81 b2 5c 8f   6.i.a.....&^..\.
    0040 - 52 c8 41 24 8a 71 08 f9-14 bc 39 6b 0c 7c 9e 9a   R.A$.q....9k.|..
    0050 - 56 d9 6b 04 58 c0 27 6c-2d ae d9 48 32 4b cd c9   V.k.X.'l-..H2K..
    0060 - 1b a9 f0 9f 59 f9 39 0b-ee 5f f3 d8 7f d9 14 99   ....Y.9.._......
    0070 - 10 5c ca e2 21 53 69 73-af 81 b5 fa 9a 95 eb 66   .\..!Sis.......f
    0080 - 94 4a c0 68 35 25 38 1f-7f 08 a7 a8 e8 f7 9d 67   .J.h5%8........g
    0090 - 48 31 e4 6d 16 6a 88 9d-6f 63 d2 f6 84 84 2f 8e   H1.m.j..oc..../.
    00a0 - e2 a1 08 53 60 63 6a 26-c0 7d 86 c9 bb 03 77 d7   ...S`cj&.}....w.
    00b0 - ed fd 38 1a 5c f0 38 4a-dd 43 18 21 1d 95 f9 69   ..8.\.8J.C.!...i

    Start Time: 1760177392
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
read from 0x21cf79c6910 [0x21cf937c5f3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 ea                                    .....
read from 0x21cf79c6910 [0x21cf937c5f8] (234 bytes => 234 (0xEA))
0000 - 10 65 f9 45 8a c2 72 6c-ee f7 67 bb 5a b6 c2 0b   .e.E..rl..g.Z...
0010 - aa 58 ad 30 5c 15 6e dd-44 0a 10 42 8a f0 43 4d   .X.0\.n.D..B..CM
0020 - 92 7e e0 27 70 11 9e 0a-14 15 c2 2f 9f 9d 27 7d   .~.'p....../..'}
0030 - b5 2f 23 5b 74 d3 56 da-3c 69 c7 26 b7 aa 35 cc   ./#[t.V.<i.&..5.
0040 - 84 68 99 53 7c 72 8d af-17 b0 83 64 a9 18 4d 86   .h.S|r.....d..M.
0050 - 46 a0 35 26 96 74 51 24-cb ab 19 8e b2 2f b1 78   F.5&.tQ$...../.x
0060 - 27 45 45 c6 e3 b1 83 18-e7 0e 72 ca de a4 af 77   'EE.......r....w
0070 - 05 cc 26 3b 87 e3 0f 06-6c bd b2 a6 c2 22 3c 88   ..&;....l...."<.
0080 - 66 b2 32 85 2e 58 4e 9e-c0 55 7c 6a b8 be 07 50   f.2..XN..U|j...P
0090 - d4 92 ee f6 9b 54 4b 46-79 e2 79 06 50 3b 7f 26   .....TKFy.y.P;.&
00a0 - df 23 8e 53 79 03 62 ef-08 40 0b f0 36 1b 34 d3   .#.Sy.b..@..6.4.
00b0 - 48 c6 e7 a5 16 43 39 46-85 d9 a4 78 70 f5 32 21   H....C9F...xp.2!
00c0 - 15 01 8d 10 dc 1b 17 97-e4 e9 57 1e 2c 7c eb 6a   ..........W.,|.j
00d0 - ee 8f fb de 6a 5d 07 04-b8 7d 5b 9b e2 4a 4a 04   ....j]...}[..JJ.
00e0 - 88 87 3a 46 0b a6 9e be-67 10                     ..:F....g.
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_CCM_SHA256
    Session-ID: C4C686B95A502BE1E2BF5373D091F2B1E71D5783316713BBC94C034289A30089
    Session-ID-ctx:
    Resumption PSK: C00361F0885E7F661F550E6C755177F3947D671F3A013DA8AA83C6440B33E7B6
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 66 83 89 03 21 d4 2c a5-49 78 c6 22 05 5c 94 47   f...!.,.Ix.".\.G
    0010 - 66 34 13 20 ce ce 9f 30-45 0b 51 54 05 61 73 ef   f4. ...0E.QT.as.
    0020 - 13 bf 5a cb 02 7c 57 0d-b1 91 c6 1b ab 11 2e c9   ..Z..|W.........
    0030 - 91 6c a4 14 e7 29 e3 a4-c0 a9 47 32 34 90 d0 e8   .l...)....G24...
    0040 - c2 9d fa c6 52 5e f7 7b-89 67 17 2f 81 fe c8 62   ....R^.{.g./...b
    0050 - 8b 03 6d 65 09 be ca cf-d9 d5 f5 f5 d5 3e bc 68   ..me.........>.h
    0060 - 1b 35 72 c1 e8 45 82 01-73 26 fb 75 92 d7 5d 7f   .5r..E..s&.u..].
    0070 - 3b 38 87 27 b9 b3 ba fa-0a f9 09 79 92 fc f7 cf   ;8.'.......y....
    0080 - 4a e8 ec 34 3d a2 82 b5-88 c8 9d ed 3f 51 50 66   J..4=.......?QPf
    0090 - 0d f8 89 f5 11 9d 11 f3-5e 06 d6 77 81 bb c7 e5   ........^..w....
    00a0 - bc 13 bd 44 b0 37 f9 08-34 03 89 40 a5 2e 9e 31   ...D.7..4..@...1
    00b0 - b4 83 6a 75 93 47 8c 11-a1 4e a3 b9 08 c7 0c bd   ..ju.G...N......

    Start Time: 1760177392
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
test
write to 0x21cf79c6910 [0x21cf9386bc3] (28 bytes => 28 (0x1C))
0000 - 17 03 03 00 17 a8 bc 1d-2c 78 ce b4 1e c9 fb bb   ........,x......
0010 - 18 b5 61 32 f9 b3 0d e9-77 8b 1e 2b               ..a2....w..+
Q
DONE
write to 0x21cf79c6910 [0x21cf9386bc3] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 23 a7 1f-f2 ff c4 4b d1 92 7e 34   .....#.....K..~4
0010 - 9d 03 a2 9b bf ab cd 1f-                          ........
SSL3 alert write:warning:close notify
read from 0x21cf79c6910 [0x21cf78effa0] (16384 bytes => 24 (0x18))
0000 - 17 03 03 00 13 23 56 09-2c 11 49 39 bd a8 97 f9   .....#V.,.I9....
0010 - b5 b0 82 e1 d8 9e 30 15-                          ......0.
read from 0x21cf79c6910 [0x21cf78effa0] (16384 bytes => 0)
````

[TOC](README.md)
