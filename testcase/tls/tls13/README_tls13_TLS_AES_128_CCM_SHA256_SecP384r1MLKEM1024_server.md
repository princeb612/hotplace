#### server

````
$ openssl s_server -accept 9000 -cert ecdsa.crt -key ecdsa.key -state -debug -status_verbose -keylogfile sslkeylog -tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256 -groups SecP384r1MLKEM1024
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x2968ed37eb0 [0x2968f133503] (5 bytes => 5 (0x5))
0000 - 16 03 01 07 30                                    ....0
read from 0x2968ed37eb0 [0x2968f133508] (1840 bytes => 1840 (0x730))
0000 - 01 00 07 2c 03 03 48 d6-db 37 65 38 94 8c 9e e6   ...,..H..7e8....
0010 - 4d ad ed 5f fe 77 e0 f7-a8 a5 0c c1 7c d8 45 6b   M.._.w......|.Ek
0020 - 9b 71 20 93 6e ae 20 30-71 04 27 1d bb 40 43 fe   .q .n. 0q.'..@C.
0030 - 2b c2 2c f0 d2 4e f8 d7-cb 38 43 3d 66 ef 06 4d   +.,..N...8C=f..M
0040 - 2b e3 36 b2 89 e2 73 00-02 13 04 01 00 06 e1 00   +.6...s.........
0050 - 0a 00 04 00 02 11 ed 00-23 00 00 00 16 00 00 00   ........#.......
0060 - 17 00 00 00 0d 00 2a 00-28 09 05 09 06 09 04 04   ......*.(.......
0070 - 03 05 03 06 03 08 07 08-08 08 1a 08 1b 08 1c 08   ................
0080 - 09 08 0a 08 0b 08 04 08-05 08 06 04 01 05 01 06   ................
0090 - 01 00 2b 00 03 02 03 04-00 2d 00 02 01 01 00 33   ..+......-.....3
00a0 - 06 87 06 85 11 ed 06 81-04 d7 f9 0d 34 bc 11 4e   ............4..N
00b0 - 53 4a 53 65 75 74 dc 4a-b1 f5 e3 bf 77 2b e6 05   SJSeut.J....w+..
00c0 - 78 49 c2 00 93 db 63 8d-17 f1 3e d0 b1 cd 73 38   xI....c...>...s8
00d0 - 1e 76 33 e0 c7 b7 71 1b-e7 39 5d 32 0d c3 34 6d   .v3...q..9]2..4m
00e0 - fc 3b 04 49 34 7c 2c 35-7a 98 f9 02 37 1d a6 f8   .;.I4|,5z...7...
00f0 - 2f 80 97 3b 9a cd 72 5b-2b c1 3a 3d 26 26 db b8   /..;..r[+.:=&&..
0100 - 74 85 b4 60 6c 07 da 10-c9 f4 a4 74 73 08 54 91   t..`l......ts.T.
0110 - f3 2f b8 02 40 43 b7 b4-eb 38 5a 33 94 0f e6 83   ./..@C...8Z3....
0120 - 8c 2d 45 b2 9e b5 0a 60-c1 3d 8e fc 86 48 f6 b8   .-E....`.=...H..
0130 - 09 c8 82 f0 11 a0 e2 86-71 85 63 c4 af 3b 51 12   ........q.c..;Q.
0140 - f2 49 0d 00 6b 50 51 9f-97 b1 ab b3 77 99 9a 0c   .I..kPQ.....w...
0150 - c6 70 81 b9 d1 65 8a 86-ec 42 43 cb 71 96 f5 37   .p...e...BC.q..7
0160 - 81 e7 7b f7 75 29 44 57-b1 f9 b1 65 50 f9 ca a1   ..{.u)DW...eP...
0170 - 72 4b b6 10 9c f9 c6 00-16 fc 01 d3 a7 58 88 56   rK...........X.V
0180 - b3 f7 10 54 c0 4c 63 ce-67 93 26 ca 2d 25 98 63   ...T.Lc.g.&.-%.c
0190 - f3 68 6d aa 20 6c a3 c8-0d 25 d6 5f fc 6b 39 3b   .hm. l...%._.k9;
01a0 - e3 55 3f d7 8d 84 a5 60-f2 c3 3c e9 46 63 b9 56   .U?....`..<.Fc.V
01b0 - 33 4e e5 bb be 75 03 58-d9 67 90 c4 6d ac 43 26   3N...u.X.g..m.C&
01c0 - 26 25 7b 09 6a 28 b9 54-4d 15 17 62 ef 9c a0 7e   &%{.j(.TM..b...~
01d0 - 81 41 5a 9a 9c 22 42 12-85 ca 06 ed f7 c3 c2 f0   .AZ.."B.........
01e0 - 15 58 0b 1c aa a7 89 63-d7 9d ac 15 48 de f6 17   .X.....c....H...
01f0 - ff c6 8f 55 14 36 ac 46-82 67 20 c5 f9 47 55 4f   ...U.6.F.g ..GUO
0200 - 41 be 48 1c 32 63 1b bb-0c 1a 05 87 c1 6e cf 52   A.H.2c.......n.R
0210 - b3 34 fb a5 2b 83 5e 7e-3c 4d f8 76 71 bb 56 cf   .4..+.^~<M.vq.V.
0220 - 67 73 02 7b bb 27 fe eb-cf 62 84 25 a2 87 b6 44   gs.{.'...b.%...D
0230 - f4 31 2c 73 71 c0 06 af-e0 cb 4a 36 15 c9 c0 60   .1,sq.....J6...`
0240 - 4f 30 7a 02 ac 44 c0 a0-d5 78 2a cb 4a 35 88 b5   O0z..D...x*.J5..
0250 - 4e d0 62 37 53 23 ce 30-87 c7 f1 1e 49 16 ae ef   N.b7S#.0....I...
0260 - d5 40 b5 eb 2c 8e 29 1b-1e f9 4d 26 c8 7c 31 e0   .@..,.)...M&.|1.
0270 - 19 70 58 9a 49 c1 74 8d-bb 06 9a 17 bb 01 16 6e   .pX.I.t........n
0280 - 34 4a 69 cc 79 2c 0c 61-72 51 e4 90 25 81 69 0d   4Ji.y,.arQ..%.i.
0290 - 88 9f 9f 43 73 db 46 0d-84 cc 34 04 7c bb 2c 65   ...Cs.F...4.|.,e
02a0 - 7c 5b 9c 89 58 ba c2 82-ca 75 48 c6 c0 72 15 9d   |[..X....uH..r..
02b0 - 55 aa b3 62 45 c1 74 30-bb 5f 42 51 09 c3 0f 8f   U..bE.t0._BQ....
02c0 - 27 ac ba b5 6d d5 08 61-4f a1 01 de 82 a9 e3 e4   '...m..aO.......
02d0 - 92 20 c1 8c c1 0c 01 d0-fc 0f 05 d1 95 d6 b2 46   . .............F
02e0 - 2f 39 a4 b2 7b 7f 5c c4-cb 02 d1 3a 66 23 0b fc   /9..{.\....:f#..
02f0 - 0a 49 c9 a9 aa 2b c8 34-1e c0 b7 da 34 51 cb f7   .I...+.4....4Q..
0300 - 7d e0 97 50 bf 2a 26 e0-bb 13 95 49 bb 0e db c1   }..P.*&....I....
0310 - 5a fa 07 13 17 83 d5 37-b3 00 1a 3b 6e f5 98 57   Z......7...;n..W
0320 - d9 9d 08 b7 c0 5d 0b 18-29 e4 35 51 db 82 29 87   .....]..).5Q..).
0330 - 83 d3 d0 41 5b cc 45 a9-61 06 20 bb cc d9 ba 44   ...A[.E.a. ....D
0340 - 6d c1 56 2e ba 0c 80 05-49 3c b8 75 8d 3c 95 74   m.V.....I<.u.<.t
0350 - c4 81 18 50 4e 84 e3 66-26 67 47 68 87 9d b5 81   ...PN..f&gGh....
0360 - 83 74 63 4f 27 46 55 b7-ac 4d a9 54 26 1c 56 63   .tcO'FU..M.T&.Vc
0370 - 06 54 36 3c 07 b6 ad fa-44 fe 3c 68 0f fa a3 22   .T6<....D.<h..."
0380 - a4 7d 95 45 74 8d 57 ae-b7 cc a4 89 a8 c0 3f 24   .}.Et.W.......?$
0390 - 9f 9b eb ab bf 4a 87 6a-31 6e 9b 80 11 24 e3 90   .....J.j1n...$..
03a0 - 73 ab 61 05 15 7b 86 f9-2b 90 9a 74 63 38 10 14   s.a..{..+..tc8..
03b0 - bb 31 2b da 83 6d d0 41-d2 a1 c5 ca ec 0e d0 8c   .1+..m.A........
03c0 - 63 3d 66 1a e2 65 a6 d7-f3 52 8e 1c 5a 2e 90 64   c=f..e...R..Z..d
03d0 - a6 2c 46 93 6b 4f 56 53-c9 17 63 2f 39 74 c4 71   .,F.kOVS..c/9t.q
03e0 - b5 c5 f7 08 b8 1f b2 12-71 e2 0b 76 d1 55 fc 56   ........q..v.U.V
03f0 - 3c 61 1a 8c 88 e8 68 46-54 34 52 c8 10 6e 45 68   <a....hFT4R..nEh
0400 - c6 01 86 9b 20 b5 82 a8-b6 12 c4 78 5a ba a8 e2   .... ......xZ...
0410 - 20 10 49 28 05 28 5c 63-74 1a 7f ae 5c 2c dd 79    .I(.(\ct...\,.y
0420 - 14 83 76 66 d7 60 6c a3-a7 3b 00 92 1d 91 e1 0e   ..vf.`l..;......
0430 - cc b5 ba ff e7 c0 3f 3a-6e ed d2 32 9f 59 78 10   ......?:n..2.Yx.
0440 - 13 64 16 d2 15 c9 a1 66-aa 1a 4d 4a 1b b7 10 7a   .d.....f..MJ...z
0450 - 7a 19 94 a5 1c 30 92 cf-63 0b aa a6 8b 6c b8 c1   z....0..c....l..
0460 - e6 e4 1c d7 07 26 06 70-a6 51 96 3c 7a 4c 23 47   .....&.p.Q.<zL#G
0470 - e3 b8 b2 0c 46 5d 2b aa-c6 2b 55 aa d5 c4 88 65   ....F]+..+U....e
0480 - 7e bb b2 30 6e d8 09 af-f5 0f 6c e5 1e 0a b1 54   ~..0n.....l....T
0490 - ba c1 b2 99 55 90 d9 c8-1c 20 c8 98 fa 26 b1 5f   ....U.... ...&._
04a0 - 5a 66 42 d0 18 fb d2 5e-6b 7b b3 58 15 78 b8 e2   ZfB....^k{.X.x..
04b0 - 94 f3 0b a0 87 aa ce f6-22 65 f5 a9 94 b2 16 73   ........"e.....s
04c0 - 22 45 36 f9 48 89 ff c4-21 ab c3 c7 87 12 57 55   "E6.H...!.....WU
04d0 - 7b 8b b8 57 87 dc 78 54-b0 a1 9e ff 4b ac d9 e9   {..W..xT....K...
04e0 - 36 e6 2c 8e 29 35 8f 76-c1 2e 8c 2b cf 3f 18 62   6.,.)5.v...+.?.b
04f0 - 24 55 5b db a3 c3 fd e3-7a bc bb 1d 4c e9 c2 a5   $U[.....z...L...
0500 - 53 b1 48 93 10 66 ec 12-de c0 22 e7 f9 b5 b5 a9   S.H..f....".....
0510 - 8a 28 6a b0 1e 58 25 79-2c 34 bc 5a 13 34 87 a6   .(j..X%y,4.Z.4..
0520 - e7 98 03 04 37 6d 0a e9-b6 68 f0 08 be e6 29 82   ....7m...h....).
0530 - 94 04 24 70 ca 67 b9 a8-b2 6a c6 a9 da 3f 93 82   ..$p.g...j...?..
0540 - 13 9a c9 b0 a3 f7 3a bd-ea 0d 44 c5 06 5f 41 bf   ......:...D.._A.
0550 - cc 45 8d 86 92 9c d1 db-3a 6f b3 77 cf 70 35 0d   .E......:o.w.p5.
0560 - 77 32 29 51 8f 6a 06 48-0c c2 00 ef fa 68 0f d3   w2)Q.j.H.....h..
0570 - 95 f2 5b 02 1f d6 92 e8-1c c0 e0 36 53 11 24 3d   ..[........6S.$=
0580 - 52 88 53 25 d0 cc fd 10-ce 4a 43 29 cd e0 5c 29   R.S%.....JC)..\)
0590 - b2 9f 78 23 53 0e 82 ca-29 bb 6e 83 e8 01 a7 ab   ..x#S...).n.....
05a0 - a4 b5 b6 66 67 f4 87 8e-60 b6 57 51 ac 61 c9 78   ...fg...`.WQ.a.x
05b0 - 07 08 1f ab 74 0c 2b 02-b8 20 d0 1a a9 6a bb 9d   ....t.+.. ...j..
05c0 - d4 7d 48 eb 91 fd d4 87-34 69 98 40 47 2e 90 18   .}H.....4i.@G...
05d0 - 10 70 17 0e 3c d9 13 59-93 c2 b9 c1 4d a5 0b a7   .p..<..Y....M...
05e0 - df 56 57 99 ec b8 0b 8a-78 7d ba bd 3a a8 b8 86   .VW.....x}..:...
05f0 - f3 87 e0 59 7d c4 13 09-44 ba 43 21 08 c3 e0 34   ...Y}...D.C!...4
0600 - 03 3f 34 1e 09 5b 52 bf-5c 17 a7 29 60 10 08 b4   .?4..[R.\..)`...
0610 - 49 c1 be 58 05 14 8c 8c-c1 5f 50 9d 89 0b 92 82   I..X....._P.....
0620 - ac bf a7 c4 20 45 82 9f-7a 15 53 c9 9b 42 08 b6   .... E..z.S..B..
0630 - c7 db 18 ca 21 3b 8f dd-08 5c 01 33 7f ef da be   ....!;...\.3....
0640 - 4f 77 b8 a5 66 47 e5 6a-65 5b c0 08 88 78 ce d2   Ow..fG.je[...x..
0650 - c3 8f af a8 7d d3 91 8a-e0 f5 b2 71 56 ae af ac   ....}......qV...
0660 - bc 2b 1a 6a 62 a6 38 ee-d2 58 e0 65 2c 69 54 ce   .+.jb.8..X.e,iT.
0670 - 7f 91 cd 9b 17 92 70 e0-71 ee 6c 5a 0f 38 b0 89   ......p.q.lZ.8..
0680 - b1 8d 78 d1 81 90 44 4e-d4 76 6d aa 65 9d 0a 75   ..x...DN.vm.e..u
0690 - 36 59 ca 64 54 71 05 3c-7c be 5e 1a 10 8d d4 80   6Y.dTq.<|.^.....
06a0 - f9 49 3e 3c 80 7e 37 e7-66 7e 27 7a dc f1 7d 9a   .I><.~7.f~'z..}.
06b0 - aa b8 f0 d8 bc e3 20 23-9f 91 ce 35 fb 04 94 a7   ...... #...5....
06c0 - ce 24 aa 4f 1e e7 5e 43-fb 98 11 f8 5f 21 72 11   .$.O..^C...._!r.
06d0 - 81 74 4c ce 0a 66 ec b8-16 6f 22 c4 dd f5 0a 22   .tL..f...o"...."
06e0 - cc b4 6f 08 11 be 35 ad-7b 8c a3 55 ac 9c a8 01   ..o...5.{..U....
06f0 - a4 73 d3 7b c3 d1 41 94-aa cb 56 42 24 23 1c 26   .s.{..A...VB$#.&
0700 - fb 04 68 43 82 75 d1 51-4c f0 4b 28 0a 17 b2 ef   ..hC.u.QL.K(....
0710 - fc 3b 32 58 ae ed 80 2a-1c ed 49 30 0c 72 c6 35   .;2X...*..I0.r.5
0720 - 4b eb 68 43 73 36 14 5b-cf 00 1b 00 03 02 00 01   K.hCs6.[........
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write change cipher spec
SSL_accept:TLSv1.3 write encrypted extensions
SSL_accept:SSLv3/TLS write certificate
SSL_accept:TLSv1.3 write server certificate verify
write to 0x2968ed37eb0 [0x2968f1324f0] (2512 bytes => 2512 (0x9D0))
0000 - 16 03 03 06 db 02 00 06-d7 03 03 07 5e 70 1e e4   ............^p..
0010 - 1f 03 b7 e5 4d de 05 9b-a2 52 00 81 d4 af 75 3f   ....M....R....u?
0020 - de 57 25 e4 45 ed f2 30-82 d2 50 20 30 71 04 27   .W%.E..0..P 0q.'
0030 - 1d bb 40 43 fe 2b c2 2c-f0 d2 4e f8 d7 cb 38 43   ..@C.+.,..N...8C
0040 - 3d 66 ef 06 4d 2b e3 36-b2 89 e2 73 13 04 00 06   =f..M+.6...s....
0050 - 8f 00 2b 00 02 03 04 00-33 06 85 11 ed 06 81 04   ..+.....3.......
0060 - 09 2f 68 d6 f4 bb 4f 31-04 20 f4 99 d8 21 bf 95   ./h...O1. ...!..
0070 - d9 3d 2c 2d e4 96 f8 ce-36 43 c3 dc a4 d3 98 ea   .=,-....6C......
0080 - fe bc 23 3f 8e 11 70 24-e3 36 85 8f bf 7f e6 97   ..#?..p$.6......
0090 - 96 04 c1 30 82 7e 68 6e-03 b2 c5 bb af b5 b9 ca   ...0.~hn........
00a0 - ef 52 49 63 c1 3c 03 16-ab 82 dc 6b d7 58 c8 3b   .RIc.<.....k.X.;
00b0 - 79 87 1a 13 a6 a1 33 d6-28 15 5d 68 df 70 43 14   y.....3.(.]h.pC.
00c0 - cc 46 1d d6 8a f8 04 a5-69 66 e6 5b 52 85 5f 6f   .F......if.[R._o
00d0 - 14 55 62 15 4f 93 2f c1-a2 bc b7 18 f7 96 f2 fa   .Ub.O./.........
00e0 - 35 69 83 dd fa 0e dd 8d-6c 20 47 29 50 98 28 2b   5i......l G)P.(+
00f0 - e6 68 09 2b 93 37 2e d4-68 5e 38 35 96 da 9e 0a   .h.+.7..h^85....
0100 - f2 bc 72 e8 11 12 1b d7-f8 7a e9 c7 fc 1e dc af   ..r......z......
0110 - 86 bb 18 e7 44 ec e2 43-88 e9 b8 ca 98 f6 6d 79   ....D..C......my
0120 - 78 fa 77 37 82 52 74 b7-ab eb 5b ab 6b 98 f5 1b   x.w7.Rt...[.k...
0130 - eb de 62 0f dd 28 08 75-79 f1 7c 0d 86 40 f7 35   ..b..(.uy.|..@.5
0140 - e9 7c 72 99 81 a8 2d ab-71 61 2c e0 fe 83 e6 1a   .|r...-.qa,.....
0150 - 2a 35 36 20 ad 18 33 50-b5 97 26 1f 44 a4 e2 aa   *56 ..3P..&.D...
0160 - 1e 04 08 8a 31 3b 9c 64-b8 84 84 67 8a 4c ab ed   ....1;.d...g.L..
0170 - 61 59 d5 65 c9 0d 3f 25-1e 0c 86 23 ce ee 7e f5   aY.e..?%...#..~.
0180 - d1 23 46 ed e9 da 51 0f-f5 82 b3 66 07 e5 a8 c3   .#F...Q....f....
0190 - 72 52 62 fd b3 f8 2b 71-3f 12 1f 60 d3 64 49 0a   rRb...+q?..`.dI.
01a0 - 95 f0 c4 5c 53 9b 60 96-1a a5 a9 b3 1b 8c d9 5e   ...\S.`........^
01b0 - 88 d2 2a 69 eb 92 52 1f-de 8d 51 70 1b 50 01 b3   ..*i..R...Qp.P..
01c0 - 01 87 a8 1a b1 2a 4e 20-a9 d5 46 6f 55 22 96 22   .....*N ..FoU"."
01d0 - 66 fc 1b 09 d8 69 fb 5a-4e ac 92 d8 9c 50 34 99   f....i.ZN....P4.
01e0 - aa a0 08 19 53 2f 95 73-51 03 62 c1 8d 9e fa ab   ....S/.sQ.b.....
01f0 - 9a 6b 2a 2a 2e 3d 94 e5-d1 8b a1 90 fe 2a 52 e5   .k**.=.......*R.
0200 - a2 37 9c 54 84 1e e0 f9-b6 50 a3 4b 7c e8 13 71   .7.T.....P.K|..q
0210 - a2 23 d8 64 52 e2 0c f2-a6 5a 67 79 f5 fb 15 31   .#.dR....Zgy...1
0220 - dc 23 6f b8 9e 37 39 cb-13 d7 b0 18 0b 74 c3 d4   .#o..79......t..
0230 - d5 2b 68 9c 78 e4 92 4b-6c e8 b7 75 ec b5 3c 72   .+h.x..Kl..u..<r
0240 - 3d 00 dc 84 7c fe b8 97-95 fe 96 43 b0 d1 5b b6   =...|......C..[.
0250 - 9c 96 0b 14 ed ce 83 11-4a c3 bc 5a 72 1f 86 74   ........J..Zr..t
0260 - 2a 14 9c 6c d8 14 2d 8f-de 87 94 7e c5 c1 6f d2   *..l..-....~..o.
0270 - b2 54 bf 9f 0b 7c 98 c7-0a 94 80 1f 08 2b f3 75   .T...|.......+.u
0280 - a1 4b dc ba 24 a5 b8 24-d3 9c 64 8c 3a dd ec ff   .K..$..$..d.:...
0290 - ce de cd a5 0c 15 3a ee-f4 48 23 66 f5 7e fe 4f   ......:..H#f.~.O
02a0 - 04 f9 03 4a 5c 04 56 d9-ce fa 84 cd 20 14 6c 37   ...J\.V..... .l7
02b0 - eb 9c af ad 5c c7 f7 c0-db d5 7b 8f a7 9c cb c1   ....\.....{.....
02c0 - 12 3a 89 89 7a 86 07 ac-fd 09 c4 a3 0a 75 1c b5   .:..z........u..
02d0 - 7f 6a 89 c3 06 8b 88 f5-a7 11 f2 2f 1a f1 19 25   .j........./...%
02e0 - 7e 28 50 23 c9 a4 4d 66-f9 a0 b6 ff 8b 71 bc bd   ~(P#..Mf.....q..
02f0 - 83 a7 0f 41 49 60 14 f6-b2 21 77 c4 7b 95 83 07   ...AI`...!w.{...
0300 - 79 27 32 2d 70 83 37 b0-8a 00 bb 92 6a f0 35 32   y'2-p.7.....j.52
0310 - 6b cf 3e 51 6f b7 d4 b6-ed a5 3f 69 c8 12 f9 45   k.>Qo.....?i...E
0320 - b2 76 28 51 e5 70 8e 9e-be 44 bd 7d b9 33 22 29   .v(Q.p...D.}.3")
0330 - 70 26 1e 52 00 4e ba 8b-ca 71 8f 80 3b b2 f3 ec   p&.R.N...q..;...
0340 - b1 e2 b2 94 4f 22 22 dd-7b 3f be 15 67 0e a1 21   ....O"".{?..g..!
0350 - 01 ce c8 8a a8 2b 0e 50-fb 58 b0 0d ed 0b bf dc   .....+.P.X......
0360 - fa 29 8f 24 ed f4 7a 60-ba 57 57 81 2a 7e e0 69   .).$..z`.WW.*~.i
0370 - fa b3 56 6e 87 c3 f1 cc-15 6e f3 24 41 61 4d de   ..Vn.....n.$AaM.
0380 - f0 e2 c4 aa dc 88 be eb-b7 1d 78 91 4d f8 0a 18   ..........x.M...
0390 - 1c 18 34 2f a9 25 e5 43-91 b4 68 39 67 3c ae 98   ..4/.%.C..h9g<..
03a0 - 3c 96 0e a7 26 e4 c4 6e-e7 a7 ad 01 d0 c4 4e 5f   <...&..n......N_
03b0 - 37 fb 77 4f 35 70 76 36-11 15 c8 3c 1f 7d a5 49   7.wO5pv6...<.}.I
03c0 - 85 3f df 31 fb 7c 36 69-5a 22 38 c6 d6 30 d2 02   .?.1.|6iZ"8..0..
03d0 - 76 94 f7 c2 45 9b 01 21-96 df 33 ad d2 29 3e 93   v...E..!..3..)>.
03e0 - 43 7f e5 dd 1c 86 07 82-2d c5 84 08 10 98 d0 d7   C.......-.......
03f0 - 40 0b 2d 2f b8 b1 82 f9-4f da ef e4 d2 7d 38 b1   @.-/....O....}8.
0400 - 8a a9 e9 ff c8 7c 69 2b-b7 ee 2a 4d d5 e8 d6 8b   .....|i+..*M....
0410 - fc b8 d1 b3 30 c0 01 94-85 17 e7 3b b5 62 f8 d0   ....0......;.b..
0420 - e5 9a b2 7a 7d a6 43 55-2f 4c e7 59 c8 5f 01 34   ...z}.CU/L.Y._.4
0430 - e6 6c 6f 37 76 5e 9f fe-ac 4a fa 46 98 6e 9a 7b   .lo7v^...J.F.n.{
0440 - 15 51 b7 7f 3f 28 c8 9c-bd e6 27 4e dc 1a 93 90   .Q..?(....'N....
0450 - f9 17 6d 00 ad a7 5b 2b-a9 d1 1a ed cf 76 63 63   ..m...[+.....vcc
0460 - 42 d1 d9 a0 10 76 e6 d3-db 1e a7 b9 8f 32 6c ba   B....v.......2l.
0470 - 76 47 38 a9 3b 5a ef 7e-bb 85 e3 68 4b fe de ee   vG8.;Z.~...hK...
0480 - 95 54 95 f1 ea 8b 64 25-52 f8 7e b1 e6 59 f7 39   .T....d%R.~..Y.9
0490 - b0 11 9f 34 4e 2b 0f 08-5f a2 b8 27 03 b7 fc 8e   ...4N+.._..'....
04a0 - 48 87 be 04 78 d2 4e 14-58 49 35 1d 7d fe 94 31   H...x.N.XI5.}..1
04b0 - d4 9a c2 e1 d2 0e 2c 91-8b 55 b5 b8 7b 35 3d da   ......,..U..{5=.
04c0 - b1 04 84 be 7d 78 7e 5b-3e 60 5d b4 c2 df ba 32   ....}x~[>`]....2
04d0 - bb 2a 35 86 cd ab 9c 59-20 dd 7a e6 b6 a0 6a 85   .*5....Y .z...j.
04e0 - e8 fb 73 f5 41 f4 0f 78-73 aa 7a 47 35 e5 d8 10   ..s.A..xs.zG5...
04f0 - 64 cc aa 36 41 b1 f3 8b-22 66 d4 95 ca 4b 39 91   d..6A..."f...K9.
0500 - 32 cc 20 f9 81 d7 4d 13-09 96 4f df 2d 61 89 b8   2. ...M...O.-a..
0510 - a2 d6 92 fc 66 34 3f b9-36 29 1d 42 81 ce 8c 77   ....f4?.6).B...w
0520 - 57 80 de 46 e3 04 ef 5f-54 af e3 87 05 b4 3f 71   W..F..._T.....?q
0530 - d6 1a ce 27 58 f6 0b d2-f9 f4 3a a1 25 ce f6 b6   ...'X.....:.%...
0540 - d1 8e 79 e4 dd 36 bf f5-23 a2 36 66 e5 71 3f c9   ..y..6..#.6f.q?.
0550 - 2c b7 77 b7 a8 50 90 88-27 4c c1 14 fb d5 b5 47   ,.w..P..'L.....G
0560 - be 5e f7 1e c8 45 88 92-76 77 76 11 1a 81 ce b0   .^...E..vwv.....
0570 - 75 c0 d9 c2 63 cb 94 90-80 43 68 5a 74 7a 72 bd   u...c....ChZtzr.
0580 - 54 4d 9a ba 54 93 aa 5d-a4 b1 1e 87 9f e1 d1 84   TM..T..]........
0590 - 18 b1 e3 74 f1 c3 01 61-68 e6 41 7e a0 59 03 a2   ...t...ah.A~.Y..
05a0 - 2a 30 41 ce df 22 54 38-d7 d2 51 d3 d6 16 de 2e   *0A.."T8..Q.....
05b0 - 17 c7 92 88 a6 34 3d b8-6d d2 48 7a fc 9b b6 94   .....4=.m.Hz....
05c0 - b4 14 4a e7 c6 a2 8b 47-43 a6 1f 2d d8 c1 d7 30   ..J....GC..-...0
05d0 - 32 c4 25 03 e0 e6 4e 92-d8 90 a3 d4 0e 41 39 f1   2.%...N......A9.
05e0 - 42 dd ed 6e b4 58 d4 cc-bc d8 13 62 e5 13 88 26   B..n.X.....b...&
05f0 - aa 97 c7 5c 08 f9 c4 1a-31 2b 42 f2 88 fc d8 f5   ...\....1+B.....
0600 - 9d 9d 11 39 4f b1 e5 d9-7b 9e 83 56 36 fb 5a 17   ...9O...{..V6.Z.
0610 - a0 bf c6 a3 3b e8 4d b2-fb 08 58 95 06 30 21 99   ....;.M...X..0!.
0620 - 7b f9 c4 95 47 a2 f7 a8-e7 d0 bd 13 82 23 59 8f   {...G........#Y.
0630 - a1 2a 31 5d 0b 1d f4 df-63 c1 82 9d 25 44 df 93   .*1]....c...%D..
0640 - 09 98 bb 11 7a ad 23 93-62 7d 31 3c 7a 49 75 04   ....z.#.b}1<zIu.
0650 - a1 f5 45 6a a2 f7 7b d2-e4 9e 75 ca d9 16 0c 54   ..Ej..{...u....T
0660 - 2a 42 14 bd 13 7f 54 aa-7b 6a 97 e9 5d 9a 3d 59   *B....T.{j..].=Y
0670 - c7 0c 8d e8 01 e2 ef 35-58 cd a4 92 d2 83 14 81   .......5X.......
0680 - 00 67 9f e1 27 91 26 ed-e4 e5 80 b3 05 32 c4 21   .g..'.&......2.!
0690 - 04 a0 fb c6 ee 8e c5 5d-c2 67 b9 3f e1 0d c9 d5   .......].g.?....
06a0 - 5f 16 21 13 ff 6a a5 c5-9f dd 70 15 18 5a 73 95   _.!..j....p..Zs.
06b0 - d7 a7 7e d3 97 f4 48 83-e7 4f f2 41 34 d1 0d 02   ..~...H..O.A4...
06c0 - 8c b4 82 6b c8 d8 5e 50-ae 68 e3 e5 9e 50 62 95   ...k..^P.h...Pb.
06d0 - 11 87 95 db e1 84 94 f1-23 ed 94 cd d8 a6 51 0d   ........#.....Q.
06e0 - 14 03 03 00 01 01 17 03-03 00 17 a9 39 58 ef cb   ............9X..
06f0 - 05 01 3d 0f 32 b6 ef 01-90 87 bf 37 30 ea 79 81   ..=.2......70.y.
0700 - a6 d4 17 03 03 02 2a a3-90 d3 2d 08 8a 27 2e 9c   ......*...-..'..
0710 - c4 bb 76 b3 15 f3 44 a8-9d 23 93 28 47 8d 4c a4   ..v...D..#.(G.L.
0720 - 47 bc 1b 9a b9 1a 13 52-e0 3a ac 63 a7 b8 19 ae   G......R.:.c....
0730 - 0f 9e 85 ba 58 de 98 27-a9 ae 7e c9 92 50 b5 f2   ....X..'..~..P..
0740 - 65 0e e2 3e cd 9f fa 33-f1 1f 10 ca c7 75 bf cd   e..>...3.....u..
0750 - 10 c0 9b 80 a5 b1 13 20-b3 f0 0a 94 10 30 f2 a4   ....... .....0..
0760 - 7b cc 94 5d f3 b9 c1 f7-41 78 c5 86 04 d5 d3 96   {..]....Ax......
0770 - 98 bb 3e de 3c 2c c6 33-b7 08 75 0f d5 61 82 bf   ..>.<,.3..u..a..
0780 - ca 6a aa 6e 45 53 c2 62-62 06 aa ea 00 e0 a6 ae   .j.nES.bb.......
0790 - ea 55 b3 3a 07 a3 db 58-7f 0a 85 df e8 f3 e6 a3   .U.:...X........
07a0 - e6 de 5c e9 16 d9 15 0e-7a 2a 61 1e e5 1b f8 c9   ..\.....z*a.....
07b0 - 58 7b 46 5c 46 47 90 bf-b8 e8 2f e0 7e 0e 37 f3   X{F\FG..../.~.7.
07c0 - ab 2e ed 5c 9c cd 73 3f-83 86 51 42 da 61 e2 da   ...\..s?..QB.a..
07d0 - 38 ec a6 d2 ab f6 f6 02-2a 88 39 98 74 90 c6 26   8.......*.9.t..&
07e0 - 45 dc 26 0e 64 dc 26 71-8d fa 2f 48 6e 15 98 03   E.&.d.&q../Hn...
07f0 - 59 90 95 65 34 95 79 da-f8 a6 cc ee 52 55 2e 1c   Y..e4.y.....RU..
0800 - 15 6c 48 c9 1e df 9a 83-ad 91 04 28 7c c1 82 be   .lH........(|...
0810 - 3f 5a ff 43 c8 f7 83 13-a8 b0 46 76 47 c6 17 2f   ?Z.C......FvG../
0820 - 03 13 51 e3 99 1b 42 39-01 0b 17 ce 2a d3 b2 9d   ..Q...B9....*...
0830 - 8a 04 67 a9 70 90 3d d7-dd 94 23 f2 78 05 5f a0   ..g.p.=...#.x._.
0840 - 30 9a b6 00 a7 0e b7 a5-70 12 d3 fd 08 a8 87 1c   0.......p.......
0850 - 9f 75 b0 4f 84 05 bc f6-47 83 f1 75 2f 26 a4 af   .u.O....G..u/&..
0860 - 6a 0d 0c 2a df 1a 18 bd-30 19 26 77 7d b7 21 db   j..*....0.&w}.!.
0870 - c7 76 62 e7 d8 61 e5 50-52 06 95 31 93 38 bc 8b   .vb..a.PR..1.8..
0880 - 4b 2d 1b e2 7c ae 2c fa-f9 fa 0d b0 bd 89 59 55   K-..|.,.......YU
0890 - 1c d5 ed 19 a0 4a e4 67-71 86 45 b8 b5 fc 41 d9   .....J.gq.E...A.
08a0 - 92 47 46 74 5e 93 25 15-44 06 52 1e e9 00 25 54   .GFt^.%.D.R...%T
08b0 - 8d d5 82 89 4a 5e 3f 0a-fe c1 e8 ac 5e 40 47 ac   ....J^?.....^@G.
08c0 - 51 ed 95 4d 19 9b 8f 09-ae 41 ad 53 34 a0 ba 9e   Q..M.....A.S4...
08d0 - a0 48 95 cd 93 d2 0d 6c-c9 22 63 a6 b8 41 b8 a7   .H.....l."c..A..
08e0 - 37 29 de ba fb 2d 7d 5e-38 c6 39 8b 80 e8 4e e5   7)...-}^8.9...N.
08f0 - 05 be 8b 85 0b bd 17 fd-5e 3d 35 ee 54 15 41 80   ........^=5.T.A.
0900 - 16 e4 ea 37 1a 63 af 94-6c be c9 5b f9 41 bc f3   ...7.c..l..[.A..
0910 - cb 13 25 0b ed 04 26 83-48 00 58 da c5 b6 f0 72   ..%...&.H.X....r
0920 - 9e 0d 66 d7 b6 b7 88 e3-59 9f c2 67 df 71 e5 ff   ..f.....Y..g.q..
0930 - 71 17 03 03 00 60 eb 96-ef 84 f6 dc 54 86 e0 9e   q....`......T...
0940 - 7d e6 c8 e3 6f f5 69 06-0b 02 2f 2f 08 41 e6 1f   }...o.i...//.A..
0950 - 83 c5 45 8d dd 49 e9 33-af 7c 67 09 51 fd 9b c1   ..E..I.3.|g.Q...
0960 - 1d 13 3d 8c 7c 40 e9 4b-ea 88 d9 a5 da 7f d4 8c   ..=.|@.K........
0970 - 51 90 86 2d 4f 03 8a 41-c8 dc 7f 72 2f d3 8a cc   Q..-O..A...r/...
0980 - b9 91 10 83 06 86 95 cc-b5 33 e7 73 15 65 49 ed   .........3.s.eI.
0990 - 40 ef 9a 5b 02 4d 17 03-03 00 35 89 6b 60 37 3c   @..[.M....5.k`7<
09a0 - 63 08 35 bf 80 87 ef 64-de 8c f7 70 60 a2 d9 01   c.5....d...p`...
09b0 - 42 2e 4d 7a d8 7c e7 09-68 47 25 e4 8f 2c 52 a0   B.Mz.|..hG%..,R.
09c0 - f5 76 84 9b d8 ce 85 14-53 52 cc 5d 24 10 3c 0a   .v......SR.]$.<.
SSL_accept:SSLv3/TLS write finished
SSL_accept:TLSv1.3 early data
read from 0x2968ed37eb0 [0x2968f133503] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x2968ed37eb0 [0x2968f133508] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x2968ed37eb0 [0x2968f133503] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
read from 0x2968ed37eb0 [0x2968f133508] (53 bytes => 53 (0x35))
0000 - 76 45 de fc 30 2d 37 45-a6 eb c7 3e 0d 2b 88 95   vE..0-7E...>.+..
0010 - e1 57 9a 6f ec 99 2e e0-21 19 74 68 5e af 5b c4   .W.o....!.th^.[.
0020 - bb 73 15 b4 64 d8 2d 93-08 f7 dc 69 56 b6 c7 0c   .s..d.-....iV...
0030 - 23 d1 84 f5 ae                                    #....
SSL_accept:TLSv1.3 early data
SSL_accept:SSLv3/TLS read finished
write to 0x2968ed37eb0 [0x2968f1324f0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea 49 76 b1-82 5e b1 96 11 2b 30 9d   .....Iv..^...+0.
0010 - 3b 5c 5e c2 ee 1c 57 0b-4e 39 9f 1a f6 b9 11 fd   ;\^...W.N9......
0020 - 81 8e 38 8e 27 56 5e 65-b5 92 18 39 36 3d 2b c5   ..8.'V^e...96=+.
0030 - 51 0b 87 94 44 43 ba b8-0b 05 5b e1 39 46 47 15   Q...DC....[.9FG.
0040 - a0 e1 1a c2 2e bd 64 58-7a 04 c4 b3 15 9c 97 76   ......dXz......v
0050 - 5d ac 1c 23 48 3b b5 6e-8c e3 b1 7b 20 dc 8a c2   ]..#H;.n...{ ...
0060 - 61 6c 9f 0b 9d c0 e9 7c-fc 6e 9f cc f4 a1 66 c7   al.....|.n....f.
0070 - ec e7 0b f5 d4 5d c8 19-fe b7 5d 0b ac b6 7c 09   .....]....]...|.
0080 - c2 c0 96 67 a6 4c a0 6d-2b e1 ae ef 81 3c 92 52   ...g.L.m+....<.R
0090 - 3f 70 84 b1 d5 d2 c9 8c-b8 20 b5 64 1c d3 14 d2   ?p....... .d....
00a0 - 81 26 97 74 1b fb 6d ed-b5 90 3d 3b f6 f4 20 4c   .&.t..m...=;.. L
00b0 - 75 82 e7 41 c5 0d d1 56-0e 73 a6 60 ad a8 5c ef   u..A...V.s.`..\.
00c0 - 9b 59 d1 f9 9d 00 83 2b-30 d7 e3 d7 fe 3a f2 95   .Y.....+0....:..
00d0 - 45 29 65 d0 c1 f0 6d ef-f0 ed d0 36 35 d2 a0 6e   E)e...m....65..n
00e0 - f4 22 59 8d 20 cb 09 37-41 6d c8 04 86 89 bd      ."Y. ..7Am.....
SSL_accept:SSLv3/TLS write session ticket
write to 0x2968ed37eb0 [0x2968f1324f0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea 10 65 f9-45 8a c2 72 6c ee f7 67   ......e.E..rl..g
0010 - bb 5a b6 c2 0b aa 58 ad-30 5c 15 6e dd 44 0a 10   .Z....X.0\.n.D..
0020 - 42 8a f0 43 4d 92 7e e0-27 70 11 9e 0a 14 15 c2   B..CM.~.'p......
0030 - 2f 9f 9d 27 7d b5 2f 23-5b 74 d3 56 da 3c 69 c7   /..'}./#[t.V.<i.
0040 - 26 b7 aa 35 cc 84 68 99-53 7c 72 8d af 17 b0 83   &..5..h.S|r.....
0050 - 64 a9 18 4d 86 46 a0 35-26 96 74 51 24 cb ab 19   d..M.F.5&.tQ$...
0060 - 8e b2 2f b1 78 27 45 45-c6 e3 b1 83 18 e7 0e 72   ../.x'EE.......r
0070 - ca de a4 af 77 05 cc 26-3b 87 e3 0f 06 6c bd b2   ....w..&;....l..
0080 - a6 c2 22 3c 88 66 b2 32-85 2e 58 4e 9e c0 55 7c   .."<.f.2..XN..U|
0090 - 6a b8 be 07 50 d4 92 ee-f6 9b 54 4b 46 79 e2 79   j...P.....TKFy.y
00a0 - 06 50 3b 7f 26 df 23 8e-53 79 03 62 ef 08 40 0b   .P;.&.#.Sy.b..@.
00b0 - f0 36 1b 34 d3 48 c6 e7-a5 16 43 39 46 85 d9 a4   .6.4.H....C9F...
00c0 - 78 70 f5 32 21 15 01 8d-10 dc 1b 17 97 e4 e9 57   xp.2!..........W
00d0 - 1e 2c 7c eb 6a ee 8f fb-de 6a 5d 07 04 b8 7d 5b   .,|.j....j]...}[
00e0 - 9b e2 4a 4a 04 88 87 3a-46 0b a6 9e be 67 10      ..JJ...:F....g.
SSL_accept:SSLv3/TLS write session ticket
-----BEGIN SSL SESSION PARAMETERS-----
MHMCAQECAgMEBAITBAQgDUExfTWs8qj3pNr77/PBBY5Z7I/EtP9UzjbM5AStN2QE
IMADYfCIXn9mH1UObHVRd/OUfWcfOgE9qKqDxkQLM+e2oQYCBGjqLPCiBAICHCCk
BgQEAQAAAK4GAgQUNQwSswQCAhHt
-----END SSL SESSION PARAMETERS-----
Shared ciphers:TLS_AES_128_CCM_SHA256
Signature Algorithms: id-ml-dsa-65:id-ml-dsa-87:id-ml-dsa-44:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:ed448:ecdsa_brainpoolP256r1_sha256:ecdsa_brainpoolP384r1_sha384:ecdsa_brainpoolP512r1_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Shared Signature Algorithms: id-ml-dsa-65:id-ml-dsa-87:id-ml-dsa-44:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:ed25519:ed448:ecdsa_brainpoolP256r1_sha256:ecdsa_brainpoolP384r1_sha384:ecdsa_brainpoolP512r1_sha512:rsa_pss_pss_sha256:rsa_pss_pss_sha384:rsa_pss_pss_sha512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Supported groups: SecP384r1MLKEM1024
Shared groups: SecP384r1MLKEM1024
CIPHER is TLS_AES_128_CCM_SHA256
This TLS version forbids renegotiation.
read from 0x2968ed37eb0 [0x2968f143d23] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x2968ed37eb0 [0x2968f143d28] (23 bytes => 23 (0x17))
0000 - a8 bc 1d 2c 78 ce b4 1e-c9 fb bb 18 b5 61 32 f9   ...,x........a2.
0010 - b3 0d e9 77 8b 1e 2b                              ...w..+
test
read from 0x2968ed37eb0 [0x2968f143d23] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 13                                    .....
read from 0x2968ed37eb0 [0x2968f143d28] (19 bytes => 19 (0x13))
0000 - 23 a7 1f f2 ff c4 4b d1-92 7e 34 9d 03 a2 9b bf   #.....K..~4.....
0010 - ab cd 1f                                          ...
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x2968ed37eb0 [0x2968f133503] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 23 56 09-2c 11 49 39 bd a8 97 f9   .....#V.,.I9....
0010 - b5 b0 82 e1 d8 9e 30 15-                          ......0.
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
