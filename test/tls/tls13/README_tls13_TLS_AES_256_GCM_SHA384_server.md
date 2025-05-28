#### tls13.pcapng - server

````
$ openssl s_server -accept 9000 -cert server.crt -key server.key -state -debug -status_verbose -keylogfile sslkeylog -tls1_3
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x2432c4e5830 [0x2432c924873] (5 bytes => 5 (0x5))
0000 - 16 03 01 00 e7                                    .....
read from 0x2432c4e5830 [0x2432c924878] (231 bytes => 231 (0xE7))
0000 - 01 00 00 e3 03 03 b9 39-8c 3a f3 5d 14 01 fe 4a   .......9.:.]...J
0010 - a6 2e a9 4b 26 43 37 f1-85 bc 84 4e 1b c2 dd ed   ...K&C7....N....
0020 - 35 86 b8 da e2 25 20 43-9a cd c3 2a 47 ca 3c 67   5....% C...*G.<g
0030 - bf d9 ae dc fa ee 66 3b-49 bc f8 c7 da 1c 8e 36   ......f;I......6
0040 - ed 29 c9 d9 43 62 30 00-06 13 02 13 03 13 01 01   .)..Cb0.........
0050 - 00 00 94 00 0b 00 04 03-00 01 02 00 0a 00 16 00   ................
0060 - 14 00 1d 00 17 00 1e 00-19 00 18 01 00 01 01 01   ................
0070 - 02 01 03 01 04 00 23 00-00 00 16 00 00 00 17 00   ......#.........
0080 - 00 00 0d 00 24 00 22 04-03 05 03 06 03 08 07 08   ....$.".........
0090 - 08 08 1a 08 1b 08 1c 08-09 08 0a 08 0b 08 04 08   ................
00a0 - 05 08 06 04 01 05 01 06-01 00 2b 00 03 02 03 04   ..........+.....
00b0 - 00 2d 00 02 01 01 00 33-00 26 00 24 00 1d 00 20   .-.....3.&.$...
00c0 - 54 10 c0 fe 90 88 d2 f5-df 0f c5 dc bf 60 75 9b   T............`u.
00d0 - 96 f5 75 f8 aa 91 14 37-5f d5 e6 d7 e9 b0 94 23   ..u....7_......#
00e0 - 00 1b 00 03 02 00 01                              .......
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write change cipher spec
SSL_accept:TLSv1.3 write encrypted extensions
SSL_accept:SSLv3/TLS write certificate
SSL_accept:TLSv1.3 write server certificate verify
write to 0x2432c4e5830 [0x2432c923860] (1420 bytes => 1420 (0x58C))
0000 - 16 03 03 00 7a 02 00 00-76 03 03 73 8a 10 e3 4d   ....z...v..s...M
0010 - 0a d3 4b 5c 0c 9b b5 6b-9b 20 f9 b6 1e 55 73 6e   ..K\...k. ...Usn
0020 - 35 ca cb a3 14 7d ff 09-f8 5a 9a 20 43 9a cd c3   5....}...Z. C...
0030 - 2a 47 ca 3c 67 bf d9 ae-dc fa ee 66 3b 49 bc f8   *G.<g......f;I..
0040 - c7 da 1c 8e 36 ed 29 c9-d9 43 62 30 13 02 00 00   ....6.)..Cb0....
0050 - 2e 00 2b 00 02 03 04 00-33 00 24 00 1d 00 20 60   ..+.....3.$... `
0060 - 63 09 ac 36 97 58 a7 33-00 a4 68 13 ce 40 6f e8   c..6.X.3..h..@o.
0070 - 3c 90 a0 0c 5b 9a be a2-52 64 00 2d 79 ec 00 14   <...[...Rd.-y...
0080 - 03 03 00 01 01 17 03 03-00 17 a1 f9 36 57 36 ea   ............6W6.
0090 - 54 b8 3b 6f b2 eb 7b 3b-6e 1a 2a e4 88 1b 24 64   T.;o..{;n.*...$d
00a0 - 03 17 03 03 03 7e 39 1a-84 b4 f7 2d 0b ee 0e 47   .....~9....-...G
00b0 - f1 9d 78 19 a5 bc 24 f8-02 51 48 1c 61 df 5d c0   ..x...$..QH.a.].
00c0 - 2d d2 76 02 1f 39 30 49-b9 66 72 67 d0 58 67 d3   -.v..90I.frg.Xg.
00d0 - 25 f9 20 53 1c 31 3b c2-a7 98 86 d7 20 1a f1 bf   %. S.1;..... ...
00e0 - 30 89 a4 d1 de f3 1d ff-91 04 2f 6e d5 f8 97 69   0........./n...i
00f0 - ef 99 96 5e b7 7c 2f 9d-4c 79 2a 47 8a 75 11 65   ...^.|/.Ly*G.u.e
0100 - ff c8 cf cb 24 eb b8 e1-10 36 b6 ec bd f1 19 cd   ....$....6......
0110 - bb 12 c0 e2 8b 7d db 8b-03 83 19 1c 6e 24 87 38   .....}......n$.8
0120 - 6c cb 2a 79 9b 89 f0 e2-4a 73 21 61 3d e2 45 19   l.*y....Js!a=.E.
0130 - 99 bf 46 64 60 d5 50 10-10 32 ec 3d 9b d3 4e 00   ..Fd`.P..2.=..N.
0140 - 0c 28 47 9a f6 d7 ca 7e-42 2b 6d 50 ca f3 56 8d   .(G....~B+mP..V.
0150 - 5f 6a 43 3f e7 2c 81 57-7b 2a 27 db 2b 86 79 16   _jC?.,.W{*'.+.y.
0160 - a3 04 6a 2f 1a 6d a9 06-da 58 0a a2 c2 47 42 16   ..j/.m...X...GB.
0170 - e5 81 1d b2 cf fe 81 c9-d9 e0 bf 8b 11 49 86 33   .............I.3
0180 - 13 be 57 78 7c 8f 8a 3e-06 06 75 b3 bc 8f 6b 0f   ..Wx|..>..u...k.
0190 - f6 5a 58 be 49 d4 d4 da-17 8a 89 5b c4 9c 6f c6   .ZX.I......[..o.
01a0 - 0a c9 15 9d 87 31 0e c5-7b e3 a3 2d 13 2c d9 9c   .....1..{..-.,..
01b0 - 58 0b a5 1f f7 c1 ba ae-b7 66 9a 90 09 11 f4 ba   X........f......
01c0 - cc f1 84 79 e2 c7 bd 5c-9a cf 11 1d c1 7f 20 97   ...y...\...... .
01d0 - 68 7f 87 8b 63 28 af 35-60 d1 ab c2 aa f8 cb 90   h...c(.5`.......
01e0 - c3 69 7b 6f e4 c2 a9 69-e5 fb e6 9f 39 9a 8b ff   .i{o...i....9...
01f0 - 07 4c ab a4 48 93 1f 63-7e 3e e8 ae 86 26 0a 36   .L..H..c~>...&.6
0200 - 9a bd cb a6 9a 22 28 bc-a3 d9 c9 16 ed e6 48 da   ....."(.......H.
0210 - 22 50 eb 17 75 52 fc 6e-95 eb d1 a2 e4 4e e9 8e   "P..uR.n.....N..
0220 - 49 37 e6 81 56 53 19 ff-e8 7d ac f1 fb e2 10 45   I7..VS...}.....E
0230 - 37 93 6a f4 39 d0 17 ea-30 0a c2 e6 7d 60 81 ab   7.j.9...0...}`..
0240 - 02 32 6c aa a1 2e 7c c4-ee 24 47 40 e5 2a 64 c4   .2l...|..$G@.*d.
0250 - f2 37 a9 9e 54 89 7a cd-74 22 6b 96 b8 e2 0d 1e   .7..T.z.t"k.....
0260 - 93 31 83 fe 63 06 3d 20-e9 8f c7 cd 79 de 03 ca   .1..c.= ....y...
0270 - d3 37 c8 a7 f5 8b f1 aa-c4 63 ef fa 2e d1 31 1b   .7.......c....1.
0280 - 04 1b ef e1 51 40 8c c6-c7 38 c8 be 02 34 42 bf   ....Q@...8...4B.
0290 - 66 a2 7f 1a f7 5f c8 c9-47 90 91 9a 3f 9f 6b 1c   f...._..G...?.k.
02a0 - 6b e0 3c 8c ed f9 aa de-bc 92 c9 26 2f f6 d3 e8   k.<........&/...
02b0 - 0e 04 77 b2 d0 cb 10 72-4a 9e 96 00 fd 5c 04 91   ..w....rJ....\..
02c0 - 08 c7 05 d0 8f 00 68 35-1e 6b 46 b8 66 f0 f9 62   ......h5.kF.f..b
02d0 - 46 59 cf a7 e2 15 7a 3c-a2 47 a8 f4 8e e8 b5 90   FY....z<.G......
02e0 - 95 4a 75 8d f5 5d cb d0-7d 69 9f 0a 3c 34 a5 41   .Ju..]..}i..<4.A
02f0 - 8c 99 6d e4 4b 66 d9 d1-18 8d 39 f1 19 25 43 1e   ..m.Kf....9..%C.
0300 - 6e 1d a4 92 04 64 f5 03-92 2d 75 e7 58 d0 f7 83   n....d...-u.X...
0310 - 83 2e ca 39 f5 99 fc 2d-4b 7d 1b e7 f6 a0 32 ea   ...9...-K}....2.
0320 - 54 03 20 16 37 b2 65 c0-b6 51 a3 a8 d4 e2 8e 3a   T. .7.e..Q.....:
0330 - 97 83 86 4e ad 16 fe d9-45 91 79 ce 84 f6 f7 40   ...N....E.y....@
0340 - 4e 2e 61 c3 1d 04 7c 04-4e 99 d5 61 98 6a bd 17   N.a...|.N..a.j..
0350 - b8 2f 3a c9 e4 db 43 02-6a 28 63 cc 12 19 e0 5f   ./:...C.j(c...._
0360 - 18 62 31 c9 c3 93 fd e4-79 d6 f2 6c c0 fc 18 1e   .b1.....y..l....
0370 - 31 6f 1b 9d 72 f0 91 f5-b7 89 20 79 cb 0e 1d d2   1o..r..... y....
0380 - 70 3a a5 dd bc 5a 60 a3-0d 01 4b a7 d9 68 d9 32   p:...Z`...K..h.2
0390 - 58 6a db 0d 67 6f 9a 54-5f 97 c2 02 87 07 30 2e   Xj..go.T_.....0.
03a0 - 38 15 33 a5 90 d1 1e 75-fe 9d e3 97 e5 b9 80 d4   8.3....u........
03b0 - 7d b0 33 13 53 6a 8d e7-a1 7d 8c d8 bc 05 3f ac   }.3.Sj...}....?.
03c0 - 0a d4 07 d4 d1 00 45 be-97 ec a0 a1 3a d1 c1 c6   ......E.....:...
03d0 - 48 48 5a ff b2 4a 9e 00-f9 a8 09 b0 08 86 9a ca   HHZ..J..........
03e0 - d0 5d 79 dc 20 5b a5 87-5c 68 45 e2 52 31 22 36   .]y. [..\hE.R1"6
03f0 - 0f cf 98 45 9c b0 81 ee-e0 2f eb 02 8e b0 7b 21   ...E...../....{!
0400 - 58 a0 d2 02 12 c2 99 82-bf 15 b1 93 cb 3a df 88   X............:..
0410 - 88 9e 44 a5 4a dc 12 35-2f 77 95 04 44 9d 90 b2   ..D.J..5/w..D...
0420 - d5 c2 29 a0 17 03 03 01-19 ed 30 de 7c 10 91 7d   ..).......0.|..}
0430 - 7d 38 0a 9b cf 9c ed 40-d8 c0 30 3e 01 ed 3f 2a   }8.....@..0>..?*
0440 - a8 c0 b1 a1 3c 1f 88 a4-fb 9e 77 2e 9a b9 78 ed   ....<.....w...x.
0450 - 22 82 4c c4 7f 65 74 ba-b4 5f 90 91 35 0a f8 16   ".L..et.._..5...
0460 - 41 ef 5f 83 a1 a5 fd 78-e7 9f f0 10 79 f4 e7 5c   A._....x....y..\
0470 - 2c 50 e1 6b 22 ff c3 62-03 e9 b8 7f 67 79 3b bd   ,P.k"..b....gy;.
0480 - b4 0d f1 83 89 2e f4 fa-99 41 a4 1b 6f d0 ee b2   .........A..o...
0490 - db 56 1c 5d 24 80 6f 1e-03 be 13 1d 4d 17 70 d2   .V.]$.o.....M.p.
04a0 - 27 81 72 31 34 e4 cf cf-3c 60 fb 07 60 18 a8 92   '.r14...<`..`...
04b0 - 17 61 95 be b7 f4 e9 1f-16 9a ae 41 2c 35 d8 71   .a.........A,5.q
04c0 - 7c 62 2a 42 17 70 eb e9-c4 ee cc 42 4c 6b 4d 3a   |b*B.p.....BLkM:
04d0 - c4 2a 5c c6 df ff 11 45-6a b8 61 2b 84 eb 3b 37   .*\....Ej.a+..;7
04e0 - ae a7 ff b5 4b 5a 3b c7-83 32 6a e1 76 4d c6 78   ....KZ;..2j.vM.x
04f0 - 10 9b be e7 85 90 5d 80-b6 ff e7 04 77 e6 28 41   ......].....w.(A
0500 - f6 69 a8 17 1d 02 8e 6d-eb 79 f9 34 8b bf 9c 10   .i.....m.y.4....
0510 - 2b 5d 51 6e 61 e5 2a e7-7c db d7 ea 2d e9 28 5f   +]Qna.*.|...-.(_
0520 - 0d 07 6d e1 05 8d 2e 71-f0 7d 53 87 ba 7e 31 11   ..m....q.}S..~1.
0530 - d8 38 93 83 05 f2 95 7b-58 99 89 df 82 2c 2d 74   .8.....{X....,-t
0540 - 82 40 17 03 03 00 45 9b-df d7 61 a6 0d 5d b2 76   .@....E...a..].v
0550 - 7c f2 ae c5 b6 c4 ee 63-21 23 6a 56 0d 9e c8 c4   |......c!#jV....
0560 - 69 36 2a e1 1c 52 a7 9d-e0 64 75 60 04 94 c9 6a   i6*..R...du`...j
0570 - bf 43 e0 0e 36 17 ca a9-93 39 c9 d7 59 d2 9e 37   .C..6....9..Y..7
0580 - d1 47 b5 dd ca 40 69 4a-7d 48 8b ad               .G...@iJ}H..
SSL_accept:SSLv3/TLS write finished
SSL_accept:TLSv1.3 early data
read from 0x2432c4e5830 [0x2432c924873] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x2432c4e5830 [0x2432c924878] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x2432c4e5830 [0x2432c924873] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 45                                    ....E
read from 0x2432c4e5830 [0x2432c924878] (69 bytes => 69 (0x45))
0000 - 3e 55 2d be a4 88 ba 1f-12 73 73 f8 84 75 05 d9   >U-......ss..u..
0010 - 9f d2 1a 84 aa b7 7c e4-3f f4 ea 4e de fa 94 da   ......|.?..N....
0020 - c7 3c 66 fc 29 95 13 f1-23 48 a0 20 68 d5 db 44   .<f.)...#H. h..D
0030 - d8 99 df 30 45 ea f9 f1-f5 ed 8e 39 5a d6 d8 ae   ...0E......9Z...
0040 - 3a 21 6e ac b1                                    :!n..
SSL_accept:TLSv1.3 early data
SSL_accept:SSLv3/TLS read finished
write to 0x2432c4e5830 [0x2432c923860] (255 bytes => 255 (0xFF))
0000 - 17 03 03 00 fa e1 f5 d3-d5 fc 93 f7 11 d4 e9 0c   ................
0010 - dc 95 00 2d 83 56 34 e6-dc 11 98 7f 89 ad 9c 36   ...-.V4........6
0020 - 95 e0 52 f4 59 4a a7 96-c9 69 63 1c b7 68 79 f6   ..R.YJ...ic..hy.
0030 - 58 86 84 91 00 bb 22 e6-58 ac 03 3f 87 58 08 fa   X.....".X..?.X..
0040 - 16 ce 29 fc d4 1a 67 df-21 8e 4d b7 0f 48 86 46   ..)...g.!.M..H.F
0050 - 66 2d fe d8 cd 13 16 f5-95 53 0d f2 f9 3b 24 0e   f-.......S...;$.
0060 - c7 fd 5d 9e 56 88 ce 8b-f0 45 a1 bc 7e 18 8e f9   ..].V....E..~...
0070 - ab 94 8b 6e fb c6 4a 1d-d6 3d ca 7d cb 30 30 83   ...n..J..=.}.00.
0080 - 4d cc 17 0d b6 47 b1 32-4f c7 49 c8 f6 d9 b8 4f   M....G.2O.I....O
0090 - d1 83 f1 e8 d4 0d fb d0-6f 44 f5 da db a2 05 7e   ........oD.....~
00a0 - 4d 5a 62 81 e8 38 0b ba-f5 58 c4 5c b4 3a 14 0c   MZb..8...X.\.:..
00b0 - b6 fe 34 c2 c3 9a f2 9e-ee 36 66 84 be af fb 8d   ..4......6f.....
00c0 - 4a 4f 1e ec f9 b6 73 84-7e 51 5a d8 23 f1 a4 0c   JO....s.~QZ.#...
00d0 - 9b ee a8 c8 32 52 68 64-d5 92 2d a4 ed b2 ed fd   ....2Rhd..-.....
00e0 - 2c be a4 ff 71 5b 8f 79-7e a0 d5 69 a1 33 65 e4   ,...q[.y~..i.3e.
00f0 - d1 ef 20 be 29 1f f9 56-15 be 2a f8 12 25 9c      .. .)..V..*..%.
SSL_accept:SSLv3/TLS write session ticket
write to 0x2432c4e5830 [0x2432c923860] (255 bytes => 255 (0xFF))
0000 - 17 03 03 00 fa 73 0c 72-9b 71 6d b8 a1 02 19 32   .....s.r.qm....2
0010 - 1d bf fa 05 89 82 b6 bb-0c c5 fd 9c 00 14 20 5c   .............. \
0020 - 2c e7 2a cb d5 f9 a5 b2-e7 68 d5 76 e3 ca 0c 71   ,.*......h.v...q
0030 - ca 7e 83 1c 1f fa 62 da-b8 fb e7 58 9f 2a 81 92   .~....b....X.*..
0040 - d9 73 82 a5 9d dc 21 4b-1e c0 27 52 63 03 b3 83   .s....!K..'Rc...
0050 - 15 bc 2b c8 08 8a 94 09-95 f2 49 ba 60 92 eb 3d   ..+.......I.`..=
0060 - 8a a9 eb eb b8 eb 42 08-e0 32 17 c3 ad 63 5c 2b   ......B..2...c\+
0070 - fa e5 68 47 32 19 a5 d3-15 26 2b 1c d2 48 b3 7b   ..hG2....&+..H.{
0080 - f4 a5 c2 2c 3e 61 0e b3-c1 81 c7 5e 87 5c 6b da   ...,>a.....^.\k.
0090 - 14 65 9e 3d 1f c1 f7 56-9b 08 f2 af cc f6 d8 c6   .e.=...V........
00a0 - 7f 94 c8 f1 5a 1b 6a 1e-57 0e 07 f2 2c dc 78 88   ....Z.j.W...,.x.
00b0 - 76 7b e7 95 6c 00 9d 76-5e 4e 62 9c e7 45 31 66   v{..l..v^Nb..E1f
00c0 - cf 84 eb bc 77 a5 4d 31-61 91 49 c1 a5 70 a7 c4   ....w.M1a.I..p..
00d0 - 99 1d 1e 05 9e 96 e2 e4-7d d6 f6 4b 56 ac 24 87   ........}..KV.$.
00e0 - 9c 33 22 62 08 1c ac d6-34 85 0e 08 81 ea 48 1b   .3"b....4.....H.
00f0 - cd 41 31 35 a4 28 34 c8-d9 43 06 9c c9 e3 1c      .A15.(4..C.....
SSL_accept:SSLv3/TLS write session ticket
-----BEGIN SSL SESSION PARAMETERS-----
MIGCAgEBAgIDBAQCEwIEIABYJJZDdgCIs1zvguH33kJ2IkfkxWyLxeAEcJWhtRMs
BDAxO8GUI6A3cImfyrOrrTbzLKZUt1hNFRhSA6W+wqWWz51vlKi2x5VMz+KLC0h5
3JyhBgIEaAEaYqIEAgIcIKQGBAQBAAAArgYCBCv8HNizAwIBHQ==
-----END SSL SESSION PARAMETERS-----
Shared ciphers:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Supported groups: x25519:secp256r1:x448:secp521r1:secp384r1:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192
Shared groups: x25519:secp256r1:x448:secp521r1:secp384r1:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192
CIPHER is TLS_AES_256_GCM_SHA384
This TLS version forbids renegotiation.
read from 0x2432c4e5830 [0x2432c92fb43] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 18                                    .....
read from 0x2432c4e5830 [0x2432c92fb48] (24 bytes => 24 (0x18))
0000 - f1 40 f0 3b 33 67 09 18-be 0a 57 fc 94 64 08 ae   .@.;3g....W..d..
0010 - b5 4f 02 20 fe 01 46 ec-                          .O. ..F.
hello
read from 0x2432c4e5830 [0x2432c92fb43] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 13                                    .....
read from 0x2432c4e5830 [0x2432c92fb48] (19 bytes => 19 (0x13))
0000 - a0 d4 71 0a 7a 11 44 63-97 ff 63 2c 0c b5 b1 23   ..q.z.Dc..c,...#
0010 - cb a9 01                                          ...
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x2432c4e5830 [0x2432c924873] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 6e ca 59-6f 00 37 ca bd 87 17 10   .....n.Yo.7.....
0010 - 1a ab 9c d9 1c 38 23 9d-                          .....8#.
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
