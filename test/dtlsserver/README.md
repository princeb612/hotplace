#### TOC

- DTLS 1.2
  - [server](#server)
  - [client](#client)

#### server

````
$ openssl s_server -accept 9000 -cert server.crt -key server.key -cipher TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 -state -debug -status_verbose -dtls1_2
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x1f53e6fcdf0 [0x1f53eb215b3] (16717 bytes => 208 (0xD0))
0000 - 16 fe ff 00 00 00 00 00-00 00 00 00 c3 01 00 00   ................
0010 - bd 00 00 00 00 00 00 00-b7 fe fd 6d 15 62 78 04   ...........m.bx.
0020 - d2 bb d6 0b aa 05 f2 c6-68 06 7a ac 89 35 37 d4   ........h.z..57.
0030 - 07 46 43 26 8d a7 03 e4-84 fb 4d 00 00 00 36 c0   .FC&......M...6.
0040 - 2c c0 30 00 9f cc a9 cc-a8 cc aa c0 2b c0 2f 00   ,.0.........+./.
0050 - 9e c0 24 c0 28 00 6b c0-23 c0 27 00 67 c0 0a c0   ..$.(.k.#.'.g...
0060 - 14 00 39 c0 09 c0 13 00-33 00 9d 00 9c 00 3d 00   ..9.....3.....=.
0070 - 3c 00 35 00 2f 01 00 00-5d ff 01 00 01 00 00 0b   <.5./...].......
0080 - 00 04 03 00 01 02 00 0a-00 0c 00 0a 00 1d 00 17   ................
0090 - 00 1e 00 19 00 18 00 23-00 00 00 16 00 00 00 17   .......#........
00a0 - 00 00 00 0d 00 30 00 2e-04 03 05 03 06 03 08 07   .....0..........
00b0 - 08 08 08 1a 08 1b 08 1c-08 09 08 0a 08 0b 08 04   ................
00c0 - 08 05 08 06 04 01 05 01-06 01 03 03 03 01 03 02   ................
read from 0x1f53e6fcdf0 [0x1f53eb215b3] (16717 bytes => 31 (0x1F))
0000 - 16 fe ff 00 00 00 00 00-00 00 01 00 12 01 00 00   ................
0010 - bd 00 00 00 00 b7 00 00-06 04 02 05 02 06 02      ...............
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
write to 0x1f53e6fcdf0 [0x1f53eb205a0] (48 bytes => 48 (0x30))
0000 - 16 fe ff 00 00 00 00 00-00 00 00 00 23 03 00 00   ............#...
0010 - 17 00 00 00 00 00 00 00-17 fe ff 14 9c 97 bf b8   ................
0020 - 5b 6a 73 10 45 43 86 9e-69 c4 2d 7e 9f 62 61 08   [js.EC..i.-~.ba.
SSL_accept:DTLS1 write hello verify request
read from 0x1f53e6fcdf0 [0x1f53eb215b3] (16717 bytes => 208 (0xD0))
0000 - 16 fe ff 00 00 00 00 00-00 00 02 00 c3 01 00 00   ................
0010 - d1 00 01 00 00 00 00 00-b7 fe fd 6d 15 62 78 04   ...........m.bx.
0020 - d2 bb d6 0b aa 05 f2 c6-68 06 7a ac 89 35 37 d4   ........h.z..57.
0030 - 07 46 43 26 8d a7 03 e4-84 fb 4d 00 14 9c 97 bf   .FC&......M.....
0040 - b8 5b 6a 73 10 45 43 86-9e 69 c4 2d 7e 9f 62 61   .[js.EC..i.-~.ba
0050 - 08 00 36 c0 2c c0 30 00-9f cc a9 cc a8 cc aa c0   ..6.,.0.........
0060 - 2b c0 2f 00 9e c0 24 c0-28 00 6b c0 23 c0 27 00   +./...$.(.k.#.'.
0070 - 67 c0 0a c0 14 00 39 c0-09 c0 13 00 33 00 9d 00   g.....9.....3...
0080 - 9c 00 3d 00 3c 00 35 00-2f 01 00 00 5d ff 01 00   ..=.<.5./...]...
0090 - 01 00 00 0b 00 04 03 00-01 02 00 0a 00 0c 00 0a   ................
00a0 - 00 1d 00 17 00 1e 00 19-00 18 00 23 00 00 00 16   ...........#....
00b0 - 00 00 00 17 00 00 00 0d-00 30 00 2e 04 03 05 03   .........0......
00c0 - 06 03 08 07 08 08 08 1a-08 1b 08 1c 08 09 08 0a   ................
read from 0x1f53e6fcdf0 [0x1f53eb215b3] (16717 bytes => 51 (0x33))
0000 - 16 fe ff 00 00 00 00 00-00 00 03 00 26 01 00 00   ............&...
0010 - d1 00 01 00 00 b7 00 00-1a 08 0b 08 04 08 05 08   ................
0020 - 06 04 01 05 01 06 01 03-03 03 01 03 02 04 02 05   ................
0030 - 02 06 02                                          ...
SSL_accept:DTLS1 write hello verify request
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
write to 0x1f53e6fcdf0 [0x1f53eb205a0] (208 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 01 00 4d 02 00 00   ............M...
0010 - 41 00 01 00 00 00 00 00-41 fe fd 09 4f 1e cb b2   A.......A...O...
0020 - 49 7b 95 a0 b5 61 14 c6-fe f7 7e 68 43 1e 11 c2   I{...a....~hC...
0030 - 78 24 70 1e b1 d2 03 dc-33 11 74 00 c0 27 00 00   x$p.....3.t..'..
0040 - 19 ff 01 00 01 00 00 0b-00 04 03 00 01 02 00 23   ...............#
0050 - 00 00 00 16 00 00 00 17-00 00 16 fe fd 00 00 00   ................
0060 - 00 00 00 00 02 00 69 0b-00 03 66 00 02 00 00 00   ......i...f.....
0070 - 00 00 5d 00 03 63 00 03-60 30 82 03 5c 30 82 02   ..]..c..`0..\0..
0080 - 44 a0 03 02 01 02 02 14-63 a6 71 10 79 d6 a6 48   D.......c.q.y..H
0090 - 59 da 67 a9 04 e8 e3 5f-e2 03 a3 26 30 0d 06 09   Y.g...._...&0...
00a0 - 2a 86 48 86 f7 0d 01 01-0b 05 00 30 59 31 0b 30   *.H........0Y1.0
00b0 - 09 06 03 55 04 06 13 02-4b 52 31 0b 30 09 06 03   ...U....KR1.0...
00c0 - 55 04 08 0c 02 47 47 31-0b 30 09 06 03 55 04 07   U....GG1.0...U..
write to 0x1f53e6fcdf0 [0x1f53eb205a0] (208 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 03 00 c3 0b 00 03   ................
0010 - 66 00 02 00 00 5d 00 00-b7 0c 02 59 49 31 0d 30   f....].....YI1.0
0020 - 0b 06 03 55 04 0a 0c 04-54 65 73 74 31 0d 30 0b   ...U....Test1.0.
0030 - 06 03 55 04 0b 0c 04 54-65 73 74 31 12 30 10 06   ..U....Test1.0..
0040 - 03 55 04 03 0c 09 54 65-73 74 20 52 6f 6f 74 30   .U....Test Root0
0050 - 1e 17 0d 32 34 30 38 32-39 30 36 32 37 31 37 5a   ...240829062717Z
0060 - 17 0d 32 35 30 38 32 39-30 36 32 37 31 37 5a 30   ..250829062717Z0
0070 - 54 31 0b 30 09 06 03 55-04 06 13 02 4b 52 31 0b   T1.0...U....KR1.
0080 - 30 09 06 03 55 04 08 0c-02 47 47 31 0b 30 09 06   0...U....GG1.0..
0090 - 03 55 04 07 0c 02 59 49-31 0d 30 0b 06 03 55 04   .U....YI1.0...U.
00a0 - 0a 0c 04 54 65 73 74 31-0d 30 0b 06 03 55 04 0b   ...Test1.0...U..
00b0 - 0c 04 54 65 73 74 31 0d-30 0b 06 03 55 04 03 0c   ..Test1.0...U...
00c0 - 04 54 65 73 74 30 82 01-22 30 0d 06 09 2a 86 48   .Test0.."0...*.H
write to 0x1f53e6fcdf0 [0x1f53eb205a0] (208 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 04 00 c3 0b 00 03   ................
0010 - 66 00 02 00 01 14 00 00-b7 86 f7 0d 01 01 01 05   f...............
0020 - 00 03 82 01 0f 00 30 82-01 0a 02 82 01 01 00 ad   ......0.........
0030 - 9a 29 67 5f f3 a4 79 b4-c6 e6 32 73 d8 d7 ed 88   .)g_..y...2s....
0040 - 94 15 83 e4 31 00 04 6c-b5 8c ac 87 ab 74 44 13   ....1..l.....tD.
0050 - 76 ca 0b 74 29 40 9e 97-2a 01 d7 8b 46 26 6e 19   v..t)@..*...F&n.
0060 - 35 4d c0 d3 b5 ea 0e 93-3a 06 e8 e5 85 b5 27 05   5M......:.....'.
0070 - 63 db 28 b8 92 da 5a 14-39 0f da 68 6d 6f 0a fb   c.(...Z.9..hmo..
0080 - 52 dc 08 0f 54 d3 e4 a2-28 9d a0 71 50 82 e0 db   R...T...(..qP...
0090 - ca d1 94 dd 42 98 3a 09-33 a8 d9 ef fb d2 35 43   ....B.:.3.....5C
00a0 - b1 22 a2 be 41 6d ba 91-dc 0b 31 4e 88 f9 4d 9c   ."..Am....1N..M.
00b0 - 61 2d ec b2 13 0a c2 91-8e a2 d6 e9 40 b9 32 b9   a-..........@.2.
00c0 - 80 8f b3 18 a3 33 13 23-d5 d0 7e d9 d0 7f 93 e0   .....3.#..~.....
write to 0x1f53e6fcdf0 [0x1f53eb205a0] (208 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 05 00 c3 0b 00 03   ................
0010 - 66 00 02 00 01 cb 00 00-b7 2d 4d 90 c5 58 24 56   f........-M..X$V
0020 - d5 c9 10 13 4a b2 99 23-7d 34 b9 8e 97 19 69 6f   ....J..#}4....io
0030 - ce c6 3f d6 17 a7 d2 43-e0 36 cb 51 7b 2f 18 8b   ..?....C.6.Q{/..
0040 - c2 33 f8 57 cf d1 61 0b-7c ed 37 35 e3 13 7a 24   .3.W..a.|.75..z$
0050 - 2e 77 08 c2 e3 d9 e6 17-d3 a5 c6 34 5a da 86 a7   .w.........4Z...
0060 - f8 02 36 1d 66 63 cf e9-c0 3d 82 fb 39 a2 8d 92   ..6.fc...=..9...
0070 - 01 4a 83 cf e2 76 3d 87-02 03 01 00 01 a3 21 30   .J...v=.......!0
0080 - 1f 30 1d 06 03 55 1d 11-04 16 30 14 82 12 74 65   .0...U....0...te
0090 - 73 74 2e 70 72 69 6e 63-65 62 36 31 32 2e 70 65   st.princeb612.pe
00a0 - 30 0d 06 09 2a 86 48 86-f7 0d 01 01 0b 05 00 03   0...*.H.........
00b0 - 82 01 01 00 00 a5 f5 54-18 ab ad 36 38 c8 fc 0b   .......T...68...
00c0 - 66 60 dd 9f 75 9d 86 5b-79 2f ee 57 f1 79 1c 15   f`..u..[y/.W.y..
write to 0x1f53e6fcdf0 [0x1f53eb205a0] (208 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 06 00 c3 0b 00 03   ................
0010 - 66 00 02 00 02 82 00 00-b7 a1 34 23 d0 1c a9 58   f.........4#...X
0020 - 51 a4 d0 08 f5 d8 f7 49-e9 c5 b5 65 91 51 2d 6d   Q......I...e.Q-m
0030 - e4 3b 0e 77 02 1f 45 8e-34 e5 bb eb f6 9d df 4a   .;.w..E.4......J
0040 - 40 60 21 b3 8e 16 33 3f-f4 b6 90 d3 3c 34 ce e6   @`!...3?....<4..
0050 - d9 47 07 a7 57 14 0c f9-78 0b 36 72 a9 88 07 07   .G..W...x.6r....
0060 - 93 b4 d7 fe 29 5e e8 41-37 20 a5 03 c7 97 cb 82   ....)^.A7 ......
0070 - ca db 14 e5 8b 96 1f a9-e9 20 3d 6b 25 ae f4 89   ......... =k%...
0080 - 4c 60 8d e9 14 33 47 4b-88 54 a2 47 19 81 c8 7b   L`...3GK.T.G...{
0090 - 0e 32 52 2b 91 88 ad 0f-6d 73 30 8c 00 af d5 fc   .2R+....ms0.....
00a0 - 46 46 af 3a c2 17 89 ec-c8 83 ae da e6 69 63 e0   FF.:.........ic.
00b0 - 9c 84 22 c5 7a de e8 23-6b 53 9d 6f 94 d2 7f 5c   ..".z..#kS.o...\
00c0 - be 1d 0c de 0e 07 0d 52-a5 43 8c e8 05 ef c0 ff   .......R.C......
SSL_accept:SSLv3/TLS write certificate
write to 0x1f53e6fcdf0 [0x1f53eb205a0] (208 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 07 00 39 0b 00 03   ............9...
0010 - 66 00 02 00 03 39 00 00-2d f0 73 fa dc 5a 51 4c   f....9..-.s..ZQL
0020 - 24 09 65 45 7d ab 52 8b-7e 5d f0 fb de a7 3d 43   $.eE}.R.~]....=C
0030 - c5 af 76 e3 6e f9 a1 dc-78 a2 bd 54 41 04 99 e5   ..v.n...x..TA...
0040 - 56 32 ba 02 fd 72 16 fe-fd 00 00 00 00 00 00 00   V2...r..........
0050 - 08 00 7d 0c 00 01 28 00-03 00 00 00 00 00 71 03   ..}...(.......q.
0060 - 00 1d 20 34 0d c9 22 f7-ee a7 2b a1 13 ca 5a dc   .. 4.."...+...Z.
0070 - 09 53 d5 05 69 a6 80 31-dc 5b fc 4d d2 06 70 68   .S..i..1.[.M..ph
0080 - 34 e1 26 08 04 01 00 67-2a 94 51 63 88 0d 13 a5   4.&....g*.Qc....
0090 - 14 33 30 96 db ba 6c 01-d7 b0 70 25 e2 60 3d 50   .30...l...p%.`=P
00a0 - aa 84 5c 32 fb 4f da 69-88 b8 70 96 78 a8 f6 ea   ..\2.O.i..p.x...
00b0 - a2 fc 61 06 45 11 94 e6-6c 4f 25 23 fd 16 36 24   ..a.E...lO%#..6$
00c0 - 75 ca d2 43 01 80 27 63-56 a8 d9 13 01 4d 25 2c   u..C..'cV....M%,
SSL_accept:SSLv3/TLS write key exchange
write to 0x1f53e6fcdf0 [0x1f53eb205a0] (208 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 09 00 c3 0c 00 01   ................
0010 - 28 00 03 00 00 71 00 00-b7 f2 3e 92 12 0a 35 87   (....q....>...5.
0020 - 85 40 56 b5 29 73 06 1d-2d 90 42 ab 12 52 a2 91   .@V.)s..-.B..R..
0030 - ca 03 92 87 1b df e9 f7-7c be 32 f3 ac cf 33 3b   ........|.2...3;
0040 - 84 56 a7 f0 06 07 c2 4f-54 c4 15 e6 dd 0f df 2d   .V.....OT......-
0050 - e0 de 7b 91 62 fb ae 38-84 32 d7 c9 f3 ba 72 3b   ..{.b..8.2....r;
0060 - ca e9 30 d3 b2 13 21 e4-02 02 bd 21 0c 46 18 a6   ..0...!....!.F..
0070 - f8 76 ec ad 81 24 44 7f-a3 e8 7d 83 0c 90 7b 80   .v...$D...}...{.
0080 - 25 b6 04 5a 11 c9 2b ed-17 c2 c8 ed 96 4c 79 06   %..Z..+......Ly.
0090 - fb cb 8e d5 a5 1e 6e 3a-12 1b bd a4 10 cd f0 7d   ......n:.......}
00a0 - fa 32 78 86 86 df db 11-9f 70 d2 b0 1d 9d c9 c1   .2x......p......
00b0 - e5 99 8b 00 3a 22 9e 32-61 de 05 69 fb fa cd 65   ....:".2a..i...e
00c0 - a8 74 8b b8 e3 23 26 d5-f8 dc df cb ed 41 89 d2   .t...#&......A..
write to 0x1f53e6fcdf0 [0x1f53eb205a0] (25 bytes => 25 (0x19))
0000 - 16 fe fd 00 00 00 00 00-00 00 0a 00 0c 0e 00 00   ................
0010 - 00 00 04 00 00 00 00 00-00                        .........
SSL_accept:SSLv3/TLS write server done
read from 0x1f53e6fcdf0 [0x1f53eb215b3] (16717 bytes => 165 (0xA5))
0000 - 16 fe fd 00 00 00 00 00-00 00 04 00 2d 10 00 00   ............-...
0010 - 21 00 02 00 00 00 00 00-21 20 72 b7 34 6a 14 e0   !.......! r.4j..
0020 - d7 20 8a e7 99 63 92 c0-8f c1 f1 1a 9c 60 48 9a   . ...c.......`H.
0030 - 41 44 09 b7 bb 3f 93 59-d7 5e 14 fe fd 00 00 00   AD...?.Y.^......
0040 - 00 00 00 00 05 00 01 01-16 fe fd 00 01 00 00 00   ................
0050 - 00 00 00 00 50 58 2f 88-eb cc 17 af 37 40 3f 1a   ....PX/.....7@?.
0060 - f0 0f c0 04 d6 17 17 05-41 c6 ca 59 3a 46 aa bd   ........A..Y:F..
0070 - 47 25 96 ea 1b 99 57 32-00 b4 39 bc 9f 2e f2 bd   G%....W2..9.....
0080 - 2e 4d c5 7c 9e 9b aa ae-1d 7c 1f 4e f9 f6 05 98   .M.|.....|.N....
0090 - 18 c1 a6 f2 f5 a8 f4 22-f3 88 e0 05 13 79 72 2d   .......".....yr-
00a0 - a5 b2 38 84 cb                                    ..8..
SSL_accept:SSLv3/TLS write server done
SSL_accept:SSLv3/TLS read client key exchange
SSL_accept:SSLv3/TLS read change cipher spec
SSL_accept:SSLv3/TLS read finished
SSL_accept:SSLv3/TLS write session ticket
write to 0x1f53e6fcdf0 [0x1f53eb205a0] (207 bytes => 207 (0xCF))
0000 - 16 fe fd 00 00 00 00 00-00 00 0b 00 c2 04 00 00   ................
0010 - b6 00 05 00 00 00 00 00-b6 00 00 1c 20 00 b0 77   ............ ..w
0020 - 15 7d 9f 0b 34 65 1b 65-82 9d d1 cf 3d 23 9b 47   .}..4e.e....=#.G
0030 - c7 5b 89 d0 1b c2 ef d3-a7 23 e8 40 5e bd 60 36   .[.......#.@^.`6
0040 - e0 5a 61 b3 68 bf 58 69-58 e9 6a dc ad 8e 1c 80   .Za.h.XiX.j.....
0050 - c0 66 5c f2 68 59 9c a0-bf 68 23 e9 37 eb 15 d8   .f\.hY...h#.7...
0060 - da cb e5 6d ef ba a9 f0-fd ab bc 32 fb e7 ff 29   ...m.......2...)
0070 - 4d 08 e5 9d 7a f9 01 cd-71 1f 7d 76 cd 3d 6a ac   M...z...q.}v.=j.
0080 - 64 b2 c1 09 9c 97 6b 3a-91 98 c0 00 d3 c0 6d c0   d.....k:......m.
0090 - c5 b9 2c a2 ff 97 de 1d-37 b2 b9 39 e1 4a 7c 88   ..,.....7..9.J|.
00a0 - 49 3e 88 9c 97 2a 3a bd-61 e9 a5 40 e9 87 29 66   I>...*:.a..@..)f
00b0 - 02 c6 d9 ed bb 5a ad d9-5a 59 51 2d ca 8d ac 9e   .....Z..ZYQ-....
00c0 - 50 13 43 08 d8 e5 bf c8-b9 4f fb e8 a3 98 c7      P.C......O.....
SSL_accept:SSLv3/TLS write change cipher spec
write to 0x1f53e6fcdf0 [0x1f53eb205a0] (107 bytes => 107 (0x6B))
0000 - 14 fe fd 00 00 00 00 00-00 00 0c 00 01 01 16 fe   ................
0010 - fd 00 01 00 00 00 00 00-00 00 50 24 28 4f f3 13   ..........P$(O..
0020 - 22 6a c4 98 d9 14 66 28-e9 82 07 d9 61 00 7e 0e   "j....f(....a.~.
0030 - a0 ee 63 99 71 e9 29 6e-8d 2e 04 12 77 9c c2 4c   ..c.q.)n....w..L
0040 - 6d 95 ce 58 bd 8c cb 0d-1b 4f da 1b a7 80 52 e6   m..X.....O....R.
0050 - 60 a2 c6 3e 05 32 df 0a-68 7f b5 5d 66 16 53 ec   `..>.2..h..]f.S.
0060 - d2 73 3e 72 12 fd 79 e1-f3 d7 71                  .s>r..y...q
SSL_accept:SSLv3/TLS write finished
-----BEGIN SSL SESSION PARAMETERS-----
MGACAQECAwD+/QQCwCcEAAQwZN4QUQ7gJqLn5KqWxE1aChytKmSnT3u+6eU83xen
gvrmGpaGqRcsRbvk9luxD7ELoQYCBGfuF9qiBAICHCCkBgQEAQAAAK0DAgEBswMC
AR0=
-----END SSL SESSION PARAMETERS-----
Shared ciphers:ECDHE-RSA-AES128-SHA256
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Supported Elliptic Curve Point Formats: uncompressed:ansiX962_compressed_prime:ansiX962_compressed_char2
Supported groups: x25519:secp256r1:x448:secp521r1:secp384r1
Shared groups: x25519:secp256r1:x448:secp521r1:secp384r1
CIPHER is ECDHE-RSA-AES128-SHA256
Secure Renegotiation IS supported
read from 0x1f53e6fcdf0 [0x1f53eb215b3] (16717 bytes => 77 (0x4D))
0000 - 17 fe fd 00 01 00 00 00-00 00 01 00 40 1e a9 65   ............@..e
0010 - 81 47 fc e3 95 e4 71 a6-bf 0c 85 61 df 2c 79 f4   .G....q....a.,y.
0020 - 70 2f 7b 15 45 e9 08 72-28 ed dc 1d bb 88 7d e4   p/{.E..r(.....}.
0030 - a4 e5 af 8a 1e 4b 4e 16-9e 6f 16 cf 8c 64 a5 01   .....KN..o...d..
0040 - f7 8f d6 6f 19 e9 34 9c-1b 51 61 43 f1            ...o..4..QaC.
hello
read from 0x1f53e6fcdf0 [0x1f53eb215b3] (16717 bytes => 77 (0x4D))
0000 - 15 fe fd 00 01 00 00 00-00 00 02 00 40 e4 ed 81   ............@...
0010 - fe 32 be f0 d1 b7 42 36-db e3 98 5f 31 61 aa 6c   .2....B6..._1a.l
0020 - b4 f6 50 4d 62 f1 a1 f3-02 1e c7 b5 57 c8 b4 35   ..PMb.......W..5
0030 - b5 97 c2 36 1e 38 f9 45-38 4f a2 d1 f7 d7 98 0d   ...6.8.E8O......
0040 - 73 4f 70 e9 17 37 a1 c0-dc 10 0e 00 d5            sOp..7.......
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x1f53e6fcdf0 [0x1f53eb33f83] (77 bytes => 77 (0x4D))
0000 - 15 fe fd 00 01 00 00 00-00 00 01 00 40 c4 f8 3e   ............@..>
0010 - 0a 39 08 4b 8b 4c 66 f4-ee ba fd a0 9e d4 5b db   .9.K.Lf.......[.
0020 - c0 3f 3c 95 66 42 58 00-b3 ca 77 ec 62 5e b0 8e   .?<.fBX...w.b^..
0030 - 4c 5e 37 af c5 d0 94 e4-62 dd 7e 94 7a 62 26 b0   L^7.....b.~.zb&.
0040 - 33 2e 41 59 65 71 e8 96-08 ad 47 53 c3            3.AYeq....GS.
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

#### client

````
$ openssl s_client -connect localhost:9000 -state -debug -dtls1_2
Connecting to ::1
CONNECTED(000001DC)
SSL_connect:before SSL initialization
write to 0x262aaf94de0 [0x262ab3853c0] (208 bytes => 208 (0xD0))
0000 - 16 fe ff 00 00 00 00 00-00 00 00 00 c3 01 00 00   ................
0010 - bd 00 00 00 00 00 00 00-b7 fe fd 6d 15 62 78 04   ...........m.bx.
0020 - d2 bb d6 0b aa 05 f2 c6-68 06 7a ac 89 35 37 d4   ........h.z..57.
0030 - 07 46 43 26 8d a7 03 e4-84 fb 4d 00 00 00 36 c0   .FC&......M...6.
0040 - 2c c0 30 00 9f cc a9 cc-a8 cc aa c0 2b c0 2f 00   ,.0.........+./.
0050 - 9e c0 24 c0 28 00 6b c0-23 c0 27 00 67 c0 0a c0   ..$.(.k.#.'.g...
0060 - 14 00 39 c0 09 c0 13 00-33 00 9d 00 9c 00 3d 00   ..9.....3.....=.
0070 - 3c 00 35 00 2f 01 00 00-5d ff 01 00 01 00 00 0b   <.5./...].......
0080 - 00 04 03 00 01 02 00 0a-00 0c 00 0a 00 1d 00 17   ................
0090 - 00 1e 00 19 00 18 00 23-00 00 00 16 00 00 00 17   .......#........
00a0 - 00 00 00 0d 00 30 00 2e-04 03 05 03 06 03 08 07   .....0..........
00b0 - 08 08 08 1a 08 1b 08 1c-08 09 08 0a 08 0b 08 04   ................
00c0 - 08 05 08 06 04 01 05 01-06 01 03 03 03 01 03 02   ................
write to 0x262aaf94de0 [0x262ab3853c0] (31 bytes => 31 (0x1F))
0000 - 16 fe ff 00 00 00 00 00-00 00 01 00 12 01 00 00   ................
0010 - bd 00 00 00 00 b7 00 00-06 04 02 05 02 06 02      ...............
SSL_connect:SSLv3/TLS write client hello
read from 0x262aaf94de0 [0x262ab38a4b3] (16717 bytes => 48 (0x30))
0000 - 16 fe ff 00 00 00 00 00-00 00 00 00 23 03 00 00   ............#...
0010 - 17 00 00 00 00 00 00 00-17 fe ff 14 9c 97 bf b8   ................
0020 - 5b 6a 73 10 45 43 86 9e-69 c4 2d 7e 9f 62 61 08   [js.EC..i.-~.ba.
SSL_connect:SSLv3/TLS write client hello
SSL_connect:DTLS1 read hello verify request
write to 0x262aaf94de0 [0x262ab3853c0] (208 bytes => 208 (0xD0))
0000 - 16 fe ff 00 00 00 00 00-00 00 02 00 c3 01 00 00   ................
0010 - d1 00 01 00 00 00 00 00-b7 fe fd 6d 15 62 78 04   ...........m.bx.
0020 - d2 bb d6 0b aa 05 f2 c6-68 06 7a ac 89 35 37 d4   ........h.z..57.
0030 - 07 46 43 26 8d a7 03 e4-84 fb 4d 00 14 9c 97 bf   .FC&......M.....
0040 - b8 5b 6a 73 10 45 43 86-9e 69 c4 2d 7e 9f 62 61   .[js.EC..i.-~.ba
0050 - 08 00 36 c0 2c c0 30 00-9f cc a9 cc a8 cc aa c0   ..6.,.0.........
0060 - 2b c0 2f 00 9e c0 24 c0-28 00 6b c0 23 c0 27 00   +./...$.(.k.#.'.
0070 - 67 c0 0a c0 14 00 39 c0-09 c0 13 00 33 00 9d 00   g.....9.....3...
0080 - 9c 00 3d 00 3c 00 35 00-2f 01 00 00 5d ff 01 00   ..=.<.5./...]...
0090 - 01 00 00 0b 00 04 03 00-01 02 00 0a 00 0c 00 0a   ................
00a0 - 00 1d 00 17 00 1e 00 19-00 18 00 23 00 00 00 16   ...........#....
00b0 - 00 00 00 17 00 00 00 0d-00 30 00 2e 04 03 05 03   .........0......
00c0 - 06 03 08 07 08 08 08 1a-08 1b 08 1c 08 09 08 0a   ................
write to 0x262aaf94de0 [0x262ab3853c0] (51 bytes => 51 (0x33))
0000 - 16 fe ff 00 00 00 00 00-00 00 03 00 26 01 00 00   ............&...
0010 - d1 00 01 00 00 b7 00 00-1a 08 0b 08 04 08 05 08   ................
0020 - 06 04 01 05 01 06 01 03-03 03 01 03 02 04 02 05   ................
0030 - 02 06 02                                          ...
SSL_connect:SSLv3/TLS write client hello
read from 0x262aaf94de0 [0x262ab38a4b3] (16717 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 01 00 4d 02 00 00   ............M...
0010 - 41 00 01 00 00 00 00 00-41 fe fd 09 4f 1e cb b2   A.......A...O...
0020 - 49 7b 95 a0 b5 61 14 c6-fe f7 7e 68 43 1e 11 c2   I{...a....~hC...
0030 - 78 24 70 1e b1 d2 03 dc-33 11 74 00 c0 27 00 00   x$p.....3.t..'..
0040 - 19 ff 01 00 01 00 00 0b-00 04 03 00 01 02 00 23   ...............#
0050 - 00 00 00 16 00 00 00 17-00 00 16 fe fd 00 00 00   ................
0060 - 00 00 00 00 02 00 69 0b-00 03 66 00 02 00 00 00   ......i...f.....
0070 - 00 00 5d 00 03 63 00 03-60 30 82 03 5c 30 82 02   ..]..c..`0..\0..
0080 - 44 a0 03 02 01 02 02 14-63 a6 71 10 79 d6 a6 48   D.......c.q.y..H
0090 - 59 da 67 a9 04 e8 e3 5f-e2 03 a3 26 30 0d 06 09   Y.g...._...&0...
00a0 - 2a 86 48 86 f7 0d 01 01-0b 05 00 30 59 31 0b 30   *.H........0Y1.0
00b0 - 09 06 03 55 04 06 13 02-4b 52 31 0b 30 09 06 03   ...U....KR1.0...
00c0 - 55 04 08 0c 02 47 47 31-0b 30 09 06 03 55 04 07   U....GG1.0...U..
SSL_connect:SSLv3/TLS write client hello
Can't use SSL_get_servername
read from 0x262aaf94de0 [0x262ab38a4b3] (16717 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 03 00 c3 0b 00 03   ................
0010 - 66 00 02 00 00 5d 00 00-b7 0c 02 59 49 31 0d 30   f....].....YI1.0
0020 - 0b 06 03 55 04 0a 0c 04-54 65 73 74 31 0d 30 0b   ...U....Test1.0.
0030 - 06 03 55 04 0b 0c 04 54-65 73 74 31 12 30 10 06   ..U....Test1.0..
0040 - 03 55 04 03 0c 09 54 65-73 74 20 52 6f 6f 74 30   .U....Test Root0
0050 - 1e 17 0d 32 34 30 38 32-39 30 36 32 37 31 37 5a   ...240829062717Z
0060 - 17 0d 32 35 30 38 32 39-30 36 32 37 31 37 5a 30   ..250829062717Z0
0070 - 54 31 0b 30 09 06 03 55-04 06 13 02 4b 52 31 0b   T1.0...U....KR1.
0080 - 30 09 06 03 55 04 08 0c-02 47 47 31 0b 30 09 06   0...U....GG1.0..
0090 - 03 55 04 07 0c 02 59 49-31 0d 30 0b 06 03 55 04   .U....YI1.0...U.
00a0 - 0a 0c 04 54 65 73 74 31-0d 30 0b 06 03 55 04 0b   ...Test1.0...U..
00b0 - 0c 04 54 65 73 74 31 0d-30 0b 06 03 55 04 03 0c   ..Test1.0...U...
00c0 - 04 54 65 73 74 30 82 01-22 30 0d 06 09 2a 86 48   .Test0.."0...*.H
read from 0x262aaf94de0 [0x262ab38a4b3] (16717 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 04 00 c3 0b 00 03   ................
0010 - 66 00 02 00 01 14 00 00-b7 86 f7 0d 01 01 01 05   f...............
0020 - 00 03 82 01 0f 00 30 82-01 0a 02 82 01 01 00 ad   ......0.........
0030 - 9a 29 67 5f f3 a4 79 b4-c6 e6 32 73 d8 d7 ed 88   .)g_..y...2s....
0040 - 94 15 83 e4 31 00 04 6c-b5 8c ac 87 ab 74 44 13   ....1..l.....tD.
0050 - 76 ca 0b 74 29 40 9e 97-2a 01 d7 8b 46 26 6e 19   v..t)@..*...F&n.
0060 - 35 4d c0 d3 b5 ea 0e 93-3a 06 e8 e5 85 b5 27 05   5M......:.....'.
0070 - 63 db 28 b8 92 da 5a 14-39 0f da 68 6d 6f 0a fb   c.(...Z.9..hmo..
0080 - 52 dc 08 0f 54 d3 e4 a2-28 9d a0 71 50 82 e0 db   R...T...(..qP...
0090 - ca d1 94 dd 42 98 3a 09-33 a8 d9 ef fb d2 35 43   ....B.:.3.....5C
00a0 - b1 22 a2 be 41 6d ba 91-dc 0b 31 4e 88 f9 4d 9c   ."..Am....1N..M.
00b0 - 61 2d ec b2 13 0a c2 91-8e a2 d6 e9 40 b9 32 b9   a-..........@.2.
00c0 - 80 8f b3 18 a3 33 13 23-d5 d0 7e d9 d0 7f 93 e0   .....3.#..~.....
read from 0x262aaf94de0 [0x262ab38a4b3] (16717 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 05 00 c3 0b 00 03   ................
0010 - 66 00 02 00 01 cb 00 00-b7 2d 4d 90 c5 58 24 56   f........-M..X$V
0020 - d5 c9 10 13 4a b2 99 23-7d 34 b9 8e 97 19 69 6f   ....J..#}4....io
0030 - ce c6 3f d6 17 a7 d2 43-e0 36 cb 51 7b 2f 18 8b   ..?....C.6.Q{/..
0040 - c2 33 f8 57 cf d1 61 0b-7c ed 37 35 e3 13 7a 24   .3.W..a.|.75..z$
0050 - 2e 77 08 c2 e3 d9 e6 17-d3 a5 c6 34 5a da 86 a7   .w.........4Z...
0060 - f8 02 36 1d 66 63 cf e9-c0 3d 82 fb 39 a2 8d 92   ..6.fc...=..9...
0070 - 01 4a 83 cf e2 76 3d 87-02 03 01 00 01 a3 21 30   .J...v=.......!0
0080 - 1f 30 1d 06 03 55 1d 11-04 16 30 14 82 12 74 65   .0...U....0...te
0090 - 73 74 2e 70 72 69 6e 63-65 62 36 31 32 2e 70 65   st.princeb612.pe
00a0 - 30 0d 06 09 2a 86 48 86-f7 0d 01 01 0b 05 00 03   0...*.H.........
00b0 - 82 01 01 00 00 a5 f5 54-18 ab ad 36 38 c8 fc 0b   .......T...68...
00c0 - 66 60 dd 9f 75 9d 86 5b-79 2f ee 57 f1 79 1c 15   f`..u..[y/.W.y..
read from 0x262aaf94de0 [0x262ab38a4b3] (16717 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 06 00 c3 0b 00 03   ................
0010 - 66 00 02 00 02 82 00 00-b7 a1 34 23 d0 1c a9 58   f.........4#...X
0020 - 51 a4 d0 08 f5 d8 f7 49-e9 c5 b5 65 91 51 2d 6d   Q......I...e.Q-m
0030 - e4 3b 0e 77 02 1f 45 8e-34 e5 bb eb f6 9d df 4a   .;.w..E.4......J
0040 - 40 60 21 b3 8e 16 33 3f-f4 b6 90 d3 3c 34 ce e6   @`!...3?....<4..
0050 - d9 47 07 a7 57 14 0c f9-78 0b 36 72 a9 88 07 07   .G..W...x.6r....
0060 - 93 b4 d7 fe 29 5e e8 41-37 20 a5 03 c7 97 cb 82   ....)^.A7 ......
0070 - ca db 14 e5 8b 96 1f a9-e9 20 3d 6b 25 ae f4 89   ......... =k%...
0080 - 4c 60 8d e9 14 33 47 4b-88 54 a2 47 19 81 c8 7b   L`...3GK.T.G...{
0090 - 0e 32 52 2b 91 88 ad 0f-6d 73 30 8c 00 af d5 fc   .2R+....ms0.....
00a0 - 46 46 af 3a c2 17 89 ec-c8 83 ae da e6 69 63 e0   FF.:.........ic.
00b0 - 9c 84 22 c5 7a de e8 23-6b 53 9d 6f 94 d2 7f 5c   ..".z..#kS.o...\
00c0 - be 1d 0c de 0e 07 0d 52-a5 43 8c e8 05 ef c0 ff   .......R.C......
read from 0x262aaf94de0 [0x262ab38a4b3] (16717 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 07 00 39 0b 00 03   ............9...
0010 - 66 00 02 00 03 39 00 00-2d f0 73 fa dc 5a 51 4c   f....9..-.s..ZQL
0020 - 24 09 65 45 7d ab 52 8b-7e 5d f0 fb de a7 3d 43   $.eE}.R.~]....=C
0030 - c5 af 76 e3 6e f9 a1 dc-78 a2 bd 54 41 04 99 e5   ..v.n...x..TA...
0040 - 56 32 ba 02 fd 72 16 fe-fd 00 00 00 00 00 00 00   V2...r..........
0050 - 08 00 7d 0c 00 01 28 00-03 00 00 00 00 00 71 03   ..}...(.......q.
0060 - 00 1d 20 34 0d c9 22 f7-ee a7 2b a1 13 ca 5a dc   .. 4.."...+...Z.
0070 - 09 53 d5 05 69 a6 80 31-dc 5b fc 4d d2 06 70 68   .S..i..1.[.M..ph
0080 - 34 e1 26 08 04 01 00 67-2a 94 51 63 88 0d 13 a5   4.&....g*.Qc....
0090 - 14 33 30 96 db ba 6c 01-d7 b0 70 25 e2 60 3d 50   .30...l...p%.`=P
00a0 - aa 84 5c 32 fb 4f da 69-88 b8 70 96 78 a8 f6 ea   ..\2.O.i..p.x...
00b0 - a2 fc 61 06 45 11 94 e6-6c 4f 25 23 fd 16 36 24   ..a.E...lO%#..6$
00c0 - 75 ca d2 43 01 80 27 63-56 a8 d9 13 01 4d 25 2c   u..C..'cV....M%,
SSL_connect:SSLv3/TLS read server hello
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify return:1
read from 0x262aaf94de0 [0x262ab38a4b3] (16717 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 09 00 c3 0c 00 01   ................
0010 - 28 00 03 00 00 71 00 00-b7 f2 3e 92 12 0a 35 87   (....q....>...5.
0020 - 85 40 56 b5 29 73 06 1d-2d 90 42 ab 12 52 a2 91   .@V.)s..-.B..R..
0030 - ca 03 92 87 1b df e9 f7-7c be 32 f3 ac cf 33 3b   ........|.2...3;
0040 - 84 56 a7 f0 06 07 c2 4f-54 c4 15 e6 dd 0f df 2d   .V.....OT......-
0050 - e0 de 7b 91 62 fb ae 38-84 32 d7 c9 f3 ba 72 3b   ..{.b..8.2....r;
0060 - ca e9 30 d3 b2 13 21 e4-02 02 bd 21 0c 46 18 a6   ..0...!....!.F..
0070 - f8 76 ec ad 81 24 44 7f-a3 e8 7d 83 0c 90 7b 80   .v...$D...}...{.
0080 - 25 b6 04 5a 11 c9 2b ed-17 c2 c8 ed 96 4c 79 06   %..Z..+......Ly.
0090 - fb cb 8e d5 a5 1e 6e 3a-12 1b bd a4 10 cd f0 7d   ......n:.......}
00a0 - fa 32 78 86 86 df db 11-9f 70 d2 b0 1d 9d c9 c1   .2x......p......
00b0 - e5 99 8b 00 3a 22 9e 32-61 de 05 69 fb fa cd 65   ....:".2a..i...e
00c0 - a8 74 8b b8 e3 23 26 d5-f8 dc df cb ed 41 89 d2   .t...#&......A..
SSL_connect:SSLv3/TLS read server certificate
read from 0x262aaf94de0 [0x262ab38a4b3] (16717 bytes => 25 (0x19))
0000 - 16 fe fd 00 00 00 00 00-00 00 0a 00 0c 0e 00 00   ................
0010 - 00 00 04 00 00 00 00 00-00                        .........
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client key exchange
SSL_connect:SSLv3/TLS write change cipher spec
write to 0x262aaf94de0 [0x262ab3853c0] (165 bytes => 165 (0xA5))
0000 - 16 fe fd 00 00 00 00 00-00 00 04 00 2d 10 00 00   ............-...
0010 - 21 00 02 00 00 00 00 00-21 20 72 b7 34 6a 14 e0   !.......! r.4j..
0020 - d7 20 8a e7 99 63 92 c0-8f c1 f1 1a 9c 60 48 9a   . ...c.......`H.
0030 - 41 44 09 b7 bb 3f 93 59-d7 5e 14 fe fd 00 00 00   AD...?.Y.^......
0040 - 00 00 00 00 05 00 01 01-16 fe fd 00 01 00 00 00   ................
0050 - 00 00 00 00 50 58 2f 88-eb cc 17 af 37 40 3f 1a   ....PX/.....7@?.
0060 - f0 0f c0 04 d6 17 17 05-41 c6 ca 59 3a 46 aa bd   ........A..Y:F..
0070 - 47 25 96 ea 1b 99 57 32-00 b4 39 bc 9f 2e f2 bd   G%....W2..9.....
0080 - 2e 4d c5 7c 9e 9b aa ae-1d 7c 1f 4e f9 f6 05 98   .M.|.....|.N....
0090 - 18 c1 a6 f2 f5 a8 f4 22-f3 88 e0 05 13 79 72 2d   .......".....yr-
00a0 - a5 b2 38 84 cb                                    ..8..
SSL_connect:SSLv3/TLS write finished
read from 0x262aaf94de0 [0x262ab38a4b3] (16717 bytes => 207 (0xCF))
0000 - 16 fe fd 00 00 00 00 00-00 00 0b 00 c2 04 00 00   ................
0010 - b6 00 05 00 00 00 00 00-b6 00 00 1c 20 00 b0 77   ............ ..w
0020 - 15 7d 9f 0b 34 65 1b 65-82 9d d1 cf 3d 23 9b 47   .}..4e.e....=#.G
0030 - c7 5b 89 d0 1b c2 ef d3-a7 23 e8 40 5e bd 60 36   .[.......#.@^.`6
0040 - e0 5a 61 b3 68 bf 58 69-58 e9 6a dc ad 8e 1c 80   .Za.h.XiX.j.....
0050 - c0 66 5c f2 68 59 9c a0-bf 68 23 e9 37 eb 15 d8   .f\.hY...h#.7...
0060 - da cb e5 6d ef ba a9 f0-fd ab bc 32 fb e7 ff 29   ...m.......2...)
0070 - 4d 08 e5 9d 7a f9 01 cd-71 1f 7d 76 cd 3d 6a ac   M...z...q.}v.=j.
0080 - 64 b2 c1 09 9c 97 6b 3a-91 98 c0 00 d3 c0 6d c0   d.....k:......m.
0090 - c5 b9 2c a2 ff 97 de 1d-37 b2 b9 39 e1 4a 7c 88   ..,.....7..9.J|.
00a0 - 49 3e 88 9c 97 2a 3a bd-61 e9 a5 40 e9 87 29 66   I>...*:.a..@..)f
00b0 - 02 c6 d9 ed bb 5a ad d9-5a 59 51 2d ca 8d ac 9e   .....Z..ZYQ-....
00c0 - 50 13 43 08 d8 e5 bf c8-b9 4f fb e8 a3 98 c7      P.C......O.....
SSL_connect:SSLv3/TLS write finished
read from 0x262aaf94de0 [0x262ab38a4b3] (16717 bytes => 107 (0x6B))
0000 - 14 fe fd 00 00 00 00 00-00 00 0c 00 01 01 16 fe   ................
0010 - fd 00 01 00 00 00 00 00-00 00 50 24 28 4f f3 13   ..........P$(O..
0020 - 22 6a c4 98 d9 14 66 28-e9 82 07 d9 61 00 7e 0e   "j....f(....a.~.
0030 - a0 ee 63 99 71 e9 29 6e-8d 2e 04 12 77 9c c2 4c   ..c.q.)n....w..L
0040 - 6d 95 ce 58 bd 8c cb 0d-1b 4f da 1b a7 80 52 e6   m..X.....O....R.
0050 - 60 a2 c6 3e 05 32 df 0a-68 7f b5 5d 66 16 53 ec   `..>.2..h..]f.S.
0060 - d2 73 3e 72 12 fd 79 e1-f3 d7 71                  .s>r..y...q
SSL_connect:SSLv3/TLS read server session ticket
SSL_connect:SSLv3/TLS read change cipher spec
SSL_connect:SSLv3/TLS read finished
---
Certificate chain
 0 s:C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
   i:C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
   a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
   v:NotBefore: Aug 29 06:27:17 2024 GMT; NotAfter: Aug 29 06:27:17 2025 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIDXDCCAkSgAwIBAgIUY6ZxEHnWpkhZ2mepBOjjX+IDoyYwDQYJKoZIhvcNAQEL
BQAwWTELMAkGA1UEBhMCS1IxCzAJBgNVBAgMAkdHMQswCQYDVQQHDAJZSTENMAsG
A1UECgwEVGVzdDENMAsGA1UECwwEVGVzdDESMBAGA1UEAwwJVGVzdCBSb290MB4X
DTI0MDgyOTA2MjcxN1oXDTI1MDgyOTA2MjcxN1owVDELMAkGA1UEBhMCS1IxCzAJ
BgNVBAgMAkdHMQswCQYDVQQHDAJZSTENMAsGA1UECgwEVGVzdDENMAsGA1UECwwE
VGVzdDENMAsGA1UEAwwEVGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAK2aKWdf86R5tMbmMnPY1+2IlBWD5DEABGy1jKyHq3REE3bKC3QpQJ6XKgHX
i0Ymbhk1TcDTteoOkzoG6OWFtScFY9souJLaWhQ5D9pobW8K+1LcCA9U0+SiKJ2g
cVCC4NvK0ZTdQpg6CTOo2e/70jVDsSKivkFtupHcCzFOiPlNnGEt7LITCsKRjqLW
6UC5MrmAj7MYozMTI9XQftnQf5PgLU2QxVgkVtXJEBNKspkjfTS5jpcZaW/Oxj/W
F6fSQ+A2y1F7LxiLwjP4V8/RYQt87Tc14xN6JC53CMLj2eYX06XGNFrahqf4AjYd
ZmPP6cA9gvs5oo2SAUqDz+J2PYcCAwEAAaMhMB8wHQYDVR0RBBYwFIISdGVzdC5w
cmluY2ViNjEyLnBlMA0GCSqGSIb3DQEBCwUAA4IBAQAApfVUGKutNjjI/AtmYN2f
dZ2GW3kv7lfxeRwVoTQj0BypWFGk0Aj12PdJ6cW1ZZFRLW3kOw53Ah9FjjTlu+v2
nd9KQGAhs44WMz/0tpDTPDTO5tlHB6dXFAz5eAs2cqmIBweTtNf+KV7oQTcgpQPH
l8uCytsU5YuWH6npID1rJa70iUxgjekUM0dLiFSiRxmByHsOMlIrkYitD21zMIwA
r9X8RkavOsIXiezIg67a5mlj4JyEIsV63ugja1Odb5TSf1y+HQzeDgcNUqVDjOgF
78D/8HP63FpRTCQJZUV9q1KLfl3w+96nPUPFr3bjbvmh3HiivVRBBJnlVjK6Av1y
-----END CERTIFICATE-----
subject=C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
issuer=C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1843 bytes and written 663 bytes
Verification error: unable to verify the first certificate
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES128-SHA256
Protocol: DTLSv1.2
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : DTLSv1.2
    Cipher    : ECDHE-RSA-AES128-SHA256
    Session-ID: 5EA4DF2E0FC72879DF8432BD7560802234D188FF9EE0EC74E5457EED38D2168B
    Session-ID-ctx:
    Master-Key: 64DE10510EE026A2E7E4AA96C44D5A0A1CAD2A64A74F7BBEE9E53CDF17A782FAE61A9686A9172C45BBE4F65BB10FB10B
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 77 15 7d 9f 0b 34 65 1b-65 82 9d d1 cf 3d 23 9b   w.}..4e.e....=#.
    0010 - 47 c7 5b 89 d0 1b c2 ef-d3 a7 23 e8 40 5e bd 60   G.[.......#.@^.`
    0020 - 36 e0 5a 61 b3 68 bf 58-69 58 e9 6a dc ad 8e 1c   6.Za.h.XiX.j....
    0030 - 80 c0 66 5c f2 68 59 9c-a0 bf 68 23 e9 37 eb 15   ..f\.hY...h#.7..
    0040 - d8 da cb e5 6d ef ba a9-f0 fd ab bc 32 fb e7 ff   ....m.......2...
    0050 - 29 4d 08 e5 9d 7a f9 01-cd 71 1f 7d 76 cd 3d 6a   )M...z...q.}v.=j
    0060 - ac 64 b2 c1 09 9c 97 6b-3a 91 98 c0 00 d3 c0 6d   .d.....k:......m
    0070 - c0 c5 b9 2c a2 ff 97 de-1d 37 b2 b9 39 e1 4a 7c   ...,.....7..9.J|
    0080 - 88 49 3e 88 9c 97 2a 3a-bd 61 e9 a5 40 e9 87 29   .I>...*:.a..@..)
    0090 - 66 02 c6 d9 ed bb 5a ad-d9 5a 59 51 2d ca 8d ac   f.....Z..ZYQ-...
    00a0 - 9e 50 13 43 08 d8 e5 bf-c8 b9 4f fb e8 a3 98 c7   .P.C......O.....

    Start Time: 1743656922
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: yes
---
hello
write to 0x262aaf94de0 [0x262ab39d2d3] (77 bytes => 77 (0x4D))
0000 - 17 fe fd 00 01 00 00 00-00 00 01 00 40 1e a9 65   ............@..e
0010 - 81 47 fc e3 95 e4 71 a6-bf 0c 85 61 df 2c 79 f4   .G....q....a.,y.
0020 - 70 2f 7b 15 45 e9 08 72-28 ed dc 1d bb 88 7d e4   p/{.E..r(.....}.
0030 - a4 e5 af 8a 1e 4b 4e 16-9e 6f 16 cf 8c 64 a5 01   .....KN..o...d..
0040 - f7 8f d6 6f 19 e9 34 9c-1b 51 61 43 f1            ...o..4..QaC.
Q
DONE
write to 0x262aaf94de0 [0x262ab39d2d3] (77 bytes => 77 (0x4D))
0000 - 15 fe fd 00 01 00 00 00-00 00 02 00 40 e4 ed 81   ............@...
0010 - fe 32 be f0 d1 b7 42 36-db e3 98 5f 31 61 aa 6c   .2....B6..._1a.l
0020 - b4 f6 50 4d 62 f1 a1 f3-02 1e c7 b5 57 c8 b4 35   ..PMb.......W..5
0030 - b5 97 c2 36 1e 38 f9 45-38 4f a2 d1 f7 d7 98 0d   ...6.8.E8O......
0040 - 73 4f 70 e9 17 37 a1 c0-dc 10 0e 00 d5            sOp..7.......
SSL3 alert write:warning:close notify
read from 0x262aaf94de0 [0x262aaed7c60] (16384 bytes => 77 (0x4D))
0000 - 15 fe fd 00 01 00 00 00-00 00 01 00 40 c4 f8 3e   ............@..>
0010 - 0a 39 08 4b 8b 4c 66 f4-ee ba fd a0 9e d4 5b db   .9.K.Lf.......[.
0020 - c0 3f 3c 95 66 42 58 00-b3 ca 77 ec 62 5e b0 8e   .?<.fBX...w.b^..
0030 - 4c 5e 37 af c5 d0 94 e4-62 dd 7e 94 7a 62 26 b0   L^7.....b.~.zb&.
0040 - 33 2e 41 59 65 71 e8 96-08 ad 47 53 c3            3.AYeq....GS.
````
