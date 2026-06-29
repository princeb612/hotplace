#### dtls12.pcapng - server

````
$ openssl s_server -accept 9000 -cert server.crt -key server.key -state -debug -status_verbose -keylogfile sslkeylog -dtls1_2
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x1f6a19a21f0 [0x1f6a19ed783] (16717 bytes => 208 (0xD0))
0000 - 16 fe ff 00 00 00 00 00-00 00 00 00 c3 01 00 00   ................
0010 - bf 00 00 00 00 00 00 00-b7 fe fd e6 e4 8c 6f e8   ..............o.
0020 - 94 0c a4 e9 64 27 54 44-13 09 33 bb 9c 2d f6 27   ....d'TD..3..-.'
0030 - d0 ee 61 e6 54 90 bf b0-1b 4f 54 00 00 00 38 c0   ..a.T....OT...8.
0040 - 2b c0 2c c0 30 00 9f cc-a9 cc a8 cc aa c0 2b c0   +.,.0.........+.
0050 - 2f 00 9e c0 24 c0 28 00-6b c0 23 c0 27 00 67 c0   /...$.(.k.#.'.g.
0060 - 0a c0 14 00 39 c0 09 c0-13 00 33 00 9d 00 9c 00   ....9.....3.....
0070 - 3d 00 3c 00 35 00 2f 01-00 00 5d ff 01 00 01 00   =.<.5./...].....
0080 - 00 0b 00 04 03 00 01 02-00 0a 00 0c 00 0a 00 1d   ................
0090 - 00 17 00 1e 00 19 00 18-00 23 00 00 00 16 00 00   .........#......
00a0 - 00 17 00 00 00 0d 00 30-00 2e 04 03 05 03 06 03   .......0........
00b0 - 08 07 08 08 08 1a 08 1b-08 1c 08 09 08 0a 08 0b   ................
00c0 - 08 04 08 05 08 06 04 01-05 01 06 01 03 03 03 01   ................
read from 0x1f6a19a21f0 [0x1f6a19ed783] (16717 bytes => 33 (0x21))
0000 - 16 fe ff 00 00 00 00 00-00 00 01 00 14 01 00 00   ................
0010 - bf 00 00 00 00 b7 00 00-08 03 02 04 02 05 02 06   ................
0020 - 02                                                .
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
write to 0x1f6a19a21f0 [0x1f6a19ec770] (48 bytes => 48 (0x30))
0000 - 16 fe ff 00 00 00 00 00-00 00 00 00 23 03 00 00   ............#...
0010 - 17 00 00 00 00 00 00 00-17 fe ff 14 8d fb 94 e1   ................
0020 - 46 14 bd 66 fa 92 61 c7-18 e2 c7 da 19 d8 1e f2   F..f..a.........
SSL_accept:DTLS1 write hello verify request
read from 0x1f6a19a21f0 [0x1f6a19ed783] (16717 bytes => 208 (0xD0))
0000 - 16 fe ff 00 00 00 00 00-00 00 02 00 c3 01 00 00   ................
0010 - d3 00 01 00 00 00 00 00-b7 fe fd e6 e4 8c 6f e8   ..............o.
0020 - 94 0c a4 e9 64 27 54 44-13 09 33 bb 9c 2d f6 27   ....d'TD..3..-.'
0030 - d0 ee 61 e6 54 90 bf b0-1b 4f 54 00 14 8d fb 94   ..a.T....OT.....
0040 - e1 46 14 bd 66 fa 92 61-c7 18 e2 c7 da 19 d8 1e   .F..f..a........
0050 - f2 00 38 c0 2b c0 2c c0-30 00 9f cc a9 cc a8 cc   ..8.+.,.0.......
0060 - aa c0 2b c0 2f 00 9e c0-24 c0 28 00 6b c0 23 c0   ..+./...$.(.k.#.
0070 - 27 00 67 c0 0a c0 14 00-39 c0 09 c0 13 00 33 00   '.g.....9.....3.
0080 - 9d 00 9c 00 3d 00 3c 00-35 00 2f 01 00 00 5d ff   ....=.<.5./...].
0090 - 01 00 01 00 00 0b 00 04-03 00 01 02 00 0a 00 0c   ................
00a0 - 00 0a 00 1d 00 17 00 1e-00 19 00 18 00 23 00 00   .............#..
00b0 - 00 16 00 00 00 17 00 00-00 0d 00 30 00 2e 04 03   ...........0....
00c0 - 05 03 06 03 08 07 08 08-08 1a 08 1b 08 1c 08 09   ................
read from 0x1f6a19a21f0 [0x1f6a19ed783] (16717 bytes => 53 (0x35))
0000 - 16 fe ff 00 00 00 00 00-00 00 03 00 28 01 00 00   ............(...
0010 - d3 00 01 00 00 b7 00 00-1c 08 0a 08 0b 08 04 08   ................
0020 - 05 08 06 04 01 05 01 06-01 03 03 03 01 03 02 04   ................
0030 - 02 05 02 06 02                                    .....
SSL_accept:DTLS1 write hello verify request
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
write to 0x1f6a19a21f0 [0x1f6a19ec770] (208 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 01 00 49 02 00 00   ............I...
0010 - 3d 00 01 00 00 00 00 00-3d fe fd a1 06 ed 4a 5d   =.......=.....J]
0020 - 65 5a f2 3a c7 9c 9c d1-bf 57 05 54 5b c2 3d 9f   eZ.:.....W.T[.=.
0030 - 16 75 e7 72 41 f3 d5 15-60 87 5c 00 c0 30 00 00   .u.rA...`.\..0..
0040 - 15 ff 01 00 01 00 00 0b-00 04 03 00 01 02 00 23   ...............#
0050 - 00 00 00 17 00 00 16 fe-fd 00 00 00 00 00 00 00   ................
0060 - 02 00 6d 0b 00 03 66 00-02 00 00 00 00 00 61 00   ..m...f.......a.
0070 - 03 63 00 03 60 30 82 03-5c 30 82 02 44 a0 03 02   .c..`0..\0..D...
0080 - 01 02 02 14 63 a6 71 10-79 d6 a6 48 59 da 67 a9   ....c.q.y..HY.g.
0090 - 04 e8 e3 5f e2 03 a3 26-30 0d 06 09 2a 86 48 86   ..._...&0...*.H.
00a0 - f7 0d 01 01 0b 05 00 30-59 31 0b 30 09 06 03 55   .......0Y1.0...U
00b0 - 04 06 13 02 4b 52 31 0b-30 09 06 03 55 04 08 0c   ....KR1.0...U...
00c0 - 02 47 47 31 0b 30 09 06-03 55 04 07 0c 02 59 49   .GG1.0...U....YI
write to 0x1f6a19a21f0 [0x1f6a19ec770] (208 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 03 00 c3 0b 00 03   ................
0010 - 66 00 02 00 00 61 00 00-b7 31 0d 30 0b 06 03 55   f....a...1.0...U
0020 - 04 0a 0c 04 54 65 73 74-31 0d 30 0b 06 03 55 04   ....Test1.0...U.
0030 - 0b 0c 04 54 65 73 74 31-12 30 10 06 03 55 04 03   ...Test1.0...U..
0040 - 0c 09 54 65 73 74 20 52-6f 6f 74 30 1e 17 0d 32   ..Test Root0...2
0050 - 34 30 38 32 39 30 36 32-37 31 37 5a 17 0d 32 35   40829062717Z..25
0060 - 30 38 32 39 30 36 32 37-31 37 5a 30 54 31 0b 30   0829062717Z0T1.0
0070 - 09 06 03 55 04 06 13 02-4b 52 31 0b 30 09 06 03   ...U....KR1.0...
0080 - 55 04 08 0c 02 47 47 31-0b 30 09 06 03 55 04 07   U....GG1.0...U..
0090 - 0c 02 59 49 31 0d 30 0b-06 03 55 04 0a 0c 04 54   ..YI1.0...U....T
00a0 - 65 73 74 31 0d 30 0b 06-03 55 04 0b 0c 04 54 65   est1.0...U....Te
00b0 - 73 74 31 0d 30 0b 06 03-55 04 03 0c 04 54 65 73   st1.0...U....Tes
00c0 - 74 30 82 01 22 30 0d 06-09 2a 86 48 86 f7 0d 01   t0.."0...*.H....
write to 0x1f6a19a21f0 [0x1f6a19ec770] (208 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 04 00 c3 0b 00 03   ................
0010 - 66 00 02 00 01 18 00 00-b7 01 01 05 00 03 82 01   f...............
0020 - 0f 00 30 82 01 0a 02 82-01 01 00 ad 9a 29 67 5f   ..0..........)g_
0030 - f3 a4 79 b4 c6 e6 32 73-d8 d7 ed 88 94 15 83 e4   ..y...2s........
0040 - 31 00 04 6c b5 8c ac 87-ab 74 44 13 76 ca 0b 74   1..l.....tD.v..t
0050 - 29 40 9e 97 2a 01 d7 8b-46 26 6e 19 35 4d c0 d3   )@..*...F&n.5M..
0060 - b5 ea 0e 93 3a 06 e8 e5-85 b5 27 05 63 db 28 b8   ....:.....'.c.(.
0070 - 92 da 5a 14 39 0f da 68-6d 6f 0a fb 52 dc 08 0f   ..Z.9..hmo..R...
0080 - 54 d3 e4 a2 28 9d a0 71-50 82 e0 db ca d1 94 dd   T...(..qP.......
0090 - 42 98 3a 09 33 a8 d9 ef-fb d2 35 43 b1 22 a2 be   B.:.3.....5C."..
00a0 - 41 6d ba 91 dc 0b 31 4e-88 f9 4d 9c 61 2d ec b2   Am....1N..M.a-..
00b0 - 13 0a c2 91 8e a2 d6 e9-40 b9 32 b9 80 8f b3 18   ........@.2.....
00c0 - a3 33 13 23 d5 d0 7e d9-d0 7f 93 e0 2d 4d 90 c5   .3.#..~.....-M..
write to 0x1f6a19a21f0 [0x1f6a19ec770] (208 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 05 00 c3 0b 00 03   ................
0010 - 66 00 02 00 01 cf 00 00-b7 58 24 56 d5 c9 10 13   f........X$V....
0020 - 4a b2 99 23 7d 34 b9 8e-97 19 69 6f ce c6 3f d6   J..#}4....io..?.
0030 - 17 a7 d2 43 e0 36 cb 51-7b 2f 18 8b c2 33 f8 57   ...C.6.Q{/...3.W
0040 - cf d1 61 0b 7c ed 37 35-e3 13 7a 24 2e 77 08 c2   ..a.|.75..z$.w..
0050 - e3 d9 e6 17 d3 a5 c6 34-5a da 86 a7 f8 02 36 1d   .......4Z.....6.
0060 - 66 63 cf e9 c0 3d 82 fb-39 a2 8d 92 01 4a 83 cf   fc...=..9....J..
0070 - e2 76 3d 87 02 03 01 00-01 a3 21 30 1f 30 1d 06   .v=.......!0.0..
0080 - 03 55 1d 11 04 16 30 14-82 12 74 65 73 74 2e 70   .U....0...test.p
0090 - 72 69 6e 63 65 62 36 31-32 2e 70 65 30 0d 06 09   rinceb612.pe0...
00a0 - 2a 86 48 86 f7 0d 01 01-0b 05 00 03 82 01 01 00   *.H.............
00b0 - 00 a5 f5 54 18 ab ad 36-38 c8 fc 0b 66 60 dd 9f   ...T...68...f`..
00c0 - 75 9d 86 5b 79 2f ee 57-f1 79 1c 15 a1 34 23 d0   u..[y/.W.y...4#.
write to 0x1f6a19a21f0 [0x1f6a19ec770] (208 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 06 00 c3 0b 00 03   ................
0010 - 66 00 02 00 02 86 00 00-b7 1c a9 58 51 a4 d0 08   f..........XQ...
0020 - f5 d8 f7 49 e9 c5 b5 65-91 51 2d 6d e4 3b 0e 77   ...I...e.Q-m.;.w
0030 - 02 1f 45 8e 34 e5 bb eb-f6 9d df 4a 40 60 21 b3   ..E.4......J@`!.
0040 - 8e 16 33 3f f4 b6 90 d3-3c 34 ce e6 d9 47 07 a7   ..3?....<4...G..
0050 - 57 14 0c f9 78 0b 36 72-a9 88 07 07 93 b4 d7 fe   W...x.6r........
0060 - 29 5e e8 41 37 20 a5 03-c7 97 cb 82 ca db 14 e5   )^.A7 ..........
0070 - 8b 96 1f a9 e9 20 3d 6b-25 ae f4 89 4c 60 8d e9   ..... =k%...L`..
0080 - 14 33 47 4b 88 54 a2 47-19 81 c8 7b 0e 32 52 2b   .3GK.T.G...{.2R+
0090 - 91 88 ad 0f 6d 73 30 8c-00 af d5 fc 46 46 af 3a   ....ms0.....FF.:
00a0 - c2 17 89 ec c8 83 ae da-e6 69 63 e0 9c 84 22 c5   .........ic...".
00b0 - 7a de e8 23 6b 53 9d 6f-94 d2 7f 5c be 1d 0c de   z..#kS.o...\....
00c0 - 0e 07 0d 52 a5 43 8c e8-05 ef c0 ff f0 73 fa dc   ...R.C.......s..
SSL_accept:SSLv3/TLS write certificate
write to 0x1f6a19a21f0 [0x1f6a19ec770] (208 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 07 00 35 0b 00 03   ............5...
0010 - 66 00 02 00 03 3d 00 00-29 5a 51 4c 24 09 65 45   f....=..)ZQL$.eE
0020 - 7d ab 52 8b 7e 5d f0 fb-de a7 3d 43 c5 af 76 e3   }.R.~]....=C..v.
0030 - 6e f9 a1 dc 78 a2 bd 54-41 04 99 e5 56 32 ba 02   n...x..TA...V2..
0040 - fd 72 16 fe fd 00 00 00-00 00 00 00 08 00 81 0c   .r..............
0050 - 00 01 28 00 03 00 00 00-00 00 75 03 00 1d 20 bf   ..(.......u... .
0060 - 6c 3d 2d c6 bd 2d eb 7c-4c 14 04 da db 56 a9 69   l=-..-.|L....V.i
0070 - ca 00 52 3a a9 8d 3b 8d-ca 9a 36 fe 2f 91 0e 08   ..R:..;...6./...
0080 - 04 01 00 a6 49 9c 48 9d-c7 ea da 16 df 98 a8 53   ....I.H........S
0090 - 65 a1 c5 5e f4 c7 77 cf-2b d6 7f e8 6c ba 32 2b   e..^..w.+...l.2+
00a0 - 66 c0 f8 93 88 ce 60 92-40 71 23 83 cd db 99 be   f.....`.@q#.....
00b0 - 47 40 b2 3a f9 cc 9a ea-15 42 0d 9d ca 3b 5a 18   G@.:.....B...;Z.
00c0 - ba 90 5c da b5 0a 06 f5-ae 32 fc 8e 8a 13 71 e9   ..\......2....q.
SSL_accept:SSLv3/TLS write key exchange
write to 0x1f6a19a21f0 [0x1f6a19ec770] (204 bytes => 204 (0xCC))
0000 - 16 fe fd 00 00 00 00 00-00 00 09 00 bf 0c 00 01   ................
0010 - 28 00 03 00 00 75 00 00-b3 76 3e 32 ed d2 51 99   (....u...v>2..Q.
0020 - 8a a9 d9 7e 38 31 13 4f-16 b1 c7 31 0e 2a 79 6c   ...~81.O...1.*yl
0030 - 0b 5c cc f0 a9 ca 69 37-5e 53 fa 81 bc 73 14 fc   .\....i7^S...s..
0040 - 44 16 5e c1 58 9d 39 c0-94 d3 48 45 70 4b cf b2   D.^.X.9...HEpK..
0050 - f0 7e 2b 49 10 d1 ff e1-0e 03 cf 16 48 23 2b e6   .~+I........H#+.
0060 - 3f 0f f5 a5 d0 28 09 e7-02 d2 ad 9b 36 99 de 6e   ?....(......6..n
0070 - a7 aa ed 65 55 74 b2 02-39 90 92 2f 13 da a6 1a   ...eUt..9../....
0080 - d1 de 0e 70 39 ff d5 93-2d 28 18 2d a1 63 00 0a   ...p9...-(.-.c..
0090 - 5d 25 3f 05 b1 44 1f e9-11 a3 23 45 e7 82 0c eb   ]%?..D....#E....
00a0 - 15 92 62 67 e9 0f 16 57-16 f0 b1 e5 c3 a4 fe 51   ..bg...W.......Q
00b0 - 71 5f 67 7d 48 a7 53 58-0b b5 1f 00 92 d4 6d ba   q_g}H.SX......m.
00c0 - 91 a0 66 eb f8 e4 6d fb-aa f3 78 0a               ..f...m...x.
write to 0x1f6a19a21f0 [0x1f6a19ec770] (25 bytes => 25 (0x19))
0000 - 16 fe fd 00 00 00 00 00-00 00 0a 00 0c 0e 00 00   ................
0010 - 00 00 04 00 00 00 00 00-00                        .........
SSL_accept:SSLv3/TLS write server done
read from 0x1f6a19a21f0 [0x1f6a19ed783] (16717 bytes => 133 (0x85))
0000 - 16 fe fd 00 00 00 00 00-00 00 04 00 2d 10 00 00   ............-...
0010 - 21 00 02 00 00 00 00 00-21 20 8e 6e 2c 0f 5d 92   !.......! .n,.].
0020 - 48 5a ea c5 0a 3b cb 45-6a 45 c1 86 05 a5 51 a8   HZ...;.EjE....Q.
0030 - a7 d5 cc 8b 0b b9 3b 45-6d 5e 14 fe fd 00 00 00   ......;Em^......
0040 - 00 00 00 00 05 00 01 01-16 fe fd 00 01 00 00 00   ................
0050 - 00 00 00 00 30 7f 99 d1-86 06 74 3b 90 1e 7e a4   ....0.....t;..~.
0060 - d7 2e d0 ec b3 8c 09 09-b4 0d e0 f2 74 c6 0f 97   ............t...
0070 - d6 41 87 68 6c 90 17 37-e3 0e 49 a9 13 23 8a 7c   .A.hl..7..I..#.|
0080 - d3 79 8a b8 8f                                    .y...
SSL_accept:SSLv3/TLS write server done
SSL_accept:SSLv3/TLS read client key exchange
SSL_accept:SSLv3/TLS read change cipher spec
SSL_accept:SSLv3/TLS read finished
SSL_accept:SSLv3/TLS write session ticket
write to 0x1f6a19a21f0 [0x1f6a19ec770] (207 bytes => 207 (0xCF))
0000 - 16 fe fd 00 00 00 00 00-00 00 0b 00 c2 04 00 00   ................
0010 - b6 00 05 00 00 00 00 00-b6 00 00 1c 20 00 b0 27   ............ ..'
0020 - 23 a6 f5 8f 44 7e 30 d9-73 ee f4 4e 25 0c 4c fc   #...D~0.s..N%.L.
0030 - f3 8e d6 38 38 ae 1c bb-df 12 5d ec 7b 60 5b c1   ...88.....].{`[.
0040 - c3 f8 99 72 12 d2 6b 13-88 4c 71 90 a3 57 cb d3   ...r..k..Lq..W..
0050 - 27 31 a4 91 21 7f c6 a0-6d f8 37 06 29 9b e8 30   '1..!...m.7.)..0
0060 - df 3f b3 72 59 f0 4a e1-c6 4b 07 58 df 51 ac 30   .?.rY.J..K.X.Q.0
0070 - 53 2d bd fb 5d 24 1a 0e-76 24 36 7b 62 55 4c 9d   S-..]$..v$6{bUL.
0080 - aa 85 db 00 46 81 4e d9-df c9 c5 9c 22 01 aa 45   ....F.N....."..E
0090 - 0e 3f be 79 80 26 ff b0-b3 20 19 ad 2d 14 42 30   .?.y.&... ..-.B0
00a0 - d3 93 1f 3d c4 7c b9 55-65 8e d2 4c 23 50 af 11   ...=.|.Ue..L#P..
00b0 - 76 30 45 49 63 1e e7 ed-53 09 0d e3 cd 45 41 23   v0EIc...S....EA#
00c0 - ae 06 ab 6e bc 4c 81 e4-13 d4 c6 2d 96 43 cd      ...n.L.....-.C.
SSL_accept:SSLv3/TLS write change cipher spec
write to 0x1f6a19a21f0 [0x1f6a19ec770] (75 bytes => 75 (0x4B))
0000 - 14 fe fd 00 00 00 00 00-00 00 0c 00 01 01 16 fe   ................
0010 - fd 00 01 00 00 00 00 00-00 00 30 dd d6 a3 34 61   ..........0...4a
0020 - 30 11 d7 a2 32 b1 e4 26-b8 55 c1 d4 f9 65 e9 af   0...2..&.U...e..
0030 - d0 68 66 ad c9 2d 90 a8-fc 78 cc 84 af b6 63 ca   .hf..-...x....c.
0040 - ae 37 3c 0c ed a4 d7 f4-ff 87 bb                  .7<........
SSL_accept:SSLv3/TLS write finished
-----BEGIN SSL SESSION PARAMETERS-----
MGACAQECAwD+/QQCwDAEAAQw5P7hKkTqm0evZfg0hapdRNR5bmzdZngbawDaH3dP
BUSJx2RxoK4ufiNvL14qccRIoQYCBGhBTdiiBAICHCCkBgQEAQAAAK0DAgEBswMC
AR0=
-----END SSL SESSION PARAMETERS-----
Shared ciphers:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Supported Elliptic Curve Point Formats: uncompressed:ansiX962_compressed_prime:ansiX962_compressed_char2
Supported groups: x25519:secp256r1:x448:secp521r1:secp384r1
Shared groups: x25519:secp256r1:x448:secp521r1:secp384r1
CIPHER is ECDHE-RSA-AES256-GCM-SHA384
Secure Renegotiation IS supported
read from 0x1f6a19a21f0 [0x1f6a19ed783] (16717 bytes => 43 (0x2B))
0000 - 17 fe fd 00 01 00 00 00-00 00 01 00 1e 7f 99 d1   ................
0010 - 86 06 74 3b 91 20 84 8b-14 55 84 37 88 c9 0b 41   ..t;. ...U.7...A
0020 - c0 47 d6 63 ab a2 32 46-d2 6a 98                  .G.c..2F.j.
test
read from 0x1f6a19a21f0 [0x1f6a19ed783] (16717 bytes => 39 (0x27))
0000 - 15 fe fd 00 01 00 00 00-00 00 02 00 1a 7f 99 d1   ................
0010 - 86 06 74 3b 92 0d 91 7e-67 ff 46 a3 31 a1 2b ed   ..t;...~g.F.1.+.
0020 - 99 56 47 9d 08 1b 49                              .VG...I
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x1f6a19a21f0 [0x1f6a1a051e3] (39 bytes => 39 (0x27))
0000 - 15 fe fd 00 01 00 00 00-00 00 01 00 1a dd d6 a3   ................
0010 - 34 61 30 11 d8 f5 96 28-5a 0b 5d 53 19 89 f6 a1   4a0....(Z.]S....
0020 - eb 5c 41 c7 96 85 f2                              .\A....
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
