#### dtls12.pcapng - client

````
$ openssl s_client -connect localhost:9000 -state -debug -keylogfile client.keylog -dtls1_2
Connecting to ::1
CONNECTED(000001E0)
SSL_connect:before SSL initialization
write to 0x2582ef94830 [0x2582f3869e0] (208 bytes => 208 (0xD0))
0000 - 16 fe ff 00 00 00 00 00-00 00 00 00 c3 01 00 00   ................
0010 - bd 00 00 00 00 00 00 00-b7 fe fd 9f c7 e2 53 87   ..............S.
0020 - 0b 87 fa a8 21 b7 76 16-c4 c3 6f 60 6f 82 ed 8c   ....!.v...o`o...
0030 - d7 86 d7 0a f2 d4 23 6e-99 2e 07 00 00 00 36 c0   ......#n......6.
0040 - 2c c0 30 00 9f cc a9 cc-a8 cc aa c0 2b c0 2f 00   ,.0.........+./.
0050 - 9e c0 24 c0 28 00 6b c0-23 c0 27 00 67 c0 0a c0   ..$.(.k.#.'.g...
0060 - 14 00 39 c0 09 c0 13 00-33 00 9d 00 9c 00 3d 00   ..9.....3.....=.
0070 - 3c 00 35 00 2f 01 00 00-5d ff 01 00 01 00 00 0b   <.5./...].......
0080 - 00 04 03 00 01 02 00 0a-00 0c 00 0a 00 1d 00 17   ................
0090 - 00 1e 00 19 00 18 00 23-00 00 00 16 00 00 00 17   .......#........
00a0 - 00 00 00 0d 00 30 00 2e-04 03 05 03 06 03 08 07   .....0..........
00b0 - 08 08 08 1a 08 1b 08 1c-08 09 08 0a 08 0b 08 04   ................
00c0 - 08 05 08 06 04 01 05 01-06 01 03 03 03 01 03 02   ................
write to 0x2582ef94830 [0x2582f3869e0] (31 bytes => 31 (0x1F))
0000 - 16 fe ff 00 00 00 00 00-00 00 01 00 12 01 00 00   ................
0010 - bd 00 00 00 00 b7 00 00-06 04 02 05 02 06 02      ...............
SSL_connect:SSLv3/TLS write client hello
read from 0x2582ef94830 [0x2582f38be73] (16717 bytes => 48 (0x30))
0000 - 16 fe ff 00 00 00 00 00-00 00 00 00 23 03 00 00   ............#...
0010 - 17 00 00 00 00 00 00 00-17 fe ff 14 d8 32 1d 16   .............2..
0020 - e2 72 e5 3c bc 26 77 2d-ff 69 a2 56 ed cd cc 0a   .r.<.&w-.i.V....
SSL_connect:SSLv3/TLS write client hello
SSL_connect:DTLS1 read hello verify request
write to 0x2582ef94830 [0x2582f3869e0] (208 bytes => 208 (0xD0))
0000 - 16 fe ff 00 00 00 00 00-00 00 02 00 c3 01 00 00   ................
0010 - d1 00 01 00 00 00 00 00-b7 fe fd 9f c7 e2 53 87   ..............S.
0020 - 0b 87 fa a8 21 b7 76 16-c4 c3 6f 60 6f 82 ed 8c   ....!.v...o`o...
0030 - d7 86 d7 0a f2 d4 23 6e-99 2e 07 00 14 d8 32 1d   ......#n......2.
0040 - 16 e2 72 e5 3c bc 26 77-2d ff 69 a2 56 ed cd cc   ..r.<.&w-.i.V...
0050 - 0a 00 36 c0 2c c0 30 00-9f cc a9 cc a8 cc aa c0   ..6.,.0.........
0060 - 2b c0 2f 00 9e c0 24 c0-28 00 6b c0 23 c0 27 00   +./...$.(.k.#.'.
0070 - 67 c0 0a c0 14 00 39 c0-09 c0 13 00 33 00 9d 00   g.....9.....3...
0080 - 9c 00 3d 00 3c 00 35 00-2f 01 00 00 5d ff 01 00   ..=.<.5./...]...
0090 - 01 00 00 0b 00 04 03 00-01 02 00 0a 00 0c 00 0a   ................
00a0 - 00 1d 00 17 00 1e 00 19-00 18 00 23 00 00 00 16   ...........#....
00b0 - 00 00 00 17 00 00 00 0d-00 30 00 2e 04 03 05 03   .........0......
00c0 - 06 03 08 07 08 08 08 1a-08 1b 08 1c 08 09 08 0a   ................
write to 0x2582ef94830 [0x2582f3869e0] (51 bytes => 51 (0x33))
0000 - 16 fe ff 00 00 00 00 00-00 00 03 00 26 01 00 00   ............&...
0010 - d1 00 01 00 00 b7 00 00-1a 08 0b 08 04 08 05 08   ................
0020 - 06 04 01 05 01 06 01 03-03 03 01 03 02 04 02 05   ................
0030 - 02 06 02                                          ...
SSL_connect:SSLv3/TLS write client hello
read from 0x2582ef94830 [0x2582f38be73] (16717 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 01 00 4d 02 00 00   ............M...
0010 - 41 00 01 00 00 00 00 00-41 fe fd f0 21 fa a3 69   A.......A...!..i
0020 - c3 88 f4 80 2c 34 4d 67-cb 23 d9 6e 79 b6 85 68   ....,4Mg.#.ny..h
0030 - d2 ad ee 45 b0 0c cc 36-a7 7f 8a 00 c0 27 00 00   ...E...6.....'..
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
read from 0x2582ef94830 [0x2582f38be73] (16717 bytes => 208 (0xD0))
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
read from 0x2582ef94830 [0x2582f38be73] (16717 bytes => 208 (0xD0))
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
read from 0x2582ef94830 [0x2582f38be73] (16717 bytes => 208 (0xD0))
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
read from 0x2582ef94830 [0x2582f38be73] (16717 bytes => 208 (0xD0))
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
read from 0x2582ef94830 [0x2582f38be73] (16717 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 07 00 39 0b 00 03   ............9...
0010 - 66 00 02 00 03 39 00 00-2d f0 73 fa dc 5a 51 4c   f....9..-.s..ZQL
0020 - 24 09 65 45 7d ab 52 8b-7e 5d f0 fb de a7 3d 43   $.eE}.R.~]....=C
0030 - c5 af 76 e3 6e f9 a1 dc-78 a2 bd 54 41 04 99 e5   ..v.n...x..TA...
0040 - 56 32 ba 02 fd 72 16 fe-fd 00 00 00 00 00 00 00   V2...r..........
0050 - 08 00 7d 0c 00 01 28 00-03 00 00 00 00 00 71 03   ..}...(.......q.
0060 - 00 1d 20 a4 a9 ba 02 fb-67 3f 13 6f bf af d8 43   .. .....g?.o...C
0070 - b9 c8 7a 23 20 d8 5e 20-de a7 d1 bc 41 59 76 68   ..z# .^ ....AYvh
0080 - c9 e5 6a 08 04 01 00 81-f4 db ab 15 fc ab 02 6b   ..j............k
0090 - 85 ef 8d 5b 5d 17 a8 d7-e8 88 a2 fa 5a 8f 2e a9   ...[].......Z...
00a0 - 53 cc 65 89 9e 9b 35 45-63 15 92 99 92 6f 3d 06   S.e...5Ec....o=.
00b0 - ce c0 0b 05 c0 d7 b1 73-c2 61 1c 65 8b f1 e0 bf   .......s.a.e....
00c0 - 68 e6 22 c4 c3 5f ff 90-70 3e 95 cc 0b e3 e6 ef   h.".._..p>......
SSL_connect:SSLv3/TLS read server hello
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify return:1
read from 0x2582ef94830 [0x2582f38be73] (16717 bytes => 208 (0xD0))
0000 - 16 fe fd 00 00 00 00 00-00 00 09 00 c3 0c 00 01   ................
0010 - 28 00 03 00 00 71 00 00-b7 81 36 3e 53 1e c2 40   (....q....6>S..@
0020 - e5 2a 99 11 79 bd 23 62-29 df d4 ba 03 7f e4 5c   .*..y.#b)......\
0030 - 6b 89 4f c0 0e f5 12 68-5f bf c4 54 f1 9f 91 db   k.O....h_..T....
0040 - 0d 58 75 f9 29 bf 8f b1-90 a2 84 0d 4a 6c 04 ad   .Xu.).......Jl..
0050 - ea 1c 35 c6 b1 8f c4 49-e4 31 d9 dc 36 9a 81 ae   ..5....I.1..6...
0060 - db 28 cf 33 1b bf c8 23-b7 c7 11 c8 cf f6 69 69   .(.3...#......ii
0070 - 3c 21 0c 1b 58 73 25 39-76 dc 33 be 71 9e 28 cb   <!..Xs%9v.3.q.(.
0080 - df 28 e8 ca df ac 64 d6-c2 09 68 cd 9f d9 0f 8a   .(....d...h.....
0090 - f7 99 dd f8 93 01 19 68-7b e8 89 f5 c5 e7 0b 27   .......h{......'
00a0 - 18 8b 62 17 5d 7b 13 c2-4a 64 9c 38 46 56 c3 11   ..b.]{..Jd.8FV..
00b0 - 3b 41 4b a5 26 20 df e0-a8 6d f9 72 31 fe 95 da   ;AK.& ...m.r1...
00c0 - a9 f3 a6 a1 54 e3 74 e1-7b 00 54 b7 eb 8e cc 5e   ....T.t.{.T....^
SSL_connect:SSLv3/TLS read server certificate
read from 0x2582ef94830 [0x2582f38be73] (16717 bytes => 25 (0x19))
0000 - 16 fe fd 00 00 00 00 00-00 00 0a 00 0c 0e 00 00   ................
0010 - 00 00 04 00 00 00 00 00-00                        .........
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client key exchange
SSL_connect:SSLv3/TLS write change cipher spec
write to 0x2582ef94830 [0x2582f3869e0] (165 bytes => 165 (0xA5))
0000 - 16 fe fd 00 00 00 00 00-00 00 04 00 2d 10 00 00   ............-...
0010 - 21 00 02 00 00 00 00 00-21 20 50 42 a8 d6 b5 bb   !.......! PB....
0020 - fe 9a 7a d0 69 fc 48 e4-59 d5 c2 be f4 c5 f2 15   ..z.i.H.Y.......
0030 - 3f 31 df 94 de 89 03 2e-f9 57 14 fe fd 00 00 00   ?1.......W......
0040 - 00 00 00 00 05 00 01 01-16 fe fd 00 01 00 00 00   ................
0050 - 00 00 00 00 50 41 e2 f4-6b 71 97 6e a4 73 76 92   ....PA..kq.n.sv.
0060 - a1 a5 d7 d0 da 07 06 ef-1b 20 34 9a 04 83 f7 ae   ......... 4.....
0070 - c6 8c 3a c6 6e 12 a3 d9-32 f3 07 a3 ef 74 cb e6   ..:.n...2....t..
0080 - 6c 29 4e c9 c2 a0 12 4e-e2 5c 98 69 c2 68 3b 10   l)N....N.\.i.h;.
0090 - 93 e2 cd ca 56 4a d7 d7-71 39 66 41 13 ec e4 96   ....VJ..q9fA....
00a0 - 73 20 46 d5 6a                                    s F.j
SSL_connect:SSLv3/TLS write finished
read from 0x2582ef94830 [0x2582f38be73] (16717 bytes => 207 (0xCF))
0000 - 16 fe fd 00 00 00 00 00-00 00 0b 00 c2 04 00 00   ................
0010 - b6 00 05 00 00 00 00 00-b6 00 00 1c 20 00 b0 81   ............ ...
0020 - 91 12 df b7 f9 8c 99 db-44 56 fa 53 74 da 51 bb   ........DV.St.Q.
0030 - 30 e2 f5 f2 f0 81 66 13-76 33 40 22 0b 0b f0 c5   0.....f.v3@"....
0040 - 20 81 2b 62 f9 fa cc ac-aa e8 08 a2 c2 c6 3e 70    .+b..........>p
0050 - 51 fc 62 e1 cb 88 8e d2-7c e3 d8 d1 ae f4 3f 01   Q.b.....|.....?.
0060 - 21 f4 37 a8 22 34 4d 66-7c d6 aa 16 70 28 f1 ca   !.7."4Mf|...p(..
0070 - 8e 66 71 8a fe 80 22 26-66 33 57 28 6d bd c5 04   .fq..."&f3W(m...
0080 - c1 66 02 d7 ac 0d 38 97-db f3 a3 77 73 4f 10 46   .f....8....wsO.F
0090 - ef f1 b9 9a e7 3b 84 fb-35 6a 44 d7 fd 94 7c b2   .....;..5jD...|.
00a0 - 78 1c b3 ff 90 be ad 1b-0b 5d 9e 95 db 51 35 e9   x........]...Q5.
00b0 - 3f 42 7f af a8 10 94 64-8f 2d e4 0d 30 ba c4 14   ?B.....d.-..0...
00c0 - a2 f2 63 3b 0d a5 6f b4-9f 52 81 e0 3b dd ac      ..c;..o..R..;..
SSL_connect:SSLv3/TLS write finished
read from 0x2582ef94830 [0x2582f38be73] (16717 bytes => 107 (0x6B))
0000 - 14 fe fd 00 00 00 00 00-00 00 0c 00 01 01 16 fe   ................
0010 - fd 00 01 00 00 00 00 00-00 00 50 43 7b 0b 20 0b   ..........PC{. .
0020 - 70 d3 a0 5e a6 31 8d af-dc 14 5f ca 16 e2 05 03   p..^.1...._.....
0030 - 40 2a a2 0d 11 74 68 17-a5 60 f0 94 5b b7 a2 30   @*...th..`..[..0
0040 - e0 7e 05 a1 80 ba f8 1d-01 a0 62 ec 7c b4 95 da   .~........b.|...
0050 - c3 99 95 90 59 4c f5 83-e3 cf 53 c8 16 6c 2d 8f   ....YL....S..l-.
0060 - 70 4e 30 15 d9 f7 43 d7-3a 65 94                  pN0...C.:e.
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
    Session-ID: D16EE06D5C2C59D0E0A5ED8248B3EEB7CE9632BF61482CDDA9A3649B78A3BFC9
    Session-ID-ctx:
    Master-Key: 93BE6304758C8B4F0E106DF7BBBB7A4EDC23ED6188D44ED4D567B6E375400A74471FDA4AD6748C84BDA37A19399BD4A4
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 81 91 12 df b7 f9 8c 99-db 44 56 fa 53 74 da 51   .........DV.St.Q
    0010 - bb 30 e2 f5 f2 f0 81 66-13 76 33 40 22 0b 0b f0   .0.....f.v3@"...
    0020 - c5 20 81 2b 62 f9 fa cc-ac aa e8 08 a2 c2 c6 3e   . .+b..........>
    0030 - 70 51 fc 62 e1 cb 88 8e-d2 7c e3 d8 d1 ae f4 3f   pQ.b.....|.....?
    0040 - 01 21 f4 37 a8 22 34 4d-66 7c d6 aa 16 70 28 f1   .!.7."4Mf|...p(.
    0050 - ca 8e 66 71 8a fe 80 22-26 66 33 57 28 6d bd c5   ..fq..."&f3W(m..
    0060 - 04 c1 66 02 d7 ac 0d 38-97 db f3 a3 77 73 4f 10   ..f....8....wsO.
    0070 - 46 ef f1 b9 9a e7 3b 84-fb 35 6a 44 d7 fd 94 7c   F.....;..5jD...|
    0080 - b2 78 1c b3 ff 90 be ad-1b 0b 5d 9e 95 db 51 35   .x........]...Q5
    0090 - e9 3f 42 7f af a8 10 94-64 8f 2d e4 0d 30 ba c4   .?B.....d.-..0..
    00a0 - 14 a2 f2 63 3b 0d a5 6f-b4 9f 52 81 e0 3b dd ac   ...c;..o..R..;..

    Start Time: 1743807635
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: yes
---
hello
write to 0x2582ef94830 [0x2582f39e7c3] (77 bytes => 77 (0x4D))
0000 - 17 fe fd 00 01 00 00 00-00 00 01 00 40 22 6b 6d   ............@"km
0010 - 36 ec 69 1e 1b db 72 89-60 db 4f a2 c8 7c cd fb   6.i...r.`.O..|..
0020 - 7b 52 24 83 e4 92 61 43-ac f2 2c 86 da 36 89 0a   {R$...aC..,..6..
0030 - 68 69 49 7e 64 b5 e7 ad-60 36 19 7e 6f 83 e2 70   hiI~d...`6.~o..p
0040 - 5e 07 9a 10 cd 3f d5 d3-cd 89 1f 94 c9            ^....?.......
Q
DONE
write to 0x2582ef94830 [0x2582f39e7c3] (77 bytes => 77 (0x4D))
0000 - 15 fe fd 00 01 00 00 00-00 00 02 00 40 7c 68 12   ............@|h.
0010 - 83 f5 e2 60 f7 0b 87 c1-46 64 75 3f 16 a3 f7 c3   ...`....Fdu?....
0020 - 22 16 21 41 a5 4b 0a e7-d6 7a e4 d3 d8 52 58 c7   ".!A.K...z...RX.
0030 - 37 80 61 63 1e b3 1f 52-54 c8 06 37 60 22 f0 1b   7.ac...RT..7`"..
0040 - a7 fd 78 98 5e e3 dd d8-7b bd 94 e1 15            ..x.^...{....
SSL3 alert write:warning:close notify
read from 0x2582ef94830 [0x2582eed7cd0] (16384 bytes => 77 (0x4D))
0000 - 15 fe fd 00 01 00 00 00-00 00 01 00 40 1c 80 74   ............@..t
0010 - c8 39 a7 19 3d 4e 1d 31-82 f0 5c f9 ca c3 1d 8b   .9..=N.1..\.....
0020 - 0f 0c 8c 3a 1a be 77 ee-4b e7 96 8d bf fb 32 ed   ...:..w.K.....2.
0030 - 06 d6 56 2d b9 e5 d9 62-23 fc c2 c0 cf 39 aa bd   ..V-...b#....9..
0040 - 3e 38 e8 ab 29 14 61 64-11 28 45 a9 59            >8..).ad.(E.Y
````

[TOC](README.md)
