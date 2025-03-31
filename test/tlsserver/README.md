### TOC

- [test](#test)
- [TLS 1.3](#tls_13)
- [TLS 1.2](#tls_12)

### test

- case1
  - [x] server 1.2/1.3, client 1.3
    - env
      - ./test-tlsserver -v -d -r -tls13 -tls12 &
      - openssl s_client -connect localhost:9000 -state -debug -tls1_3
    - summary : TLSv1.3, TLS_AES_256_GCM_SHA384
    - result  : PASS
  - [x] server 1.2/1.3, client 1.2
    - env
      - ./test-tlsserver -v -d -r -tls13 -tls12 &
      - openssl s_client -connect localhost:9000 -state -debug -tls1_3
    - summary : TLSv1.2, ECDHE-RSA-AES256-GCM-SHA384
    - result  : PASS
- case2
  - [x] server 1.3, client 1.3
    - env
      - ./test-tlsserver -v -d -r -tls13 &
        - it works like ./test-tlsserver -v -d -r
      - openssl s_client -connect localhost:9000 -state -debug -tls1_3
    - summary : TLSv1.3, TLS_AES_256_GCM_SHA384
    - result  : PASS
  - [x] server 1.3, client 1.2 (handshake failure)
    - env
      - ./test-tlsserver -v -d -r -tls13 &
      - openssl s_client -connect localhost:9000 -state -debug -tls1_2
    - summary : cipher NONE
    - result  : PASS (negative test, expected)
- case3
  - [x] server 1.2, client 1.3 (handshake failure)
    - env
      - ./test-tlsserver -v -d -r -tls12 &
      - openssl s_client -connect localhost:9000 -state -debug -tls1_3
    - summary : cipher NONE
    - result  : PASS (negative test, expected)
  - [x] server 1.2, client 1.2
    - env
      - ./test-tlsserver -v -d -r -tls12 &
      - openssl s_client -connect localhost:9000 -state -debug -tls1_2
    - summary : TLSv1.2, ECDHE-RSA-AES256-GCM-SHA384
    - result  : PASS

### TLS 1.3

- TLS 1.3
  - openssl s_server -accept 9000 -cert server.crt -key server.key -cipher TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 -state -debug -status_verbose -tls1_3
  - openssl s_client -connect localhost:9000 -state -debug -tls1_3

````
$ openssl s_server -accept 9000 -cert server.crt -key server.key -cipher TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 -state -debug -status_verbose -tls1_3
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x23749460100 [0x2374b15db13] (5 bytes => 5 (0x5))
0000 - 16 03 01 00 e7                                    .....
read from 0x23749460100 [0x2374b15db18] (231 bytes => 231 (0xE7))
0000 - 01 00 00 e3 03 03 5d 41-10 d4 31 55 11 85 7a cb   ......]A..1U..z.
0010 - 39 9f c4 90 f2 d2 62 63-7b 9f 20 0f f8 63 ef 18   9.....bc{. ..c..
0020 - 74 78 34 83 d8 61 20 ba-b8 21 08 a7 38 2d ac ae   tx4..a ..!..8-..
0030 - 7e e9 69 0e 14 c9 3f 5d-6f c0 9a 05 16 17 48 4f   ~.i...?]o.....HO
0040 - c2 0d 5e ae 2a d5 b3 00-06 13 02 13 03 13 01 01   ..^.*...........
0050 - 00 00 94 00 0b 00 04 03-00 01 02 00 0a 00 16 00   ................
0060 - 14 00 1d 00 17 00 1e 00-19 00 18 01 00 01 01 01   ................
0070 - 02 01 03 01 04 00 23 00-00 00 16 00 00 00 17 00   ......#.........
0080 - 00 00 0d 00 24 00 22 04-03 05 03 06 03 08 07 08   ....$.".........
0090 - 08 08 1a 08 1b 08 1c 08-09 08 0a 08 0b 08 04 08   ................
00a0 - 05 08 06 04 01 05 01 06-01 00 2b 00 03 02 03 04   ..........+.....
00b0 - 00 2d 00 02 01 01 00 33-00 26 00 24 00 1d 00 20   .-.....3.&.$...
00c0 - e5 29 63 18 05 3a 40 4e-2b 62 f1 ad 81 75 7b eb   .)c..:@N+b...u{.
00d0 - d6 f0 42 22 e6 f2 c1 f4-78 e5 7b 97 4d 63 0f 4a   ..B"....x.{.Mc.J
00e0 - 00 1b 00 03 02 00 01                              .......
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write change cipher spec
SSL_accept:TLSv1.3 write encrypted extensions
SSL_accept:SSLv3/TLS write certificate
SSL_accept:TLSv1.3 write server certificate verify
write to 0x23749460100 [0x2374b15cb00] (1420 bytes => 1420 (0x58C))
0000 - 16 03 03 00 7a 02 00 00-76 03 03 14 09 01 06 c1   ....z...v.......
0010 - 9e 00 f7 8e af 2a 77 f1-77 2e 02 9a ed 11 e5 67   .....*w.w......g
0020 - cb d4 c6 f1 05 bf 62 5a-c2 54 38 20 ba b8 21 08   ......bZ.T8 ..!.
0030 - a7 38 2d ac ae 7e e9 69-0e 14 c9 3f 5d 6f c0 9a   .8-..~.i...?]o..
0040 - 05 16 17 48 4f c2 0d 5e-ae 2a d5 b3 13 02 00 00   ...HO..^.*......
0050 - 2e 00 2b 00 02 03 04 00-33 00 24 00 1d 00 20 94   ..+.....3.$... .
0060 - 45 ba b0 50 51 73 4f 59-f7 35 c6 5f 22 3b 84 b7   E..PQsOY.5._";..
0070 - b4 ab c6 d4 82 f3 74 4e-ee 5d 39 22 f3 cc 6b 14   ......tN.]9"..k.
0080 - 03 03 00 01 01 17 03 03-00 17 3f f7 a5 e6 a1 94   ..........?.....
0090 - ba c6 77 16 c1 54 3c 54-3a 98 05 34 3e 5d 0a 8f   ..w..T<T:..4>]..
00a0 - e9 17 03 03 03 7e 22 5f-f2 2d a3 09 9e e2 03 3c   .....~"_.-.....<
00b0 - 38 49 87 b9 34 85 9c 28-8c 23 bd 9e fb 5a b1 5c   8I..4..(.#...Z.\
00c0 - 02 f4 73 27 23 94 de d9-48 9e 3f 82 37 3b e0 35   ..s'#...H.?.7;.5
00d0 - e9 0a 4a 70 eb 2e da a5-ab d6 5a 23 b9 e6 c7 92   ..Jp......Z#....
00e0 - 5e 84 b7 03 52 cb 1f c0-69 6a 80 de 94 8b 24 bd   ^...R...ij....$.
00f0 - 29 01 9b e3 ee f2 bd 1f-71 35 7b ba 62 d4 7d 9e   ).......q5{.b.}.
0100 - 1f b5 3c 3e 82 37 38 72-17 da 46 26 3e b3 1c 66   ..<>.78r..F&>..f
0110 - 80 4c 9e 65 0f 52 22 64-60 42 9f 61 f7 ce 2f d4   .L.e.R"d`B.a../.
0120 - b6 b7 75 c6 8d 38 8e f3-59 ed fa d4 e9 bd 37 f7   ..u..8..Y.....7.
0130 - da ae 7d 6e c8 19 af 14-94 ad f6 9b 61 64 d8 7c   ..}n........ad.|
0140 - 01 70 1a 05 61 89 41 d1-30 b9 3a b8 cd 75 7c 5c   .p..a.A.0.:..u|\
0150 - bc 90 6d c9 f4 8d f1 94-a5 ed aa 23 52 16 87 81   ..m........#R...
0160 - fb 3e f3 71 49 ab 91 03-7d 71 68 4b 3e 83 ba 67   .>.qI...}qhK>..g
0170 - 22 e7 a6 b3 ed 67 84 1b-72 f2 8a 78 7a 58 fb 68   "....g..r..xzX.h
0180 - 15 79 2f 41 44 88 8d 7c-5b 4d 8f 31 73 d0 37 13   .y/AD..|[M.1s.7.
0190 - ff 9e ee 4c 90 8f 15 05-d7 35 ae 85 af 95 bd 63   ...L.....5.....c
01a0 - 9b aa 4a e8 39 0f 21 2a-64 51 4c 9a c5 74 21 98   ..J.9.!*dQL..t!.
01b0 - e5 4c 33 de d5 dd d9 09-fb 40 1b d9 95 11 8d be   .L3......@......
01c0 - 32 b4 bd d7 49 21 3a d8-85 9b a0 dc 43 8b 59 ff   2...I!:.....C.Y.
01d0 - 0f ab 0d 81 06 1e be 8f-57 4b 43 87 bd 99 fb a6   ........WKC.....
01e0 - 80 fe d9 09 db b6 de dd-86 14 78 10 61 ee 6e 8a   ..........x.a.n.
01f0 - 84 53 b5 47 e3 e5 85 58-fa ec 77 d2 65 74 b6 02   .S.G...X..w.et..
0200 - fc ad c2 ff dc dd ba 3d-62 af 82 fc 31 ba 92 e8   .......=b...1...
0210 - c3 66 5a 2c cc 6d 63 77-3d 32 a5 4a b3 82 6d f9   .fZ,.mcw=2.J..m.
0220 - c6 51 fe 07 5b f0 4e c9-5a f1 2d d0 e0 ce 5a 09   .Q..[.N.Z.-...Z.
0230 - 3b 5e 99 4d 3d ac 8d ec-71 d8 80 7c e9 c7 4e bc   ;^.M=...q..|..N.
0240 - 15 d7 27 64 95 75 51 76-4b d3 89 c0 94 20 5a 87   ..'d.uQvK.... Z.
0250 - 4e 71 2a 2b d5 68 8b 12-14 21 88 f5 6d 03 51 39   Nq*+.h...!..m.Q9
0260 - 61 87 e0 05 be f0 73 7e-29 c1 f9 0a e8 94 01 9a   a.....s~).......
0270 - 5e a5 e1 e0 5e 12 45 47-69 dc 65 6c 23 3d ee 01   ^...^.EGi.el#=..
0280 - ee b5 21 89 2b 5f 6a e5-95 62 c8 0b a3 d7 7b 5a   ..!.+_j..b....{Z
0290 - e5 b5 56 25 33 f1 ca 08-d8 de c3 58 eb e7 f3 5a   ..V%3......X...Z
02a0 - 20 18 06 d9 cd b2 18 88-95 88 23 3e af 77 41 5e    .........#>.wA^
02b0 - 5b 6f de 35 b4 16 02 9a-ff 0a bd 73 84 5c 15 c6   [o.5.......s.\..
02c0 - 89 27 0a 7c d3 4e b7 d0-28 db a2 90 16 f5 91 4c   .'.|.N..(......L
02d0 - 7a 59 bc 94 84 c9 07 35-e6 ee 90 ba db 4f 17 6f   zY.....5.....O.o
02e0 - 04 f6 fa 0c 8c b5 d4 bc-14 e3 28 3c 09 53 75 a6   ..........(<.Su.
02f0 - 91 cb 8a f7 ad b8 d3 db-a4 e0 1c a3 44 08 0f e4   ............D...
0300 - ed c8 7e 76 eb c2 b1 a0-dc 9a 5f 19 a8 31 ff a6   ..~v......_..1..
0310 - a7 a7 57 74 8b f1 d8 be-19 22 7e 98 93 55 a3 22   ..Wt....."~..U."
0320 - a4 98 01 7f 90 f6 c6 77-7f 28 ad 82 4a ae 46 0e   .......w.(..J.F.
0330 - 3a 68 27 1f ab 69 94 19-be 09 7d b1 09 d6 1a 30   :h'..i....}....0
0340 - 07 10 d6 f5 7e 39 80 db-32 4c 50 87 72 63 47 83   ....~9..2LP.rcG.
0350 - 38 de 6a 0a 5e 2d c7 b7-ce 9c f8 fe a5 3d f8 d0   8.j.^-.......=..
0360 - 92 3b 83 74 66 5f d5 57-45 58 2f 83 10 84 e1 7a   .;.tf_.WEX/....z
0370 - a9 ed 2c 11 9a 33 40 6f-a8 71 97 1e 4f c7 e9 22   ..,..3@o.q..O.."
0380 - eb a8 91 12 00 89 b9 10-da 3f 3f eb 65 da 41 1e   .........??.e.A.
0390 - 96 8f 5e 97 b3 b8 e7 4e-2e 6b c2 f3 cb 4d f4 ca   ..^....N.k...M..
03a0 - 5b bf 99 26 15 0a c7 67-35 8a 40 04 1c cc c6 e8   [..&...g5.@.....
03b0 - 21 02 5a 7c 2e e7 b2 40-3a f1 5b b7 fe f1 2d 5f   !.Z|...@:.[...-_
03c0 - 3d 3e c2 15 05 55 cb ca-53 ad e3 3e e8 ba b2 40   =>...U..S..>...@
03d0 - 6b 51 c5 a7 5b a9 72 bd-fa ad f7 c4 77 4d b0 8d   kQ..[.r.....wM..
03e0 - d4 fe 98 75 55 eb e0 36-de 88 15 5f 14 aa 1e f6   ...uU..6..._....
03f0 - 69 50 31 2b 05 14 1a 89-bf fd 4a 97 3a 29 8d f4   iP1+......J.:)..
0400 - 43 ad ef 64 9c b7 0a 5a-8a b0 23 f8 da 60 af 03   C..d...Z..#..`..
0410 - 9e 0d 24 8c 77 a9 89 89-a7 10 ea 6c d6 23 6d ba   ..$.w......l.#m.
0420 - 58 42 cb 02 17 03 03 01-19 cf d2 d8 15 23 51 b0   XB...........#Q.
0430 - 2d d9 98 0f 0f 48 d2 8b-16 b1 dd 05 b1 0e d5 79   -....H.........y
0440 - 80 23 17 60 dc 21 e0 b3-b0 0d ab 5c e6 db 3f 71   .#.`.!.....\..?q
0450 - 8c d6 1e 1a a2 db 8a 03-fc a0 78 7a 23 f2 23 8d   ..........xz#.#.
0460 - 63 57 b5 b4 40 25 75 6c-c3 7b 3d 35 57 ae 7e 8f   cW..@%ul.{=5W.~.
0470 - 4c 8a 39 17 95 d0 79 5a-34 d8 a9 f0 2d 7c ac 95   L.9...yZ4...-|..
0480 - fe 60 56 0e 73 ce ac 4d-e7 4a 95 4b cb 46 3c 28   .`V.s..M.J.K.F<(
0490 - c5 52 66 8e 7b 04 bc 83-64 64 ce aa 23 d6 dc 3e   .Rf.{...dd..#..>
04a0 - 40 09 c6 f0 7a dc be 9e-6d 87 15 70 6b 43 4b 0e   @...z...m..pkCK.
04b0 - eb 3b ff 4b 3c d8 be 39-f6 79 1c 7f 88 ca bd f7   .;.K<..9.y......
04c0 - 56 48 a3 c0 99 2f 42 14-be a5 89 ad 2f a0 18 cd   VH.../B...../...
04d0 - 5e 98 56 34 f9 23 22 c7-12 bb 72 c6 0c 53 3f 42   ^.V4.#"...r..S?B
04e0 - 07 b3 61 cc 0d b9 90 3c-7f 5b e6 6a 26 13 ee 16   ..a....<.[.j&...
04f0 - d2 e2 18 72 ad 4c da 35-5c c3 e7 2c 45 bb 3d 93   ...r.L.5\..,E.=.
0500 - a1 de da 76 a1 8f 57 83-f1 f4 9d 6d af b2 e9 58   ...v..W....m...X
0510 - 19 20 3a f2 ea 1b c9 87-e7 64 5e 20 f2 d5 ad 0a   . :......d^ ....
0520 - 15 64 5c 04 6e 86 37 d8-44 01 f6 f3 3a 8c c2 ba   .d\.n.7.D...:...
0530 - fa ff 6e 6c f7 19 59 07-32 29 1a b9 b4 99 4a ba   ..nl..Y.2)....J.
0540 - 8c 59 17 03 03 00 45 52-49 3e 4a 8d 79 75 c0 12   .Y....ERI>J.yu..
0550 - e7 ab 89 97 38 0d 88 18-39 26 31 d2 56 f4 2d d0   ....8...9&1.V.-.
0560 - a0 be db f4 9b de be 43-ce 08 d8 88 ca 21 10 37   .......C.....!.7
0570 - a1 f0 ed 6f 15 89 7c 44-8c 54 65 35 a4 03 30 9d   ...o..|D.Te5..0.
0580 - ee b8 4d 2d 0e 70 25 89-bf ea de 37               ..M-.p%....7
SSL_accept:SSLv3/TLS write finished
SSL_accept:TLSv1.3 early data
read from 0x23749460100 [0x2374b15db13] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x23749460100 [0x2374b15db18] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x23749460100 [0x2374b15db13] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 45                                    ....E
read from 0x23749460100 [0x2374b15db18] (69 bytes => 69 (0x45))
0000 - 2e 1a 56 75 ea 50 97 25-e4 b0 f1 83 49 ad 22 f9   ..Vu.P.%....I.".
0010 - 10 74 97 18 8e e9 c0 9d-e5 c2 db ab cf 74 7f 5b   .t...........t.[
0020 - 28 fe 0c 9e b4 35 51 71-00 a8 44 9c 7a 67 08 02   (....5Qq..D.zg..
0030 - 8e 2b 09 18 c2 57 b5 89-9b 26 c0 44 0a 48 80 44   .+...W...&.D.H.D
0040 - 22 ec c9 b0 bc                                    "....
SSL_accept:TLSv1.3 early data
SSL_accept:SSLv3/TLS read finished
write to 0x23749460100 [0x2374b15cb00] (255 bytes => 255 (0xFF))
0000 - 17 03 03 00 fa f7 0e 28-a9 ab 94 95 33 06 67 3f   .......(....3.g?
0010 - 04 28 37 ee 98 67 38 ea-c9 e7 b8 31 66 cb b5 ae   .(7..g8....1f...
0020 - e4 a7 9d 58 5e 6a 13 63-19 9a 77 c8 b1 22 de 8b   ...X^j.c..w.."..
0030 - d1 9c 17 bf 1f fe 2c 3d-d7 16 84 fa 3f cf a6 92   ......,=....?...
0040 - b5 0c be 3a 3d fa 6e 26-ca 6e 5a b8 77 d5 e5 97   ...:=.n&.nZ.w...
0050 - 4b b5 d2 72 80 d2 00 bd-d5 2b 28 57 db fa 06 bd   K..r.....+(W....
0060 - 00 17 29 97 08 7d f0 74-88 5c 9e f2 16 d2 46 24   ..)..}.t.\....F$
0070 - 08 5c 6b 69 16 8b 4b b3-65 84 a6 c0 29 c2 e0 64   .\ki..K.e...)..d
0080 - ae 77 8f 92 c4 12 5d 05-1c 10 8c 68 78 42 02 c3   .w....]....hxB..
0090 - aa 34 c7 3b f5 19 ee 9b-c4 ba 4d b6 6c 04 5a f7   .4.;......M.l.Z.
00a0 - 58 e2 7e 42 32 ae a4 4e-f6 2c 82 3a d8 29 1f 8d   X.~B2..N.,.:.)..
00b0 - 4e 65 83 8c df fe e6 ad-a4 65 e9 06 44 59 37 b2   Ne.......e..DY7.
00c0 - de 65 0f 09 6b cb 02 e6-fd 9d 24 1c 6d d6 7e ec   .e..k.....$.m.~.
00d0 - b5 47 c1 2b 36 59 c2 8b-72 d4 4b b2 ab 82 a2 32   .G.+6Y..r.K....2
00e0 - 3c c9 80 85 1f ab 43 84-b8 93 90 a3 1d 07 f0 04   <.....C.........
00f0 - 58 96 05 a1 3e 7d 44 75-4d 49 ce 54 81 db cf      X...>}DuMI.T...
SSL_accept:SSLv3/TLS write session ticket
write to 0x23749460100 [0x2374b15cb00] (255 bytes => 255 (0xFF))
0000 - 17 03 03 00 fa b5 18 99-e2 a2 21 b3 16 ad 94 23   ..........!....#
0010 - 4e 70 7b 7b 60 ef 68 82-c7 ff f8 2d 6b 04 34 49   Np{{`.h....-k.4I
0020 - eb 2e a4 b5 4f a0 38 40-95 37 95 42 fe b6 69 ef   ....O.8@.7.B..i.
0030 - 96 e7 06 02 bf 9c cf 25-cc 27 0e bf f4 89 fc 16   .......%.'......
0040 - 5b 96 87 ca c3 c3 2f eb-04 3e 48 f5 76 40 60 75   [...../..>H.v@`u
0050 - c9 02 78 75 05 22 94 f5-e5 44 5b f4 85 a3 9d 4d   ..xu."...D[....M
0060 - ba ac 25 97 4b e5 44 da-be 4b 84 62 48 0c 1c 4b   ..%.K.D..K.bH..K
0070 - aa 7a df 78 61 c2 43 49-a6 a7 42 99 18 7b 0e e7   .z.xa.CI..B..{..
0080 - 81 5d c7 21 c4 87 8a 30-3a 9c 2b fc c2 f2 c5 a5   .].!...0:.+.....
0090 - 29 d0 f5 67 33 17 04 30-21 34 1d fe 1e e7 b8 6b   )..g3..0!4.....k
00a0 - f4 91 e3 7f f9 5b 8e 2b-45 19 50 1e c7 a8 c3 27   .....[.+E.P....'
00b0 - 39 e0 61 42 ea 78 90 43-cd 89 ae 7c 04 6a 35 7b   9.aB.x.C...|.j5{
00c0 - c9 39 f3 8b da 7f fc 67-4f 28 a3 c1 8d e6 4b fc   .9.....gO(....K.
00d0 - 5c 87 c4 ab 14 a7 78 56-98 3f 35 c7 ea a0 0a b5   \.....xV.?5.....
00e0 - 25 81 c3 c9 67 73 f4 e3-50 a5 f9 55 0e 3b e8 78   %...gs..P..U.;.x
00f0 - dc 01 18 c5 9e 09 05 15-b6 2b ed fe 23 eb e4      .........+..#..
SSL_accept:SSLv3/TLS write session ticket
-----BEGIN SSL SESSION PARAMETERS-----
MIGDAgEBAgIDBAQCEwIEIPxwwxMhkYDqtdjNT5Lyh5NOCnFStgRNw6Oz8x09cVdx
BDB4HSrrPenovMSRpNw8wzidI+h5eMyZmNCtxFfI71KlufXdk2L3tP6244earKqQ
Kt6hBgIEZ+oarqIEAgIcIKQGBAQBAAAArgcCBQDBJ+lqswMCAR0=
-----END SSL SESSION PARAMETERS-----
Shared ciphers:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Supported groups: x25519:secp256r1:x448:secp521r1:secp384r1:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192
Shared groups: x25519:secp256r1:x448:secp521r1:secp384r1:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192
CIPHER is TLS_AES_256_GCM_SHA384
This TLS version forbids renegotiation.
read from 0x23749460100 [0x2374b166013] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 18                                    .....
read from 0x23749460100 [0x2374b166018] (24 bytes => 24 (0x18))
0000 - 3f f0 77 53 be bf c8 26-64 7a c9 fb 5b 9c 3d 56   ?.wS...&dz..[.=V
0010 - f0 5e 43 f7 1a 94 bf 60-                          .^C....`
hello
read from 0x23749460100 [0x2374b166013] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 13                                    .....
read from 0x23749460100 [0x2374b166018] (19 bytes => 19 (0x13))
0000 - 8f 5e 08 ef 1b 04 12 fa-61 ae fe 79 f9 8e 88 29   .^......a..y...)
0010 - b1 f0 20                                          ..
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x23749460100 [0x2374b15db13] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 52 e2 57-6d 25 df c1 7a 02 20 7d   .....R.Wm%..z. }
0010 - e6 71 08 6f 54 aa d8 94-                          .q.oT...
SSL3 alert write:warning:close notify
CONNECTION CLOSED

````

````
$ openssl s_client -connect localhost:9000 -state -debug -tls1_3
Connecting to ::1
CONNECTED(000001FC)
SSL_connect:before SSL initialization
write to 0x27911612ee0 [0x27913222e80] (236 bytes => 236 (0xEC))
0000 - 16 03 01 00 e7 01 00 00-e3 03 03 5d 41 10 d4 31   ...........]A..1
0010 - 55 11 85 7a cb 39 9f c4-90 f2 d2 62 63 7b 9f 20   U..z.9.....bc{.
0020 - 0f f8 63 ef 18 74 78 34-83 d8 61 20 ba b8 21 08   ..c..tx4..a ..!.
0030 - a7 38 2d ac ae 7e e9 69-0e 14 c9 3f 5d 6f c0 9a   .8-..~.i...?]o..
0040 - 05 16 17 48 4f c2 0d 5e-ae 2a d5 b3 00 06 13 02   ...HO..^.*......
0050 - 13 03 13 01 01 00 00 94-00 0b 00 04 03 00 01 02   ................
0060 - 00 0a 00 16 00 14 00 1d-00 17 00 1e 00 19 00 18   ................
0070 - 01 00 01 01 01 02 01 03-01 04 00 23 00 00 00 16   ...........#....
0080 - 00 00 00 17 00 00 00 0d-00 24 00 22 04 03 05 03   .........$."....
0090 - 06 03 08 07 08 08 08 1a-08 1b 08 1c 08 09 08 0a   ................
00a0 - 08 0b 08 04 08 05 08 06-04 01 05 01 06 01 00 2b   ...............+
00b0 - 00 03 02 03 04 00 2d 00-02 01 01 00 33 00 26 00   ......-.....3.&.
00c0 - 24 00 1d 00 20 e5 29 63-18 05 3a 40 4e 2b 62 f1   $... .)c..:@N+b.
00d0 - ad 81 75 7b eb d6 f0 42-22 e6 f2 c1 f4 78 e5 7b   ..u{...B"....x.{
00e0 - 97 4d 63 0f 4a 00 1b 00-03 02 00 01               .Mc.J.......
SSL_connect:SSLv3/TLS write client hello
read from 0x27911612ee0 [0x27913227f53] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 7a                                    ....z
read from 0x27911612ee0 [0x27913227f58] (122 bytes => 122 (0x7A))
0000 - 02 00 00 76 03 03 14 09-01 06 c1 9e 00 f7 8e af   ...v............
0010 - 2a 77 f1 77 2e 02 9a ed-11 e5 67 cb d4 c6 f1 05   *w.w......g.....
0020 - bf 62 5a c2 54 38 20 ba-b8 21 08 a7 38 2d ac ae   .bZ.T8 ..!..8-..
0030 - 7e e9 69 0e 14 c9 3f 5d-6f c0 9a 05 16 17 48 4f   ~.i...?]o.....HO
0040 - c2 0d 5e ae 2a d5 b3 13-02 00 00 2e 00 2b 00 02   ..^.*........+..
0050 - 03 04 00 33 00 24 00 1d-00 20 94 45 ba b0 50 51   ...3.$... .E..PQ
0060 - 73 4f 59 f7 35 c6 5f 22-3b 84 b7 b4 ab c6 d4 82   sOY.5._";.......
0070 - f3 74 4e ee 5d 39 22 f3-cc 6b                     .tN.]9"..k
SSL_connect:SSLv3/TLS write client hello
read from 0x27911612ee0 [0x27913227f53] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x27911612ee0 [0x27913227f58] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x27911612ee0 [0x27913227f53] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x27911612ee0 [0x27913227f58] (23 bytes => 23 (0x17))
0000 - 3f f7 a5 e6 a1 94 ba c6-77 16 c1 54 3c 54 3a 98   ?.......w..T<T:.
0010 - 05 34 3e 5d 0a 8f e9                              .4>]...
SSL_connect:SSLv3/TLS read server hello
Can't use SSL_get_servername
read from 0x27911612ee0 [0x27913227f53] (5 bytes => 5 (0x5))
0000 - 17 03 03 03 7e                                    ....~
read from 0x27911612ee0 [0x27913227f58] (894 bytes => 894 (0x37E))
0000 - 22 5f f2 2d a3 09 9e e2-03 3c 38 49 87 b9 34 85   "_.-.....<8I..4.
0010 - 9c 28 8c 23 bd 9e fb 5a-b1 5c 02 f4 73 27 23 94   .(.#...Z.\..s'#.
0020 - de d9 48 9e 3f 82 37 3b-e0 35 e9 0a 4a 70 eb 2e   ..H.?.7;.5..Jp..
0030 - da a5 ab d6 5a 23 b9 e6-c7 92 5e 84 b7 03 52 cb   ....Z#....^...R.
0040 - 1f c0 69 6a 80 de 94 8b-24 bd 29 01 9b e3 ee f2   ..ij....$.).....
0050 - bd 1f 71 35 7b ba 62 d4-7d 9e 1f b5 3c 3e 82 37   ..q5{.b.}...<>.7
0060 - 38 72 17 da 46 26 3e b3-1c 66 80 4c 9e 65 0f 52   8r..F&>..f.L.e.R
0070 - 22 64 60 42 9f 61 f7 ce-2f d4 b6 b7 75 c6 8d 38   "d`B.a../...u..8
0080 - 8e f3 59 ed fa d4 e9 bd-37 f7 da ae 7d 6e c8 19   ..Y.....7...}n..
0090 - af 14 94 ad f6 9b 61 64-d8 7c 01 70 1a 05 61 89   ......ad.|.p..a.
00a0 - 41 d1 30 b9 3a b8 cd 75-7c 5c bc 90 6d c9 f4 8d   A.0.:..u|\..m...
00b0 - f1 94 a5 ed aa 23 52 16-87 81 fb 3e f3 71 49 ab   .....#R....>.qI.
00c0 - 91 03 7d 71 68 4b 3e 83-ba 67 22 e7 a6 b3 ed 67   ..}qhK>..g"....g
00d0 - 84 1b 72 f2 8a 78 7a 58-fb 68 15 79 2f 41 44 88   ..r..xzX.h.y/AD.
00e0 - 8d 7c 5b 4d 8f 31 73 d0-37 13 ff 9e ee 4c 90 8f   .|[M.1s.7....L..
00f0 - 15 05 d7 35 ae 85 af 95-bd 63 9b aa 4a e8 39 0f   ...5.....c..J.9.
0100 - 21 2a 64 51 4c 9a c5 74-21 98 e5 4c 33 de d5 dd   !*dQL..t!..L3...
0110 - d9 09 fb 40 1b d9 95 11-8d be 32 b4 bd d7 49 21   ...@......2...I!
0120 - 3a d8 85 9b a0 dc 43 8b-59 ff 0f ab 0d 81 06 1e   :.....C.Y.......
0130 - be 8f 57 4b 43 87 bd 99-fb a6 80 fe d9 09 db b6   ..WKC...........
0140 - de dd 86 14 78 10 61 ee-6e 8a 84 53 b5 47 e3 e5   ....x.a.n..S.G..
0150 - 85 58 fa ec 77 d2 65 74-b6 02 fc ad c2 ff dc dd   .X..w.et........
0160 - ba 3d 62 af 82 fc 31 ba-92 e8 c3 66 5a 2c cc 6d   .=b...1....fZ,.m
0170 - 63 77 3d 32 a5 4a b3 82-6d f9 c6 51 fe 07 5b f0   cw=2.J..m..Q..[.
0180 - 4e c9 5a f1 2d d0 e0 ce-5a 09 3b 5e 99 4d 3d ac   N.Z.-...Z.;^.M=.
0190 - 8d ec 71 d8 80 7c e9 c7-4e bc 15 d7 27 64 95 75   ..q..|..N...'d.u
01a0 - 51 76 4b d3 89 c0 94 20-5a 87 4e 71 2a 2b d5 68   QvK.... Z.Nq*+.h
01b0 - 8b 12 14 21 88 f5 6d 03-51 39 61 87 e0 05 be f0   ...!..m.Q9a.....
01c0 - 73 7e 29 c1 f9 0a e8 94-01 9a 5e a5 e1 e0 5e 12   s~).......^...^.
01d0 - 45 47 69 dc 65 6c 23 3d-ee 01 ee b5 21 89 2b 5f   EGi.el#=....!.+_
01e0 - 6a e5 95 62 c8 0b a3 d7-7b 5a e5 b5 56 25 33 f1   j..b....{Z..V%3.
01f0 - ca 08 d8 de c3 58 eb e7-f3 5a 20 18 06 d9 cd b2   .....X...Z .....
0200 - 18 88 95 88 23 3e af 77-41 5e 5b 6f de 35 b4 16   ....#>.wA^[o.5..
0210 - 02 9a ff 0a bd 73 84 5c-15 c6 89 27 0a 7c d3 4e   .....s.\...'.|.N
0220 - b7 d0 28 db a2 90 16 f5-91 4c 7a 59 bc 94 84 c9   ..(......LzY....
0230 - 07 35 e6 ee 90 ba db 4f-17 6f 04 f6 fa 0c 8c b5   .5.....O.o......
0240 - d4 bc 14 e3 28 3c 09 53-75 a6 91 cb 8a f7 ad b8   ....(<.Su.......
0250 - d3 db a4 e0 1c a3 44 08-0f e4 ed c8 7e 76 eb c2   ......D.....~v..
0260 - b1 a0 dc 9a 5f 19 a8 31-ff a6 a7 a7 57 74 8b f1   ...._..1....Wt..
0270 - d8 be 19 22 7e 98 93 55-a3 22 a4 98 01 7f 90 f6   ..."~..U."......
0280 - c6 77 7f 28 ad 82 4a ae-46 0e 3a 68 27 1f ab 69   .w.(..J.F.:h'..i
0290 - 94 19 be 09 7d b1 09 d6-1a 30 07 10 d6 f5 7e 39   ....}....0....~9
02a0 - 80 db 32 4c 50 87 72 63-47 83 38 de 6a 0a 5e 2d   ..2LP.rcG.8.j.^-
02b0 - c7 b7 ce 9c f8 fe a5 3d-f8 d0 92 3b 83 74 66 5f   .......=...;.tf_
02c0 - d5 57 45 58 2f 83 10 84-e1 7a a9 ed 2c 11 9a 33   .WEX/....z..,..3
02d0 - 40 6f a8 71 97 1e 4f c7-e9 22 eb a8 91 12 00 89   @o.q..O.."......
02e0 - b9 10 da 3f 3f eb 65 da-41 1e 96 8f 5e 97 b3 b8   ...??.e.A...^...
02f0 - e7 4e 2e 6b c2 f3 cb 4d-f4 ca 5b bf 99 26 15 0a   .N.k...M..[..&..
0300 - c7 67 35 8a 40 04 1c cc-c6 e8 21 02 5a 7c 2e e7   .g5.@.....!.Z|..
0310 - b2 40 3a f1 5b b7 fe f1-2d 5f 3d 3e c2 15 05 55   .@:.[...-_=>...U
0320 - cb ca 53 ad e3 3e e8 ba-b2 40 6b 51 c5 a7 5b a9   ..S..>...@kQ..[.
0330 - 72 bd fa ad f7 c4 77 4d-b0 8d d4 fe 98 75 55 eb   r.....wM.....uU.
0340 - e0 36 de 88 15 5f 14 aa-1e f6 69 50 31 2b 05 14   .6..._....iP1+..
0350 - 1a 89 bf fd 4a 97 3a 29-8d f4 43 ad ef 64 9c b7   ....J.:)..C..d..
0360 - 0a 5a 8a b0 23 f8 da 60-af 03 9e 0d 24 8c 77 a9   .Z..#..`....$.w.
0370 - 89 89 a7 10 ea 6c d6 23-6d ba 58 42 cb 02         .....l.#m.XB..
SSL_connect:TLSv1.3 read encrypted extensions
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify return:1
read from 0x27911612ee0 [0x27913227f53] (5 bytes => 5 (0x5))
0000 - 17 03 03 01 19                                    .....
read from 0x27911612ee0 [0x27913227f58] (281 bytes => 281 (0x119))
0000 - cf d2 d8 15 23 51 b0 2d-d9 98 0f 0f 48 d2 8b 16   ....#Q.-....H...
0010 - b1 dd 05 b1 0e d5 79 80-23 17 60 dc 21 e0 b3 b0   ......y.#.`.!...
0020 - 0d ab 5c e6 db 3f 71 8c-d6 1e 1a a2 db 8a 03 fc   ..\..?q.........
0030 - a0 78 7a 23 f2 23 8d 63-57 b5 b4 40 25 75 6c c3   .xz#.#.cW..@%ul.
0040 - 7b 3d 35 57 ae 7e 8f 4c-8a 39 17 95 d0 79 5a 34   {=5W.~.L.9...yZ4
0050 - d8 a9 f0 2d 7c ac 95 fe-60 56 0e 73 ce ac 4d e7   ...-|...`V.s..M.
0060 - 4a 95 4b cb 46 3c 28 c5-52 66 8e 7b 04 bc 83 64   J.K.F<(.Rf.{...d
0070 - 64 ce aa 23 d6 dc 3e 40-09 c6 f0 7a dc be 9e 6d   d..#..>@...z...m
0080 - 87 15 70 6b 43 4b 0e eb-3b ff 4b 3c d8 be 39 f6   ..pkCK..;.K<..9.
0090 - 79 1c 7f 88 ca bd f7 56-48 a3 c0 99 2f 42 14 be   y......VH.../B..
00a0 - a5 89 ad 2f a0 18 cd 5e-98 56 34 f9 23 22 c7 12   .../...^.V4.#"..
00b0 - bb 72 c6 0c 53 3f 42 07-b3 61 cc 0d b9 90 3c 7f   .r..S?B..a....<.
00c0 - 5b e6 6a 26 13 ee 16 d2-e2 18 72 ad 4c da 35 5c   [.j&......r.L.5\
00d0 - c3 e7 2c 45 bb 3d 93 a1-de da 76 a1 8f 57 83 f1   ..,E.=....v..W..
00e0 - f4 9d 6d af b2 e9 58 19-20 3a f2 ea 1b c9 87 e7   ..m...X. :......
00f0 - 64 5e 20 f2 d5 ad 0a 15-64 5c 04 6e 86 37 d8 44   d^ .....d\.n.7.D
0100 - 01 f6 f3 3a 8c c2 ba fa-ff 6e 6c f7 19 59 07 32   ...:.....nl..Y.2
0110 - 29 1a b9 b4 99 4a ba 8c-59                        )....J..Y
SSL_connect:SSLv3/TLS read server certificate
read from 0x27911612ee0 [0x27913227f53] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 45                                    ....E
read from 0x27911612ee0 [0x27913227f58] (69 bytes => 69 (0x45))
0000 - 52 49 3e 4a 8d 79 75 c0-12 e7 ab 89 97 38 0d 88   RI>J.yu......8..
0010 - 18 39 26 31 d2 56 f4 2d-d0 a0 be db f4 9b de be   .9&1.V.-........
0020 - 43 ce 08 d8 88 ca 21 10-37 a1 f0 ed 6f 15 89 7c   C.....!.7...o..|
0030 - 44 8c 54 65 35 a4 03 30-9d ee b8 4d 2d 0e 70 25   D.Te5..0...M-.p%
0040 - 89 bf ea de 37                                    ....7
SSL_connect:TLSv1.3 read server certificate verify
SSL_connect:SSLv3/TLS read finished
SSL_connect:SSLv3/TLS write change cipher spec
write to 0x27911612ee0 [0x27913222e80] (80 bytes => 80 (0x50))
0000 - 14 03 03 00 01 01 17 03-03 00 45 2e 1a 56 75 ea   ..........E..Vu.
0010 - 50 97 25 e4 b0 f1 83 49-ad 22 f9 10 74 97 18 8e   P.%....I."..t...
0020 - e9 c0 9d e5 c2 db ab cf-74 7f 5b 28 fe 0c 9e b4   ........t.[(....
0030 - 35 51 71 00 a8 44 9c 7a-67 08 02 8e 2b 09 18 c2   5Qq..D.zg...+...
0040 - 57 b5 89 9b 26 c0 44 0a-48 80 44 22 ec c9 b0 bc   W...&.D.H.D"....
SSL_connect:SSLv3/TLS write finished
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
SSL handshake has read 1420 bytes and written 316 bytes
Verification error: unable to verify the first certificate
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
Server public key is 2048 bit
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 21 (unable to verify the first certificate)
---
read from 0x27911612ee0 [0x2791321c7c3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 fa                                    .....
read from 0x27911612ee0 [0x2791321c7c8] (250 bytes => 250 (0xFA))
0000 - f7 0e 28 a9 ab 94 95 33-06 67 3f 04 28 37 ee 98   ..(....3.g?.(7..
0010 - 67 38 ea c9 e7 b8 31 66-cb b5 ae e4 a7 9d 58 5e   g8....1f......X^
0020 - 6a 13 63 19 9a 77 c8 b1-22 de 8b d1 9c 17 bf 1f   j.c..w..".......
0030 - fe 2c 3d d7 16 84 fa 3f-cf a6 92 b5 0c be 3a 3d   .,=....?......:=
0040 - fa 6e 26 ca 6e 5a b8 77-d5 e5 97 4b b5 d2 72 80   .n&.nZ.w...K..r.
0050 - d2 00 bd d5 2b 28 57 db-fa 06 bd 00 17 29 97 08   ....+(W......)..
0060 - 7d f0 74 88 5c 9e f2 16-d2 46 24 08 5c 6b 69 16   }.t.\....F$.\ki.
0070 - 8b 4b b3 65 84 a6 c0 29-c2 e0 64 ae 77 8f 92 c4   .K.e...)..d.w...
0080 - 12 5d 05 1c 10 8c 68 78-42 02 c3 aa 34 c7 3b f5   .]....hxB...4.;.
0090 - 19 ee 9b c4 ba 4d b6 6c-04 5a f7 58 e2 7e 42 32   .....M.l.Z.X.~B2
00a0 - ae a4 4e f6 2c 82 3a d8-29 1f 8d 4e 65 83 8c df   ..N.,.:.)..Ne...
00b0 - fe e6 ad a4 65 e9 06 44-59 37 b2 de 65 0f 09 6b   ....e..DY7..e..k
00c0 - cb 02 e6 fd 9d 24 1c 6d-d6 7e ec b5 47 c1 2b 36   .....$.m.~..G.+6
00d0 - 59 c2 8b 72 d4 4b b2 ab-82 a2 32 3c c9 80 85 1f   Y..r.K....2<....
00e0 - ab 43 84 b8 93 90 a3 1d-07 f0 04 58 96 05 a1 3e   .C.........X...>
00f0 - 7d 44 75 4d 49 ce 54 81-db cf                     }DuMI.T...
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 211C7600B1D65DDBB0968D8A9C387EEC86E36708504A5945B2D15FFB15085E87
    Session-ID-ctx:
    Resumption PSK: BCB050BB47C4F3C3B2A562E3500F00BAB497ACC9DD1D9B4C3B8CAD9750443BC6233EE9DC77AB3F7EC84C9E28F0263CC6
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 8b 2e f0 fc 92 e6 a8 d7-9e 30 ff 0e 3e a5 0d b0   .........0..>...
    0010 - bf 8f d1 1f e8 26 5a a1-22 e6 f7 18 1c f5 dc 36   .....&Z."......6
    0020 - 5f 2f 6f 06 8b 3d ae 49-33 ed 76 55 ca 88 ad d3   _/o..=.I3.vU....
    0030 - b6 a0 a5 52 bd 83 25 de-1d a4 b1 9b a6 f3 be 23   ...R..%........#
    0040 - 24 a2 6a 02 8e bf 36 eb-9e 04 0e 82 fc 3b aa bb   $.j...6......;..
    0050 - 26 1c bd 6f 89 35 5c 1e-34 7b fc b3 60 4f 0e 00   &..o.5\.4{..`O..
    0060 - 60 b7 95 b6 cb 2f 74 1b-fd 49 af b4 7c 15 79 4f   `..../t..I..|.yO
    0070 - cc 4a a3 32 de c4 8a ee-da e4 c7 90 7a f7 85 3f   .J.2........z..?
    0080 - c4 de df 90 82 e2 80 68-c3 e0 99 e7 2e 8e 4e 57   .......h......NW
    0090 - 67 9b 4c ff 6a 59 90 35-58 82 1e 6c 85 f5 68 31   g.L.jY.5X..l..h1
    00a0 - da 59 85 9b 09 88 af 96-e4 3f 50 47 a9 a6 17 af   .Y.......?PG....
    00b0 - ab bd 1f 34 f4 9d ba d3-82 04 06 2c df 46 e5 a8   ...4.......,.F..
    00c0 - a5 8e 39 10 7c 43 34 53-a8 51 b8 00 85 f3 3e 79   ..9.|C4S.Q....>y

    Start Time: 1743395502
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
read from 0x27911612ee0 [0x2791321c7c3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 fa                                    .....
read from 0x27911612ee0 [0x2791321c7c8] (250 bytes => 250 (0xFA))
0000 - b5 18 99 e2 a2 21 b3 16-ad 94 23 4e 70 7b 7b 60   .....!....#Np{{`
0010 - ef 68 82 c7 ff f8 2d 6b-04 34 49 eb 2e a4 b5 4f   .h....-k.4I....O
0020 - a0 38 40 95 37 95 42 fe-b6 69 ef 96 e7 06 02 bf   .8@.7.B..i......
0030 - 9c cf 25 cc 27 0e bf f4-89 fc 16 5b 96 87 ca c3   ..%.'......[....
0040 - c3 2f eb 04 3e 48 f5 76-40 60 75 c9 02 78 75 05   ./..>H.v@`u..xu.
0050 - 22 94 f5 e5 44 5b f4 85-a3 9d 4d ba ac 25 97 4b   "...D[....M..%.K
0060 - e5 44 da be 4b 84 62 48-0c 1c 4b aa 7a df 78 61   .D..K.bH..K.z.xa
0070 - c2 43 49 a6 a7 42 99 18-7b 0e e7 81 5d c7 21 c4   .CI..B..{...].!.
0080 - 87 8a 30 3a 9c 2b fc c2-f2 c5 a5 29 d0 f5 67 33   ..0:.+.....)..g3
0090 - 17 04 30 21 34 1d fe 1e-e7 b8 6b f4 91 e3 7f f9   ..0!4.....k.....
00a0 - 5b 8e 2b 45 19 50 1e c7-a8 c3 27 39 e0 61 42 ea   [.+E.P....'9.aB.
00b0 - 78 90 43 cd 89 ae 7c 04-6a 35 7b c9 39 f3 8b da   x.C...|.j5{.9...
00c0 - 7f fc 67 4f 28 a3 c1 8d-e6 4b fc 5c 87 c4 ab 14   ..gO(....K.\....
00d0 - a7 78 56 98 3f 35 c7 ea-a0 0a b5 25 81 c3 c9 67   .xV.?5.....%...g
00e0 - 73 f4 e3 50 a5 f9 55 0e-3b e8 78 dc 01 18 c5 9e   s..P..U.;.x.....
00f0 - 09 05 15 b6 2b ed fe 23-eb e4                     ....+..#..
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 2DA47A58FB545D0EC1B314E4D3BA14E29339C7D6B92BAF1CE3E98B62A9E21BC3
    Session-ID-ctx:
    Resumption PSK: 781D2AEB3DE9E8BCC491A4DC3CC3389D23E87978CC9998D0ADC457C8EF52A5B9F5DD9362F7B4FEB6E3879AACAA902ADE
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 8b 2e f0 fc 92 e6 a8 d7-9e 30 ff 0e 3e a5 0d b0   .........0..>...
    0010 - 5c 3a cf 6e 56 83 a6 ff-0c 18 f7 e4 ad 6b 29 05   \:.nV........k).
    0020 - c3 d3 12 3f e9 07 5e a7-f0 c4 bd 7a b3 e9 b7 80   ...?..^....z....
    0030 - eb 42 15 7e 2c 62 8c ac-d0 d9 e0 d7 15 66 ed e5   .B.~,b.......f..
    0040 - 60 73 08 11 99 f9 17 0e-7b 21 96 20 c2 79 9b dd   `s......{!. .y..
    0050 - 37 70 b6 9b 8e ee d0 38-f5 46 ac ec e3 b2 23 4b   7p.....8.F....#K
    0060 - ea 99 02 52 48 1d 79 44-40 58 1c aa c3 23 c6 ab   ...RH.yD@X...#..
    0070 - 16 36 ea af 9c 30 41 78-48 8c cf c3 40 a8 5b 11   .6...0AxH...@.[.
    0080 - dc 08 b0 c5 d9 c7 ef 32-76 e5 ab 3c a5 6b 46 7e   .......2v..<.kF~
    0090 - 3a f4 3f db 2b 68 8e 40-f4 a6 ef 4f 80 56 44 39   :.?.+h.@...O.VD9
    00a0 - 01 65 62 b7 d7 78 80 08-1e 13 8f 10 7a 1a b8 c5   .eb..x......z...
    00b0 - 7f 61 1c cf f0 f4 b9 c5-89 50 31 57 af ca 77 be   .a.......P1W..w.
    00c0 - 70 a4 f5 b7 6c ee b5 70-c8 84 c1 37 09 ca b3 d6   p...l..p...7....

    Start Time: 1743395502
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
hello
write to 0x27911612ee0 [0x27913220913] (29 bytes => 29 (0x1D))
0000 - 17 03 03 00 18 3f f0 77-53 be bf c8 26 64 7a c9   .....?.wS...&dz.
0010 - fb 5b 9c 3d 56 f0 5e 43-f7 1a 94 bf 60            .[.=V.^C....`
Q
DONE
write to 0x27911612ee0 [0x27913220913] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 8f 5e 08-ef 1b 04 12 fa 61 ae fe   ......^......a..
0010 - 79 f9 8e 88 29 b1 f0 20-                          y...)..
SSL3 alert write:warning:close notify
read from 0x27911612ee0 [0x27911557c60] (16384 bytes => 24 (0x18))
0000 - 17 03 03 00 13 52 e2 57-6d 25 df c1 7a 02 20 7d   .....R.Wm%..z. }
0010 - e6 71 08 6f 54 aa d8 94-                          .q.oT...
read from 0x27911612ee0 [0x27911557c60] (16384 bytes => 0)

````

### TLS 1.2

- TLS 1.2
  - openssl s_server -accept 9000 -cert server.crt -key server.key -cipher TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 -state -debug -status_verbose -no_tls1_3
  - openssl s_client -connect localhost:9000 -state -debug -tls1_2

````
$ openssl s_server -accept 9000 -cert server.crt -key server.key -cipher TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 -state -debug -status_verbose -no_tls1_3
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x2042710f960 [0x20427521643] (5 bytes => 5 (0x5))
0000 - 16 03 01 00 c0                                    .....
read from 0x2042710f960 [0x20427521648] (192 bytes => 192 (0xC0))
0000 - 01 00 00 bc 03 03 f6 0c-97 e9 78 c1 61 b1 d6 c8   ..........x.a...
0010 - dd 0e f3 89 23 78 72 cd-7c c0 a1 df 53 3d a5 22   ....#xr.|...S=."
0020 - 00 19 42 d4 af 73 00 00-36 c0 2c c0 30 00 9f cc   ..B..s..6.,.0...
0030 - a9 cc a8 cc aa c0 2b c0-2f 00 9e c0 24 c0 28 00   ......+./...$.(.
0040 - 6b c0 23 c0 27 00 67 c0-0a c0 14 00 39 c0 09 c0   k.#.'.g.....9...
0050 - 13 00 33 00 9d 00 9c 00-3d 00 3c 00 35 00 2f 01   ..3.....=.<.5./.
0060 - 00 00 5d ff 01 00 01 00-00 0b 00 04 03 00 01 02   ..].............
0070 - 00 0a 00 0c 00 0a 00 1d-00 17 00 1e 00 19 00 18   ................
0080 - 00 23 00 00 00 16 00 00-00 17 00 00 00 0d 00 30   .#.............0
0090 - 00 2e 04 03 05 03 06 03-08 07 08 08 08 1a 08 1b   ................
00a0 - 08 1c 08 09 08 0a 08 0b-08 04 08 05 08 06 04 01   ................
00b0 - 05 01 06 01 03 03 03 01-03 02 04 02 05 02 06 02   ................
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write certificate
SSL_accept:SSLv3/TLS write key exchange
write to 0x2042710f960 [0x2042750dfa0] (1267 bytes => 1267 (0x4F3))
0000 - 16 03 03 00 45 02 00 00-41 03 03 af 57 4b 63 16   ....E...A...WKc.
0010 - bd 63 e3 c8 b7 c7 12 34-63 83 a1 a9 57 90 4d 97   .c.....4c...W.M.
0020 - 74 00 e1 fa 23 fd f9 55-02 ff 02 00 c0 27 00 00   t...#..U.....'..
0030 - 19 ff 01 00 01 00 00 0b-00 04 03 00 01 02 00 23   ...............#
0040 - 00 00 00 16 00 00 00 17-00 00 16 03 03 03 6a 0b   ..............j.
0050 - 00 03 66 00 03 63 00 03-60 30 82 03 5c 30 82 02   ..f..c..`0..\0..
0060 - 44 a0 03 02 01 02 02 14-63 a6 71 10 79 d6 a6 48   D.......c.q.y..H
0070 - 59 da 67 a9 04 e8 e3 5f-e2 03 a3 26 30 0d 06 09   Y.g...._...&0...
0080 - 2a 86 48 86 f7 0d 01 01-0b 05 00 30 59 31 0b 30   *.H........0Y1.0
0090 - 09 06 03 55 04 06 13 02-4b 52 31 0b 30 09 06 03   ...U....KR1.0...
00a0 - 55 04 08 0c 02 47 47 31-0b 30 09 06 03 55 04 07   U....GG1.0...U..
00b0 - 0c 02 59 49 31 0d 30 0b-06 03 55 04 0a 0c 04 54   ..YI1.0...U....T
00c0 - 65 73 74 31 0d 30 0b 06-03 55 04 0b 0c 04 54 65   est1.0...U....Te
00d0 - 73 74 31 12 30 10 06 03-55 04 03 0c 09 54 65 73   st1.0...U....Tes
00e0 - 74 20 52 6f 6f 74 30 1e-17 0d 32 34 30 38 32 39   t Root0...240829
00f0 - 30 36 32 37 31 37 5a 17-0d 32 35 30 38 32 39 30   062717Z..2508290
0100 - 36 32 37 31 37 5a 30 54-31 0b 30 09 06 03 55 04   62717Z0T1.0...U.
0110 - 06 13 02 4b 52 31 0b 30-09 06 03 55 04 08 0c 02   ...KR1.0...U....
0120 - 47 47 31 0b 30 09 06 03-55 04 07 0c 02 59 49 31   GG1.0...U....YI1
0130 - 0d 30 0b 06 03 55 04 0a-0c 04 54 65 73 74 31 0d   .0...U....Test1.
0140 - 30 0b 06 03 55 04 0b 0c-04 54 65 73 74 31 0d 30   0...U....Test1.0
0150 - 0b 06 03 55 04 03 0c 04-54 65 73 74 30 82 01 22   ...U....Test0.."
0160 - 30 0d 06 09 2a 86 48 86-f7 0d 01 01 01 05 00 03   0...*.H.........
0170 - 82 01 0f 00 30 82 01 0a-02 82 01 01 00 ad 9a 29   ....0..........)
0180 - 67 5f f3 a4 79 b4 c6 e6-32 73 d8 d7 ed 88 94 15   g_..y...2s......
0190 - 83 e4 31 00 04 6c b5 8c-ac 87 ab 74 44 13 76 ca   ..1..l.....tD.v.
01a0 - 0b 74 29 40 9e 97 2a 01-d7 8b 46 26 6e 19 35 4d   .t)@..*...F&n.5M
01b0 - c0 d3 b5 ea 0e 93 3a 06-e8 e5 85 b5 27 05 63 db   ......:.....'.c.
01c0 - 28 b8 92 da 5a 14 39 0f-da 68 6d 6f 0a fb 52 dc   (...Z.9..hmo..R.
01d0 - 08 0f 54 d3 e4 a2 28 9d-a0 71 50 82 e0 db ca d1   ..T...(..qP.....
01e0 - 94 dd 42 98 3a 09 33 a8-d9 ef fb d2 35 43 b1 22   ..B.:.3.....5C."
01f0 - a2 be 41 6d ba 91 dc 0b-31 4e 88 f9 4d 9c 61 2d   ..Am....1N..M.a-
0200 - ec b2 13 0a c2 91 8e a2-d6 e9 40 b9 32 b9 80 8f   ..........@.2...
0210 - b3 18 a3 33 13 23 d5 d0-7e d9 d0 7f 93 e0 2d 4d   ...3.#..~.....-M
0220 - 90 c5 58 24 56 d5 c9 10-13 4a b2 99 23 7d 34 b9   ..X$V....J..#}4.
0230 - 8e 97 19 69 6f ce c6 3f-d6 17 a7 d2 43 e0 36 cb   ...io..?....C.6.
0240 - 51 7b 2f 18 8b c2 33 f8-57 cf d1 61 0b 7c ed 37   Q{/...3.W..a.|.7
0250 - 35 e3 13 7a 24 2e 77 08-c2 e3 d9 e6 17 d3 a5 c6   5..z$.w.........
0260 - 34 5a da 86 a7 f8 02 36-1d 66 63 cf e9 c0 3d 82   4Z.....6.fc...=.
0270 - fb 39 a2 8d 92 01 4a 83-cf e2 76 3d 87 02 03 01   .9....J...v=....
0280 - 00 01 a3 21 30 1f 30 1d-06 03 55 1d 11 04 16 30   ...!0.0...U....0
0290 - 14 82 12 74 65 73 74 2e-70 72 69 6e 63 65 62 36   ...test.princeb6
02a0 - 31 32 2e 70 65 30 0d 06-09 2a 86 48 86 f7 0d 01   12.pe0...*.H....
02b0 - 01 0b 05 00 03 82 01 01-00 00 a5 f5 54 18 ab ad   ............T...
02c0 - 36 38 c8 fc 0b 66 60 dd-9f 75 9d 86 5b 79 2f ee   68...f`..u..[y/.
02d0 - 57 f1 79 1c 15 a1 34 23-d0 1c a9 58 51 a4 d0 08   W.y...4#...XQ...
02e0 - f5 d8 f7 49 e9 c5 b5 65-91 51 2d 6d e4 3b 0e 77   ...I...e.Q-m.;.w
02f0 - 02 1f 45 8e 34 e5 bb eb-f6 9d df 4a 40 60 21 b3   ..E.4......J@`!.
0300 - 8e 16 33 3f f4 b6 90 d3-3c 34 ce e6 d9 47 07 a7   ..3?....<4...G..
0310 - 57 14 0c f9 78 0b 36 72-a9 88 07 07 93 b4 d7 fe   W...x.6r........
0320 - 29 5e e8 41 37 20 a5 03-c7 97 cb 82 ca db 14 e5   )^.A7 ..........
0330 - 8b 96 1f a9 e9 20 3d 6b-25 ae f4 89 4c 60 8d e9   ..... =k%...L`..
0340 - 14 33 47 4b 88 54 a2 47-19 81 c8 7b 0e 32 52 2b   .3GK.T.G...{.2R+
0350 - 91 88 ad 0f 6d 73 30 8c-00 af d5 fc 46 46 af 3a   ....ms0.....FF.:
0360 - c2 17 89 ec c8 83 ae da-e6 69 63 e0 9c 84 22 c5   .........ic...".
0370 - 7a de e8 23 6b 53 9d 6f-94 d2 7f 5c be 1d 0c de   z..#kS.o...\....
0380 - 0e 07 0d 52 a5 43 8c e8-05 ef c0 ff f0 73 fa dc   ...R.C.......s..
0390 - 5a 51 4c 24 09 65 45 7d-ab 52 8b 7e 5d f0 fb de   ZQL$.eE}.R.~]...
03a0 - a7 3d 43 c5 af 76 e3 6e-f9 a1 dc 78 a2 bd 54 41   .=C..v.n...x..TA
03b0 - 04 99 e5 56 32 ba 02 fd-72 16 03 03 01 2c 0c 00   ...V2...r....,..
03c0 - 01 28 03 00 1d 20 9e e0-04 f5 6d de 7a 77 7c cc   .(... ....m.zw|.
03d0 - 21 a1 b2 04 0b eb 3f 4d-7e 52 8d 53 ba 8b 9b 75   !.....?M~R.S...u
03e0 - fc 8a 26 37 0f 0a 08 04-01 00 74 71 22 08 2b ef   ..&7......tq".+.
03f0 - 7a 0f ba e6 1a af 27 99-e5 8c 10 a1 24 15 44 c1   z.....'.....$.D.
0400 - 20 8e c6 f4 67 f7 32 cc-78 b6 c6 ec e2 7e 83 d6    ...g.2.x....~..
0410 - 82 3f d6 99 23 05 e2 69-0c 6f 1f 9d ef 1e 49 7b   .?..#..i.o....I{
0420 - 03 1b 77 ce 83 26 fe e5-13 ec a1 3e bf e1 7d 7a   ..w..&.....>..}z
0430 - b3 03 35 00 d2 1a 4b 48-9b 63 8a b9 94 b1 4e c3   ..5...KH.c....N.
0440 - 13 12 3b e2 2f e4 f8 65-ee 0c 58 8c b1 a9 f7 a8   ..;./..e..X.....
0450 - 6f 2e c7 8f db 65 e8 69-62 87 14 ba 7d cc 99 7e   o....e.ib...}..~
0460 - 4a e5 eb 31 a6 de b8 c3-23 51 b4 88 16 57 04 8b   J..1....#Q...W..
0470 - 09 5f e1 37 26 f2 ab b9-c7 19 b8 7f 73 21 1a ba   ._.7&.......s!..
0480 - fa 3c ab 4e 7c 10 13 42-88 dd f8 92 f3 e0 8e ab   .<.N|..B........
0490 - 8b 6b 95 dd af 7c d0 87-7e 75 24 fe 60 60 2a 13   .k...|..~u$.``*.
04a0 - 6e 34 f7 ba e9 39 d2 72-97 3b 5b 9f 58 f7 34 01   n4...9.r.;[.X.4.
04b0 - 62 e5 58 4e e0 bf 39 07-c2 77 d0 0f 5f ce 9d 91   b.XN..9..w.._...
04c0 - ac 65 14 51 56 01 1e d1-42 b9 d7 8a a4 6f 3a 10   .e.QV...B....o:.
04d0 - e7 4f 47 5e 11 d8 03 2d-71 26 0b d8 09 96 d0 f1   .OG^...-q&......
04e0 - 68 55 2a 44 9d 71 be 9a-d9 00 16 03 03 00 04 0e   hU*D.q..........
04f0 - 00 00 00                                          ...
SSL_accept:SSLv3/TLS write server done
read from 0x2042710f960 [0x20427521643] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 25                                    ....%
read from 0x2042710f960 [0x20427521648] (37 bytes => 37 (0x25))
0000 - 10 00 00 21 20 d6 d1 b3-30 65 1b 96 1d 6d e3 8b   ...! ...0e...m..
0010 - 20 12 07 e6 3d 5e 11 59-04 d4 88 e2 eb 53 4e 3c    ...=^.Y.....SN<
0020 - 48 04 d6 4a 5d                                    H..J]
SSL_accept:SSLv3/TLS write server done
read from 0x2042710f960 [0x20427521643] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x2042710f960 [0x20427521648] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_accept:SSLv3/TLS read client key exchange
read from 0x2042710f960 [0x20427521643] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 50                                    ....P
read from 0x2042710f960 [0x20427521648] (80 bytes => 80 (0x50))
0000 - f1 ec 59 47 5f 50 f1 14-c7 b6 60 e1 e1 b8 06 8f   ..YG_P....`.....
0010 - d0 32 60 e7 e8 58 94 8b-fb 63 bb 8e e2 f5 a8 47   .2`..X...c.....G
0020 - 5b 4e b7 e5 7d 9b ab ef-da 34 9a 08 39 aa 82 24   [N..}....4..9..$
0030 - 79 70 89 68 33 0e ae 64-1c 92 ed ff d1 73 58 32   yp.h3..d.....sX2
0040 - 99 b2 26 2c a2 b0 36 bc-ef 84 9e 1b 75 77 4e e3   ..&,..6.....uwN.
SSL_accept:SSLv3/TLS read change cipher spec
SSL_accept:SSLv3/TLS read finished
SSL_accept:SSLv3/TLS write session ticket
SSL_accept:SSLv3/TLS write change cipher spec
write to 0x2042710f960 [0x2042750dfa0] (282 bytes => 282 (0x11A))
0000 - 16 03 03 00 ba 04 00 00-b6 00 00 1c 20 00 b0 81   ............ ...
0010 - 6c 9f 53 2f 36 b1 ef 97-3d 5d 30 00 a1 63 ce 69   l.S/6...=]0..c.i
0020 - 1a 7b 8a d8 e6 1d 20 d4-1b b3 e3 f6 0d 00 02 55   .{.... ........U
0030 - 7c ef 32 a2 1e 54 62 5a-cb 46 96 3f 11 ee fb 88   |.2..TbZ.F.?....
0040 - ce ba 97 ed 39 84 cb c7-78 92 35 a8 2c 1a b8 f4   ....9...x.5.,...
0050 - d7 9a 84 3b 39 2d d7 a4-41 78 69 db be 7e 0b 51   ...;9-..Axi..~.Q
0060 - 84 84 85 86 0a 23 e7 ab-2d 27 85 9a da f9 ff 13   .....#..-'......
0070 - 7b 6f e6 52 ab 55 8e 78-6d ef 6e e6 c4 1f 72 4b   {o.R.U.xm.n...rK
0080 - 4a f4 d3 2f 46 98 c6 bd-5b f1 e7 99 7c 57 44 31   J../F...[...|WD1
0090 - f1 96 81 32 b6 07 c3 8a-52 b9 eb f1 ad e9 3e 2b   ...2....R.....>+
00a0 - 0b 77 57 43 ca 18 28 16-36 ad 0d 3a be fb 7c de   .wWC..(.6..:..|.
00b0 - 5c a3 cf 26 cf d5 27 d8-4f 79 66 86 70 a4 4e 14   \..&..'.Oyf.p.N.
00c0 - 03 03 00 01 01 16 03 03-00 50 f9 5b 33 f3 1a 8b   .........P.[3...
00d0 - 3f 7c 92 f7 31 4a ef f2-55 bf 52 bf e0 12 e8 e9   ?|..1J..U.R.....
00e0 - 54 55 d0 f0 61 e4 d6 52-b7 4d c3 c1 7e ae e3 3a   TU..a..R.M..~..:
00f0 - c4 ec 8b 3e df d7 b7 6a-6b b3 47 82 a2 d9 41 21   ...>...jk.G...A!
0100 - 2b eb 97 d0 f8 0c f3 8e-80 1a 6f 92 3f 92 11 58   +.........o.?..X
0110 - fb da 57 45 bb a3 22 cc-11 c9                     ..WE.."...
SSL_accept:SSLv3/TLS write finished
-----BEGIN SSL SESSION PARAMETERS-----
MF8CAQECAgMDBALAJwQABDDTxz29eCLFIQpe1HM6xI9EpzKrdly7jRomksHRQb4X
V1Kvx0Oj8y8YIV3QXJ85U4KhBgIEZ+obVaIEAgIcIKQGBAQBAAAArQMCAQGzAwIB
HQ==
-----END SSL SESSION PARAMETERS-----
Shared ciphers:ECDHE-RSA-AES128-SHA256
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Supported Elliptic Curve Point Formats: uncompressed:ansiX962_compressed_prime:ansiX962_compressed_char2
Supported groups: x25519:secp256r1:x448:secp521r1:secp384r1
Shared groups: x25519:secp256r1:x448:secp521r1:secp384r1
CIPHER is ECDHE-RSA-AES128-SHA256
Secure Renegotiation IS supported
read from 0x2042710f960 [0x20427521643] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 40                                    ....@
read from 0x2042710f960 [0x20427521648] (64 bytes => 64 (0x40))
0000 - 68 7a e2 47 a9 78 89 e7-17 dd ca cb 36 ce 01 67   hz.G.x......6..g
0010 - 02 fc dc e4 65 2c 61 fd-45 41 26 04 bb 81 a4 75   ....e,a.EA&....u
0020 - 85 37 3a e5 86 fd ba 27-c2 07 eb 7d a1 b6 23 40   .7:....'...}..#@
0030 - 24 b5 d4 ca 7d c8 d9 3a-1a d7 cd a2 f3 15 07 f6   $...}..:........
hello
read from 0x2042710f960 [0x20427521643] (5 bytes => 5 (0x5))
0000 - 15 03 03 00 40                                    ....@
read from 0x2042710f960 [0x20427521648] (64 bytes => 64 (0x40))
0000 - a2 6d 72 a8 c8 b0 53 81-cb a5 b0 4f c4 cf 57 64   .mr...S....O..Wd
0010 - 02 95 59 dd dd 00 c0 94-9d bd a3 96 44 0e 1f f0   ..Y.........D...
0020 - 0f c2 b5 58 1d ce 4c 39-99 97 af 0a fc f1 07 d8   ...X..L9........
0030 - b4 6d 67 c7 cf ff 67 d0-8a b2 2c da 34 99 65 09   .mg...g...,.4.e.
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x2042710f960 [0x204275399f3] (69 bytes => 69 (0x45))
0000 - 15 03 03 00 40 a5 b7 0c-71 e9 ac c6 b7 49 fc a3   ....@...q....I..
0010 - 17 78 8f f3 bb 1b d5 77-81 cc 13 1f 1a fe a1 a8   .x.....w........
0020 - ef e7 d2 a5 5a 98 99 3e-57 89 bf f5 34 25 58 15   ....Z..>W...4%X.
0030 - 95 a8 fc ed 3a 1d 2c 93-00 eb b3 63 bb eb 42 0c   ....:.,....c..B.
0040 - 4b ff 5b 1d 32                                    K.[.2
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

````
$ openssl s_client -connect localhost:9000 -state -debug -tls1_2
Connecting to ::1
CONNECTED(000001EC)
SSL_connect:before SSL initialization
write to 0x290f2525640 [0x290f29c2e80] (197 bytes => 197 (0xC5))
0000 - 16 03 01 00 c0 01 00 00-bc 03 03 f6 0c 97 e9 78   ...............x
0010 - c1 61 b1 d6 c8 dd 0e f3-89 23 78 72 cd 7c c0 a1   .a.......#xr.|..
0020 - df 53 3d a5 22 00 19 42-d4 af 73 00 00 36 c0 2c   .S=."..B..s..6.,
0030 - c0 30 00 9f cc a9 cc a8-cc aa c0 2b c0 2f 00 9e   .0.........+./..
0040 - c0 24 c0 28 00 6b c0 23-c0 27 00 67 c0 0a c0 14   .$.(.k.#.'.g....
0050 - 00 39 c0 09 c0 13 00 33-00 9d 00 9c 00 3d 00 3c   .9.....3.....=.<
0060 - 00 35 00 2f 01 00 00 5d-ff 01 00 01 00 00 0b 00   .5./...]........
0070 - 04 03 00 01 02 00 0a 00-0c 00 0a 00 1d 00 17 00   ................
0080 - 1e 00 19 00 18 00 23 00-00 00 16 00 00 00 17 00   ......#.........
0090 - 00 00 0d 00 30 00 2e 04-03 05 03 06 03 08 07 08   ....0...........
00a0 - 08 08 1a 08 1b 08 1c 08-09 08 0a 08 0b 08 04 08   ................
00b0 - 05 08 06 04 01 05 01 06-01 03 03 03 01 03 02 04   ................
00c0 - 02 05 02 06 02                                    .....
SSL_connect:SSLv3/TLS write client hello
read from 0x290f2525640 [0x290f29c7f53] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 45                                    ....E
read from 0x290f2525640 [0x290f29c7f58] (69 bytes => 69 (0x45))
0000 - 02 00 00 41 03 03 af 57-4b 63 16 bd 63 e3 c8 b7   ...A...WKc..c...
0010 - c7 12 34 63 83 a1 a9 57-90 4d 97 74 00 e1 fa 23   ..4c...W.M.t...#
0020 - fd f9 55 02 ff 02 00 c0-27 00 00 19 ff 01 00 01   ..U.....'.......
0030 - 00 00 0b 00 04 03 00 01-02 00 23 00 00 00 16 00   ..........#.....
0040 - 00 00 17 00 00                                    .....
SSL_connect:SSLv3/TLS write client hello
Can't use SSL_get_servername
read from 0x290f2525640 [0x290f29c7f53] (5 bytes => 5 (0x5))
0000 - 16 03 03 03 6a                                    ....j
read from 0x290f2525640 [0x290f29c7f58] (874 bytes => 874 (0x36A))
0000 - 0b 00 03 66 00 03 63 00-03 60 30 82 03 5c 30 82   ...f..c..`0..\0.
0010 - 02 44 a0 03 02 01 02 02-14 63 a6 71 10 79 d6 a6   .D.......c.q.y..
0020 - 48 59 da 67 a9 04 e8 e3-5f e2 03 a3 26 30 0d 06   HY.g...._...&0..
0030 - 09 2a 86 48 86 f7 0d 01-01 0b 05 00 30 59 31 0b   .*.H........0Y1.
0040 - 30 09 06 03 55 04 06 13-02 4b 52 31 0b 30 09 06   0...U....KR1.0..
0050 - 03 55 04 08 0c 02 47 47-31 0b 30 09 06 03 55 04   .U....GG1.0...U.
0060 - 07 0c 02 59 49 31 0d 30-0b 06 03 55 04 0a 0c 04   ...YI1.0...U....
0070 - 54 65 73 74 31 0d 30 0b-06 03 55 04 0b 0c 04 54   Test1.0...U....T
0080 - 65 73 74 31 12 30 10 06-03 55 04 03 0c 09 54 65   est1.0...U....Te
0090 - 73 74 20 52 6f 6f 74 30-1e 17 0d 32 34 30 38 32   st Root0...24082
00a0 - 39 30 36 32 37 31 37 5a-17 0d 32 35 30 38 32 39   9062717Z..250829
00b0 - 30 36 32 37 31 37 5a 30-54 31 0b 30 09 06 03 55   062717Z0T1.0...U
00c0 - 04 06 13 02 4b 52 31 0b-30 09 06 03 55 04 08 0c   ....KR1.0...U...
00d0 - 02 47 47 31 0b 30 09 06-03 55 04 07 0c 02 59 49   .GG1.0...U....YI
00e0 - 31 0d 30 0b 06 03 55 04-0a 0c 04 54 65 73 74 31   1.0...U....Test1
00f0 - 0d 30 0b 06 03 55 04 0b-0c 04 54 65 73 74 31 0d   .0...U....Test1.
0100 - 30 0b 06 03 55 04 03 0c-04 54 65 73 74 30 82 01   0...U....Test0..
0110 - 22 30 0d 06 09 2a 86 48-86 f7 0d 01 01 01 05 00   "0...*.H........
0120 - 03 82 01 0f 00 30 82 01-0a 02 82 01 01 00 ad 9a   .....0..........
0130 - 29 67 5f f3 a4 79 b4 c6-e6 32 73 d8 d7 ed 88 94   )g_..y...2s.....
0140 - 15 83 e4 31 00 04 6c b5-8c ac 87 ab 74 44 13 76   ...1..l.....tD.v
0150 - ca 0b 74 29 40 9e 97 2a-01 d7 8b 46 26 6e 19 35   ..t)@..*...F&n.5
0160 - 4d c0 d3 b5 ea 0e 93 3a-06 e8 e5 85 b5 27 05 63   M......:.....'.c
0170 - db 28 b8 92 da 5a 14 39-0f da 68 6d 6f 0a fb 52   .(...Z.9..hmo..R
0180 - dc 08 0f 54 d3 e4 a2 28-9d a0 71 50 82 e0 db ca   ...T...(..qP....
0190 - d1 94 dd 42 98 3a 09 33-a8 d9 ef fb d2 35 43 b1   ...B.:.3.....5C.
01a0 - 22 a2 be 41 6d ba 91 dc-0b 31 4e 88 f9 4d 9c 61   "..Am....1N..M.a
01b0 - 2d ec b2 13 0a c2 91 8e-a2 d6 e9 40 b9 32 b9 80   -..........@.2..
01c0 - 8f b3 18 a3 33 13 23 d5-d0 7e d9 d0 7f 93 e0 2d   ....3.#..~.....-
01d0 - 4d 90 c5 58 24 56 d5 c9-10 13 4a b2 99 23 7d 34   M..X$V....J..#}4
01e0 - b9 8e 97 19 69 6f ce c6-3f d6 17 a7 d2 43 e0 36   ....io..?....C.6
01f0 - cb 51 7b 2f 18 8b c2 33-f8 57 cf d1 61 0b 7c ed   .Q{/...3.W..a.|.
0200 - 37 35 e3 13 7a 24 2e 77-08 c2 e3 d9 e6 17 d3 a5   75..z$.w........
0210 - c6 34 5a da 86 a7 f8 02-36 1d 66 63 cf e9 c0 3d   .4Z.....6.fc...=
0220 - 82 fb 39 a2 8d 92 01 4a-83 cf e2 76 3d 87 02 03   ..9....J...v=...
0230 - 01 00 01 a3 21 30 1f 30-1d 06 03 55 1d 11 04 16   ....!0.0...U....
0240 - 30 14 82 12 74 65 73 74-2e 70 72 69 6e 63 65 62   0...test.princeb
0250 - 36 31 32 2e 70 65 30 0d-06 09 2a 86 48 86 f7 0d   612.pe0...*.H...
0260 - 01 01 0b 05 00 03 82 01-01 00 00 a5 f5 54 18 ab   .............T..
0270 - ad 36 38 c8 fc 0b 66 60-dd 9f 75 9d 86 5b 79 2f   .68...f`..u..[y/
0280 - ee 57 f1 79 1c 15 a1 34-23 d0 1c a9 58 51 a4 d0   .W.y...4#...XQ..
0290 - 08 f5 d8 f7 49 e9 c5 b5-65 91 51 2d 6d e4 3b 0e   ....I...e.Q-m.;.
02a0 - 77 02 1f 45 8e 34 e5 bb-eb f6 9d df 4a 40 60 21   w..E.4......J@`!
02b0 - b3 8e 16 33 3f f4 b6 90-d3 3c 34 ce e6 d9 47 07   ...3?....<4...G.
02c0 - a7 57 14 0c f9 78 0b 36-72 a9 88 07 07 93 b4 d7   .W...x.6r.......
02d0 - fe 29 5e e8 41 37 20 a5-03 c7 97 cb 82 ca db 14   .)^.A7 .........
02e0 - e5 8b 96 1f a9 e9 20 3d-6b 25 ae f4 89 4c 60 8d   ...... =k%...L`.
02f0 - e9 14 33 47 4b 88 54 a2-47 19 81 c8 7b 0e 32 52   ..3GK.T.G...{.2R
0300 - 2b 91 88 ad 0f 6d 73 30-8c 00 af d5 fc 46 46 af   +....ms0.....FF.
0310 - 3a c2 17 89 ec c8 83 ae-da e6 69 63 e0 9c 84 22   :.........ic..."
0320 - c5 7a de e8 23 6b 53 9d-6f 94 d2 7f 5c be 1d 0c   .z..#kS.o...\...
0330 - de 0e 07 0d 52 a5 43 8c-e8 05 ef c0 ff f0 73 fa   ....R.C.......s.
0340 - dc 5a 51 4c 24 09 65 45-7d ab 52 8b 7e 5d f0 fb   .ZQL$.eE}.R.~]..
0350 - de a7 3d 43 c5 af 76 e3-6e f9 a1 dc 78 a2 bd 54   ..=C..v.n...x..T
0360 - 41 04 99 e5 56 32 ba 02-fd 72                     A...V2...r
SSL_connect:SSLv3/TLS read server hello
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify return:1
read from 0x290f2525640 [0x290f29c7f53] (5 bytes => 5 (0x5))
0000 - 16 03 03 01 2c                                    ....,
read from 0x290f2525640 [0x290f29c7f58] (300 bytes => 300 (0x12C))
0000 - 0c 00 01 28 03 00 1d 20-9e e0 04 f5 6d de 7a 77   ...(... ....m.zw
0010 - 7c cc 21 a1 b2 04 0b eb-3f 4d 7e 52 8d 53 ba 8b   |.!.....?M~R.S..
0020 - 9b 75 fc 8a 26 37 0f 0a-08 04 01 00 74 71 22 08   .u..&7......tq".
0030 - 2b ef 7a 0f ba e6 1a af-27 99 e5 8c 10 a1 24 15   +.z.....'.....$.
0040 - 44 c1 20 8e c6 f4 67 f7-32 cc 78 b6 c6 ec e2 7e   D. ...g.2.x....~
0050 - 83 d6 82 3f d6 99 23 05-e2 69 0c 6f 1f 9d ef 1e   ...?..#..i.o....
0060 - 49 7b 03 1b 77 ce 83 26-fe e5 13 ec a1 3e bf e1   I{..w..&.....>..
0070 - 7d 7a b3 03 35 00 d2 1a-4b 48 9b 63 8a b9 94 b1   }z..5...KH.c....
0080 - 4e c3 13 12 3b e2 2f e4-f8 65 ee 0c 58 8c b1 a9   N...;./..e..X...
0090 - f7 a8 6f 2e c7 8f db 65-e8 69 62 87 14 ba 7d cc   ..o....e.ib...}.
00a0 - 99 7e 4a e5 eb 31 a6 de-b8 c3 23 51 b4 88 16 57   .~J..1....#Q...W
00b0 - 04 8b 09 5f e1 37 26 f2-ab b9 c7 19 b8 7f 73 21   ..._.7&.......s!
00c0 - 1a ba fa 3c ab 4e 7c 10-13 42 88 dd f8 92 f3 e0   ...<.N|..B......
00d0 - 8e ab 8b 6b 95 dd af 7c-d0 87 7e 75 24 fe 60 60   ...k...|..~u$.``
00e0 - 2a 13 6e 34 f7 ba e9 39-d2 72 97 3b 5b 9f 58 f7   *.n4...9.r.;[.X.
00f0 - 34 01 62 e5 58 4e e0 bf-39 07 c2 77 d0 0f 5f ce   4.b.XN..9..w.._.
0100 - 9d 91 ac 65 14 51 56 01-1e d1 42 b9 d7 8a a4 6f   ...e.QV...B....o
0110 - 3a 10 e7 4f 47 5e 11 d8-03 2d 71 26 0b d8 09 96   :..OG^...-q&....
0120 - d0 f1 68 55 2a 44 9d 71-be 9a d9 00               ..hU*D.q....
SSL_connect:SSLv3/TLS read server certificate
read from 0x290f2525640 [0x290f29c7f53] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 04                                    .....
read from 0x290f2525640 [0x290f29c7f58] (4 bytes => 4 (0x4))
0000 - 0e 00 00 00                                       ....
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client key exchange
SSL_connect:SSLv3/TLS write change cipher spec
write to 0x290f2525640 [0x290f29c2e80] (133 bytes => 133 (0x85))
0000 - 16 03 03 00 25 10 00 00-21 20 d6 d1 b3 30 65 1b   ....%...! ...0e.
0010 - 96 1d 6d e3 8b 20 12 07-e6 3d 5e 11 59 04 d4 88   ..m.. ...=^.Y...
0020 - e2 eb 53 4e 3c 48 04 d6-4a 5d 14 03 03 00 01 01   ..SN<H..J]......
0030 - 16 03 03 00 50 f1 ec 59-47 5f 50 f1 14 c7 b6 60   ....P..YG_P....`
0040 - e1 e1 b8 06 8f d0 32 60-e7 e8 58 94 8b fb 63 bb   ......2`..X...c.
0050 - 8e e2 f5 a8 47 5b 4e b7-e5 7d 9b ab ef da 34 9a   ....G[N..}....4.
0060 - 08 39 aa 82 24 79 70 89-68 33 0e ae 64 1c 92 ed   .9..$yp.h3..d...
0070 - ff d1 73 58 32 99 b2 26-2c a2 b0 36 bc ef 84 9e   ..sX2..&,..6....
0080 - 1b 75 77 4e e3                                    .uwN.
SSL_connect:SSLv3/TLS write finished
read from 0x290f2525640 [0x290f29c7f53] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 ba                                    .....
read from 0x290f2525640 [0x290f29c7f58] (186 bytes => 186 (0xBA))
0000 - 04 00 00 b6 00 00 1c 20-00 b0 81 6c 9f 53 2f 36   ....... ...l.S/6
0010 - b1 ef 97 3d 5d 30 00 a1-63 ce 69 1a 7b 8a d8 e6   ...=]0..c.i.{...
0020 - 1d 20 d4 1b b3 e3 f6 0d-00 02 55 7c ef 32 a2 1e   . ........U|.2..
0030 - 54 62 5a cb 46 96 3f 11-ee fb 88 ce ba 97 ed 39   TbZ.F.?........9
0040 - 84 cb c7 78 92 35 a8 2c-1a b8 f4 d7 9a 84 3b 39   ...x.5.,......;9
0050 - 2d d7 a4 41 78 69 db be-7e 0b 51 84 84 85 86 0a   -..Axi..~.Q.....
0060 - 23 e7 ab 2d 27 85 9a da-f9 ff 13 7b 6f e6 52 ab   #..-'......{o.R.
0070 - 55 8e 78 6d ef 6e e6 c4-1f 72 4b 4a f4 d3 2f 46   U.xm.n...rKJ../F
0080 - 98 c6 bd 5b f1 e7 99 7c-57 44 31 f1 96 81 32 b6   ...[...|WD1...2.
0090 - 07 c3 8a 52 b9 eb f1 ad-e9 3e 2b 0b 77 57 43 ca   ...R.....>+.wWC.
00a0 - 18 28 16 36 ad 0d 3a be-fb 7c de 5c a3 cf 26 cf   .(.6..:..|.\..&.
00b0 - d5 27 d8 4f 79 66 86 70-a4 4e                     .'.Oyf.p.N
SSL_connect:SSLv3/TLS write finished
read from 0x290f2525640 [0x290f29c7f53] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x290f2525640 [0x290f29c7f58] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_connect:SSLv3/TLS read server session ticket
read from 0x290f2525640 [0x290f29c3e93] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 50                                    ....P
read from 0x290f2525640 [0x290f29c3e98] (80 bytes => 80 (0x50))
0000 - f9 5b 33 f3 1a 8b 3f 7c-92 f7 31 4a ef f2 55 bf   .[3...?|..1J..U.
0010 - 52 bf e0 12 e8 e9 54 55-d0 f0 61 e4 d6 52 b7 4d   R.....TU..a..R.M
0020 - c3 c1 7e ae e3 3a c4 ec-8b 3e df d7 b7 6a 6b b3   ..~..:...>...jk.
0030 - 47 82 a2 d9 41 21 2b eb-97 d0 f8 0c f3 8e 80 1a   G...A!+.........
0040 - 6f 92 3f 92 11 58 fb da-57 45 bb a3 22 cc 11 c9   o.?..X..WE.."...
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
SSL handshake has read 1549 bytes and written 330 bytes
Verification error: unable to verify the first certificate
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES128-SHA256
Protocol: TLSv1.2
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES128-SHA256
    Session-ID: C3845969EFCAE4068FC6F595810E63180CB95242F1306B3C8ED0BFBFFFA13400
    Session-ID-ctx:
    Master-Key: D3C73DBD7822C5210A5ED4733AC48F44A732AB765CBB8D1A2692C1D141BE175752AFC743A3F32F18215DD05C9F395382
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 81 6c 9f 53 2f 36 b1 ef-97 3d 5d 30 00 a1 63 ce   .l.S/6...=]0..c.
    0010 - 69 1a 7b 8a d8 e6 1d 20-d4 1b b3 e3 f6 0d 00 02   i.{.... ........
    0020 - 55 7c ef 32 a2 1e 54 62-5a cb 46 96 3f 11 ee fb   U|.2..TbZ.F.?...
    0030 - 88 ce ba 97 ed 39 84 cb-c7 78 92 35 a8 2c 1a b8   .....9...x.5.,..
    0040 - f4 d7 9a 84 3b 39 2d d7-a4 41 78 69 db be 7e 0b   ....;9-..Axi..~.
    0050 - 51 84 84 85 86 0a 23 e7-ab 2d 27 85 9a da f9 ff   Q.....#..-'.....
    0060 - 13 7b 6f e6 52 ab 55 8e-78 6d ef 6e e6 c4 1f 72   .{o.R.U.xm.n...r
    0070 - 4b 4a f4 d3 2f 46 98 c6-bd 5b f1 e7 99 7c 57 44   KJ../F...[...|WD
    0080 - 31 f1 96 81 32 b6 07 c3-8a 52 b9 eb f1 ad e9 3e   1...2....R.....>
    0090 - 2b 0b 77 57 43 ca 18 28-16 36 ad 0d 3a be fb 7c   +.wWC..(.6..:..|
    00a0 - de 5c a3 cf 26 cf d5 27-d8 4f 79 66 86 70 a4 4e   .\..&..'.Oyf.p.N

    Start Time: 1743395669
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: yes
---
hello
write to 0x290f2525640 [0x290f29d8bb3] (69 bytes => 69 (0x45))
0000 - 17 03 03 00 40 68 7a e2-47 a9 78 89 e7 17 dd ca   ....@hz.G.x.....
0010 - cb 36 ce 01 67 02 fc dc-e4 65 2c 61 fd 45 41 26   .6..g....e,a.EA&
0020 - 04 bb 81 a4 75 85 37 3a-e5 86 fd ba 27 c2 07 eb   ....u.7:....'...
0030 - 7d a1 b6 23 40 24 b5 d4-ca 7d c8 d9 3a 1a d7 cd   }..#@$...}..:...
0040 - a2 f3 15 07 f6                                    .....
Q
DONE
write to 0x290f2525640 [0x290f29d8bb3] (69 bytes => 69 (0x45))
0000 - 15 03 03 00 40 a2 6d 72-a8 c8 b0 53 81 cb a5 b0   ....@.mr...S....
0010 - 4f c4 cf 57 64 02 95 59-dd dd 00 c0 94 9d bd a3   O..Wd..Y........
0020 - 96 44 0e 1f f0 0f c2 b5-58 1d ce 4c 39 99 97 af   .D......X..L9...
0030 - 0a fc f1 07 d8 b4 6d 67-c7 cf ff 67 d0 8a b2 2c   ......mg...g...,
0040 - da 34 99 65 09                                    .4.e.
SSL3 alert write:warning:close notify
read from 0x290f2525640 [0x290f2467c60] (16384 bytes => 69 (0x45))
0000 - 15 03 03 00 40 a5 b7 0c-71 e9 ac c6 b7 49 fc a3   ....@...q....I..
0010 - 17 78 8f f3 bb 1b d5 77-81 cc 13 1f 1a fe a1 a8   .x.....w........
0020 - ef e7 d2 a5 5a 98 99 3e-57 89 bf f5 34 25 58 15   ....Z..>W...4%X.
0030 - 95 a8 fc ed 3a 1d 2c 93-00 eb b3 63 bb eb 42 0c   ....:.,....c..B.
0040 - 4b ff 5b 1d 32                                    K.[.2
read from 0x290f2525640 [0x290f2467c60] (16384 bytes => 0)
````
