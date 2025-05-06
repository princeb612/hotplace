#### tls12mte.pcapng - server

````
$ openssl s_server -accept 9000 -cert server.crt -key server.key -state -debug -status_verbose -keylogfile server.keylog
SSL_accept:before SSL initialization
read from 0x2629d5f61a0 [0x2629d5e61e3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 cc                                    .....
read from 0x2629d5f61a0 [0x2629d5e61e8] (204 bytes => 204 (0xCC))
0000 - 01 00 00 c8 03 03 88 06-aa f3 ba b7 cf a0 06 49   ...............I
0010 - 7e f5 06 20 dd ae 53 20-bf 15 41 d2 d2 a9 7a fb   ~.. ..S ..A...z.
0020 - 85 14 5a a1 d2 75 20 b4-81 ac d6 e0 a2 2e 0f a5   ..Z..u .........
0030 - d6 0d b9 fd 2d 02 3c 32-fb 20 89 4a 64 af 87 4e   ....-.<2. .Jd..N
0040 - 7a 68 4f df 4f 6f 5a 00-10 c0 23 c0 24 c0 27 c0   zhO.OoZ...#.$.'.
0050 - 28 c0 2b c0 2c c0 2f c0-30 01 00 00 6f 00 0b 00   (.+.,./.0...o...
0060 - 02 01 00 00 0a 00 0c 00-0a 00 1d 00 17 00 1e 00   ................
0070 - 19 00 18 00 0d 00 1e 00-1c 04 03 05 03 06 03 08   ................
0080 - 07 08 08 04 01 05 01 06-01 08 09 08 0a 08 0b 08   ................
0090 - 04 08 05 08 06 00 2b 00-03 02 03 03 00 2d 00 02   ......+......-..
00a0 - 01 01 00 33 00 26 00 24-00 1d 00 20 ab a4 8c ab   ...3.&.$... ....
00b0 - ab 5b e5 92 54 cc 25 c8-b3 67 ae 0d 35 8b 69 1f   .[..T.%..g..5.i.
00c0 - 3b 98 d0 4b 5c 67 3b 55-f0 d2 91 57               ;..K\g;U...W
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write certificate
SSL_accept:SSLv3/TLS write key exchange
write to 0x2629d5f61a0 [0x2629d5fe1e0] (1282 bytes => 1282 (0x502))
0000 - 16 03 03 00 54 02 00 00-50 03 03 e7 36 be 0b f5   ....T...P...6...
0010 - e6 d9 ff ec 34 8b 1d 22-2e 5e 5f 0d d2 d4 a4 6c   ....4..".^_....l
0020 - 99 ae 52 1d e3 54 08 88-72 ca ab 20 37 9e f9 6b   ..R..T..r.. 7..k
0030 - 1c 03 10 52 81 88 10 c9-2b 67 f0 b7 f9 e0 5f 7b   ...R....+g...._{
0040 - d4 e2 e8 aa ed ff 4d 55-d8 7d a7 77 c0 27 00 00   ......MU.}.w.'..
0050 - 08 00 0b 00 04 03 00 01-02 16 03 03 03 6a 0b 00   .............j..
0060 - 03 66 00 03 63 00 03 60-30 82 03 5c 30 82 02 44   .f..c..`0..\0..D
0070 - a0 03 02 01 02 02 14 63-a6 71 10 79 d6 a6 48 59   .......c.q.y..HY
0080 - da 67 a9 04 e8 e3 5f e2-03 a3 26 30 0d 06 09 2a   .g...._...&0...*
0090 - 86 48 86 f7 0d 01 01 0b-05 00 30 59 31 0b 30 09   .H........0Y1.0.
00a0 - 06 03 55 04 06 13 02 4b-52 31 0b 30 09 06 03 55   ..U....KR1.0...U
00b0 - 04 08 0c 02 47 47 31 0b-30 09 06 03 55 04 07 0c   ....GG1.0...U...
00c0 - 02 59 49 31 0d 30 0b 06-03 55 04 0a 0c 04 54 65   .YI1.0...U....Te
00d0 - 73 74 31 0d 30 0b 06 03-55 04 0b 0c 04 54 65 73   st1.0...U....Tes
00e0 - 74 31 12 30 10 06 03 55-04 03 0c 09 54 65 73 74   t1.0...U....Test
00f0 - 20 52 6f 6f 74 30 1e 17-0d 32 34 30 38 32 39 30    Root0...2408290
0100 - 36 32 37 31 37 5a 17 0d-32 35 30 38 32 39 30 36   62717Z..25082906
0110 - 32 37 31 37 5a 30 54 31-0b 30 09 06 03 55 04 06   2717Z0T1.0...U..
0120 - 13 02 4b 52 31 0b 30 09-06 03 55 04 08 0c 02 47   ..KR1.0...U....G
0130 - 47 31 0b 30 09 06 03 55-04 07 0c 02 59 49 31 0d   G1.0...U....YI1.
0140 - 30 0b 06 03 55 04 0a 0c-04 54 65 73 74 31 0d 30   0...U....Test1.0
0150 - 0b 06 03 55 04 0b 0c 04-54 65 73 74 31 0d 30 0b   ...U....Test1.0.
0160 - 06 03 55 04 03 0c 04 54-65 73 74 30 82 01 22 30   ..U....Test0.."0
0170 - 0d 06 09 2a 86 48 86 f7-0d 01 01 01 05 00 03 82   ...*.H..........
0180 - 01 0f 00 30 82 01 0a 02-82 01 01 00 ad 9a 29 67   ...0..........)g
0190 - 5f f3 a4 79 b4 c6 e6 32-73 d8 d7 ed 88 94 15 83   _..y...2s.......
01a0 - e4 31 00 04 6c b5 8c ac-87 ab 74 44 13 76 ca 0b   .1..l.....tD.v..
01b0 - 74 29 40 9e 97 2a 01 d7-8b 46 26 6e 19 35 4d c0   t)@..*...F&n.5M.
01c0 - d3 b5 ea 0e 93 3a 06 e8-e5 85 b5 27 05 63 db 28   .....:.....'.c.(
01d0 - b8 92 da 5a 14 39 0f da-68 6d 6f 0a fb 52 dc 08   ...Z.9..hmo..R..
01e0 - 0f 54 d3 e4 a2 28 9d a0-71 50 82 e0 db ca d1 94   .T...(..qP......
01f0 - dd 42 98 3a 09 33 a8 d9-ef fb d2 35 43 b1 22 a2   .B.:.3.....5C.".
0200 - be 41 6d ba 91 dc 0b 31-4e 88 f9 4d 9c 61 2d ec   .Am....1N..M.a-.
0210 - b2 13 0a c2 91 8e a2 d6-e9 40 b9 32 b9 80 8f b3   .........@.2....
0220 - 18 a3 33 13 23 d5 d0 7e-d9 d0 7f 93 e0 2d 4d 90   ..3.#..~.....-M.
0230 - c5 58 24 56 d5 c9 10 13-4a b2 99 23 7d 34 b9 8e   .X$V....J..#}4..
0240 - 97 19 69 6f ce c6 3f d6-17 a7 d2 43 e0 36 cb 51   ..io..?....C.6.Q
0250 - 7b 2f 18 8b c2 33 f8 57-cf d1 61 0b 7c ed 37 35   {/...3.W..a.|.75
0260 - e3 13 7a 24 2e 77 08 c2-e3 d9 e6 17 d3 a5 c6 34   ..z$.w.........4
0270 - 5a da 86 a7 f8 02 36 1d-66 63 cf e9 c0 3d 82 fb   Z.....6.fc...=..
0280 - 39 a2 8d 92 01 4a 83 cf-e2 76 3d 87 02 03 01 00   9....J...v=.....
0290 - 01 a3 21 30 1f 30 1d 06-03 55 1d 11 04 16 30 14   ..!0.0...U....0.
02a0 - 82 12 74 65 73 74 2e 70-72 69 6e 63 65 62 36 31   ..test.princeb61
02b0 - 32 2e 70 65 30 0d 06 09-2a 86 48 86 f7 0d 01 01   2.pe0...*.H.....
02c0 - 0b 05 00 03 82 01 01 00-00 a5 f5 54 18 ab ad 36   ...........T...6
02d0 - 38 c8 fc 0b 66 60 dd 9f-75 9d 86 5b 79 2f ee 57   8...f`..u..[y/.W
02e0 - f1 79 1c 15 a1 34 23 d0-1c a9 58 51 a4 d0 08 f5   .y...4#...XQ....
02f0 - d8 f7 49 e9 c5 b5 65 91-51 2d 6d e4 3b 0e 77 02   ..I...e.Q-m.;.w.
0300 - 1f 45 8e 34 e5 bb eb f6-9d df 4a 40 60 21 b3 8e   .E.4......J@`!..
0310 - 16 33 3f f4 b6 90 d3 3c-34 ce e6 d9 47 07 a7 57   .3?....<4...G..W
0320 - 14 0c f9 78 0b 36 72 a9-88 07 07 93 b4 d7 fe 29   ...x.6r........)
0330 - 5e e8 41 37 20 a5 03 c7-97 cb 82 ca db 14 e5 8b   ^.A7 ...........
0340 - 96 1f a9 e9 20 3d 6b 25-ae f4 89 4c 60 8d e9 14   .... =k%...L`...
0350 - 33 47 4b 88 54 a2 47 19-81 c8 7b 0e 32 52 2b 91   3GK.T.G...{.2R+.
0360 - 88 ad 0f 6d 73 30 8c 00-af d5 fc 46 46 af 3a c2   ...ms0.....FF.:.
0370 - 17 89 ec c8 83 ae da e6-69 63 e0 9c 84 22 c5 7a   ........ic...".z
0380 - de e8 23 6b 53 9d 6f 94-d2 7f 5c be 1d 0c de 0e   ..#kS.o...\.....
0390 - 07 0d 52 a5 43 8c e8 05-ef c0 ff f0 73 fa dc 5a   ..R.C.......s..Z
03a0 - 51 4c 24 09 65 45 7d ab-52 8b 7e 5d f0 fb de a7   QL$.eE}.R.~]....
03b0 - 3d 43 c5 af 76 e3 6e f9-a1 dc 78 a2 bd 54 41 04   =C..v.n...x..TA.
03c0 - 99 e5 56 32 ba 02 fd 72-16 03 03 01 2c 0c 00 01   ..V2...r....,...
03d0 - 28 03 00 1d 20 f4 29 00-ff 3d 69 88 1d a1 44 60   (... .)..=i...D`
03e0 - 74 0f ac 51 a0 4c b5 ef-3f fd eb ff 76 63 6e 9c   t..Q.L..?...vcn.
03f0 - 5d fe 3d 31 2b 04 01 01-00 4d 94 81 0f dd 66 c6   ].=1+....M....f.
0400 - 7a fd 9b b4 22 eb 76 b7-db 28 4b ad 39 00 d5 f7   z...".v..(K.9...
0410 - e5 7a 41 db d9 30 72 b4-c5 b9 09 ed 75 c1 ed 72   .zA..0r.....u..r
0420 - e2 15 6f 3f d0 4b 81 46-fb 7a ae 8c c3 c3 10 16   ..o?.K.F.z......
0430 - f2 71 69 ce 4e d2 84 49-2c 40 37 0e b9 60 60 36   .qi.N..I,@7..``6
0440 - ce 66 2c 05 f1 a3 59 e5-6d 4d 06 bd 72 7d eb c2   .f,...Y.mM..r}..
0450 - 72 2e 1b 55 85 51 1f 03-55 68 6d 6d a8 ea 96 be   r..U.Q..Uhmm....
0460 - a6 20 eb 08 24 e5 a8 86-18 0a 06 58 37 da 81 e0   . ..$......X7...
0470 - ea 9e 05 6c 2c cf 76 4b-29 fe 52 f4 6a a6 fa b8   ...l,.vK).R.j...
0480 - d9 81 db eb 08 db c4 80-c2 1d 04 b1 fb 7c 5c b2   .............|\.
0490 - 73 bf 06 c8 61 7d 18 bb-f8 2b 02 68 9b 52 e2 fa   s...a}...+.h.R..
04a0 - ca 74 3d 07 dd eb 0c 59-24 61 c2 21 5e 09 12 4e   .t=....Y$a.!^..N
04b0 - db 7e 2e d4 d7 bc d6 2b-21 b7 d7 ce b1 65 f8 0e   .~.....+!....e..
04c0 - 2f ec 8c 36 c4 5a 03 3a-13 57 6d 2b 15 df 65 29   /..6.Z.:.Wm+..e)
04d0 - 75 41 e0 1d a0 82 ba ee-12 45 8a e8 57 75 6d 85   uA.......E..Wum.
04e0 - 3e c2 d3 dc 5a 69 f7 d5-34 12 51 67 98 2d a0 f1   >...Zi..4.Qg.-..
04f0 - 81 41 12 1c f6 41 f1 a0-09 16 03 03 00 04 0e 00   .A...A..........
0500 - 00 00                                             ..
SSL_accept:SSLv3/TLS write server done
read from 0x2629d5f61a0 [0x2629d5e61e3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 25                                    ....%
read from 0x2629d5f61a0 [0x2629d5e61e8] (37 bytes => 37 (0x25))
0000 - 10 00 00 21 20 c7 34 68-18 ac 64 38 c9 5a 9a 50   ...! .4h..d8.Z.P
0010 - 38 1d 70 0e 21 ca a9 0c-91 22 ea 8e 15 e6 bf cc   8.p.!...."......
0020 - aa dd 7e 80 23                                    ..~.#
SSL_accept:SSLv3/TLS write server done
read from 0x2629d5f61a0 [0x2629d5e61e3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x2629d5f61a0 [0x2629d5e61e8] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_accept:SSLv3/TLS read client key exchange
read from 0x2629d5f61a0 [0x2629d5e61e3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 50                                    ....P
read from 0x2629d5f61a0 [0x2629d5e61e8] (80 bytes => 80 (0x50))
0000 - 03 b6 79 08 6a b0 11 61-c3 db 15 1d 62 b7 75 50   ..y.j..a....b.uP
0010 - f1 e8 2e e2 82 85 1b 22-73 b6 05 df e8 c4 40 f8   ......."s.....@.
0020 - 86 b1 4d ce 29 32 f6 74-35 2f f5 3a f5 8c 60 0b   ..M.)2.t5/.:..`.
0030 - bb 8e af 45 57 bd 31 66-3b 55 33 d1 59 57 3b 50   ...EW.1f;U3.YW;P
0040 - 94 dc c4 9d 51 98 15 6b-9e 49 72 76 59 eb 23 f7   ....Q..k.IrvY.#.
SSL_accept:SSLv3/TLS read change cipher spec
SSL_accept:SSLv3/TLS read finished
SSL_accept:SSLv3/TLS write change cipher spec
write to 0x2629d5f61a0 [0x2629d5fe1e0] (91 bytes => 91 (0x5B))
0000 - 14 03 03 00 01 01 16 03-03 00 50 cb 3a 05 2d 43   ..........P.:.-C
0010 - 3e e8 bb 9f 8a 50 d8 3d-97 b9 0f 44 e1 06 b3 e4   >....P.=...D....
0020 - 26 87 a7 37 14 d9 b4 e7-80 69 60 b0 c7 17 ce cb   &..7.....i`.....
0030 - aa 8e e9 3d a0 08 e3 8e-59 b7 52 67 96 c6 9f f2   ...=....Y.Rg....
0040 - f5 c7 c0 18 32 d2 27 9d-cc 44 e1 b1 56 a8 1a 17   ....2.'..D..V...
0050 - ae 8b 55 7e c2 b7 1b 3f-03 e2 ca                  ..U~...?...
SSL_accept:SSLv3/TLS write finished
-----BEGIN SSL SESSION PARAMETERS-----
MHoCAQECAgMDBALAJwQgN575axwDEFKBiBDJK2fwt/ngX3vU4uiq7f9NVdh9p3cE
MBWYqXAbNZNhGdOxFLm032ltPQ+82S7hImErWc3wdS85Lj/yezi5tYWqYOCUCIM6
NqEGAgRn+v8iogQCAhwgpAYEBAEAAACzAwIBHQ==
-----END SSL SESSION PARAMETERS-----
Shared ciphers:ECDHE-RSA-AES128-SHA256
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA+SHA256:RSA+SHA384:RSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA+SHA256:RSA+SHA384:RSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512
Supported Elliptic Curve Point Formats: uncompressed
Supported groups: x25519:secp256r1:x448:secp521r1:secp384r1
Shared groups: x25519:secp256r1:x448:secp521r1:secp384r1
CIPHER is ECDHE-RSA-AES128-SHA256
Secure Renegotiation IS NOT supported
read from 0x2629d5f61a0 [0x2629d5e61e3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 40                                    ....@
read from 0x2629d5f61a0 [0x2629d5e61e8] (64 bytes => 64 (0x40))
0000 - a7 99 3a d1 45 c1 8e 6f-25 14 16 71 a3 56 d6 81   ..:.E..o%..q.V..
0010 - df 39 1e 62 10 68 9a 8e-7e bd 5a 4c 67 fa fa f4   .9.b.h..~.ZLg...
0020 - 9d 1e 9f 91 4d 11 d2 01-ff ac b6 08 97 91 45 ac   ....M.........E.
0030 - 88 78 af be 99 af 03 a8-81 d2 2c a4 fb ac 35 c8   .x........,...5.
helloread from 0x2629d5f61a0 [0x2629d5e61e3] (5 bytes => 5 (0x5))
0000 - 15 03 03 00 40                                    ....@
read from 0x2629d5f61a0 [0x2629d5e61e8] (64 bytes => 64 (0x40))
0000 - 48 61 45 6b a1 a0 c2 7a-29 d5 2e 13 26 53 9b 13   HaEk...z)...&S..
0010 - cc a1 5d ee ca ea af bb-a6 15 7c f7 0f d2 c0 38   ..].......|....8
0020 - c5 a1 be 8a 39 63 be af-da b1 1a 61 20 62 7c d4   ....9c.....a b|.
0030 - 29 3b 0b 14 45 96 7e 5d-4f 21 24 2f 19 2e 34 23   );..E.~]O!$/..4#
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x2629d5f61a0 [0x2629d5ea333] (69 bytes => 69 (0x45))
0000 - 15 03 03 00 40 06 ef 55-b7 23 a5 c9 61 8c 0e 76   ....@..U.#..a..v
0010 - 89 3f 14 4f e3 e6 29 0c-39 99 f2 be a2 32 a8 f4   .?.O..).9....2..
0020 - d0 fc 79 38 ef 2f e6 2d-d8 9f c2 82 19 a5 04 95   ..y8./.-........
0030 - 31 04 b5 28 7f 4e 36 7c-74 40 4a eb fa fe c6 98   1..(.N6|t@J.....
0040 - 60 0c f4 a4 d6                                    `....
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
