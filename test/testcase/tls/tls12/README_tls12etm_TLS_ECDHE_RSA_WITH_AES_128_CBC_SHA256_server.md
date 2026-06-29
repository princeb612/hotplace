#### server

````
$ openssl s_server -accept 9000 -cert server.crt -key server.key -state -debug -status_verbose -keylogfile sslkeylog
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x20d957e4110 [0x20d95c2ce53] (5 bytes => 5 (0x5))
0000 - 16 03 01 00 c0                                    .....
read from 0x20d957e4110 [0x20d95c2ce58] (192 bytes => 192 (0xC0))
0000 - 01 00 00 bc 03 03 96 89-88 b1 0e d8 d7 2b e8 7f   .............+..
0010 - ae a5 64 a0 d8 15 a4 62-f1 41 ca 80 19 ad c5 33   ..d....b.A.....3
0020 - ae c9 89 15 2b ff 00 00-36 c0 2c c0 30 00 9f cc   ....+...6.,.0...
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
write to 0x20d957e4110 [0x20d95c2be40] (1267 bytes => 1267 (0x4F3))
0000 - 16 03 03 00 45 02 00 00-41 03 03 65 8b 66 a2 af   ....E...A..e.f..
0010 - 4e 1b 13 dd 8b 50 51 78-90 21 13 a5 bf b0 21 ee   N....PQx.!....!.
0020 - 8b 24 30 cf ab 97 20 b1-37 6d 63 00 c0 27 00 00   .$0... .7mc..'..
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
03c0 - 01 28 03 00 1d 20 8e 93-3b 4c a7 02 61 06 89 0b   .(... ..;L..a...
03d0 - e2 d0 3e 0e 05 64 a7 37-9e b8 b9 0b 5b 3d 68 2c   ..>..d.7....[=h,
03e0 - 55 f4 a5 ef 46 67 08 04-01 00 50 ec 45 47 75 24   U...Fg....P.EGu$
03f0 - 3b 9c af e9 2f 3a af 50-bb aa 85 f0 67 5c b6 cd   ;.../:.P....g\..
0400 - 12 e6 7d 01 1a 3f a5 f4-0a 38 a2 4b 7d 90 b1 3f   ..}..?...8.K}..?
0410 - 7e 41 3b c6 d2 e0 c6 97-39 6f 22 aa 2b ee 09 d6   ~A;.....9o".+...
0420 - 83 b9 ab 77 c0 a4 63 e8-cb f2 0a 67 1d 72 71 b8   ...w..c....g.rq.
0430 - 7a a9 36 b4 90 ad 6d 22-25 01 ee 52 3b ce b9 56   z.6...m"%..R;..V
0440 - 8b f6 46 38 cf d9 dc d5-30 8e 3c aa e8 05 d7 05   ..F8....0.<.....
0450 - c4 bb 25 33 43 8f a7 5c-72 a6 c1 c1 f9 3d 89 a8   ..%3C..\r....=..
0460 - 9c b2 15 86 82 11 0e 1f-9c 00 12 6f cd 64 01 57   ...........o.d.W
0470 - 08 fa 5a 85 f6 5a be 58-e4 18 20 79 d8 13 6a cf   ..Z..Z.X.. y..j.
0480 - 9a 3a 81 b7 ba 08 e4 4c-ed e6 53 f9 f9 a5 7d 25   .:.....L..S...}%
0490 - 27 b7 84 a2 73 86 83 fe-28 d5 50 c4 ad c6 c2 10   '...s...(.P.....
04a0 - 24 f7 89 ec b1 18 a7 75-84 ef d5 52 08 dc 6d 74   $......u...R..mt
04b0 - 0e 99 a7 2e 0b cf af 85-3b c7 15 a3 52 29 26 19   ........;...R)&.
04c0 - d0 cf fc 29 f2 1d d8 59-b1 5d 4a 54 2b 9e 1e dd   ...)...Y.]JT+...
04d0 - 52 fe d8 74 a2 78 ca f5-1b c8 3a c1 06 16 ad 35   R..t.x....:....5
04e0 - 4a 84 be 16 2b c6 10 a8-b2 f7 16 03 03 00 04 0e   J...+...........
04f0 - 00 00 00                                          ...
SSL_accept:SSLv3/TLS write server done
read from 0x20d957e4110 [0x20d95c2ce53] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 25                                    ....%
read from 0x20d957e4110 [0x20d95c2ce58] (37 bytes => 37 (0x25))
0000 - 10 00 00 21 20 86 be ac-52 20 97 62 d5 c1 50 61   ...! ...R .b..Pa
0010 - 5c 9b c5 ba b2 11 89 6c-70 a2 e8 21 27 b8 80 f4   \......lp..!'...
0020 - a1 b1 03 3a 28                                    ...:(
SSL_accept:SSLv3/TLS write server done
read from 0x20d957e4110 [0x20d95c2ce53] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x20d957e4110 [0x20d95c2ce58] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_accept:SSLv3/TLS read client key exchange
read from 0x20d957e4110 [0x20d95c2ce53] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 50                                    ....P
read from 0x20d957e4110 [0x20d95c2ce58] (80 bytes => 80 (0x50))
0000 - b2 08 4a 5b 1d d6 15 cd-05 6d 1f 28 8f b8 e5 7b   ..J[.....m.(...{
0010 - 7e eb d2 6f bb 00 18 32-c0 6c de 4b 8f a4 77 10   ~..o...2.l.K..w.
0020 - 43 71 e5 ba 2a 09 1b 70-3b bc 80 69 bc 97 bc 2d   Cq..*..p;..i...-
0030 - d0 d2 36 fa 30 89 55 3b-17 e9 6e c6 a4 64 10 c0   ..6.0.U;..n..d..
0040 - 00 2d ab 9e 5c e6 df b4-a8 53 9c 90 63 48 d9 ab   .-..\....S..cH..
SSL_accept:SSLv3/TLS read change cipher spec
SSL_accept:SSLv3/TLS read finished
SSL_accept:SSLv3/TLS write session ticket
SSL_accept:SSLv3/TLS write change cipher spec
write to 0x20d957e4110 [0x20d95c2be40] (282 bytes => 282 (0x11A))
0000 - 16 03 03 00 ba 04 00 00-b6 00 00 1c 20 00 b0 96   ............ ...
0010 - 67 2d fe 2d c6 99 a8 e9-d1 0f 5a 23 4b 99 af 2a   g-.-......Z#K..*
0020 - f6 45 88 e7 d5 34 6c 9c-09 62 46 73 32 9a dc a9   .E...4l..bFs2...
0030 - e8 0b 1c f0 77 b2 e7 cf-e8 a1 2c c9 39 34 31 9a   ....w.....,.941.
0040 - af b1 95 e3 b8 4d 78 96-d1 7d 12 4d c6 d7 72 34   .....Mx..}.M..r4
0050 - 1d 3c e5 56 07 f1 92 a2-4a ed 9e cb 0a b3 e6 ea   .<.V....J.......
0060 - a5 4b fb 14 5e 2f 93 e6-0e 1b 04 9c c1 54 64 4b   .K..^/.......TdK
0070 - c3 b5 d0 50 0a 59 19 9e-42 5a 7f e7 ac 80 f7 c7   ...P.Y..BZ......
0080 - 2f 06 74 50 3d 5b 2d 34-a5 4f e6 2a 14 74 42 91   /.tP=[-4.O.*.tB.
0090 - a0 4c 51 00 7a e1 41 e2-b5 c2 a0 8b 25 a6 8e 64   .LQ.z.A.....%..d
00a0 - fd 4a 82 21 22 ff 76 eb-72 ce ed 26 80 d7 13 27   .J.!".v.r..&...'
00b0 - 48 cd d1 da 89 d8 fc d8-fe 47 0b 4c 5c 93 b0 14   H........G.L\...
00c0 - 03 03 00 01 01 16 03 03-00 50 aa 69 b7 80 25 eb   .........P.i..%.
00d0 - 0b 3d f4 0c 35 dc 01 a8-95 fc d2 53 66 af 6b b1   .=..5......Sf.k.
00e0 - 83 46 a7 27 5f 5c 48 2d-62 39 80 c2 b3 84 20 c1   .F.'_\H-b9.... .
00f0 - ea ba bb b2 08 2a 41 c9-e1 e1 29 a5 ce c9 a8 66   .....*A...)....f
0100 - eb f1 f8 ef e4 e5 62 86-be e2 8a b6 c6 93 42 92   ......b.......B.
0110 - 4f 2b 76 91 e7 9e 40 f4-33 31                     O+v...@.31
SSL_accept:SSLv3/TLS write finished
-----BEGIN SSL SESSION PARAMETERS-----
MF8CAQECAgMDBALAJwQABDA6OEek0g+XZv+BBAuduJ+F9WsblSavxibAE45bidYs
dGgK94uk2CfuOJiVGIRbyYWhBgIEZ/nDKaIEAgIcIKQGBAQBAAAArQMCAQGzAwIB
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
read from 0x20d957e4110 [0x20d95c2ce53] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 40                                    ....@
read from 0x20d957e4110 [0x20d95c2ce58] (64 bytes => 64 (0x40))
0000 - 94 b3 62 f1 1e 8d 44 5d-51 bb 33 6b bd 23 65 75   ..b...D]Q.3k.#eu
0010 - f8 7e b6 4f 32 e9 fe 23-16 a3 7f 05 5f 6f 54 66   .~.O2..#...._oTf
0020 - 49 a0 05 59 df e3 9d 94-d8 82 9f 85 e7 76 49 14   I..Y.........vI.
0030 - 73 48 d7 e3 9e 02 e3 f6-20 f8 d7 b2 95 09 c0 6a   sH...... ......j
hello
read from 0x20d957e4110 [0x20d95c2ce53] (5 bytes => 5 (0x5))
0000 - 15 03 03 00 40                                    ....@
read from 0x20d957e4110 [0x20d95c2ce58] (64 bytes => 64 (0x40))
0000 - 61 43 21 ca 8f 02 65 10-a4 d4 b4 4a 0c 85 41 9f   aC!...e....J..A.
0010 - cc c6 f6 95 4c 21 3e e2-13 12 6b 29 47 3e 3f d6   ....L!>...k)G>?.
0020 - 17 9f cd f2 81 0c 1b 6c-ef 28 5c d2 e7 1a 97 2f   .......l.(\..../
0030 - d0 96 ac 0e 98 f7 d3 ae-ee 48 1b c5 c1 7d b1 88   .........H...}..
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x20d957e4110 [0x20d95c3d343] (69 bytes => 69 (0x45))
0000 - 15 03 03 00 40 57 61 d6-68 76 c5 bd b4 bc 5d 3d   ....@Wa.hv....]=
0010 - c6 67 3b db 44 96 67 0d-24 2e 67 6d 23 24 f5 75   .g;.D.g.$.gm#$.u
0020 - 4c 67 be e5 57 11 54 29-00 85 c6 0d 43 83 a6 67   Lg..W.T)....C..g
0030 - fe b8 b2 58 a2 26 1b 9b-ec dc eb 52 6e 49 c0 a1   ...X.&.....RnI..
0040 - 1f 93 e5 d6 ea                                    .....
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
