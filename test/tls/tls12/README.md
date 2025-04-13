#### TLS 1.2

* tls12etm.pcapng
  * [server](#tls_12_server_etm)
  * [client](#tls_12_client_etm)
* tls12mte.pcapng
  * [server](#tls_12_server_mte)
  * [client](#tls_12_client_mte)

#### TLS 1.2 server EtM

````
$ openssl s_server -accept 9000 -cert server.crt -key server.key -cipher TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 -state -debug -status_verbose -keylogfile server.keylog -no_tls1_3
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

#### TLS 1.2 client EtM

````
$ openssl s_client -connect localhost:9000 -state -debug -keylogfile client.keylog -tls1_2
Connecting to ::1
CONNECTED(00000074)
SSL_connect:before SSL initialization
write to 0x17eebe223f0 [0x17eec2e5d20] (197 bytes => 197 (0xC5))
0000 - 16 03 01 00 c0 01 00 00-bc 03 03 96 89 88 b1 0e   ................
0010 - d8 d7 2b e8 7f ae a5 64-a0 d8 15 a4 62 f1 41 ca   ..+....d....b.A.
0020 - 80 19 ad c5 33 ae c9 89-15 2b ff 00 00 36 c0 2c   ....3....+...6.,
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
read from 0x17eebe223f0 [0x17eec2eadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 45                                    ....E
read from 0x17eebe223f0 [0x17eec2eadf8] (69 bytes => 69 (0x45))
0000 - 02 00 00 41 03 03 65 8b-66 a2 af 4e 1b 13 dd 8b   ...A..e.f..N....
0010 - 50 51 78 90 21 13 a5 bf-b0 21 ee 8b 24 30 cf ab   PQx.!....!..$0..
0020 - 97 20 b1 37 6d 63 00 c0-27 00 00 19 ff 01 00 01   . .7mc..'.......
0030 - 00 00 0b 00 04 03 00 01-02 00 23 00 00 00 16 00   ..........#.....
0040 - 00 00 17 00 00                                    .....
SSL_connect:SSLv3/TLS write client hello
Can't use SSL_get_servername
read from 0x17eebe223f0 [0x17eec2eadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 03 6a                                    ....j
read from 0x17eebe223f0 [0x17eec2eadf8] (874 bytes => 874 (0x36A))
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
read from 0x17eebe223f0 [0x17eec2eadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 01 2c                                    ....,
read from 0x17eebe223f0 [0x17eec2eadf8] (300 bytes => 300 (0x12C))
0000 - 0c 00 01 28 03 00 1d 20-8e 93 3b 4c a7 02 61 06   ...(... ..;L..a.
0010 - 89 0b e2 d0 3e 0e 05 64-a7 37 9e b8 b9 0b 5b 3d   ....>..d.7....[=
0020 - 68 2c 55 f4 a5 ef 46 67-08 04 01 00 50 ec 45 47   h,U...Fg....P.EG
0030 - 75 24 3b 9c af e9 2f 3a-af 50 bb aa 85 f0 67 5c   u$;.../:.P....g\
0040 - b6 cd 12 e6 7d 01 1a 3f-a5 f4 0a 38 a2 4b 7d 90   ....}..?...8.K}.
0050 - b1 3f 7e 41 3b c6 d2 e0-c6 97 39 6f 22 aa 2b ee   .?~A;.....9o".+.
0060 - 09 d6 83 b9 ab 77 c0 a4-63 e8 cb f2 0a 67 1d 72   .....w..c....g.r
0070 - 71 b8 7a a9 36 b4 90 ad-6d 22 25 01 ee 52 3b ce   q.z.6...m"%..R;.
0080 - b9 56 8b f6 46 38 cf d9-dc d5 30 8e 3c aa e8 05   .V..F8....0.<...
0090 - d7 05 c4 bb 25 33 43 8f-a7 5c 72 a6 c1 c1 f9 3d   ....%3C..\r....=
00a0 - 89 a8 9c b2 15 86 82 11-0e 1f 9c 00 12 6f cd 64   .............o.d
00b0 - 01 57 08 fa 5a 85 f6 5a-be 58 e4 18 20 79 d8 13   .W..Z..Z.X.. y..
00c0 - 6a cf 9a 3a 81 b7 ba 08-e4 4c ed e6 53 f9 f9 a5   j..:.....L..S...
00d0 - 7d 25 27 b7 84 a2 73 86-83 fe 28 d5 50 c4 ad c6   }%'...s...(.P...
00e0 - c2 10 24 f7 89 ec b1 18-a7 75 84 ef d5 52 08 dc   ..$......u...R..
00f0 - 6d 74 0e 99 a7 2e 0b cf-af 85 3b c7 15 a3 52 29   mt........;...R)
0100 - 26 19 d0 cf fc 29 f2 1d-d8 59 b1 5d 4a 54 2b 9e   &....)...Y.]JT+.
0110 - 1e dd 52 fe d8 74 a2 78-ca f5 1b c8 3a c1 06 16   ..R..t.x....:...
0120 - ad 35 4a 84 be 16 2b c6-10 a8 b2 f7               .5J...+.....
SSL_connect:SSLv3/TLS read server certificate
read from 0x17eebe223f0 [0x17eec2eadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 04                                    .....
read from 0x17eebe223f0 [0x17eec2eadf8] (4 bytes => 4 (0x4))
0000 - 0e 00 00 00                                       ....
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client key exchange
SSL_connect:SSLv3/TLS write change cipher spec
write to 0x17eebe223f0 [0x17eec2e5d20] (133 bytes => 133 (0x85))
0000 - 16 03 03 00 25 10 00 00-21 20 86 be ac 52 20 97   ....%...! ...R .
0010 - 62 d5 c1 50 61 5c 9b c5-ba b2 11 89 6c 70 a2 e8   b..Pa\......lp..
0020 - 21 27 b8 80 f4 a1 b1 03-3a 28 14 03 03 00 01 01   !'......:(......
0030 - 16 03 03 00 50 b2 08 4a-5b 1d d6 15 cd 05 6d 1f   ....P..J[.....m.
0040 - 28 8f b8 e5 7b 7e eb d2-6f bb 00 18 32 c0 6c de   (...{~..o...2.l.
0050 - 4b 8f a4 77 10 43 71 e5-ba 2a 09 1b 70 3b bc 80   K..w.Cq..*..p;..
0060 - 69 bc 97 bc 2d d0 d2 36-fa 30 89 55 3b 17 e9 6e   i...-..6.0.U;..n
0070 - c6 a4 64 10 c0 00 2d ab-9e 5c e6 df b4 a8 53 9c   ..d...-..\....S.
0080 - 90 63 48 d9 ab                                    .cH..
SSL_connect:SSLv3/TLS write finished
read from 0x17eebe223f0 [0x17eec2eadf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 ba                                    .....
read from 0x17eebe223f0 [0x17eec2eadf8] (186 bytes => 186 (0xBA))
0000 - 04 00 00 b6 00 00 1c 20-00 b0 96 67 2d fe 2d c6   ....... ...g-.-.
0010 - 99 a8 e9 d1 0f 5a 23 4b-99 af 2a f6 45 88 e7 d5   .....Z#K..*.E...
0020 - 34 6c 9c 09 62 46 73 32-9a dc a9 e8 0b 1c f0 77   4l..bFs2.......w
0030 - b2 e7 cf e8 a1 2c c9 39-34 31 9a af b1 95 e3 b8   .....,.941......
0040 - 4d 78 96 d1 7d 12 4d c6-d7 72 34 1d 3c e5 56 07   Mx..}.M..r4.<.V.
0050 - f1 92 a2 4a ed 9e cb 0a-b3 e6 ea a5 4b fb 14 5e   ...J........K..^
0060 - 2f 93 e6 0e 1b 04 9c c1-54 64 4b c3 b5 d0 50 0a   /.......TdK...P.
0070 - 59 19 9e 42 5a 7f e7 ac-80 f7 c7 2f 06 74 50 3d   Y..BZ....../.tP=
0080 - 5b 2d 34 a5 4f e6 2a 14-74 42 91 a0 4c 51 00 7a   [-4.O.*.tB..LQ.z
0090 - e1 41 e2 b5 c2 a0 8b 25-a6 8e 64 fd 4a 82 21 22   .A.....%..d.J.!"
00a0 - ff 76 eb 72 ce ed 26 80-d7 13 27 48 cd d1 da 89   .v.r..&...'H....
00b0 - d8 fc d8 fe 47 0b 4c 5c-93 b0                     ....G.L\..
SSL_connect:SSLv3/TLS write finished
read from 0x17eebe223f0 [0x17eec2eadf3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x17eebe223f0 [0x17eec2eadf8] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_connect:SSLv3/TLS read server session ticket
read from 0x17eebe223f0 [0x17eec2e8d43] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 50                                    ....P
read from 0x17eebe223f0 [0x17eec2e8d48] (80 bytes => 80 (0x50))
0000 - aa 69 b7 80 25 eb 0b 3d-f4 0c 35 dc 01 a8 95 fc   .i..%..=..5.....
0010 - d2 53 66 af 6b b1 83 46-a7 27 5f 5c 48 2d 62 39   .Sf.k..F.'_\H-b9
0020 - 80 c2 b3 84 20 c1 ea ba-bb b2 08 2a 41 c9 e1 e1   .... ......*A...
0030 - 29 a5 ce c9 a8 66 eb f1-f8 ef e4 e5 62 86 be e2   )....f......b...
0040 - 8a b6 c6 93 42 92 4f 2b-76 91 e7 9e 40 f4 33 31   ....B.O+v...@.31
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
    Session-ID: BAA6E64595379987438B33FE734229ADCB2B6B1E333FC75E35B6BCCC145B99A7
    Session-ID-ctx:
    Master-Key: 3A3847A4D20F9766FF81040B9DB89F85F56B1B9526AFC626C0138E5B89D62C74680AF78BA4D827EE38989518845BC985
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 96 67 2d fe 2d c6 99 a8-e9 d1 0f 5a 23 4b 99 af   .g-.-......Z#K..
    0010 - 2a f6 45 88 e7 d5 34 6c-9c 09 62 46 73 32 9a dc   *.E...4l..bFs2..
    0020 - a9 e8 0b 1c f0 77 b2 e7-cf e8 a1 2c c9 39 34 31   .....w.....,.941
    0030 - 9a af b1 95 e3 b8 4d 78-96 d1 7d 12 4d c6 d7 72   ......Mx..}.M..r
    0040 - 34 1d 3c e5 56 07 f1 92-a2 4a ed 9e cb 0a b3 e6   4.<.V....J......
    0050 - ea a5 4b fb 14 5e 2f 93-e6 0e 1b 04 9c c1 54 64   ..K..^/.......Td
    0060 - 4b c3 b5 d0 50 0a 59 19-9e 42 5a 7f e7 ac 80 f7   K...P.Y..BZ.....
    0070 - c7 2f 06 74 50 3d 5b 2d-34 a5 4f e6 2a 14 74 42   ./.tP=[-4.O.*.tB
    0080 - 91 a0 4c 51 00 7a e1 41-e2 b5 c2 a0 8b 25 a6 8e   ..LQ.z.A.....%..
    0090 - 64 fd 4a 82 21 22 ff 76-eb 72 ce ed 26 80 d7 13   d.J.!".v.r..&...
    00a0 - 27 48 cd d1 da 89 d8 fc-d8 fe 47 0b 4c 5c 93 b0   'H........G.L\..

    Start Time: 1744421673
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: yes
---
hello
write to 0x17eebe223f0 [0x17eec2fa6e3] (69 bytes => 69 (0x45))
0000 - 17 03 03 00 40 94 b3 62-f1 1e 8d 44 5d 51 bb 33   ....@..b...D]Q.3
0010 - 6b bd 23 65 75 f8 7e b6-4f 32 e9 fe 23 16 a3 7f   k.#eu.~.O2..#...
0020 - 05 5f 6f 54 66 49 a0 05-59 df e3 9d 94 d8 82 9f   ._oTfI..Y.......
0030 - 85 e7 76 49 14 73 48 d7-e3 9e 02 e3 f6 20 f8 d7   ..vI.sH...... ..
0040 - b2 95 09 c0 6a                                    ....j
Q
DONE
write to 0x17eebe223f0 [0x17eec2fa6e3] (69 bytes => 69 (0x45))
0000 - 15 03 03 00 40 61 43 21-ca 8f 02 65 10 a4 d4 b4   ....@aC!...e....
0010 - 4a 0c 85 41 9f cc c6 f6-95 4c 21 3e e2 13 12 6b   J..A.....L!>...k
0020 - 29 47 3e 3f d6 17 9f cd-f2 81 0c 1b 6c ef 28 5c   )G>?........l.(\
0030 - d2 e7 1a 97 2f d0 96 ac-0e 98 f7 d3 ae ee 48 1b   ..../.........H.
0040 - c5 c1 7d b1 88                                    ..}..
SSL3 alert write:warning:close notify
read from 0x17eebe223f0 [0x17eebd67cf0] (16384 bytes => 69 (0x45))
0000 - 15 03 03 00 40 57 61 d6-68 76 c5 bd b4 bc 5d 3d   ....@Wa.hv....]=
0010 - c6 67 3b db 44 96 67 0d-24 2e 67 6d 23 24 f5 75   .g;.D.g.$.gm#$.u
0020 - 4c 67 be e5 57 11 54 29-00 85 c6 0d 43 83 a6 67   Lg..W.T)....C..g
0030 - fe b8 b2 58 a2 26 1b 9b-ec dc eb 52 6e 49 c0 a1   ...X.&.....RnI..
0040 - 1f 93 e5 d6 ea                                    .....
read from 0x17eebe223f0 [0x17eebd67cf0] (16384 bytes => 0)
````

#### TLS 1.2 server MtE

````
$  openssl s_server -accept 9000 -cert server.crt -key server.key -cipher TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 -state -debug -status_verbose -keylogfile server.keylog -no_tls1_3
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

#### TLS 1.2 client MtE

````
$ ./test-netclient.exe -v -d -A -P tls12
socket 464 created family 2(AF_INET) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 000001e4 created
iocp handle 000001e4 bind 464
- event_loop_new tid 0000660c
# write record content type 0x16(22) (handshake)
# write handshake type 0x01(1) (client_hello)
version 30400000
no bf-cbc
no bf-cfb
no bf-ecb
no bf-ofb
no camellia-128-gcm
no camellia-192-gcm
no camellia-256-gcm
no cast5-cbc
no cast5-cfb
no cast5-ecb
no cast5-ofb
no idea-cbc
no idea-cfb
no idea-ecb
no idea-ofb
no rc2-cbc
no rc2-cfb
no rc2-ecb
no rc2-ofb
no rc5-cbc
no rc5-cfb
no rc5-ecb
no rc5-ofb
no seed-cbc
no seed-cfb
no seed-ecb
no seed-ofb
no rc4
no md4
no whirlpool
# record constructed
   00000000 : 16 03 03 00 CC 01 00 00 C8 03 03 88 06 AA F3 BA | ................
   00000010 : B7 CF A0 06 49 7E F5 06 20 DD AE 53 20 BF 15 41 | ....I~.. ..S ..A
   00000020 : D2 D2 A9 7A FB 85 14 5A A1 D2 75 20 B4 81 AC D6 | ...z...Z..u ....
   00000030 : E0 A2 2E 0F A5 D6 0D B9 FD 2D 02 3C 32 FB 20 89 | .........-.<2. .
   00000040 : 4A 64 AF 87 4E 7A 68 4F DF 4F 6F 5A 00 10 C0 23 | Jd..NzhO.OoZ...#
   00000050 : C0 24 C0 27 C0 28 C0 2B C0 2C C0 2F C0 30 01 00 | .$.'.(.+.,./.0..
   00000060 : 00 6F 00 0B 00 02 01 00 00 0A 00 0C 00 0A 00 1D | .o..............
   00000070 : 00 17 00 1E 00 19 00 18 00 0D 00 1E 00 1C 04 03 | ................
   00000080 : 05 03 06 03 08 07 08 08 04 01 05 01 06 01 08 09 | ................
   00000090 : 08 0A 08 0B 08 04 08 05 08 06 00 2B 00 03 02 03 | ...........+....
   000000A0 : 03 00 2D 00 02 01 01 00 33 00 26 00 24 00 1D 00 | ..-.....3.&.$...
   000000B0 : 20 AB A4 8C AB AB 5B E5 92 54 CC 25 C8 B3 67 AE |  .....[..T.%..g.
   000000C0 : 0D 35 8B 69 1F 3B 98 D0 4B 5C 67 3B 55 F0 D2 91 | .5.i.;..K\g;U...
   000000D0 : 57 -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- | W
[ns] read 0x502
   00000000 : 16 03 03 00 54 02 00 00 50 03 03 E7 36 BE 0B F5 | ....T...P...6...
   00000010 : E6 D9 FF EC 34 8B 1D 22 2E 5E 5F 0D D2 D4 A4 6C | ....4..".^_....l
   00000020 : 99 AE 52 1D E3 54 08 88 72 CA AB 20 37 9E F9 6B | ..R..T..r.. 7..k
   00000030 : 1C 03 10 52 81 88 10 C9 2B 67 F0 B7 F9 E0 5F 7B | ...R....+g...._{
   00000040 : D4 E2 E8 AA ED FF 4D 55 D8 7D A7 77 C0 27 00 00 | ......MU.}.w.'..
   00000050 : 08 00 0B 00 04 03 00 01 02 16 03 03 03 6A 0B 00 | .............j..
   00000060 : 03 66 00 03 63 00 03 60 30 82 03 5C 30 82 02 44 | .f..c..`0..\0..D
   00000070 : A0 03 02 01 02 02 14 63 A6 71 10 79 D6 A6 48 59 | .......c.q.y..HY
   00000080 : DA 67 A9 04 E8 E3 5F E2 03 A3 26 30 0D 06 09 2A | .g...._...&0...*
   00000090 : 86 48 86 F7 0D 01 01 0B 05 00 30 59 31 0B 30 09 | .H........0Y1.0.
   000000A0 : 06 03 55 04 06 13 02 4B 52 31 0B 30 09 06 03 55 | ..U....KR1.0...U
   000000B0 : 04 08 0C 02 47 47 31 0B 30 09 06 03 55 04 07 0C | ....GG1.0...U...
   000000C0 : 02 59 49 31 0D 30 0B 06 03 55 04 0A 0C 04 54 65 | .YI1.0...U....Te
   000000D0 : 73 74 31 0D 30 0B 06 03 55 04 0B 0C 04 54 65 73 | st1.0...U....Tes
   000000E0 : 74 31 12 30 10 06 03 55 04 03 0C 09 54 65 73 74 | t1.0...U....Test
   000000F0 : 20 52 6F 6F 74 30 1E 17 0D 32 34 30 38 32 39 30 |  Root0...2408290
   00000100 : 36 32 37 31 37 5A 17 0D 32 35 30 38 32 39 30 36 | 62717Z..25082906
   00000110 : 32 37 31 37 5A 30 54 31 0B 30 09 06 03 55 04 06 | 2717Z0T1.0...U..
   00000120 : 13 02 4B 52 31 0B 30 09 06 03 55 04 08 0C 02 47 | ..KR1.0...U....G
   00000130 : 47 31 0B 30 09 06 03 55 04 07 0C 02 59 49 31 0D | G1.0...U....YI1.
   00000140 : 30 0B 06 03 55 04 0A 0C 04 54 65 73 74 31 0D 30 | 0...U....Test1.0
   00000150 : 0B 06 03 55 04 0B 0C 04 54 65 73 74 31 0D 30 0B | ...U....Test1.0.
   00000160 : 06 03 55 04 03 0C 04 54 65 73 74 30 82 01 22 30 | ..U....Test0.."0
   00000170 : 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00 03 82 | ...*.H..........
   00000180 : 01 0F 00 30 82 01 0A 02 82 01 01 00 AD 9A 29 67 | ...0..........)g
   00000190 : 5F F3 A4 79 B4 C6 E6 32 73 D8 D7 ED 88 94 15 83 | _..y...2s.......
   000001A0 : E4 31 00 04 6C B5 8C AC 87 AB 74 44 13 76 CA 0B | .1..l.....tD.v..
   000001B0 : 74 29 40 9E 97 2A 01 D7 8B 46 26 6E 19 35 4D C0 | t)@..*...F&n.5M.
   000001C0 : D3 B5 EA 0E 93 3A 06 E8 E5 85 B5 27 05 63 DB 28 | .....:.....'.c.(
   000001D0 : B8 92 DA 5A 14 39 0F DA 68 6D 6F 0A FB 52 DC 08 | ...Z.9..hmo..R..
   000001E0 : 0F 54 D3 E4 A2 28 9D A0 71 50 82 E0 DB CA D1 94 | .T...(..qP......
   000001F0 : DD 42 98 3A 09 33 A8 D9 EF FB D2 35 43 B1 22 A2 | .B.:.3.....5C.".
   00000200 : BE 41 6D BA 91 DC 0B 31 4E 88 F9 4D 9C 61 2D EC | .Am....1N..M.a-.
   00000210 : B2 13 0A C2 91 8E A2 D6 E9 40 B9 32 B9 80 8F B3 | .........@.2....
   00000220 : 18 A3 33 13 23 D5 D0 7E D9 D0 7F 93 E0 2D 4D 90 | ..3.#..~.....-M.
   00000230 : C5 58 24 56 D5 C9 10 13 4A B2 99 23 7D 34 B9 8E | .X$V....J..#}4..
   00000240 : 97 19 69 6F CE C6 3F D6 17 A7 D2 43 E0 36 CB 51 | ..io..?....C.6.Q
   00000250 : 7B 2F 18 8B C2 33 F8 57 CF D1 61 0B 7C ED 37 35 | {/...3.W..a.|.75
   00000260 : E3 13 7A 24 2E 77 08 C2 E3 D9 E6 17 D3 A5 C6 34 | ..z$.w.........4
   00000270 : 5A DA 86 A7 F8 02 36 1D 66 63 CF E9 C0 3D 82 FB | Z.....6.fc...=..
   00000280 : 39 A2 8D 92 01 4A 83 CF E2 76 3D 87 02 03 01 00 | 9....J...v=.....
   00000290 : 01 A3 21 30 1F 30 1D 06 03 55 1D 11 04 16 30 14 | ..!0.0...U....0.
   000002A0 : 82 12 74 65 73 74 2E 70 72 69 6E 63 65 62 36 31 | ..test.princeb61
   000002B0 : 32 2E 70 65 30 0D 06 09 2A 86 48 86 F7 0D 01 01 | 2.pe0...*.H.....
   000002C0 : 0B 05 00 03 82 01 01 00 00 A5 F5 54 18 AB AD 36 | ...........T...6
   000002D0 : 38 C8 FC 0B 66 60 DD 9F 75 9D 86 5B 79 2F EE 57 | 8...f`..u..[y/.W
   000002E0 : F1 79 1C 15 A1 34 23 D0 1C A9 58 51 A4 D0 08 F5 | .y...4#...XQ....
   000002F0 : D8 F7 49 E9 C5 B5 65 91 51 2D 6D E4 3B 0E 77 02 | ..I...e.Q-m.;.w.
   00000300 : 1F 45 8E 34 E5 BB EB F6 9D DF 4A 40 60 21 B3 8E | .E.4......J@`!..
   00000310 : 16 33 3F F4 B6 90 D3 3C 34 CE E6 D9 47 07 A7 57 | .3?....<4...G..W
   00000320 : 14 0C F9 78 0B 36 72 A9 88 07 07 93 B4 D7 FE 29 | ...x.6r........)
   00000330 : 5E E8 41 37 20 A5 03 C7 97 CB 82 CA DB 14 E5 8B | ^.A7 ...........
   00000340 : 96 1F A9 E9 20 3D 6B 25 AE F4 89 4C 60 8D E9 14 | .... =k%...L`...
   00000350 : 33 47 4B 88 54 A2 47 19 81 C8 7B 0E 32 52 2B 91 | 3GK.T.G...{.2R+.
   00000360 : 88 AD 0F 6D 73 30 8C 00 AF D5 FC 46 46 AF 3A C2 | ...ms0.....FF.:.
   00000370 : 17 89 EC C8 83 AE DA E6 69 63 E0 9C 84 22 C5 7A | ........ic...".z
   00000380 : DE E8 23 6B 53 9D 6F 94 D2 7F 5C BE 1D 0C DE 0E | ..#kS.o...\.....
   00000390 : 07 0D 52 A5 43 8C E8 05 EF C0 FF F0 73 FA DC 5A | ..R.C.......s..Z
   000003A0 : 51 4C 24 09 65 45 7D AB 52 8B 7E 5D F0 FB DE A7 | QL$.eE}.R.~]....
   000003B0 : 3D 43 C5 AF 76 E3 6E F9 A1 DC 78 A2 BD 54 41 04 | =C..v.n...x..TA.
   000003C0 : 99 E5 56 32 BA 02 FD 72 16 03 03 01 2C 0C 00 01 | ..V2...r....,...
   000003D0 : 28 03 00 1D 20 F4 29 00 FF 3D 69 88 1D A1 44 60 | (... .)..=i...D`
   000003E0 : 74 0F AC 51 A0 4C B5 EF 3F FD EB FF 76 63 6E 9C | t..Q.L..?...vcn.
   000003F0 : 5D FE 3D 31 2B 04 01 01 00 4D 94 81 0F DD 66 C6 | ].=1+....M....f.
   00000400 : 7A FD 9B B4 22 EB 76 B7 DB 28 4B AD 39 00 D5 F7 | z...".v..(K.9...
   00000410 : E5 7A 41 DB D9 30 72 B4 C5 B9 09 ED 75 C1 ED 72 | .zA..0r.....u..r
   00000420 : E2 15 6F 3F D0 4B 81 46 FB 7A AE 8C C3 C3 10 16 | ..o?.K.F.z......
   00000430 : F2 71 69 CE 4E D2 84 49 2C 40 37 0E B9 60 60 36 | .qi.N..I,@7..``6
   00000440 : CE 66 2C 05 F1 A3 59 E5 6D 4D 06 BD 72 7D EB C2 | .f,...Y.mM..r}..
   00000450 : 72 2E 1B 55 85 51 1F 03 55 68 6D 6D A8 EA 96 BE | r..U.Q..Uhmm....
   00000460 : A6 20 EB 08 24 E5 A8 86 18 0A 06 58 37 DA 81 E0 | . ..$......X7...
   00000470 : EA 9E 05 6C 2C CF 76 4B 29 FE 52 F4 6A A6 FA B8 | ...l,.vK).R.j...
   00000480 : D9 81 DB EB 08 DB C4 80 C2 1D 04 B1 FB 7C 5C B2 | .............|\.
   00000490 : 73 BF 06 C8 61 7D 18 BB F8 2B 02 68 9B 52 E2 FA | s...a}...+.h.R..
   000004A0 : CA 74 3D 07 DD EB 0C 59 24 61 C2 21 5E 09 12 4E | .t=....Y$a.!^..N
   000004B0 : DB 7E 2E D4 D7 BC D6 2B 21 B7 D7 CE B1 65 F8 0E | .~.....+!....e..
   000004C0 : 2F EC 8C 36 C4 5A 03 3A 13 57 6D 2B 15 DF 65 29 | /..6.Z.:.Wm+..e)
   000004D0 : 75 41 E0 1D A0 82 BA EE 12 45 8A E8 57 75 6D 85 | uA.......E..Wum.
   000004E0 : 3E C2 D3 DC 5A 69 F7 D5 34 12 51 67 98 2D A0 F1 | >...Zi..4.Qg.-..
   000004F0 : 81 41 12 1C F6 41 F1 A0 09 16 03 03 00 04 0E 00 | .A...A..........
   00000500 : 00 00 -- -- -- -- -- -- -- -- -- -- -- -- -- -- | ..
# record (server) [size 0x502 pos 0x0]
   00000000 : 16 03 03 00 54 02 00 00 50 03 03 E7 36 BE 0B F5 | ....T...P...6...
   00000010 : E6 D9 FF EC 34 8B 1D 22 2E 5E 5F 0D D2 D4 A4 6C | ....4..".^_....l
   00000020 : 99 AE 52 1D E3 54 08 88 72 CA AB 20 37 9E F9 6B | ..R..T..r.. 7..k
   00000030 : 1C 03 10 52 81 88 10 C9 2B 67 F0 B7 F9 E0 5F 7B | ...R....+g...._{
   00000040 : D4 E2 E8 AA ED FF 4D 55 D8 7D A7 77 C0 27 00 00 | ......MU.}.w.'..
   00000050 : 08 00 0B 00 04 03 00 01 02 -- -- -- -- -- -- -- | .........
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x0054(84)
 > handshake type 0x02(2) (server_hello)
  > length 0x000050(80)
  > version 0x0303 (TLS v1.2)
  > random
    e736be0bf5e6d9ffec348b1d222e5e5f0dd2d4a46c99ae521de354088872caab
  > session id
    379ef96b1c031052818810c92b67f0b7f9e05f7bd4e2e8aaedff4d55d87da777
  > cipher suite 0xc027 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  > compression method 0 null
  > extension len 0x08(8)
  > extension - 000b ec_point_formats
    00000000 : 00 0B 00 04 03 00 01 02 -- -- -- -- -- -- -- -- | ........
   > extension len 0x0004(4)
   > formats 3
     [0] 0x00(0) uncompressed
     [1] 0x01(1) ansiX962_compressed_prime
     [2] 0x02(2) ansiX962_compressed_char2
# starting transcript_hash
 > cipher suite 0xc027 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
 > sha256
# record (server) [size 0x502 pos 0x59]
   00000000 : 16 03 03 03 6A 0B 00 03 66 00 03 63 00 03 60 30 | ....j...f..c..`0
   00000010 : 82 03 5C 30 82 02 44 A0 03 02 01 02 02 14 63 A6 | ..\0..D.......c.
   00000020 : 71 10 79 D6 A6 48 59 DA 67 A9 04 E8 E3 5F E2 03 | q.y..HY.g...._..
   00000030 : A3 26 30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 05 | .&0...*.H.......
   00000040 : 00 30 59 31 0B 30 09 06 03 55 04 06 13 02 4B 52 | .0Y1.0...U....KR
   00000050 : 31 0B 30 09 06 03 55 04 08 0C 02 47 47 31 0B 30 | 1.0...U....GG1.0
   00000060 : 09 06 03 55 04 07 0C 02 59 49 31 0D 30 0B 06 03 | ...U....YI1.0...
   00000070 : 55 04 0A 0C 04 54 65 73 74 31 0D 30 0B 06 03 55 | U....Test1.0...U
   00000080 : 04 0B 0C 04 54 65 73 74 31 12 30 10 06 03 55 04 | ....Test1.0...U.
   00000090 : 03 0C 09 54 65 73 74 20 52 6F 6F 74 30 1E 17 0D | ...Test Root0...
   000000A0 : 32 34 30 38 32 39 30 36 32 37 31 37 5A 17 0D 32 | 240829062717Z..2
   000000B0 : 35 30 38 32 39 30 36 32 37 31 37 5A 30 54 31 0B | 50829062717Z0T1.
   000000C0 : 30 09 06 03 55 04 06 13 02 4B 52 31 0B 30 09 06 | 0...U....KR1.0..
   000000D0 : 03 55 04 08 0C 02 47 47 31 0B 30 09 06 03 55 04 | .U....GG1.0...U.
   000000E0 : 07 0C 02 59 49 31 0D 30 0B 06 03 55 04 0A 0C 04 | ...YI1.0...U....
   000000F0 : 54 65 73 74 31 0D 30 0B 06 03 55 04 0B 0C 04 54 | Test1.0...U....T
   00000100 : 65 73 74 31 0D 30 0B 06 03 55 04 03 0C 04 54 65 | est1.0...U....Te
   00000110 : 73 74 30 82 01 22 30 0D 06 09 2A 86 48 86 F7 0D | st0.."0...*.H...
   00000120 : 01 01 01 05 00 03 82 01 0F 00 30 82 01 0A 02 82 | ..........0.....
   00000130 : 01 01 00 AD 9A 29 67 5F F3 A4 79 B4 C6 E6 32 73 | .....)g_..y...2s
   00000140 : D8 D7 ED 88 94 15 83 E4 31 00 04 6C B5 8C AC 87 | ........1..l....
   00000150 : AB 74 44 13 76 CA 0B 74 29 40 9E 97 2A 01 D7 8B | .tD.v..t)@..*...
   00000160 : 46 26 6E 19 35 4D C0 D3 B5 EA 0E 93 3A 06 E8 E5 | F&n.5M......:...
   00000170 : 85 B5 27 05 63 DB 28 B8 92 DA 5A 14 39 0F DA 68 | ..'.c.(...Z.9..h
   00000180 : 6D 6F 0A FB 52 DC 08 0F 54 D3 E4 A2 28 9D A0 71 | mo..R...T...(..q
   00000190 : 50 82 E0 DB CA D1 94 DD 42 98 3A 09 33 A8 D9 EF | P.......B.:.3...
   000001A0 : FB D2 35 43 B1 22 A2 BE 41 6D BA 91 DC 0B 31 4E | ..5C."..Am....1N
   000001B0 : 88 F9 4D 9C 61 2D EC B2 13 0A C2 91 8E A2 D6 E9 | ..M.a-..........
   000001C0 : 40 B9 32 B9 80 8F B3 18 A3 33 13 23 D5 D0 7E D9 | @.2......3.#..~.
   000001D0 : D0 7F 93 E0 2D 4D 90 C5 58 24 56 D5 C9 10 13 4A | ....-M..X$V....J
   000001E0 : B2 99 23 7D 34 B9 8E 97 19 69 6F CE C6 3F D6 17 | ..#}4....io..?..
   000001F0 : A7 D2 43 E0 36 CB 51 7B 2F 18 8B C2 33 F8 57 CF | ..C.6.Q{/...3.W.
   00000200 : D1 61 0B 7C ED 37 35 E3 13 7A 24 2E 77 08 C2 E3 | .a.|.75..z$.w...
   00000210 : D9 E6 17 D3 A5 C6 34 5A DA 86 A7 F8 02 36 1D 66 | ......4Z.....6.f
   00000220 : 63 CF E9 C0 3D 82 FB 39 A2 8D 92 01 4A 83 CF E2 | c...=..9....J...
   00000230 : 76 3D 87 02 03 01 00 01 A3 21 30 1F 30 1D 06 03 | v=.......!0.0...
   00000240 : 55 1D 11 04 16 30 14 82 12 74 65 73 74 2E 70 72 | U....0...test.pr
   00000250 : 69 6E 63 65 62 36 31 32 2E 70 65 30 0D 06 09 2A | inceb612.pe0...*
   00000260 : 86 48 86 F7 0D 01 01 0B 05 00 03 82 01 01 00 00 | .H..............
   00000270 : A5 F5 54 18 AB AD 36 38 C8 FC 0B 66 60 DD 9F 75 | ..T...68...f`..u
   00000280 : 9D 86 5B 79 2F EE 57 F1 79 1C 15 A1 34 23 D0 1C | ..[y/.W.y...4#..
   00000290 : A9 58 51 A4 D0 08 F5 D8 F7 49 E9 C5 B5 65 91 51 | .XQ......I...e.Q
   000002A0 : 2D 6D E4 3B 0E 77 02 1F 45 8E 34 E5 BB EB F6 9D | -m.;.w..E.4.....
   000002B0 : DF 4A 40 60 21 B3 8E 16 33 3F F4 B6 90 D3 3C 34 | .J@`!...3?....<4
   000002C0 : CE E6 D9 47 07 A7 57 14 0C F9 78 0B 36 72 A9 88 | ...G..W...x.6r..
   000002D0 : 07 07 93 B4 D7 FE 29 5E E8 41 37 20 A5 03 C7 97 | ......)^.A7 ....
   000002E0 : CB 82 CA DB 14 E5 8B 96 1F A9 E9 20 3D 6B 25 AE | ........... =k%.
   000002F0 : F4 89 4C 60 8D E9 14 33 47 4B 88 54 A2 47 19 81 | ..L`...3GK.T.G..
   00000300 : C8 7B 0E 32 52 2B 91 88 AD 0F 6D 73 30 8C 00 AF | .{.2R+....ms0...
   00000310 : D5 FC 46 46 AF 3A C2 17 89 EC C8 83 AE DA E6 69 | ..FF.:.........i
   00000320 : 63 E0 9C 84 22 C5 7A DE E8 23 6B 53 9D 6F 94 D2 | c...".z..#kS.o..
   00000330 : 7F 5C BE 1D 0C DE 0E 07 0D 52 A5 43 8C E8 05 EF | .\.......R.C....
   00000340 : C0 FF F0 73 FA DC 5A 51 4C 24 09 65 45 7D AB 52 | ...s..ZQL$.eE}.R
   00000350 : 8B 7E 5D F0 FB DE A7 3D 43 C5 AF 76 E3 6E F9 A1 | .~]....=C..v.n..
   00000360 : DC 78 A2 BD 54 41 04 99 E5 56 32 BA 02 FD 72 -- | .x..TA...V2...r
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x036a(874)
 > handshake type 0x0b(11) (certificate)
  > length 0x000366(870)
  > request context len 0
  > certifcates len 0x0363(867)
  > certifcate len 0x0360(864)
    00000000 : 30 82 03 5C 30 82 02 44 A0 03 02 01 02 02 14 63 | 0..\0..D.......c
    00000010 : A6 71 10 79 D6 A6 48 59 DA 67 A9 04 E8 E3 5F E2 | .q.y..HY.g...._.
    00000020 : 03 A3 26 30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B | ..&0...*.H......
    00000030 : 05 00 30 59 31 0B 30 09 06 03 55 04 06 13 02 4B | ..0Y1.0...U....K
    00000040 : 52 31 0B 30 09 06 03 55 04 08 0C 02 47 47 31 0B | R1.0...U....GG1.
    00000050 : 30 09 06 03 55 04 07 0C 02 59 49 31 0D 30 0B 06 | 0...U....YI1.0..
    00000060 : 03 55 04 0A 0C 04 54 65 73 74 31 0D 30 0B 06 03 | .U....Test1.0...
    00000070 : 55 04 0B 0C 04 54 65 73 74 31 12 30 10 06 03 55 | U....Test1.0...U
    00000080 : 04 03 0C 09 54 65 73 74 20 52 6F 6F 74 30 1E 17 | ....Test Root0..
    00000090 : 0D 32 34 30 38 32 39 30 36 32 37 31 37 5A 17 0D | .240829062717Z..
    000000A0 : 32 35 30 38 32 39 30 36 32 37 31 37 5A 30 54 31 | 250829062717Z0T1
    000000B0 : 0B 30 09 06 03 55 04 06 13 02 4B 52 31 0B 30 09 | .0...U....KR1.0.
    000000C0 : 06 03 55 04 08 0C 02 47 47 31 0B 30 09 06 03 55 | ..U....GG1.0...U
    000000D0 : 04 07 0C 02 59 49 31 0D 30 0B 06 03 55 04 0A 0C | ....YI1.0...U...
    000000E0 : 04 54 65 73 74 31 0D 30 0B 06 03 55 04 0B 0C 04 | .Test1.0...U....
    000000F0 : 54 65 73 74 31 0D 30 0B 06 03 55 04 03 0C 04 54 | Test1.0...U....T
    00000100 : 65 73 74 30 82 01 22 30 0D 06 09 2A 86 48 86 F7 | est0.."0...*.H..
    00000110 : 0D 01 01 01 05 00 03 82 01 0F 00 30 82 01 0A 02 | ...........0....
    00000120 : 82 01 01 00 AD 9A 29 67 5F F3 A4 79 B4 C6 E6 32 | ......)g_..y...2
    00000130 : 73 D8 D7 ED 88 94 15 83 E4 31 00 04 6C B5 8C AC | s........1..l...
    00000140 : 87 AB 74 44 13 76 CA 0B 74 29 40 9E 97 2A 01 D7 | ..tD.v..t)@..*..
    00000150 : 8B 46 26 6E 19 35 4D C0 D3 B5 EA 0E 93 3A 06 E8 | .F&n.5M......:..
    00000160 : E5 85 B5 27 05 63 DB 28 B8 92 DA 5A 14 39 0F DA | ...'.c.(...Z.9..
    00000170 : 68 6D 6F 0A FB 52 DC 08 0F 54 D3 E4 A2 28 9D A0 | hmo..R...T...(..
    00000180 : 71 50 82 E0 DB CA D1 94 DD 42 98 3A 09 33 A8 D9 | qP.......B.:.3..
    00000190 : EF FB D2 35 43 B1 22 A2 BE 41 6D BA 91 DC 0B 31 | ...5C."..Am....1
    000001A0 : 4E 88 F9 4D 9C 61 2D EC B2 13 0A C2 91 8E A2 D6 | N..M.a-.........
    000001B0 : E9 40 B9 32 B9 80 8F B3 18 A3 33 13 23 D5 D0 7E | .@.2......3.#..~
    000001C0 : D9 D0 7F 93 E0 2D 4D 90 C5 58 24 56 D5 C9 10 13 | .....-M..X$V....
    000001D0 : 4A B2 99 23 7D 34 B9 8E 97 19 69 6F CE C6 3F D6 | J..#}4....io..?.
    000001E0 : 17 A7 D2 43 E0 36 CB 51 7B 2F 18 8B C2 33 F8 57 | ...C.6.Q{/...3.W
    000001F0 : CF D1 61 0B 7C ED 37 35 E3 13 7A 24 2E 77 08 C2 | ..a.|.75..z$.w..
    00000200 : E3 D9 E6 17 D3 A5 C6 34 5A DA 86 A7 F8 02 36 1D | .......4Z.....6.
    00000210 : 66 63 CF E9 C0 3D 82 FB 39 A2 8D 92 01 4A 83 CF | fc...=..9....J..
    00000220 : E2 76 3D 87 02 03 01 00 01 A3 21 30 1F 30 1D 06 | .v=.......!0.0..
    00000230 : 03 55 1D 11 04 16 30 14 82 12 74 65 73 74 2E 70 | .U....0...test.p
    00000240 : 72 69 6E 63 65 62 36 31 32 2E 70 65 30 0D 06 09 | rinceb612.pe0...
    00000250 : 2A 86 48 86 F7 0D 01 01 0B 05 00 03 82 01 01 00 | *.H.............
    00000260 : 00 A5 F5 54 18 AB AD 36 38 C8 FC 0B 66 60 DD 9F | ...T...68...f`..
    00000270 : 75 9D 86 5B 79 2F EE 57 F1 79 1C 15 A1 34 23 D0 | u..[y/.W.y...4#.
    00000280 : 1C A9 58 51 A4 D0 08 F5 D8 F7 49 E9 C5 B5 65 91 | ..XQ......I...e.
    00000290 : 51 2D 6D E4 3B 0E 77 02 1F 45 8E 34 E5 BB EB F6 | Q-m.;.w..E.4....
    000002A0 : 9D DF 4A 40 60 21 B3 8E 16 33 3F F4 B6 90 D3 3C | ..J@`!...3?....<
    000002B0 : 34 CE E6 D9 47 07 A7 57 14 0C F9 78 0B 36 72 A9 | 4...G..W...x.6r.
    000002C0 : 88 07 07 93 B4 D7 FE 29 5E E8 41 37 20 A5 03 C7 | .......)^.A7 ...
    000002D0 : 97 CB 82 CA DB 14 E5 8B 96 1F A9 E9 20 3D 6B 25 | ............ =k%
    000002E0 : AE F4 89 4C 60 8D E9 14 33 47 4B 88 54 A2 47 19 | ...L`...3GK.T.G.
    000002F0 : 81 C8 7B 0E 32 52 2B 91 88 AD 0F 6D 73 30 8C 00 | ..{.2R+....ms0..
    00000300 : AF D5 FC 46 46 AF 3A C2 17 89 EC C8 83 AE DA E6 | ...FF.:.........
    00000310 : 69 63 E0 9C 84 22 C5 7A DE E8 23 6B 53 9D 6F 94 | ic...".z..#kS.o.
    00000320 : D2 7F 5C BE 1D 0C DE 0E 07 0D 52 A5 43 8C E8 05 | ..\.......R.C...
    00000330 : EF C0 FF F0 73 FA DC 5A 51 4C 24 09 65 45 7D AB | ....s..ZQL$.eE}.
    00000340 : 52 8B 7E 5D F0 FB DE A7 3D 43 C5 AF 76 E3 6E F9 | R.~]....=C..v.n.
    00000350 : A1 DC 78 A2 BD 54 41 04 99 E5 56 32 BA 02 FD 72 | ..x..TA...V2...r
  > certificate extensions 0x0000(0)
 RSA (public key)
   modulus (00:n)
     00:ad:9a:29:67:5f:f3:a4:79:b4:c6:e6:32:73:d8:
     d7:ed:88:94:15:83:e4:31:00:04:6c:b5:8c:ac:87:
     ab:74:44:13:76:ca:0b:74:29:40:9e:97:2a:01:d7:
     8b:46:26:6e:19:35:4d:c0:d3:b5:ea:0e:93:3a:06:
     e8:e5:85:b5:27:05:63:db:28:b8:92:da:5a:14:39:
     0f:da:68:6d:6f:0a:fb:52:dc:08:0f:54:d3:e4:a2:
     28:9d:a0:71:50:82:e0:db:ca:d1:94:dd:42:98:3a:
     09:33:a8:d9:ef:fb:d2:35:43:b1:22:a2:be:41:6d:
     ba:91:dc:0b:31:4e:88:f9:4d:9c:61:2d:ec:b2:13:
     0a:c2:91:8e:a2:d6:e9:40:b9:32:b9:80:8f:b3:18:
     a3:33:13:23:d5:d0:7e:d9:d0:7f:93:e0:2d:4d:90:
     c5:58:24:56:d5:c9:10:13:4a:b2:99:23:7d:34:b9:
     8e:97:19:69:6f:ce:c6:3f:d6:17:a7:d2:43:e0:36:
     cb:51:7b:2f:18:8b:c2:33:f8:57:cf:d1:61:0b:7c:
     ed:37:35:e3:13:7a:24:2e:77:08:c2:e3:d9:e6:17:
     d3:a5:c6:34:5a:da:86:a7:f8:02:36:1d:66:63:cf:
     e9:c0:3d:82:fb:39:a2:8d:92:01:4a:83:cf:e2:76:
     3d:87
     rZopZ1_zpHm0xuYyc9jX7YiUFYPkMQAEbLWMrIerdEQTdsoLdClAnpcqAdeLRiZuGTVNwNO16g6TOgbo5YW1JwVj2yi4ktpaFDkP2mhtbwr7UtwID1TT5KIonaBxUILg28rRlN1CmDoJM6jZ7_vSNUOxIqK-QW26kdwLMU6I-U2cYS3sshMKwpGOotbpQLkyuYCPsxijMxMj1dB-2dB_k-AtTZDFWCRW1ckQE0qymSN9NLmOlxlpb87GP9YXp9JD4DbLUXsvGIvCM_hXz9FhC3ztNzXjE3okLncIwuPZ5hfTpcY0WtqGp_gCNh1mY8_pwD2C-zmijZIBSoPP4nY9hw
     h'ad9a29675ff3a479b4c6e63273d8d7ed88941583e43100046cb58cac87ab74441376ca0b7429409e972a01d78b46266e19354dc0d3b5ea0e933a06e8e585b5270563db28b892da5a14390fda686d6f0afb52dc080f54d3e4a2289da0715082e0dbcad194dd42983a0933a8d9effbd23543b122a2be416dba91dc0b314e88f94d9c612decb2130ac2918ea2d6e940b932b9808fb318a3331323d5d07ed9d07f93e02d4d90c5582456d5c910134ab299237d34b98e9719696fcec63fd617a7d243e036cb517b2f188bc233f857cfd1610b7ced3735e3137a242e7708c2e3d9e617d3a5c6345ada86a7f802361d6663cfe9c03d82fb39a28d92014a83cfe2763d87'
   public exponent (e)
     01:00:01
     AQAB
     h'010001'
 -----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEArZopZ1/zpHm0xuYyc9jX7YiUFYPkMQAEbLWMrIerdEQTdsoLdClA
npcqAdeLRiZuGTVNwNO16g6TOgbo5YW1JwVj2yi4ktpaFDkP2mhtbwr7UtwID1TT
5KIonaBxUILg28rRlN1CmDoJM6jZ7/vSNUOxIqK+QW26kdwLMU6I+U2cYS3sshMK
wpGOotbpQLkyuYCPsxijMxMj1dB+2dB/k+AtTZDFWCRW1ckQE0qymSN9NLmOlxlp
b87GP9YXp9JD4DbLUXsvGIvCM/hXz9FhC3ztNzXjE3okLncIwuPZ5hfTpcY0WtqG
p/gCNh1mY8/pwD2C+zmijZIBSoPP4nY9hwIDAQAB
-----END RSA PUBLIC KEY-----

# record (server) [size 0x502 pos 0x3c8]
   00000000 : 16 03 03 01 2C 0C 00 01 28 03 00 1D 20 F4 29 00 | ....,...(... .).
   00000010 : FF 3D 69 88 1D A1 44 60 74 0F AC 51 A0 4C B5 EF | .=i...D`t..Q.L..
   00000020 : 3F FD EB FF 76 63 6E 9C 5D FE 3D 31 2B 04 01 01 | ?...vcn.].=1+...
   00000030 : 00 4D 94 81 0F DD 66 C6 7A FD 9B B4 22 EB 76 B7 | .M....f.z...".v.
   00000040 : DB 28 4B AD 39 00 D5 F7 E5 7A 41 DB D9 30 72 B4 | .(K.9....zA..0r.
   00000050 : C5 B9 09 ED 75 C1 ED 72 E2 15 6F 3F D0 4B 81 46 | ....u..r..o?.K.F
   00000060 : FB 7A AE 8C C3 C3 10 16 F2 71 69 CE 4E D2 84 49 | .z.......qi.N..I
   00000070 : 2C 40 37 0E B9 60 60 36 CE 66 2C 05 F1 A3 59 E5 | ,@7..``6.f,...Y.
   00000080 : 6D 4D 06 BD 72 7D EB C2 72 2E 1B 55 85 51 1F 03 | mM..r}..r..U.Q..
   00000090 : 55 68 6D 6D A8 EA 96 BE A6 20 EB 08 24 E5 A8 86 | Uhmm..... ..$...
   000000A0 : 18 0A 06 58 37 DA 81 E0 EA 9E 05 6C 2C CF 76 4B | ...X7......l,.vK
   000000B0 : 29 FE 52 F4 6A A6 FA B8 D9 81 DB EB 08 DB C4 80 | ).R.j...........
   000000C0 : C2 1D 04 B1 FB 7C 5C B2 73 BF 06 C8 61 7D 18 BB | .....|\.s...a}..
   000000D0 : F8 2B 02 68 9B 52 E2 FA CA 74 3D 07 DD EB 0C 59 | .+.h.R...t=....Y
   000000E0 : 24 61 C2 21 5E 09 12 4E DB 7E 2E D4 D7 BC D6 2B | $a.!^..N.~.....+
   000000F0 : 21 B7 D7 CE B1 65 F8 0E 2F EC 8C 36 C4 5A 03 3A | !....e../..6.Z.:
   00000100 : 13 57 6D 2B 15 DF 65 29 75 41 E0 1D A0 82 BA EE | .Wm+..e)uA......
   00000110 : 12 45 8A E8 57 75 6D 85 3E C2 D3 DC 5A 69 F7 D5 | .E..Wum.>...Zi..
   00000120 : 34 12 51 67 98 2D A0 F1 81 41 12 1C F6 41 F1 A0 | 4.Qg.-...A...A..
   00000130 : 09 -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- | .
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x012c(300)
 > handshake type 0x0c(12) (server_key_exchange)
  > length 0x000128(296)
  > curve info 3 (named_curve)
  > curve 0x001d x25519
  > public key
   > public key len 32
      00000000 : F4 29 00 FF 3D 69 88 1D A1 44 60 74 0F AC 51 A0 | .)..=i...D`t..Q.
      00000010 : 4C B5 EF 3F FD EB FF 76 63 6E 9C 5D FE 3D 31 2B | L..?...vcn.].=1+
  > signature
   > 0x0401 rsa_pkcs1_sha256
   > signature len 256
     00000000 : 4D 94 81 0F DD 66 C6 7A FD 9B B4 22 EB 76 B7 DB | M....f.z...".v..
     00000010 : 28 4B AD 39 00 D5 F7 E5 7A 41 DB D9 30 72 B4 C5 | (K.9....zA..0r..
     00000020 : B9 09 ED 75 C1 ED 72 E2 15 6F 3F D0 4B 81 46 FB | ...u..r..o?.K.F.
     00000030 : 7A AE 8C C3 C3 10 16 F2 71 69 CE 4E D2 84 49 2C | z.......qi.N..I,
     00000040 : 40 37 0E B9 60 60 36 CE 66 2C 05 F1 A3 59 E5 6D | @7..``6.f,...Y.m
     00000050 : 4D 06 BD 72 7D EB C2 72 2E 1B 55 85 51 1F 03 55 | M..r}..r..U.Q..U
     00000060 : 68 6D 6D A8 EA 96 BE A6 20 EB 08 24 E5 A8 86 18 | hmm..... ..$....
     00000070 : 0A 06 58 37 DA 81 E0 EA 9E 05 6C 2C CF 76 4B 29 | ..X7......l,.vK)
     00000080 : FE 52 F4 6A A6 FA B8 D9 81 DB EB 08 DB C4 80 C2 | .R.j............
     00000090 : 1D 04 B1 FB 7C 5C B2 73 BF 06 C8 61 7D 18 BB F8 | ....|\.s...a}...
     000000A0 : 2B 02 68 9B 52 E2 FA CA 74 3D 07 DD EB 0C 59 24 | +.h.R...t=....Y$
     000000B0 : 61 C2 21 5E 09 12 4E DB 7E 2E D4 D7 BC D6 2B 21 | a.!^..N.~.....+!
     000000C0 : B7 D7 CE B1 65 F8 0E 2F EC 8C 36 C4 5A 03 3A 13 | ....e../..6.Z.:.
     000000D0 : 57 6D 2B 15 DF 65 29 75 41 E0 1D A0 82 BA EE 12 | Wm+..e)uA.......
     000000E0 : 45 8A E8 57 75 6D 85 3E C2 D3 DC 5A 69 F7 D5 34 | E..Wum.>...Zi..4
     000000F0 : 12 51 67 98 2D A0 F1 81 41 12 1C F6 41 F1 A0 09 | .Qg.-...A...A...
# record (server) [size 0x502 pos 0x4f9]
   00000000 : 16 03 03 00 04 0E 00 00 00 -- -- -- -- -- -- -- | .........
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x0004(4)
 > handshake type 0x0e(14) (server_hello_done)
  > length 0x000000(0)
# write record content type 0x16(22) (handshake)
# write handshake type 0x10(16) (client_key_exchange)
> SKE
X25519 (public key)
curve X25519
 x
   00:f4:29:00:ff:3d:69:88:1d:a1:44:60:74:0f:ac:51:
   a0:4c:b5:ef:3f:fd:eb:ff:76:63:6e:9c:5d:fe:3d:31:
   2b
   9CkA_z1piB2hRGB0D6xRoEy17z_96_92Y26cXf49MSs
   h'f42900ff3d69881da14460740fac51a04cb5ef3ffdebff76636e9c5dfe3d312b'

> CKE
X25519 (private key)
curve X25519
 x
   00:c7:34:68:18:ac:64:38:c9:5a:9a:50:38:1d:70:0e:
   21:ca:a9:0c:91:22:ea:8e:15:e6:bf:cc:aa:dd:7e:80:
   23
   xzRoGKxkOMlamlA4HXAOIcqpDJEi6o4V5r_Mqt1-gCM
   h'c7346818ac6438c95a9a50381d700e21caa90c9122ea8e15e6bfccaadd7e8023'
 d (private)
   00:30:07:dc:49:4a:42:fa:ff:0b:58:a2:72:a9:da:4c:
   d9:54:32:e0:a0:c2:9d:33:39:7a:18:b8:98:3b:c1:b8:
   6f
   MAfcSUpC-v8LWKJyqdpM2VQy4KDCnTM5ehi4mDvBuG8
   h'3007dc494a42faff0b58a272a9da4cd95432e0a0c29d33397a18b8983bc1b86f'

> hmac alg 5
> client hello random 8806aaf3bab7cfa006497ef50620ddae5320bf1541d2d2a97afb85145aa1d275
> server hello random e736be0bf5e6d9ffec348b1d222e5e5f0dd2d4a46c99ae521de354088872caab
> pre master secret 823fb60b83460ee2575f75fdd2ca9743f870f5c8aaba1bd3c141db7660a1fb11
# CLIENT_RANDOM 8806aaf3bab7cfa006497ef50620ddae5320bf1541d2d2a97afb85145aa1d275 1598a9701b35936119d3b114b9b4df696d3d0fbcd92ee122612b59cdf0752f392e3ff27b38b9b585aa60e09408833a36
> secret_client_mac_key[00000102] d5e395deabd848cf72cb35fb271ae3c0fc359713df2310c15fe411ee2e168648
> secret_server_mac_key[00000103] 8700692ad8d830958ed756828a79a5a63a692cff6cb52c0b33f4e87463eb3779
> secret_client_key[00000108] 8dbce7ce8a9e60e9483a2160aa155bbb
> secret_server_key[0000010b] dd12fd12e3f2592cf8c0ee55739eb163
> secret_client_iv[00000109] ec0e5d7d436c674d96af8b4f3d5fa78c
> secret_server_iv[0000010c] 6d628e23d17b7b8cd0f355611a6c22cf
# record constructed
   00000000 : 16 03 03 00 25 10 00 00 21 20 C7 34 68 18 AC 64 | ....%...! .4h..d
   00000010 : 38 C9 5A 9A 50 38 1D 70 0E 21 CA A9 0C 91 22 EA | 8.Z.P8.p.!....".
   00000020 : 8E 15 E6 BF CC AA DD 7E 80 23 -- -- -- -- -- -- | .......~.#
# write record content type 0x14(20) (change_cipher_spec)
# record constructed
   00000000 : 16 03 03 00 25 10 00 00 21 20 C7 34 68 18 AC 64 | ....%...! .4h..d
   00000010 : 38 C9 5A 9A 50 38 1D 70 0E 21 CA A9 0C 91 22 EA | 8.Z.P8.p.!....".
   00000020 : 8E 15 E6 BF CC AA DD 7E 80 23 14 03 03 00 01 01 | .......~.#......
# write record content type 0x16(22) (handshake)
# write handshake type 0x14(20) (finished)
> verify data
   00000000 : 01 51 3C 99 95 DB 12 DE 88 A8 4C AB -- -- -- -- | .Q<.......L.
  > secret (internal) 0x00000106
  > algorithm sha256 size 12
  > verify data 01513c9995db12de88a84cab
> encrypt
 > aad 0000000000000000160303
 > enc aes-128-cbc
 > enckey[00000108] 8dbce7ce8a9e60e9483a2160aa155bbb
 > iv 03b679086ab01161c3db151d62b77550
 > mac sha256
 > mackey[00000102] d5e395deabd848cf72cb35fb271ae3c0fc359713df2310c15fe411ee2e168648
 > record no 0
 > plaintext
   00000000 : 14 00 00 0C 01 51 3C 99 95 DB 12 DE 88 A8 4C AB | .....Q<.......L.
 > ciphertext
   00000000 : F1 E8 2E E2 82 85 1B 22 73 B6 05 DF E8 C4 40 F8 | ......."s.....@.
   00000010 : 86 B1 4D CE 29 32 F6 74 35 2F F5 3A F5 8C 60 0B | ..M.)2.t5/.:..`.
   00000020 : BB 8E AF 45 57 BD 31 66 3B 55 33 D1 59 57 3B 50 | ...EW.1f;U3.YW;P
   00000030 : 94 DC C4 9D 51 98 15 6B 9E 49 72 76 59 EB 23 F7 | ....Q..k.IrvY.#.
# record constructed
   00000000 : 16 03 03 00 25 10 00 00 21 20 C7 34 68 18 AC 64 | ....%...! .4h..d
   00000010 : 38 C9 5A 9A 50 38 1D 70 0E 21 CA A9 0C 91 22 EA | 8.Z.P8.p.!....".
   00000020 : 8E 15 E6 BF CC AA DD 7E 80 23 14 03 03 00 01 01 | .......~.#......
   00000030 : 16 03 03 00 50 03 B6 79 08 6A B0 11 61 C3 DB 15 | ....P..y.j..a...
   00000040 : 1D 62 B7 75 50 F1 E8 2E E2 82 85 1B 22 73 B6 05 | .b.uP......."s..
   00000050 : DF E8 C4 40 F8 86 B1 4D CE 29 32 F6 74 35 2F F5 | ...@...M.)2.t5/.
   00000060 : 3A F5 8C 60 0B BB 8E AF 45 57 BD 31 66 3B 55 33 | :..`....EW.1f;U3
   00000070 : D1 59 57 3B 50 94 DC C4 9D 51 98 15 6B 9E 49 72 | .YW;P....Q..k.Ir
   00000080 : 76 59 EB 23 F7 -- -- -- -- -- -- -- -- -- -- -- | vY.#.
[ns] read 0x5b
   00000000 : 14 03 03 00 01 01 16 03 03 00 50 CB 3A 05 2D 43 | ..........P.:.-C
   00000010 : 3E E8 BB 9F 8A 50 D8 3D 97 B9 0F 44 E1 06 B3 E4 | >....P.=...D....
   00000020 : 26 87 A7 37 14 D9 B4 E7 80 69 60 B0 C7 17 CE CB | &..7.....i`.....
   00000030 : AA 8E E9 3D A0 08 E3 8E 59 B7 52 67 96 C6 9F F2 | ...=....Y.Rg....
   00000040 : F5 C7 C0 18 32 D2 27 9D CC 44 E1 B1 56 A8 1A 17 | ....2.'..D..V...
   00000050 : AE 8B 55 7E C2 B7 1B 3F 03 E2 CA -- -- -- -- -- | ..U~...?...
# record (server) [size 0x5b pos 0x0]
   00000000 : 14 03 03 00 01 01 -- -- -- -- -- -- -- -- -- -- | ......
> record content type 0x14(20) (change_cipher_spec)
 > record version 0x0303 (TLS v1.2)
 > len 0x0001(1)
# record (server) [size 0x5b pos 0x6]
   00000000 : 16 03 03 00 50 CB 3A 05 2D 43 3E E8 BB 9F 8A 50 | ....P.:.-C>....P
   00000010 : D8 3D 97 B9 0F 44 E1 06 B3 E4 26 87 A7 37 14 D9 | .=...D....&..7..
   00000020 : B4 E7 80 69 60 B0 C7 17 CE CB AA 8E E9 3D A0 08 | ...i`........=..
   00000030 : E3 8E 59 B7 52 67 96 C6 9F F2 F5 C7 C0 18 32 D2 | ..Y.Rg........2.
   00000040 : 27 9D CC 44 E1 B1 56 A8 1A 17 AE 8B 55 7E C2 B7 | '..D..V.....U~..
   00000050 : 1B 3F 03 E2 CA -- -- -- -- -- -- -- -- -- -- -- | .?...
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x0050(80)
> tag
   00000000 : D0 3F 70 B5 CC 61 B7 FF CB 4B 9D 16 D9 6E 60 84 | .?p..a...K...n`.
   00000010 : 38 E8 CD DC AA C5 2D 06 5D 54 26 51 79 B0 F9 0A | 8.....-.]T&Qy...
> decrypt
 > aad 0000000000000000160303
 > enc aes-128-cbc
 > enckey[0000010b] dd12fd12e3f2592cf8c0ee55739eb163
 > iv cb3a052d433ee8bb9f8a50d83d97b90f
 > mac sha256
 > mackey[00000103] 8700692ad8d830958ed756828a79a5a63a692cff6cb52c0b33f4e87463eb3779
 > record no 0
 > ciphertext
   00000000 : 44 E1 06 B3 E4 26 87 A7 37 14 D9 B4 E7 80 69 60 | D....&..7.....i`
   00000010 : B0 C7 17 CE CB AA 8E E9 3D A0 08 E3 8E 59 B7 52 | ........=....Y.R
   00000020 : 67 96 C6 9F F2 F5 C7 C0 18 32 D2 27 9D CC 44 E1 | g........2.'..D.
   00000030 : B1 56 A8 1A 17 AE 8B 55 7E C2 B7 1B 3F 03 E2 CA | .V.....U~...?...
 > plaintext 0x0(0)
   00000000 : 14 00 00 0C F5 78 03 22 92 BE B2 B3 69 F6 72 DB | .....x."....i.r.
 > handshake type 0x14(20) (finished)
  > length 0x00000c(12)
 > verify data true
    00000000 : F5 78 03 22 92 BE B2 B3 69 F6 72 DB -- -- -- -- | .x."....i.r.
   > secret (internal) 0x00000106
   > algorithm sha256 size 12
   > verify data f578032292beb2b369f672db
   > maced       f578032292beb2b369f672db
[00000000][async_tls_client] connect
# write record content type 0x17(23) (application_data)
> encrypt
 > aad 0000000000000001170303
 > enc aes-128-cbc
 > enckey[00000108] 8dbce7ce8a9e60e9483a2160aa155bbb
 > iv a7993ad145c18e6f25141671a356d681
 > mac sha256
 > mackey[00000102] d5e395deabd848cf72cb35fb271ae3c0fc359713df2310c15fe411ee2e168648
 > record no 1
 > plaintext
   00000000 : 68 65 6C 6C 6F 17 -- -- -- -- -- -- -- -- -- -- | hello.
 > ciphertext
   00000000 : DF 39 1E 62 10 68 9A 8E 7E BD 5A 4C 67 FA FA F4 | .9.b.h..~.ZLg...
   00000010 : 9D 1E 9F 91 4D 11 D2 01 FF AC B6 08 97 91 45 AC | ....M.........E.
   00000020 : 88 78 AF BE 99 AF 03 A8 81 D2 2C A4 FB AC 35 C8 | .x........,...5.
# record constructed
   00000000 : 17 03 03 00 40 A7 99 3A D1 45 C1 8E 6F 25 14 16 | ....@..:.E..o%..
   00000010 : 71 A3 56 D6 81 DF 39 1E 62 10 68 9A 8E 7E BD 5A | q.V...9.b.h..~.Z
   00000020 : 4C 67 FA FA F4 9D 1E 9F 91 4D 11 D2 01 FF AC B6 | Lg.......M......
   00000030 : 08 97 91 45 AC 88 78 AF BE 99 AF 03 A8 81 D2 2C | ...E..x........,
   00000040 : A4 FB AC 35 C8 -- -- -- -- -- -- -- -- -- -- -- | ...5.
received response: [464][len 0]
# write record content type 0x15(21) (alert)
> encrypt
 > aad 0000000000000002150303
 > enc aes-128-cbc
 > enckey[00000108] 8dbce7ce8a9e60e9483a2160aa155bbb
 > iv 4861456ba1a0c27a29d52e1326539b13
 > mac sha256
 > mackey[00000102] d5e395deabd848cf72cb35fb271ae3c0fc359713df2310c15fe411ee2e168648
 > record no 2
 > plaintext
   00000000 : 01 00 -- -- -- -- -- -- -- -- -- -- -- -- -- -- | ..
 > ciphertext
   00000000 : CC A1 5D EE CA EA AF BB A6 15 7C F7 0F D2 C0 38 | ..].......|....8
   00000010 : C5 A1 BE 8A 39 63 BE AF DA B1 1A 61 20 62 7C D4 | ....9c.....a b|.
   00000020 : 29 3B 0B 14 45 96 7E 5D 4F 21 24 2F 19 2E 34 23 | );..E.~]O!$/..4#
# record constructed
   00000000 : 15 03 03 00 40 48 61 45 6B A1 A0 C2 7A 29 D5 2E | ....@HaEk...z)..
   00000010 : 13 26 53 9B 13 CC A1 5D EE CA EA AF BB A6 15 7C | .&S....].......|
   00000020 : F7 0F D2 C0 38 C5 A1 BE 8A 39 63 BE AF DA B1 1A | ....8....9c.....
   00000030 : 61 20 62 7C D4 29 3B 0B 14 45 96 7E 5D 4F 21 24 | a b|.);..E.~]O!$
   00000040 : 2F 19 2E 34 23 -- -- -- -- -- -- -- -- -- -- -- | /..4#
- event_loop_break_concurrent : break 1/1
[ns] read 0x45
   00000000 : 15 03 03 00 40 06 EF 55 B7 23 A5 C9 61 8C 0E 76 | ....@..U.#..a..v
   00000010 : 89 3F 14 4F E3 E6 29 0C 39 99 F2 BE A2 32 A8 F4 | .?.O..).9....2..
   00000020 : D0 FC 79 38 EF 2F E6 2D D8 9F C2 82 19 A5 04 95 | ..y8./.-........
   00000030 : 31 04 B5 28 7F 4E 36 7C 74 40 4A EB FA FE C6 98 | 1..(.N6|t@J.....
   00000040 : 60 0C F4 A4 D6 -- -- -- -- -- -- -- -- -- -- -- | `....
# record (server) [size 0x45 pos 0x0]
   00000000 : 15 03 03 00 40 06 EF 55 B7 23 A5 C9 61 8C 0E 76 | ....@..U.#..a..v
   00000010 : 89 3F 14 4F E3 E6 29 0C 39 99 F2 BE A2 32 A8 F4 | .?.O..).9....2..
   00000020 : D0 FC 79 38 EF 2F E6 2D D8 9F C2 82 19 A5 04 95 | ..y8./.-........
   00000030 : 31 04 B5 28 7F 4E 36 7C 74 40 4A EB FA FE C6 98 | 1..(.N6|t@J.....
   00000040 : 60 0C F4 A4 D6 -- -- -- -- -- -- -- -- -- -- -- | `....
> record content type 0x15(21) (alert)
 > record version 0x0303 (TLS v1.2)
 > len 0x0040(64)
> tag
   00000000 : D8 A2 55 A0 C6 2A 84 52 20 45 F2 A2 0F EB 8B AF | ..U..*.R E......
   00000010 : 83 0C A8 2B 62 EC A5 89 C5 92 9D 2C 4F 85 2A E5 | ...+b......,O.*.
> decrypt
 > aad 0000000000000001150303
 > enc aes-128-cbc
 > enckey[0000010b] dd12fd12e3f2592cf8c0ee55739eb163
 > iv 06ef55b723a5c9618c0e76893f144fe3
 > mac sha256
 > mackey[00000103] 8700692ad8d830958ed756828a79a5a63a692cff6cb52c0b33f4e87463eb3779
 > record no 1
 > ciphertext
   00000000 : E6 29 0C 39 99 F2 BE A2 32 A8 F4 D0 FC 79 38 EF | .).9....2....y8.
   00000010 : 2F E6 2D D8 9F C2 82 19 A5 04 95 31 04 B5 28 7F | /.-........1..(.
   00000020 : 4E 36 7C 74 40 4A EB FA FE C6 98 60 0C F4 A4 D6 | N6|t@J.....`....
 > plaintext 0x0(0)
   00000000 : 01 00 -- -- -- -- -- -- -- -- -- -- -- -- -- -- | ..
 > alert
 > alert level 1 warning
 > alert desc  0 close_notify
- event_loop_test_broken : broken detected
[00000000][async_tls_client] client 127.0.0.1:9000
````
