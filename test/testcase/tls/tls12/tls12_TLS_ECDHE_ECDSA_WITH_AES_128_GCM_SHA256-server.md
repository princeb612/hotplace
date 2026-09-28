#### server

````
$ openssl s_server -accept 9000 -cert ecdsa.crt -key ecdsa.key -state -debug -status_verbose -keylogfile sslkeylog
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x2550e9be4d0 [0x2550eddb4b3] (5 bytes => 5 (0x5))
0000 - 16 03 01 00 c2                                    .....
read from 0x2550e9be4d0 [0x2550eddb4b8] (194 bytes => 194 (0xC2))
0000 - 01 00 00 be 03 03 8d 4e-72 ac f5 51 11 54 4e ad   .......Nr..Q.TN.
0010 - c5 0e 5e 9e 0c 30 15 64-80 25 88 11 94 32 8b ce   ..^..0.d.%...2..
0020 - 15 73 de c8 9e d6 00 00-38 c0 2b c0 2c c0 30 00   .s......8.+.,.0.
0030 - 9f cc a9 cc a8 cc aa c0-2b c0 2f 00 9e c0 24 c0   ........+./...$.
0040 - 28 00 6b c0 23 c0 27 00-67 c0 0a c0 14 00 39 c0   (.k.#.'.g.....9.
0050 - 09 c0 13 00 33 00 9d 00-9c 00 3d 00 3c 00 35 00   ....3.....=.<.5.
0060 - 2f 01 00 00 5d ff 01 00-01 00 00 0b 00 04 03 00   /...]...........
0070 - 01 02 00 0a 00 0c 00 0a-00 1d 00 17 00 1e 00 19   ................
0080 - 00 18 00 23 00 00 00 16-00 00 00 17 00 00 00 0d   ...#............
0090 - 00 30 00 2e 04 03 05 03-06 03 08 07 08 08 08 1a   .0..............
00a0 - 08 1b 08 1c 08 09 08 0a-08 0b 08 04 08 05 08 06   ................
00b0 - 04 01 05 01 06 01 03 03-03 01 03 02 04 02 05 02   ................
00c0 - 06 02                                             ..
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write certificate
SSL_accept:SSLv3/TLS write key exchange
write to 0x2550e9be4d0 [0x2550edda4a0] (738 bytes => 738 (0x2E2))
0000 - 16 03 03 00 41 02 00 00-3d 03 03 07 4a 0c b6 fe   ....A...=...J...
0010 - 8a 12 a0 47 0f c3 29 88-f9 8e ef ee 81 e3 d6 a6   ...G..).........
0020 - 09 9d df 44 4f 57 4e 47-52 44 01 00 c0 2b 00 00   ...DOWNGRD...+..
0030 - 15 ff 01 00 01 00 00 0b-00 04 03 00 01 02 00 23   ...............#
0040 - 00 00 00 17 00 00 16 03-03 02 16 0b 00 02 12 00   ................
0050 - 02 0f 00 02 0c 30 82 02-08 30 82 01 ad a0 03 02   .....0...0......
0060 - 01 02 02 14 41 4d f6 cb-ca 7e 42 21 ee 06 a6 88   ....AM...~B!....
0070 - 02 79 a4 e0 c0 48 88 92-30 0a 06 08 2a 86 48 ce   .y...H..0...*.H.
0080 - 3d 04 03 02 30 59 31 0b-30 09 06 03 55 04 06 13   =...0Y1.0...U...
0090 - 02 4b 52 31 0b 30 09 06-03 55 04 08 0c 02 47 47   .KR1.0...U....GG
00a0 - 31 0b 30 09 06 03 55 04-07 0c 02 59 49 31 0d 30   1.0...U....YI1.0
00b0 - 0b 06 03 55 04 0a 0c 04-54 65 73 74 31 0d 30 0b   ...U....Test1.0.
00c0 - 06 03 55 04 0b 0c 04 54-65 73 74 31 12 30 10 06   ..U....Test1.0..
00d0 - 03 55 04 03 0c 09 54 65-73 74 20 52 6f 6f 74 30   .U....Test Root0
00e0 - 1e 17 0d 32 35 30 32 30-39 31 34 34 39 35 37 5a   ...250209144957Z
00f0 - 17 0d 32 36 30 32 30 39-31 34 34 39 35 37 5a 30   ..260209144957Z0
0100 - 59 31 0b 30 09 06 03 55-04 06 13 02 4b 52 31 0b   Y1.0...U....KR1.
0110 - 30 09 06 03 55 04 08 0c-02 47 47 31 0b 30 09 06   0...U....GG1.0..
0120 - 03 55 04 07 0c 02 59 49-31 0d 30 0b 06 03 55 04   .U....YI1.0...U.
0130 - 0a 0c 04 54 65 73 74 31-0d 30 0b 06 03 55 04 0b   ...Test1.0...U..
0140 - 0c 04 54 65 73 74 31 12-30 10 06 03 55 04 03 0c   ..Test1.0...U...
0150 - 09 54 65 73 74 20 52 6f-6f 74 30 59 30 13 06 07   .Test Root0Y0...
0160 - 2a 86 48 ce 3d 02 01 06-08 2a 86 48 ce 3d 03 01   *.H.=....*.H.=..
0170 - 07 03 42 00 04 56 af c0-cb 7b 57 8e 97 f3 4a 06   ..B..V...{W...J.
0180 - 2d a5 91 ca 5f ac 2a 6a-24 f2 f1 16 c2 b7 91 28   -..._.*j$......(
0190 - 2c 3e da 87 cc c1 40 14-33 f1 c5 1a 79 cc 31 01   ,>....@.3...y.1.
01a0 - 4a c7 f2 62 3f 28 79 00-4c e1 6c a3 cc 90 23 a8   J..b?(y.L.l...#.
01b0 - 96 c1 73 3f 04 a3 53 30-51 30 1d 06 03 55 1d 0e   ..s?..S0Q0...U..
01c0 - 04 16 04 14 03 e0 ab e4-28 de e7 2f 73 e9 e1 5f   ........(../s.._
01d0 - 5e 47 0d b6 5f e8 24 ff-30 1f 06 03 55 1d 23 04   ^G.._.$.0...U.#.
01e0 - 18 30 16 80 14 03 e0 ab-e4 28 de e7 2f 73 e9 e1   .0.......(../s..
01f0 - 5f 5e 47 0d b6 5f e8 24-ff 30 0f 06 03 55 1d 13   _^G.._.$.0...U..
0200 - 01 01 ff 04 05 30 03 01-01 ff 30 0a 06 08 2a 86   .....0....0...*.
0210 - 48 ce 3d 04 03 02 03 49-00 30 46 02 21 00 93 6c   H.=....I.0F.!..l
0220 - 1f 79 f6 7b 8e 21 b8 ff-00 91 9b 01 c9 0d 66 46   .y.{.!........fF
0230 - a2 72 44 c2 a4 8d fe 4e-12 41 d8 7a 07 94 02 21   .rD....N.A.z...!
0240 - 00 fb bc a9 86 0e eb c5-a6 74 38 5f 05 54 2a fb   .........t8_.T*.
0250 - d2 57 7b 76 88 d7 fc d6-e4 e2 3b 55 05 df 38 d6   .W{v......;U..8.
0260 - 8e 16 03 03 00 73 0c 00-00 6f 03 00 1d 20 80 aa   .....s...o... ..
0270 - 59 31 f2 23 0c 66 29 5e-eb 05 1a e9 47 aa e7 a0   Y1.#.f)^....G...
0280 - 1b 9e e1 12 44 65 f5 4c-21 f9 77 88 ec 00 04 03   ....De.L!.w.....
0290 - 00 47 30 45 02 20 29 9d-6b 03 af 88 8f 01 a9 cc   .G0E. ).k.......
02a0 - 50 c9 3f 92 87 de 28 98-97 c8 a8 e1 94 91 a0 02   P.?...(.........
02b0 - 67 33 ba e5 64 60 02 21-00 d3 2c e3 0b c0 87 60   g3..d`.!..,....`
02c0 - 73 ad 75 70 30 ff 59 47-83 ca 91 c1 26 f1 b8 e0   s.up0.YG....&...
02d0 - 54 40 f1 a0 c3 9a 81 fa-6d 16 03 03 00 04 0e 00   T@......m.......
02e0 - 00 00                                             ..
SSL_accept:SSLv3/TLS write server done
read from 0x2550e9be4d0 [0x2550eddb4b3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 25                                    ....%
read from 0x2550e9be4d0 [0x2550eddb4b8] (37 bytes => 37 (0x25))
0000 - 10 00 00 21 20 ff 5f 0a-76 36 70 e2 5d b7 ca 20   ...! ._.v6p.]..
0010 - 5e 76 55 ab ad 09 76 83-6c c0 5c 0d 5e 78 c1 fc   ^vU...v.l.\.^x..
0020 - 37 a2 a0 51 39                                    7..Q9
SSL_accept:SSLv3/TLS write server done
read from 0x2550e9be4d0 [0x2550eddb4b3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x2550e9be4d0 [0x2550eddb4b8] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_accept:SSLv3/TLS read client key exchange
read from 0x2550e9be4d0 [0x2550eddb4b3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 28                                    ....(
read from 0x2550e9be4d0 [0x2550eddb4b8] (40 bytes => 40 (0x28))
0000 - f1 b1 d2 e2 78 b9 f2 34-5d d1 73 bb f2 f3 7c ef   ....x..4].s...|.
0010 - 1f 1e 54 c5 af bb 79 b6-b0 e2 f8 03 e9 98 40 94   ..T...y.......@.
0020 - 3c 28 51 8b 1d b1 8f a8-                          <(Q.....
SSL_accept:SSLv3/TLS read change cipher spec
SSL_accept:SSLv3/TLS read finished
SSL_accept:SSLv3/TLS write session ticket
SSL_accept:SSLv3/TLS write change cipher spec
write to 0x2550e9be4d0 [0x2550edda4a0] (242 bytes => 242 (0xF2))
0000 - 16 03 03 00 ba 04 00 00-b6 00 00 1c 20 00 b0 60   ............ ..`
0010 - a0 3d 87 d7 e1 a2 7f b2-4b 57 b5 01 cc 06 ac 77   .=......KW.....w
0020 - 7b eb 16 e1 8c 1f 76 34-b1 c1 f7 93 1d e6 3f e6   {.....v4......?.
0030 - 02 e4 e4 1d 5e a7 34 4c-1c 1b f9 14 28 57 90 de   ....^.4L....(W..
0040 - ec 13 3b 1b 6b 5e bb 34-69 2c a7 bc 3f c3 a9 8f   ..;.k^.4i,..?...
0050 - 1b b9 fe 28 87 22 8f 15-ff 30 20 df 6a 9d 42 44   ...(."...0 .j.BD
0060 - 70 85 21 b9 a6 f8 e8 39-3e e6 0f 4e 82 ee da 9d   p.!....9>..N....
0070 - 6e 7f dd 53 f2 fa f3 e3-34 63 da 7d 44 37 0d ba   n..S....4c.}D7..
0080 - fe 1a 4c c1 ec a0 34 15-29 c4 7d 02 44 f1 0c 4d   ..L...4.).}.D..M
0090 - fb ee 28 f7 a2 08 6f 87-d5 be 1e 7d 0f f3 da 0a   ..(...o....}....
00a0 - 30 8a 8c db b1 17 57 c6-f8 e7 03 56 ed 92 3b 63   0.....W....V..;c
00b0 - 1f e5 de 87 e7 64 4d 7a-c8 48 e3 3d e4 9b 25 14   .....dMz.H.=..%.
00c0 - 03 03 00 01 01 16 03 03-00 28 a8 89 ac 79 78 9b   .........(...yx.
00d0 - 9a 83 83 ec 32 32 c3 1d-c8 95 a8 43 3d 71 4c 5e   ....22.....C=qL^
00e0 - 4e f4 d2 2e b2 05 30 90-e9 fe ba 3f a0 1d 39 cc   N.....0....?..9.
00f0 - 41 dc                                             A.
SSL_accept:SSLv3/TLS write finished
-----BEGIN SSL SESSION PARAMETERS-----
MF8CAQECAgMDBALAKwQABDAgwn0j/T9kFwsrY5F8z+clG3kuqUkvpStZxq3MxxCV
EC5yrRsIiAp48/gxbBI0qJuhBgIEaDAEcaIEAgIcIKQGBAQBAAAArQMCAQGzAwIB
HQ==
-----END SSL SESSION PARAMETERS-----
Shared ciphers:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Supported Elliptic Curve Point Formats: uncompressed:ansiX962_compressed_prime:ansiX962_compressed_char2
Supported groups: x25519:secp256r1:x448:secp521r1:secp384r1
Shared groups: x25519:secp256r1:x448:secp521r1:secp384r1
CIPHER is ECDHE-ECDSA-AES128-GCM-SHA256
Secure Renegotiation IS supported
read from 0x2550e9be4d0 [0x2550eddb4b3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 1e                                    .....
read from 0x2550e9be4d0 [0x2550eddb4b8] (30 bytes => 30 (0x1E))
0000 - f1 b1 d2 e2 78 b9 f2 35-09 38 1f 19 29 04 b3 fe   ....x..5.8..)...
0010 - 1a 05 2a 2e ce d8 05 84-04 10 e3 b9 75 44         ..*.........uD
test
read from 0x2550e9be4d0 [0x2550eddb4b3] (5 bytes => 5 (0x5))
0000 - 15 03 03 00 1a                                    .....
read from 0x2550e9be4d0 [0x2550eddb4b8] (26 bytes => 26 (0x1A))
0000 - f1 b1 d2 e2 78 b9 f2 36-cf b1 9b ea 4b f4 47 e8   ....x..6....K.G.
0010 - c7 cc 93 fd 64 d5 dd 2d-63 cc                     ....d..-c.
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x2550e9be4d0 [0x2550ede4823] (31 bytes => 31 (0x1F))
0000 - 15 03 03 00 1a a8 89 ac-79 78 9b 9a 84 71 05 60   ........yx...q.`
0010 - 9e 34 20 56 86 ca a8 df-f0 d2 6b 74 40 3a 07      .4 V......kt@:.
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
