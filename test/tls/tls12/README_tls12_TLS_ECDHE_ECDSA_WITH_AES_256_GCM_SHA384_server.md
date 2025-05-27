#### server

````
$ openssl s_server -accept 9000 -cert ecdsa.crt -key ecdsa.key -state -debug -status_verbose -keylogfile sslkeylog
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x1b53640dd40 [0x1b5368284b3] (5 bytes => 5 (0x5))
0000 - 16 03 01 00 c0                                    .....
read from 0x1b53640dd40 [0x1b5368284b8] (192 bytes => 192 (0xC0))
0000 - 01 00 00 bc 03 03 96 c6-c3 5f f6 e9 0a ca 13 05   ........._......
0010 - dd 42 ea 2f be 50 fc da-bb 56 00 cf e2 46 97 b2   .B./.P...V...F..
0020 - f0 1f bf 23 62 53 00 00-36 c0 2c c0 30 00 9f cc   ...#bS..6.,.0...
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
write to 0x1b53640dd40 [0x1b5368274a0] (737 bytes => 737 (0x2E1))
0000 - 16 03 03 00 41 02 00 00-3d 03 03 3b 6a ca b1 3f   ....A...=..;j..?
0010 - 5a 35 32 2b f2 df 69 77-0a 24 8c ff 91 44 cd 35   Z52+..iw.$...D.5
0020 - 5b b5 b4 44 4f 57 4e 47-52 44 01 00 c0 2c 00 00   [..DOWNGRD...,..
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
0260 - 8e 16 03 03 00 72 0c 00-00 6e 03 00 1d 20 f0 d2   .....r...n... ..
0270 - 20 2c c0 73 90 62 d8 d7-aa d7 c4 24 81 11 22 6e    ,.s.b.....$.."n
0280 - 49 a1 40 8d 59 40 a0 48-53 b1 8b a6 3d 36 04 03   I.@.Y@.HS...=6..
0290 - 00 46 30 44 02 20 29 02-00 65 0b c7 2a 8e d8 d3   .F0D. )..e..*...
02a0 - 06 7e e4 09 b2 20 75 d5-e1 b5 75 4a 28 8e 71 75   .~... u...uJ(.qu
02b0 - a5 b3 01 5e ee 46 02 20-49 c2 b4 e0 a0 3b c1 aa   ...^.F. I....;..
02c0 - d0 61 33 03 7c 2a c2 f3-9f 27 40 48 d7 dd f3 53   .a3.|*...'@H...S
02d0 - a9 f1 af 5f 91 f9 6b ff-16 03 03 00 04 0e 00 00   ..._..k.........
02e0 - 00                                                .
SSL_accept:SSLv3/TLS write server done
read from 0x1b53640dd40 [0x1b5368284b3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 25                                    ....%
read from 0x1b53640dd40 [0x1b5368284b8] (37 bytes => 37 (0x25))
0000 - 10 00 00 21 20 b8 57 12-cb 04 22 c3 b0 5b a1 eb   ...! .W..."..[..
0010 - 45 78 26 c3 bf 8f ab 6a-8d 7b c7 2f 2a df f3 5f   Ex&....j.{./*.._
0020 - 2b f9 ed fa 75                                    +...u
SSL_accept:SSLv3/TLS write server done
read from 0x1b53640dd40 [0x1b5368284b3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x1b53640dd40 [0x1b5368284b8] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_accept:SSLv3/TLS read client key exchange
read from 0x1b53640dd40 [0x1b5368284b3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 28                                    ....(
read from 0x1b53640dd40 [0x1b5368284b8] (40 bytes => 40 (0x28))
0000 - a5 15 62 a0 74 39 c5 81-80 f6 06 53 cb b6 31 4c   ..b.t9.....S..1L
0010 - a7 ee 98 c1 87 bd 2e f5-6b 61 51 1b 08 0e 0d e1   ........kaQ.....
0020 - ee 07 68 c1 64 8e c6 f0-                          ..h.d...
SSL_accept:SSLv3/TLS read change cipher spec
SSL_accept:SSLv3/TLS read finished
SSL_accept:SSLv3/TLS write session ticket
SSL_accept:SSLv3/TLS write change cipher spec
write to 0x1b53640dd40 [0x1b5368274a0] (242 bytes => 242 (0xF2))
0000 - 16 03 03 00 ba 04 00 00-b6 00 00 1c 20 00 b0 b8   ............ ...
0010 - 17 08 f8 39 11 12 e7 c9-63 e3 af fb b4 79 2f 15   ...9....c....y/.
0020 - 78 8b 2e 82 e9 18 fe 3c-4a 25 3a 25 99 0f d2 c0   x......<J%:%....
0030 - 7d 12 82 df 11 2e 39 2a-d8 a9 01 1c 71 d3 1c 8e   }.....9*....q...
0040 - 2a 66 c4 1a 58 78 65 ef-ac fe 95 3e 6d c8 04 f0   *f..Xxe....>m...
0050 - 3a 7d 0e 27 85 41 c3 7a-5e c8 9b d3 4b d3 9d 14   :}.'.A.z^...K...
0060 - ba 79 91 14 6e dd 20 1a-a8 b2 59 11 4a 56 11 fa   .y..n. ...Y.JV..
0070 - 4b 79 3f 51 1d e0 f9 73-42 33 8a 26 46 8a a0 60   Ky?Q...sB3.&F..`
0080 - af 3a 2b b2 41 7c 94 b2-50 3e 31 d1 b0 74 30 a2   .:+.A|..P>1..t0.
0090 - d9 e9 f2 aa 00 5a b7 c4-2a 8d 8b 60 a7 f1 eb a5   .....Z..*..`....
00a0 - d0 d6 53 44 d1 90 12 90-7d 19 a5 77 00 d6 bb d4   ..SD....}..w....
00b0 - d2 f1 9b c5 77 87 d7 3b-4d dc 80 be b5 2b 8a 14   ....w..;M....+..
00c0 - 03 03 00 01 01 16 03 03-00 28 d1 d5 10 d4 68 62   .........(....hb
00d0 - b9 26 55 17 2b 36 c5 8c-ef e2 45 9a a1 39 79 40   .&U.+6....E..9y@
00e0 - 43 fb 67 42 be db a6 f5-a2 1e 38 69 d6 96 6b 1a   C.gB......8i..k.
00f0 - d6 e7                                             ..
SSL_accept:SSLv3/TLS write finished
-----BEGIN SSL SESSION PARAMETERS-----
MF8CAQECAgMDBALALAQABDBTrAUaUj1ISoxVKGjn+3zgo0lFNLEQwtlWeu7BBxrx
WyHaPjsSO8kJqVtFa/3T1n2hBgIEaCqxF6IEAgIcIKQGBAQBAAAArQMCAQGzAwIB
HQ==
-----END SSL SESSION PARAMETERS-----
Shared ciphers:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Supported Elliptic Curve Point Formats: uncompressed:ansiX962_compressed_prime:ansiX962_compressed_char2
Supported groups: x25519:secp256r1:x448:secp521r1:secp384r1
Shared groups: x25519:secp256r1:x448:secp521r1:secp384r1
CIPHER is ECDHE-ECDSA-AES256-GCM-SHA384
Secure Renegotiation IS supported
read from 0x1b53640dd40 [0x1b5368284b3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 1e                                    .....
read from 0x1b53640dd40 [0x1b5368284b8] (30 bytes => 30 (0x1E))
0000 - a5 15 62 a0 74 39 c5 82-14 24 2e c5 55 13 30 20   ..b.t9...$..U.0
0010 - a5 7c c0 52 8f 85 f0 07-79 5e fa 28 71 f3         .|.R....y^.(q.
test
read from 0x1b53640dd40 [0x1b5368284b3] (5 bytes => 5 (0x5))
0000 - 15 03 03 00 1a                                    .....
read from 0x1b53640dd40 [0x1b5368284b8] (26 bytes => 26 (0x1A))
0000 - a5 15 62 a0 74 39 c5 83-e4 39 b3 ad 24 ae 47 24   ..b.t9...9..$.G$
0010 - ce 96 10 3b ba 3b e6 aa-c7 9e                     ...;.;....
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x1b53640dd40 [0x1b536833373] (31 bytes => 31 (0x1F))
0000 - 15 03 03 00 1a d1 d5 10-d4 68 62 b9 27 38 f7 9a   .........hb.'8..
0010 - 01 db 8c 1f 50 6e 81 34-ca fe 1e c9 b6 85 91      ....Pn.4.......
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
