#### server

````
$ openssl s_server -accept 9000 -cert ecdsa.crt -key ecdsa.key -state -debug -status_verbose -keylogfile sslkeylog
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x116f4ae8d40 [0x116f4f07d93] (5 bytes => 5 (0x5))
0000 - 16 03 01 00 c2                                    .....
read from 0x116f4ae8d40 [0x116f4f07d98] (194 bytes => 194 (0xC2))
0000 - 01 00 00 be 03 03 19 58-76 98 67 6b 7f e8 6d 78   .......Xv.gk..mx
0010 - 56 40 51 c0 c4 4d 0d 81-23 93 95 67 da fb c0 1b   V@Q..M..#..g....
0020 - bf 8f 78 b3 23 c0 00 00-38 cc a9 c0 2c c0 30 00   ..x.#...8...,.0.
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
write to 0x116f4ae8d40 [0x116f4f06d80] (738 bytes => 738 (0x2E2))
0000 - 16 03 03 00 41 02 00 00-3d 03 03 55 fb 6e 5d be   ....A...=..U.n].
0010 - 1f 6e c9 7a 7e 30 a6 d2-28 ab c6 70 79 3a d3 f6   .n.z~0..(..py:..
0020 - e5 bb a6 44 4f 57 4e 47-52 44 01 00 cc a9 00 00   ...DOWNGRD......
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
0260 - 8e 16 03 03 00 73 0c 00-00 6f 03 00 1d 20 29 16   .....s...o... ).
0270 - 0d e3 5b 2e de ae a7 9a-72 0f 5e 74 fc 60 5e ce   ..[.....r.^t.`^.
0280 - a7 df dc 82 83 79 b3 9b-1a da b9 dc 8f 75 04 03   .....y.......u..
0290 - 00 47 30 45 02 20 22 c8-c3 7e e3 ce e2 56 14 96   .G0E. "..~...V..
02a0 - 78 53 45 b1 57 5a 94 ba-48 4c fd fa a3 b6 de bf   xSE.WZ..HL......
02b0 - d4 04 6e 52 6d 50 02 21-00 9e 97 b0 aa 31 9d 5b   ..nRmP.!.....1.[
02c0 - 3a 0c d9 b6 f8 88 76 43-73 b5 7b 8d 8c 67 5e 31   :.....vCs.{..g^1
02d0 - 76 08 71 90 c9 95 52 1a-8f 16 03 03 00 04 0e 00   v.q...R.........
02e0 - 00 00                                             ..
SSL_accept:SSLv3/TLS write server done
read from 0x116f4ae8d40 [0x116f4f07d93] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 25                                    ....%
read from 0x116f4ae8d40 [0x116f4f07d98] (37 bytes => 37 (0x25))
0000 - 10 00 00 21 20 bf 37 a9-3e a7 d9 c5 de 95 f2 c3   ...! .7.>.......
0010 - 78 a0 e1 9a e5 b7 50 f4-2e 01 08 6f 94 e5 34 1b   x.....P....o..4.
0020 - d1 0a 82 33 65                                    ...3e
SSL_accept:SSLv3/TLS write server done
read from 0x116f4ae8d40 [0x116f4f07d93] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x116f4ae8d40 [0x116f4f07d98] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_accept:SSLv3/TLS read client key exchange
read from 0x116f4ae8d40 [0x116f4f07d93] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 20                                    ....
read from 0x116f4ae8d40 [0x116f4f07d98] (32 bytes => 32 (0x20))
0000 - be f5 78 ab c8 59 33 50-3c cf 80 07 91 fe 3c 78   ..x..Y3P<.....<x
0010 - e2 af 2c 60 e7 f4 4b c7-ea 33 21 c5 9d f9 02 36   ..,`..K..3!....6
SSL_accept:SSLv3/TLS read change cipher spec
SSL_accept:SSLv3/TLS read finished
SSL_accept:SSLv3/TLS write session ticket
SSL_accept:SSLv3/TLS write change cipher spec
write to 0x116f4ae8d40 [0x116f4f06d80] (234 bytes => 234 (0xEA))
0000 - 16 03 03 00 ba 04 00 00-b6 00 00 1c 20 00 b0 45   ............ ..E
0010 - da bd 56 b9 c1 0c 6d c1-e2 5a 87 8c ad ae 6d 0a   ..V...m..Z....m.
0020 - 2e 89 89 d1 7e d8 ce ed-b4 ae 88 e4 35 62 34 bf   ....~.......5b4.
0030 - ea 39 2c bd 82 80 0a 19-3a 3f 58 db f8 16 06 2e   .9,.....:?X.....
0040 - 7d 6d c3 a1 b8 43 c7 ca-44 01 0f f3 60 1b 69 d2   }m...C..D...`.i.
0050 - fb b8 e5 1f 8e 8c 7d b9-39 b4 5b 9a eb 14 68 78   ......}.9.[...hx
0060 - 50 c8 ea 8e d4 5b 38 2c-5b d7 46 ae 53 6c 5a 73   P....[8,[.F.SlZs
0070 - b9 4d 15 24 70 a2 e5 fb-db 48 4e 3a dc 0d bf 84   .M.$p....HN:....
0080 - f8 67 32 66 6b ba 42 99-6a 22 1b 74 ed 0d 95 d8   .g2fk.B.j".t....
0090 - b6 ac af 8d a1 32 8e 39-46 21 2e 3b ec 09 bc 1b   .....2.9F!.;....
00a0 - 8a 7b 10 ea 71 9e ac a9-20 27 78 9b 93 99 78 fb   .{..q... 'x...x.
00b0 - a5 7d 9a 03 39 37 67 cd-26 a5 8d 17 c9 37 07 14   .}..97g.&....7..
00c0 - 03 03 00 01 01 16 03 03-00 20 fc 96 42 59 c2 1b   ......... ..BY..
00d0 - ce 2a 85 75 b5 a8 ce a0-c5 71 ec 99 dd 73 47 b4   .*.u.....q...sG.
00e0 - 15 2a 1c 2e f7 c3 7d 34-5e 64                     .*....}4^d
SSL_accept:SSLv3/TLS write finished
-----BEGIN SSL SESSION PARAMETERS-----
MF8CAQECAgMDBALMqQQABDBlJZQ9h5eKFKRVOpVrb3FQHQy/2XqoVs5puaykp7XB
IJ1mOziXeDkxcOnkwGjlGEOhBgIEaD++LqIEAgIcIKQGBAQBAAAArQMCAQGzAwIB
HQ==
-----END SSL SESSION PARAMETERS-----
Shared ciphers:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:RSA+SHA224:DSA+SHA224:DSA+SHA256:DSA+SHA384:DSA+SHA512
Supported Elliptic Curve Point Formats: uncompressed:ansiX962_compressed_prime:ansiX962_compressed_char2
Supported groups: x25519:secp256r1:x448:secp521r1:secp384r1
Shared groups: x25519:secp256r1:x448:secp521r1:secp384r1
CIPHER is ECDHE-ECDSA-CHACHA20-POLY1305
Secure Renegotiation IS supported
read from 0x116f4ae8d40 [0x116f4f07d93] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 16                                    .....
read from 0x116f4ae8d40 [0x116f4f07d98] (22 bytes => 22 (0x16))
0000 - ef 2f cc c0 67 46 6d 26-cd 29 b4 97 58 92 b8 44   ./..gFm&.)..X..D
0010 - 3c 4c d3 e3 58 44                                 <L..XD
test
read from 0x116f4ae8d40 [0x116f4f07d93] (5 bytes => 5 (0x5))
0000 - 15 03 03 00 12                                    .....
read from 0x116f4ae8d40 [0x116f4f07d98] (18 bytes => 18 (0x12))
0000 - fd 7c 83 2c fd ef 75 ff-f5 3d 95 17 a8 3b dc 38   .|.,..u..=...;.8
0010 - 72 81                                             r.
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x116f4ae8d40 [0x116f4f0bee3] (23 bytes => 23 (0x17))
0000 - 15 03 03 00 12 14 d9 a3-06 be 23 39 a4 40 fa a8   ..........#9.@..
0010 - 5a 20 a8 83 78 bc 01                              Z ..x..
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
