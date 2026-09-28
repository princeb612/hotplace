#### server

````
openssl s_server -accept 9000 -cert ecdsa.crt -key ecdsa.key -state -debug -status_verbose -keylogfile sslkeylog -ciphersuites TLS_AES_128_CCM_SHA256
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x16a92df0510 [0x16a949f64b3] (5 bytes => 5 (0x5))
0000 - 16 03 01 00 e3                                    .....
read from 0x16a92df0510 [0x16a949f64b8] (227 bytes => 227 (0xE3))
0000 - 01 00 00 df 03 03 20 e4-66 26 7b 48 0e d9 19 49   ...... .f&{H...I
0010 - cb 1c 27 50 38 02 6b e8-16 b9 b4 bb d4 90 cc 1c   ..'P8.k.........
0020 - e5 64 5e b5 c6 b7 20 f0-13 dc e6 e5 5b ab 34 72   .d^... .....[.4r
0030 - 73 fe 10 b9 7e 51 f4 6e-1c 23 1b 58 0e df d9 98   s...~Q.n.#.X....
0040 - 85 f6 c3 2a 39 7b fc 00-02 13 04 01 00 00 94 00   ...*9{..........
0050 - 0b 00 04 03 00 01 02 00-0a 00 16 00 14 00 1d 00   ................
0060 - 17 00 1e 00 19 00 18 01-00 01 01 01 02 01 03 01   ................
0070 - 04 00 23 00 00 00 16 00-00 00 17 00 00 00 0d 00   ..#.............
0080 - 24 00 22 04 03 05 03 06-03 08 07 08 08 08 1a 08   $.".............
0090 - 1b 08 1c 08 09 08 0a 08-0b 08 04 08 05 08 06 04   ................
00a0 - 01 05 01 06 01 00 2b 00-03 02 03 04 00 2d 00 02   ......+......-..
00b0 - 01 01 00 33 00 26 00 24-00 1d 00 20 e0 5f 8f d5   ...3.&.$... ._..
00c0 - 1d d4 35 d2 27 44 d5 6e-0f cc 4b cd d4 d2 54 97   ..5.'D.n..K...T.
00d0 - 8c 1b b5 08 82 8e c6 ed-fb 8d d4 24 00 1b 00 03   ...........$....
00e0 - 02 00 01                                          ...
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write change cipher spec
SSL_accept:TLSv1.3 write encrypted extensions
SSL_accept:SSLv3/TLS write certificate
SSL_accept:TLSv1.3 write server certificate verify
write to 0x16a92df0510 [0x16a949f54a0] (879 bytes => 879 (0x36F))
0000 - 16 03 03 00 7a 02 00 00-76 03 03 49 33 3c d0 4d   ....z...v..I3<.M
0010 - ce b0 2a 1e f7 19 5d d7-3f 2f f1 0f 14 be 20 c6   ..*...].?/.... .
0020 - 4a 5b 4d 61 a2 6c 39 ac-c3 9c 47 20 f0 13 dc e6   J[Ma.l9...G ....
0030 - e5 5b ab 34 72 73 fe 10-b9 7e 51 f4 6e 1c 23 1b   .[.4rs...~Q.n.#.
0040 - 58 0e df d9 98 85 f6 c3-2a 39 7b fc 13 04 00 00   X.......*9{.....
0050 - 2e 00 2b 00 02 03 04 00-33 00 24 00 1d 00 20 c0   ..+.....3.$... .
0060 - 53 5b 9d e6 5b ce 35 fe-db 74 0a 10 5a 45 0b 6a   S[..[.5..t..ZE.j
0070 - 50 63 fa eb 08 ae 18 3d-74 27 8e fd c7 c7 65 14   Pc.....=t'....e.
0080 - 03 03 00 01 01 17 03 03-00 17 76 b9 00 be 11 57   ..........v....W
0090 - da a3 5d 08 05 ba bf 35-48 9c 0c 24 35 dd 7b eb   ..]....5H..$5.{.
00a0 - 46 17 03 03 02 2a 48 b0-dd f7 01 16 13 d1 7a db   F....*H.......z.
00b0 - 26 51 c9 58 eb ef 22 48-f8 eb 46 8b 89 3d dc 91   &Q.X.."H..F..=..
00c0 - 28 1a 99 66 35 34 56 af-f2 91 8d 42 cc a3 4e 73   (..f54V....B..Ns
00d0 - cd 87 af 6b f7 10 c4 07-c4 82 21 f9 10 15 ae 57   ...k......!....W
00e0 - 91 bd 0a f2 06 96 db 1c-b2 15 a6 06 73 0b 4b 13   ............s.K.
00f0 - be b1 13 11 e6 d9 60 d7-3f 69 73 1d 83 c8 d9 cf   ......`.?is.....
0100 - b5 ba a0 38 ae 3d b3 ff-cf 13 96 2f df 8d c3 ca   ...8.=...../....
0110 - a8 7c 3c 65 a3 dd ff 04-53 09 88 82 64 50 1a e9   .|<e....S...dP..
0120 - b3 27 b6 20 c3 8c 49 bd-17 d6 c1 04 a7 2b c5 d4   .'. ..I......+..
0130 - f5 6d 38 55 e1 37 5a ff-fb 02 b9 98 36 2b fb 6b   .m8U.7Z.....6+.k
0140 - 00 9b 87 82 4f 1d d1 7f-da c2 be 19 a5 41 68 6e   ....O........Ahn
0150 - 16 6e 94 7f ce 70 12 96-16 98 57 92 3d 6e db 8c   .n...p....W.=n..
0160 - 82 49 be f2 51 79 6e 9c-50 db ed 1b f6 42 ee 9c   .I..Qyn.P....B..
0170 - 31 a9 53 c9 35 47 34 93-e2 ee 74 78 c1 5c 17 16   1.S.5G4...tx.\..
0180 - b5 3c 39 79 a2 79 c2 56-b3 31 2a d0 8d 26 56 37   .<9y.y.V.1*..&V7
0190 - d0 86 cd 87 b8 d4 e3 20-40 f2 a0 a8 e3 d0 39 84   ....... @.....9.
01a0 - c9 38 de 02 34 de 04 9b-bc dc 65 4a cf c2 df 69   .8..4.....eJ...i
01b0 - cc 87 80 6c 05 ff 1c be-51 6b 23 38 90 c9 92 d9   ...l....Qk#8....
01c0 - e6 52 f8 8a 3d 13 b5 f0-29 83 37 86 72 39 78 45   .R..=...).7.r9xE
01d0 - e9 6f ba e2 6a 96 41 fe-9d 08 56 4d b5 7b d1 cf   .o..j.A...VM.{..
01e0 - 86 95 4e b4 ae f9 84 2e-3e ae 80 bb 0d aa 81 64   ..N.....>......d
01f0 - f3 e2 ee 86 c8 ba 88 6e-e2 49 ce f4 8c c0 6a 81   .......n.I....j.
0200 - fe 62 35 ff e7 d1 11 47-e3 d6 da 57 3d 71 18 9e   .b5....G...W=q..
0210 - 93 cb 9d b4 0d a7 39 c8-16 51 fb c6 7c 02 92 00   ......9..Q..|...
0220 - 1a de 0a 7f 68 22 b8 62-20 23 94 69 0e 46 b5 63   ....h".b #.i.F.c
0230 - 52 bf 27 87 79 d1 d4 b3-6f 63 87 ad c6 a0 d5 9d   R.'.y...oc......
0240 - 11 c4 6a 99 69 55 34 6f-d2 fb 68 7e d5 9e 5c a8   ..j.iU4o..h~..\.
0250 - aa 79 6d 93 07 10 c9 2f-5c 79 e3 33 82 86 5a c2   .ym..../\y.3..Z.
0260 - 26 10 e2 b3 51 c0 05 c1-38 6d dc 7e 38 b1 70 8f   &...Q...8m.~8.p.
0270 - c5 7d 0c 2c c5 af 78 2c-34 26 a9 57 17 07 4f 94   .}.,..x,4&.W..O.
0280 - e7 ea 53 b6 93 73 a2 e9-a9 cd b4 af e5 73 d9 a4   ..S..s.......s..
0290 - a0 bc 9f a9 d4 d5 f4 73-65 25 22 6c ca 66 e3 94   .......se%"l.f..
02a0 - 8e e1 0c a1 e4 33 3f 4e-20 c5 72 47 dc 1c 08 57   .....3?N .rG...W
02b0 - 86 9c 95 3b ec 2a dc 8a-b0 38 02 f8 07 65 52 fd   ...;.*...8...eR.
02c0 - 06 86 56 eb f7 08 0a d3-5a 84 98 09 af 93 1c 86   ..V.....Z.......
02d0 - 17 03 03 00 60 c0 a6 0d-74 0e a9 c1 68 66 0c 1c   ....`...t...hf..
02e0 - e2 d6 d6 cf 29 c0 2a c1-b6 36 d6 13 af 26 be 2d   ....).*..6...&.-
02f0 - a8 0f 1d bc 8f 05 3e 8d-bd f0 e9 6f f8 f4 76 32   ......>....o..v2
0300 - c7 cb 93 52 15 0e ad ed-83 79 04 1f 98 c4 f0 fe   ...R.....y......
0310 - 28 87 fb fd f1 dd 2f 08-c8 e6 d3 eb 98 22 43 b0   (...../......"C.
0320 - c2 6e 54 ae 4f 79 02 ad-e4 16 cb 84 10 d0 8b c5   .nT.Oy..........
0330 - 67 28 5d 79 66 17 03 03-00 35 e7 34 ee 17 47 04   g(]yf....5.4..G.
0340 - 7a fa d7 b8 c5 ef 8d 1d-9f 9f c3 93 ed a3 d0 92   z...............
0350 - 9a 4a 25 3c 98 f6 1e ec-58 df 54 76 01 ac 4e 5f   .J%<....X.Tv..N_
0360 - 4d d5 32 31 1f 68 83 45-33 88 f7 15 ae f6 45      M.21.h.E3.....E
SSL_accept:SSLv3/TLS write finished
SSL_accept:TLSv1.3 early data
read from 0x16a92df0510 [0x16a949f64b3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x16a92df0510 [0x16a949f64b8] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x16a92df0510 [0x16a949f64b3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
read from 0x16a92df0510 [0x16a949f64b8] (53 bytes => 53 (0x35))
0000 - 10 e1 6d b0 73 df 52 90-e2 d5 a6 3c 5a c5 ea 2c   ..m.s.R....<Z..,
0010 - b6 5f b4 2b 8b 92 ba 84-6d 27 aa d7 de 4e cb dd   ._.+....m'...N..
0020 - 8a 4f 8f 4b a5 0d 84 44-22 2a 01 f5 87 45 b3 5c   .O.K...D"*...E.\
0030 - e0 1f 6a 44 a8                                    ..jD.
SSL_accept:TLSv1.3 early data
SSL_accept:SSLv3/TLS read finished
write to 0x16a92df0510 [0x16a949f54a0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea 74 57 a5-a5 37 db 2a 8f b9 0c d4   .....tW..7.*....
0010 - ce d9 ad 0f 81 d7 a3 ee-c6 39 fb 18 fb 77 8e 07   .........9...w..
0020 - d5 c0 5c c6 74 05 9e b9-ef 99 13 ad c6 fb c8 96   ..\.t...........
0030 - b6 5c 1f 85 6c b2 6e 15-45 24 d3 1b 52 de 2c 2f   .\..l.n.E$..R.,/
0040 - ee da 4c 3c c6 90 7e f3-aa 58 19 09 05 76 a7 0b   ..L<..~..X...v..
0050 - 79 f5 cd 50 30 bb e1 d1-75 e1 85 dd 3e 02 eb 8f   y..P0...u...>...
0060 - 66 ed a4 ff 20 49 6d 33-42 1e cd 64 db 02 84 1d   f... Im3B..d....
0070 - 45 aa b1 6f 21 55 47 ca-4c 2b 2d c9 30 68 d0 f3   E..o!UG.L+-.0h..
0080 - 02 aa 49 73 d6 e5 a5 07-a5 82 5a c8 15 6a 66 d7   ..Is......Z..jf.
0090 - b7 ff 52 03 fc 1a 24 1b-2c c9 21 71 eb ff 58 76   ..R...$.,.!q..Xv
00a0 - db b8 af a2 af e5 e3 10-58 c2 15 0e 9a f6 e2 8e   ........X.......
00b0 - 28 06 84 26 41 04 37 9f-5f a7 e8 1e 41 16 14 ad   (..&A.7._...A...
00c0 - 8b a9 19 f1 49 18 a7 12-37 37 eb 3d 6d 49 6a 07   ....I...77.=mIj.
00d0 - 98 e4 6c 24 83 94 96 28-7b 12 fa 6e 51 e8 df 11   ..l$...({..nQ...
00e0 - ef ed 53 87 e0 c9 58 07-1e 97 9c 7e 42 d8 2e      ..S...X....~B..
SSL_accept:SSLv3/TLS write session ticket
write to 0x16a92df0510 [0x16a949f54a0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea 57 44 a5-b6 b5 84 4c ad e0 e3 0e   .....WD....L....
0010 - 37 af 8d ac 4b 80 95 a4-d7 bd a0 45 34 44 ac e7   7...K......E4D..
0020 - 46 17 99 85 98 63 f2 8e-d3 69 bc f9 37 82 35 99   F....c...i..7.5.
0030 - be 13 ee ed f1 e8 01 52-90 9a fb f1 0a 5e 47 eb   .......R.....^G.
0040 - f9 96 1d ff 7d 6a 08 ef-e5 0d a9 32 78 6e 69 41   ....}j.....2xniA
0050 - d4 73 14 13 d6 7c e1 0c-e2 0f 1e 43 0b 80 60 f4   .s...|.....C..`.
0060 - d8 a7 a8 c4 59 7b a9 34-5c a1 6f 1c ab a4 07 b9   ....Y{.4\.o.....
0070 - 77 a3 bb 1f f5 c6 9e 9a-0b 0b 58 5d 94 03 d0 8a   w.........X]....
0080 - 9e 34 7e 14 c9 29 02 d5-67 71 49 a2 6c dd a8 f9   .4~..)..gqI.l...
0090 - 05 6d d4 89 e5 79 78 eb-ea 23 85 d5 7e a3 59 02   .m...yx..#..~.Y.
00a0 - a8 ed fb 71 ec b0 f3 00-76 f6 6f 4c 87 d5 da 3e   ...q....v.oL...>
00b0 - da 9e 27 e5 5a 37 3e 84-f7 0b 0d 75 39 49 74 57   ..'.Z7>....u9ItW
00c0 - 6d f8 c3 e6 fe aa 9e 1d-4f 24 d9 a5 6f 4a e4 f7   m.......O$..oJ..
00d0 - dc d6 32 f0 ed 66 53 54-1b 16 ae 7d 89 07 13 43   ..2..fST...}...C
00e0 - ff 36 7d 3d 73 9d c8 8f-53 0a 0d ab 1f a0 3e      .6}=s...S.....>
SSL_accept:SSLv3/TLS write session ticket
-----BEGIN SSL SESSION PARAMETERS-----
MHICAQECAgMEBAITBAQgnqEPkIZfnYzImdMDg4yg6CtDutEQbghEG9vfQTOjH8ME
ILD2lqY767paSHhEj6eO4NlPUKbds4FlFJIBi/5PaDDcoQYCBGg2qiyiBAICHCCk
BgQEAQAAAK4GAgRIbjFWswMCAR0=
-----END SSL SESSION PARAMETERS-----
Shared ciphers:TLS_AES_128_CCM_SHA256
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Supported groups: x25519:secp256r1:x448:secp521r1:secp384r1:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192
Shared groups: x25519:secp256r1:x448:secp521r1:secp384r1:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192
CIPHER is TLS_AES_128_CCM_SHA256
This TLS version forbids renegotiation.
read from 0x16a92df0510 [0x16a949eede3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x16a92df0510 [0x16a949eede8] (23 bytes => 23 (0x17))
0000 - de c7 2b 92 cd 5a eb d7-09 23 79 c2 ea 39 32 5f   ..+..Z...#y..92_
0010 - 3c ea 2e ea 6e 6d 28                              <...nm(
test
read from 0x16a92df0510 [0x16a949eede3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 13                                    .....
read from 0x16a92df0510 [0x16a949eede8] (19 bytes => 19 (0x13))
0000 - 8d c4 d6 ce d5 f1 0c 0f-b5 2d 3f 9d 99 1c fd 95   .........-?.....
0010 - 42 04 87                                          B..
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x16a92df0510 [0x16a949ffb13] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 06 a9 a4-a9 6f fd f2 cb 13 00 c1   .........o......
0010 - b0 3c 79 52 15 fb d8 db-                          .<yR....
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
