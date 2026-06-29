#### server

````
$ openssl s_server -accept 9000 -cert ecdsa.crt -key ecdsa.key -state -debug -status_verbose -keylogfile sslkeylog
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x1e4ad79f0f0 [0x1e4adbb84b3] (5 bytes => 5 (0x5))
0000 - 16 03 01 00 e3                                    .....
read from 0x1e4ad79f0f0 [0x1e4adbb84b8] (227 bytes => 227 (0xE3))
0000 - 01 00 00 df 03 03 c5 5d-7d e4 cc a2 ee 3f 72 5c   .......]}....?r\
0010 - a0 27 cb b3 0a 1b f3 b8-57 f2 96 2a a4 b7 bc cf   .'......W..*....
0020 - 31 06 bb c9 e7 b3 20 cd-b0 2b 3b 2b 06 fe cc 9f   1..... ..+;+....
0030 - fc 32 0c 46 e7 55 cc 51-41 7a 30 84 e4 bd 8a 64   .2.F.U.QAz0....d
0040 - 78 53 ff 34 37 6e 86 00-02 13 03 01 00 00 94 00   xS.47n..........
0050 - 0b 00 04 03 00 01 02 00-0a 00 16 00 14 00 1d 00   ................
0060 - 17 00 1e 00 19 00 18 01-00 01 01 01 02 01 03 01   ................
0070 - 04 00 23 00 00 00 16 00-00 00 17 00 00 00 0d 00   ..#.............
0080 - 24 00 22 04 03 05 03 06-03 08 07 08 08 08 1a 08   $.".............
0090 - 1b 08 1c 08 09 08 0a 08-0b 08 04 08 05 08 06 04   ................
00a0 - 01 05 01 06 01 00 2b 00-03 02 03 04 00 2d 00 02   ......+......-..
00b0 - 01 01 00 33 00 26 00 24-00 1d 00 20 90 08 ff 08   ...3.&.$... ....
00c0 - 34 3c ab 2b 32 2e a0 b5-02 ca c0 9c 34 bd 07 30   4<.+2.......4..0
00d0 - 39 98 f9 1f 96 c6 ef 14-c5 f6 cf 43 00 1b 00 03   9..........C....
00e0 - 02 00 01                                          ...
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write change cipher spec
SSL_accept:TLSv1.3 write encrypted extensions
SSL_accept:SSLv3/TLS write certificate
SSL_accept:TLSv1.3 write server certificate verify
write to 0x1e4ad79f0f0 [0x1e4adbb74a0] (879 bytes => 879 (0x36F))
0000 - 16 03 03 00 7a 02 00 00-76 03 03 94 d9 85 bd 42   ....z...v......B
0010 - 8c 53 b2 85 92 da cd 71-d6 95 96 78 17 80 19 8e   .S.....q...x....
0020 - 94 d4 f0 4f cc 89 62 71-5f 6a f6 20 cd b0 2b 3b   ...O..bq_j. ..+;
0030 - 2b 06 fe cc 9f fc 32 0c-46 e7 55 cc 51 41 7a 30   +.....2.F.U.QAz0
0040 - 84 e4 bd 8a 64 78 53 ff-34 37 6e 86 13 03 00 00   ....dxS.47n.....
0050 - 2e 00 2b 00 02 03 04 00-33 00 24 00 1d 00 20 20   ..+.....3.$...
0060 - 72 6f 25 f8 d7 c3 08 35-83 10 1b 81 b7 c5 4e 02   ro%....5......N.
0070 - cc d4 13 1b 7d 16 84 8a-8c e7 25 68 94 27 50 14   ....}.....%h.'P.
0080 - 03 03 00 01 01 17 03 03-00 17 49 e7 75 95 d0 5d   ..........I.u..]
0090 - 20 cc 42 7d ba 15 2c ef-4d 28 0b 38 93 c1 18 9d    .B}..,.M(.8....
00a0 - 42 17 03 03 02 2a e3 37-0e 36 1a 40 06 56 9c 69   B....*.7.6.@.V.i
00b0 - b9 f8 50 3e 30 0d ce 59-8b c5 6d fb b0 a6 72 c3   ..P>0..Y..m...r.
00c0 - 10 13 9f d4 a9 de a8 44-a2 f6 bf 1a e8 5e 52 64   .......D.....^Rd
00d0 - bd b3 f4 e1 93 8e e3 52-a5 25 05 c4 b1 6d 87 94   .......R.%...m..
00e0 - 41 0e 71 60 bb 22 8c a1-82 0f 5f 40 44 74 ed 2b   A.q`."...._@Dt.+
00f0 - 44 59 3b b3 7f f2 23 f4-1d 86 17 96 c2 20 7a 0b   DY;...#...... z.
0100 - 2b c8 ff 4e 0e 4d eb a0-44 dc ea f7 64 95 df d3   +..N.M..D...d...
0110 - 2e e0 b0 84 70 35 e6 ba-80 a5 4b 82 db 49 7c f9   ....p5....K..I|.
0120 - 57 02 3c 50 c0 05 22 1e-84 e8 bc 11 53 da 5c 0a   W.<P..".....S.\.
0130 - 8c 36 45 b0 60 d5 04 2d-ea bb c7 82 d5 3c 08 cc   .6E.`..-.....<..
0140 - 96 b4 99 dc 7b 60 37 27-37 66 19 09 a5 9d 27 d4   ....{`7'7f....'.
0150 - d8 7a 24 2c 6f 23 1a 63-ab b1 c3 e3 6c 07 e4 1e   .z$,o#.c....l...
0160 - 7e 9b bf 29 d5 85 91 89-4c ef 14 a3 7f 20 22 99   ~..)....L.... ".
0170 - f5 5d f1 47 db b4 57 e6-07 38 7e 9f de 0f 2b ec   .].G..W..8~...+.
0180 - e9 d0 24 a1 a2 e2 ef a2-1f df ed 0c 2d 6d c4 a9   ..$.........-m..
0190 - a5 0c 89 ce 61 bc 64 5e-d3 2e 4d cc 5a ed 29 a9   ....a.d^..M.Z.).
01a0 - fa d1 33 8d 1b 3f 48 b4-7c 79 bf af f9 fe 71 85   ..3..?H.|y....q.
01b0 - 6d 60 1e 0e 2f c8 2a cd-80 d2 ec f0 86 f4 df 9e   m`../.*.........
01c0 - 2f 72 9b 84 13 9b b1 6e-87 ae 58 f0 75 06 30 83   /r.....n..X.u.0.
01d0 - 22 74 82 09 1b b8 01 66-65 49 41 70 ab 9e e8 12   "t.....feIAp....
01e0 - 08 57 f3 af 51 9c 56 15-c5 b3 75 00 4d 9d e5 b3   .W..Q.V...u.M...
01f0 - e0 c5 b5 59 4c ea 2d a8-2d 06 bf 88 3a 50 7e 5e   ...YL.-.-...:P~^
0200 - f4 19 5e 1b 4a ce a6 e9-8d f9 ed 3d e1 57 ea b0   ..^.J......=.W..
0210 - 10 a4 f9 18 94 cc 7e 65-88 f3 0d e3 cb b4 bd fb   ......~e........
0220 - f5 d4 c5 7a 68 3f 22 82-30 a1 90 37 7d 9c b5 f0   ...zh?".0..7}...
0230 - 6b 4e 6f f2 c8 c9 b0 79-a3 d1 c4 05 a6 ed e0 a5   kNo....y........
0240 - 37 93 6b da 43 a7 ee c0-ed 60 32 16 0f 0c 7a d4   7.k.C....`2...z.
0250 - 67 71 3c d3 68 0f f2 b6-1d d7 31 a4 87 8d 42 06   gq<.h.....1...B.
0260 - d9 38 6c a1 ec a4 ab 91-3f 77 a9 67 c1 7f c6 27   .8l.....?w.g...'
0270 - 6c 5b d2 7f 53 8d c5 d8-5c 07 eb c0 a9 0d 35 59   l[..S...\.....5Y
0280 - 6c 4e d7 f4 f2 0c 2d f8-4d 1c 78 16 dc 5c 48 b6   lN....-.M.x..\H.
0290 - 85 f2 ff af 17 17 b1 2c-7f 08 86 bf 89 c6 a7 70   .......,.......p
02a0 - 80 f1 fb d2 af 7a e9 09-08 b9 df f1 03 54 76 66   .....z.......Tvf
02b0 - 15 4b 9d 5b a1 61 8f 6c-7b 4e 63 46 55 a7 b0 0a   .K.[.a.l{NcFU...
02c0 - 58 fb fb c4 c2 d5 c2 37-e2 2c bd 46 23 7f c6 1e   X......7.,.F#...
02d0 - 17 03 03 00 60 cb 6b 7d-79 1e 14 47 a5 d1 78 b9   ....`.k}y..G..x.
02e0 - b2 59 37 83 59 90 dc 46-8e f3 28 19 a3 cd 7b d5   .Y7.Y..F..(...{.
02f0 - 25 80 39 8e f7 dd 6a b0-9c 91 c8 6d 66 af 00 a2   %.9...j....mf...
0300 - 76 ea 26 0d 31 e1 61 9a-bd 11 f6 42 fe 9d 76 ad   v.&.1.a....B..v.
0310 - 7d 62 50 da 42 fe d5 52-37 0f 67 de ec bf e1 e1   }bP.B..R7.g.....
0320 - 98 ed 69 91 2f 9e 37 20-ef cd 8b 68 8c 2f e9 5b   ..i./.7 ...h./.[
0330 - 5c 32 21 9f 2c 17 03 03-00 35 86 67 ea e2 4f 8a   \2!.,....5.g..O.
0340 - bb 08 87 59 b8 4a 27 fc-26 51 43 ba 68 cb 94 01   ...Y.J'.&QC.h...
0350 - 13 bc db 9a 41 4a 50 c4-26 49 fa b6 73 e6 88 d5   ....AJP.&I..s...
0360 - 55 1e 3c e7 2c 10 fb fe-53 8d ff cd dc d4 40      U.<.,...S.....@
SSL_accept:SSLv3/TLS write finished
SSL_accept:TLSv1.3 early data
read from 0x1e4ad79f0f0 [0x1e4adbbc9a3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x1e4ad79f0f0 [0x1e4adbbc9a8] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x1e4ad79f0f0 [0x1e4adbbc9a3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
read from 0x1e4ad79f0f0 [0x1e4adbbc9a8] (53 bytes => 53 (0x35))
0000 - de 19 ea 02 75 ab 10 91-7a 37 c2 77 50 9e ac 25   ....u...z7.wP..%
0010 - 8a 2e 0c 72 b5 15 62 5c-d0 db df 0d b7 c2 2c 26   ...r..b\......,&
0020 - 73 d6 a6 10 61 34 c0 ad-cf 26 90 cf b4 65 c5 bf   s...a4...&...e..
0030 - 7c af 61 9d 85                                    |.a..
SSL_accept:TLSv1.3 early data
SSL_accept:SSLv3/TLS read finished
write to 0x1e4ad79f0f0 [0x1e4adbb74a0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea 2e 66 ba-03 04 78 98 2f eb 84 96   ......f...x./...
0010 - 67 70 5d 2f 63 d9 cf f1-df f8 d3 8a 83 eb c6 87   gp]/c...........
0020 - f4 b2 a0 f0 b3 aa b7 fe-00 68 a7 9f 53 45 20 da   .........h..SE .
0030 - c6 1d e0 54 33 8e 2b 25-ee 5a d3 92 42 d3 ae 89   ...T3.+%.Z..B...
0040 - d3 b6 61 c6 b0 a4 f8 36-a0 05 ef a3 d8 db 67 c6   ..a....6......g.
0050 - 0b bc 48 43 8b 62 e4 53-e7 78 85 11 ec ef 41 3d   ..HC.b.S.x....A=
0060 - 32 92 32 5a 8e f9 7c 33-96 1f 8b 5f 02 f8 1c b7   2.2Z..|3..._....
0070 - ca 33 72 44 c5 50 0f 66-d6 06 a9 bc aa d2 b1 0b   .3rD.P.f........
0080 - 3e 54 90 0c a8 d9 4c f9-e0 83 df 0c 23 70 5a 59   >T....L.....#pZY
0090 - 15 c7 51 50 ad 44 77 c3-d7 bf f6 04 d7 42 06 2f   ..QP.Dw......B./
00a0 - 1a 03 ca 3b cc 41 04 98-36 3c c9 f3 04 3f 95 32   ...;.A..6<...?.2
00b0 - 3d e3 b1 11 4b 9e 6c 94-bf e3 a7 ea c4 61 97 d5   =...K.l......a..
00c0 - 9c 6b 3f 06 20 a1 f7 0f-65 8a 3f 4b 05 f1 a4 d2   .k?. ...e.?K....
00d0 - 88 51 65 71 2f 7d bd ff-31 88 cc 58 a9 4c 70 08   .Qeq/}..1..X.Lp.
00e0 - e5 c2 21 06 3c a2 b6 09-9e 7f ad 63 78 20 70      ..!.<......cx p
SSL_accept:SSLv3/TLS write session ticket
write to 0x1e4ad79f0f0 [0x1e4adbb74a0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea 2b 97 be-44 5a ca 9a 5f 14 18 76   .....+..DZ.._..v
0010 - 46 ec 29 5f 01 69 8f b6-ac aa 2f fb 32 00 d8 ca   F.)_.i..../.2...
0020 - b0 ea 77 e5 2b 60 0f 72-4f 85 a4 a9 b2 d3 c6 d9   ..w.+`.rO.......
0030 - ab ad 4b a9 b2 f0 f0 94-07 c5 c2 48 a6 65 d8 91   ..K........H.e..
0040 - 2d 66 83 e6 f2 44 a2 48-bf 64 76 ba e4 db 45 0b   -f...D.H.dv...E.
0050 - 3a e3 39 6e ae 9d db b6-00 ec 7f 07 a2 94 a3 3c   :.9n...........<
0060 - 6d 87 33 99 4e 86 30 52-4e 14 0e 05 f1 f7 67 eb   m.3.N.0RN.....g.
0070 - d9 78 ec 54 a0 4d 8b 52-45 96 1f 25 9a 30 29 cc   .x.T.M.RE..%.0).
0080 - 3d 80 40 fc 01 c4 cc 1d-9b 91 82 64 32 84 be e8   =.@........d2...
0090 - 08 ef ff 66 0e 34 66 2c-94 80 cf f4 7b 89 b5 1a   ...f.4f,....{...
00a0 - c4 57 df b8 f8 89 01 53-6b ca f8 dc 86 7b 30 ae   .W.....Sk....{0.
00b0 - 6b 3f af d8 9f fe 7c 2b-69 26 40 b2 42 87 31 e1   k?....|+i&@.B.1.
00c0 - 07 e1 e6 14 26 cb 31 9f-bc e6 5f 67 53 4c 62 9e   ....&.1..._gSLb.
00d0 - 7f e8 75 0a 4b ea af 6b-09 1b 72 87 82 3a f5 d4   ..u.K..k..r..:..
00e0 - 14 f4 3b 72 98 46 07 ce-9d 34 1c 52 ee ce e8      ..;r.F...4.R...
SSL_accept:SSLv3/TLS write session ticket
-----BEGIN SSL SESSION PARAMETERS-----
MHMCAQECAgMEBAITAwQgHodLgBu14nb9wbx4LxF6WiBCaBjUDZ+I8UE369mgPwIE
IBXoU2Lua8na1VCBIHiFrVa5xD7HTU2KzNYJZMGrgLCvoQYCBGg2n3+iBAICHCCk
BgQEAQAAAK4HAgUAgiSOdbMDAgEd
-----END SSL SESSION PARAMETERS-----
Shared ciphers:TLS_CHACHA20_POLY1305_SHA256
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Supported groups: x25519:secp256r1:x448:secp521r1:secp384r1:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192
Shared groups: x25519:secp256r1:x448:secp521r1:secp384r1:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192
CIPHER is TLS_CHACHA20_POLY1305_SHA256
This TLS version forbids renegotiation.
read from 0x1e4ad79f0f0 [0x1e4adbb03e3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x1e4ad79f0f0 [0x1e4adbb03e8] (23 bytes => 23 (0x17))
0000 - a7 08 39 a3 f8 53 2b 8b-1e e8 20 bb 86 cc ef 9f   ..9..S+... .....
0010 - 8d a4 7c e7 b7 68 79                              ..|..hy
test
read from 0x1e4ad79f0f0 [0x1e4adbb03e3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 13                                    .....
read from 0x1e4ad79f0f0 [0x1e4adbb03e8] (19 bytes => 19 (0x13))
0000 - f9 81 52 9f a2 78 a7 b9-c4 f1 74 16 f2 28 bf f2   ..R..x....t..(..
0010 - e8 ed bc                                          ...
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x1e4ad79f0f0 [0x1e4adbbc9a3] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 ec dc 93-21 f5 3b ce e3 dd 8b 6f   ........!.;....o
0010 - db e6 c6 20 b5 6c d8 a8-                          ... .l..
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
