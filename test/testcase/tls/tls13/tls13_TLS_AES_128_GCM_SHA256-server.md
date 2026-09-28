#### server

````
openssl s_server -accept 9000 -cert ecdsa.crt -key ecdsa.key -state -debug -status_verbose -keylogfile sslkeylog
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x29b8aece640 [0x29b8b2e84b3] (5 bytes => 5 (0x5))
0000 - 16 03 01 00 e3                                    .....
read from 0x29b8aece640 [0x29b8b2e84b8] (227 bytes => 227 (0xE3))
0000 - 01 00 00 df 03 03 80 9e-81 58 ce 56 15 09 69 11   .........X.V..i.
0010 - 89 60 42 af a6 6b 1b df-63 67 8c 35 ac e0 66 18   .`B..k..cg.5..f.
0020 - e5 da 52 0c 2d ed 20 f7-9f 1a 7a 3f ad 6e 27 80   ..R.-. ...z?.n'.
0030 - 28 4f 41 2c df 99 29 f0-2d 86 8e d4 0a 83 0e b2   (OA,..).-.......
0040 - b8 36 38 51 d8 e1 04 00-02 13 01 01 00 00 94 00   .68Q............
0050 - 0b 00 04 03 00 01 02 00-0a 00 16 00 14 00 1d 00   ................
0060 - 17 00 1e 00 19 00 18 01-00 01 01 01 02 01 03 01   ................
0070 - 04 00 23 00 00 00 16 00-00 00 17 00 00 00 0d 00   ..#.............
0080 - 24 00 22 04 03 05 03 06-03 08 07 08 08 08 1a 08   $.".............
0090 - 1b 08 1c 08 09 08 0a 08-0b 08 04 08 05 08 06 04   ................
00a0 - 01 05 01 06 01 00 2b 00-03 02 03 04 00 2d 00 02   ......+......-..
00b0 - 01 01 00 33 00 26 00 24-00 1d 00 20 c6 f8 68 91   ...3.&.$... ..h.
00c0 - cb 99 eb 2c cc 1f c2 05-4d a2 6f fa ee 70 d3 69   ...,....M.o..p.i
00d0 - 82 97 8d a8 9d 2b 1a 40-a3 c7 7a 42 00 1b 00 03   .....+.@..zB....
00e0 - 02 00 01                                          ...
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write change cipher spec
SSL_accept:TLSv1.3 write encrypted extensions
SSL_accept:SSLv3/TLS write certificate
SSL_accept:TLSv1.3 write server certificate verify
write to 0x29b8aece640 [0x29b8b2e74a0] (879 bytes => 879 (0x36F))
0000 - 16 03 03 00 7a 02 00 00-76 03 03 1a ec 8f 05 c3   ....z...v.......
0010 - 3b 74 5e 02 80 08 53 a1-1a b9 28 a4 5f 26 0a 57   ;t^...S...(._&.W
0020 - 2f 6a f6 a6 da 41 76 62-8e 59 59 20 f7 9f 1a 7a   /j...Avb.YY ...z
0030 - 3f ad 6e 27 80 28 4f 41-2c df 99 29 f0 2d 86 8e   ?.n'.(OA,..).-..
0040 - d4 0a 83 0e b2 b8 36 38-51 d8 e1 04 13 01 00 00   ......68Q.......
0050 - 2e 00 2b 00 02 03 04 00-33 00 24 00 1d 00 20 11   ..+.....3.$... .
0060 - 53 8f 59 ea 97 5f 73 69-7e 93 b8 de 74 00 30 b5   S.Y.._si~...t.0.
0070 - 1e a3 1e f6 7a fa db 43-55 8e 7f 93 2d 8f 37 14   ....z..CU...-.7.
0080 - 03 03 00 01 01 17 03 03-00 17 f5 e2 92 8c 6c ae   ..............l.
0090 - 19 63 88 fa 9d 36 f6 e8-4a 7b 6f 7d a1 64 51 48   .c...6..J{o}.dQH
00a0 - 39 17 03 03 02 2a a9 68-4b bb 75 b7 76 c9 b7 ba   9....*.hK.u.v...
00b0 - 8a d6 a9 c5 42 f8 26 8f-97 fe c2 a9 a2 ec 4d 5e   ....B.&.......M^
00c0 - 7d 71 73 03 84 a2 31 87-b4 39 11 d6 29 37 4b b0   }qs...1..9..)7K.
00d0 - c0 22 30 1a 1f 85 98 9c-71 86 57 8f 0a 38 01 f3   ."0.....q.W..8..
00e0 - 38 96 92 9c 3b d0 da 6b-dd 4f 7c 57 ad cf 60 9e   8...;..k.O|W..`.
00f0 - 95 fe af b8 60 7d 89 25-6d 1f ba fa 82 7e f5 f8   ....`}.%m....~..
0100 - 55 e4 72 21 ff fd 38 4f-b2 a0 2d 37 ad 5a cd 19   U.r!..8O..-7.Z..
0110 - e2 a7 be ce d5 76 ee c8-e1 83 7f c0 6c 45 d7 52   .....v......lE.R
0120 - 9a 7a 0f ab 8b 7f e4 0b-34 32 29 60 6f 02 6c f3   .z......42)`o.l.
0130 - 62 00 9e c0 75 84 ca 4b-61 02 3c 40 b3 65 10 49   b...u..Ka.<@.e.I
0140 - f4 26 93 29 16 2e 63 93-01 3c bc 70 f4 b0 fa 22   .&.)..c..<.p..."
0150 - 42 6c 9f 9a 33 ad b9 4e-91 42 2d 96 6b 6a 47 62   Bl..3..N.B-.kjGb
0160 - 06 30 8e 4f da 12 7b f1-11 6d 34 78 52 4b db 09   .0.O..{..m4xRK..
0170 - d7 f0 39 52 fb eb 3d 65-ab a7 0f cf fc 6f 7d 50   ..9R..=e.....o}P
0180 - db 5f 5d 18 a8 c5 d9 db-38 74 81 9d 4c b6 11 c2   ._].....8t..L...
0190 - 57 98 31 42 ff 2f ce d3-ca 16 4b fe f1 40 ae bd   W.1B./....K..@..
01a0 - 0f bb 56 72 01 3c 30 96-89 40 99 50 67 2b 9a 64   ..Vr.<0..@.Pg+.d
01b0 - e9 87 36 cc 1c ee 13 87-ff fd f5 b0 40 9b 78 82   ..6.........@.x.
01c0 - ae c0 86 20 60 14 16 ef-3a 83 35 f1 8c 7b 1a bc   ... `...:.5..{..
01d0 - ce c8 ce 54 e9 81 2e 4a-87 0f 4e a0 24 c5 11 bd   ...T...J..N.$...
01e0 - c9 b6 f4 61 4a be 00 2e-ff 8b 3f db 46 8e fb 5e   ...aJ.....?.F..^
01f0 - b0 4a 59 2a 92 42 a5 c3-92 01 16 ad 76 a9 13 9a   .JY*.B......v...
0200 - c0 4e 44 49 20 24 e6 25-89 c9 78 08 db e0 ff 6f   .NDI $.%..x....o
0210 - 43 5e 44 bc 3b a9 f8 94-2d 60 da 95 36 24 7c cc   C^D.;...-`..6$|.
0220 - 0d e2 1a 79 90 f6 bc 66-79 1b 1a 28 fc 66 8c 46   ...y...fy..(.f.F
0230 - 29 4e aa 6a a3 eb 28 d9-b3 7a 3a 92 03 53 a7 bb   )N.j..(..z:..S..
0240 - b9 26 e4 dc 0c 91 42 ac-b3 d4 44 52 be c8 b1 d4   .&....B...DR....
0250 - ce 5a 95 64 f7 cb 0a 6c-8e 7c 88 a1 f6 ef 58 d1   .Z.d...l.|....X.
0260 - 08 40 a9 5b b7 c9 ad 8e-b3 9a 53 b5 62 07 17 90   .@.[......S.b...
0270 - fa aa ff cb a7 b3 ad bf-4d e2 a1 5f fb 4a 79 96   ........M.._.Jy.
0280 - a7 3c 88 7c 8b 15 57 20-ce 8a aa 74 02 c7 0c 5c   .<.|..W ...t...\
0290 - 3b 99 45 89 b8 00 08 a3-79 ae e9 96 54 80 41 e9   ;.E.....y...T.A.
02a0 - fe 30 88 9e af 1f 6c 23-f5 1d 1a 2f 3f e2 db eb   .0....l#.../?...
02b0 - ef b9 7d 19 3c b8 d2 5c-59 4c 00 2b b6 6a 0a b4   ..}.<..\YL.+.j..
02c0 - de e3 72 07 7f d1 f2 54-7f 60 ce 77 7e f5 43 c5   ..r....T.`.w~.C.
02d0 - 17 03 03 00 60 23 bc f5-d4 62 52 b5 11 0b 96 2a   ....`#...bR....*
02e0 - 93 87 02 e4 94 62 35 20-9b a5 c7 87 3d 54 fc e0   .....b5 ....=T..
02f0 - f2 74 a8 ec b4 98 0e 04-24 7c 47 b0 4f 40 65 b0   .t......$|G.O@e.
0300 - 40 86 52 84 12 df 8e 3e-f0 4e 6d 7c 9a bb 5b a1   @.R....>.Nm|..[.
0310 - 93 ed 8d 02 45 3d 16 3b-74 53 a0 db 05 2b bb 21   ....E=.;tS...+.!
0320 - 94 23 0d 84 35 c3 d6 ea-82 59 7d 30 53 cf 29 aa   .#..5....Y}0S.).
0330 - 8e 29 b4 d3 c1 17 03 03-00 35 64 46 bb 8b f1 80   .).......5dF....
0340 - d7 a7 b0 08 ae 1d 4a 60-18 a2 6e 3f c2 a3 ea d1   ......J`..n?....
0350 - b3 02 19 b9 72 5b 69 7b-c3 c6 fd ab 83 cd 6c 52   ....r[i{......lR
0360 - eb 0c 08 80 3e e5 90 26-80 66 a7 2f 98 5d 7e      ....>..&.f./.]~
SSL_accept:SSLv3/TLS write finished
SSL_accept:TLSv1.3 early data
read from 0x29b8aece640 [0x29b8b2ec9a3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x29b8aece640 [0x29b8b2ec9a8] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x29b8aece640 [0x29b8b2ec9a3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
read from 0x29b8aece640 [0x29b8b2ec9a8] (53 bytes => 53 (0x35))
0000 - 51 11 89 9e 96 36 37 43-e2 6c 51 36 59 79 87 1c   Q....67C.lQ6Yy..
0010 - cf 33 83 5e 01 d8 9d fe-33 d8 0d 91 a7 b3 16 f1   .3.^....3.......
0020 - b0 35 5f c3 f2 58 33 b9-27 94 a8 03 f2 08 57 97   .5_..X3.'.....W.
0030 - b6 48 c3 7c ac                                    .H.|.
SSL_accept:TLSv1.3 early data
SSL_accept:SSLv3/TLS read finished
write to 0x29b8aece640 [0x29b8b2e74a0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea 37 46 36-b1 0b 9a ee d9 8a 7c d8   .....7F6......|.
0010 - 76 96 49 6d d5 4d 30 7c-77 f4 e9 0d 2e 64 4f 93   v.Im.M0|w....dO.
0020 - 3d 28 0a 5f fb 6b e9 76-12 0e bd ec b8 b3 f7 62   =(._.k.v.......b
0030 - cd 63 3d eb bb fd b9 9d-e1 db 53 cd 07 0c f8 4a   .c=.......S....J
0040 - e9 98 3d fa 2a b8 90 73-7d bd 21 d2 b1 ca 33 8d   ..=.*..s}.!...3.
0050 - 12 0d 08 40 23 fa e0 e2-21 9f b8 b8 29 1f 17 4f   ...@#...!...)..O
0060 - f6 bc a1 8d c1 41 fc 10-da 5d 82 f5 f4 88 42 76   .....A...]....Bv
0070 - d2 ab 2a bc e1 2c 3f 5a-2a a1 1e 8d a6 08 28 ab   ..*..,?Z*.....(.
0080 - fd c3 b7 17 06 7f b9 d0-97 13 d5 82 c9 37 c8 dd   .............7..
0090 - 6b 48 56 52 11 30 b7 9d-80 8d 9f 29 e3 6d 61 98   kHVR.0.....).ma.
00a0 - 65 03 b3 f7 ec 6e df 48-48 79 d3 2f a7 a9 51 d9   e....n.HHy./..Q.
00b0 - 64 91 af 96 0d 68 d7 77-d6 f4 93 69 1c e9 d1 ab   d....h.w...i....
00c0 - 76 bd 3c 96 95 f0 62 d2-db ac 14 0d ce 89 f4 04   v.<...b.........
00d0 - ab 75 74 e9 b3 ef fd 37-ac ff 7c 72 7b b4 e8 ad   .ut....7..|r{...
00e0 - 90 a8 b9 9d 03 5d 61 29-e2 8b 0d 2d 10 33 08      .....]a)...-.3.
SSL_accept:SSLv3/TLS write session ticket
write to 0x29b8aece640 [0x29b8b2e74a0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea 15 0d c6-fc 46 1c 65 8c be cd 80   .........F.e....
0010 - bc a5 30 eb b7 c5 e6 81-b4 15 91 87 bb 66 78 82   ..0..........fx.
0020 - ae cc ae da df 8d ed a3-0b 5a 61 61 1e 3d 98 c9   .........Zaa.=..
0030 - 79 d3 30 a9 e4 39 d5 a1-b5 ba 66 aa 7e 8c 98 ee   y.0..9....f.~...
0040 - f1 7b 32 27 47 d7 75 02-53 eb 5b 4f e7 97 e1 ca   .{2'G.u.S.[O....
0050 - 78 15 f2 16 dc 03 ec ad-08 a4 fa 63 7c 21 bb af   x..........c|!..
0060 - 3b a5 7e aa 82 a6 2b 5a-d6 06 9d 53 8f 9e 3a ab   ;.~...+Z...S..:.
0070 - 1c 84 0c 61 70 f4 75 1f-53 d1 e8 11 57 87 6e 7a   ...ap.u.S...W.nz
0080 - fe 2c dd 6a d3 67 67 a0-41 de 0b fa 95 db d8 e6   .,.j.gg.A.......
0090 - 92 26 c4 9a b3 76 6f d4-ca a1 3d cb e1 5a b2 18   .&...vo...=..Z..
00a0 - 69 e8 31 29 e3 7a fe 69-a0 96 17 b9 77 47 6e 86   i.1).z.i....wGn.
00b0 - a8 d6 93 fb dc 8d b3 b1-b1 37 7a 2a b8 5c 1e f4   .........7z*.\..
00c0 - 58 44 39 2c 6b 99 c2 d1-54 57 ab d3 ec 4e 80 15   XD9,k...TW...N..
00d0 - c0 c5 d9 ae e7 74 83 6a-74 13 bc 60 2d 44 a8 0b   .....t.jt..`-D..
00e0 - f6 eb 0c 41 4f f9 19 bb-52 8e d6 53 28 00 3a      ...AO...R..S(.:
SSL_accept:SSLv3/TLS write session ticket
-----BEGIN SSL SESSION PARAMETERS-----
MHMCAQECAgMEBAITAQQgkrFp7e4uY1O+NGJOuClmGzvzPinNWyxTe4Lruv97iLsE
IOdJY1zGbP0bsT6RwlvCirlZrMa0zElxkdZBmCPEGQdVoQYCBGg2p06iBAICHCCk
BgQEAQAAAK4HAgUAnK345LMDAgEd
-----END SSL SESSION PARAMETERS-----
Shared ciphers:TLS_AES_128_GCM_SHA256
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Supported groups: x25519:secp256r1:x448:secp521r1:secp384r1:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192
Shared groups: x25519:secp256r1:x448:secp521r1:secp384r1:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192
CIPHER is TLS_AES_128_GCM_SHA256
This TLS version forbids renegotiation.
read from 0x29b8aece640 [0x29b8b2e0de3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x29b8aece640 [0x29b8b2e0de8] (23 bytes => 23 (0x17))
0000 - ab a5 35 84 e5 9c 28 a4-09 23 8f 2e 73 9e 56 84   ..5...(..#..s.V.
0010 - 79 01 9f 57 75 9b 98                              y..Wu..
test
read from 0x29b8aece640 [0x29b8b2e0de3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 13                                    .....
read from 0x29b8aece640 [0x29b8b2e0de8] (19 bytes => 19 (0x13))
0000 - 8d 24 ce 45 63 68 f0 c4-16 60 8a 73 c2 90 5f e2   .$.Ech...`.s.._.
0010 - 31 38 e0                                          18.
SSL3 alert read:warning:close notify
DONE
shutting down SSL
write to 0x29b8aece640 [0x29b8b2ec9a3] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 d2 f3 f4-a5 33 e5 91 3d 7a 85 9e   .........3..=z..
0010 - 5b 97 cf 7e c1 1c ba 03-                          [..~....
SSL3 alert write:warning:close notify
CONNECTION CLOSED
````

[TOC](README.md)
