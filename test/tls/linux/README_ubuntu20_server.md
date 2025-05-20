#### server

````
hush@hush:~/hotplace/build/test/tls$ openssl s_server -accept 9000 -cert server.crt -key server.key -state -debug -status_verbose -keylogfile sslkeylog
Using default temp DH parameters
ACCEPT
SSL_accept:before SSL initialization
read from 0x5561374426b0 [0x55613744dfd3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 af                                    .....
read from 0x5561374426b0 [0x55613744dfd8] (175 bytes => 175 (0xAF))
0000 - 01 00 00 ab 03 03 68 2a-69 5d 1e 01 33 8d 0e 6d   ......h*i]..3..m
0010 - 12 56 cd 93 3b 36 8e 0a-27 c9 1e 26 48 96 ab 5c   .V..;6..'..&H..\
0020 - 6b 50 8f e8 31 57 00 00-0a 13 01 13 02 13 03 13   kP..1W..........
0030 - 04 13 05 01 00 00 78 00-0b 00 02 01 00 00 0a 00   ......x.........
0040 - 0c 00 0a 00 1d 00 17 00-1e 00 19 00 18 00 0d 00   ................
0050 - 1e 00 1c 04 03 05 03 06-03 08 07 08 08 04 01 05   ................
0060 - 01 06 01 08 09 08 0a 08-0b 08 04 08 05 08 06 00   ................
0070 - 2b 00 03 02 03 04 00 2d-00 02 01 01 00 33 00 26   +......-.....3.&
0080 - 00 24 00 1d 00 20 cb cb-4c 0f ed 17 f2 7f d6 64   .$... ..L......d
0090 - 38 0b 97 04 d3 14 c1 cd-0b f1 8b f8 52 0a f6 73   8...........R..s
00a0 - 5b 2c 59 dc 8e 3a 00 23-00 00 ff 01 00 01 00      [,Y..:.#.......
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write change cipher spec
SSL_accept:TLSv1.3 write encrypted extensions
SSL_accept:SSLv3/TLS write certificate
SSL_accept:TLSv1.3 write server certificate verify
write to 0x5561374426b0 [0x5561374572e0] (1372 bytes => 1372 (0x55C))
0000 - 16 03 03 00 5a 02 00 00-56 03 03 63 fa 49 e0 a5   ....Z...V..c.I..
0010 - 68 2f 57 96 4a b5 1c 9e-18 4a 24 8c 02 8f f5 d9   h/W.J....J$.....
0020 - 3d 11 d4 80 9f 3f bc a5-5d 3f a8 00 13 01 00 00   =....?..]?......
0030 - 2e 00 2b 00 02 03 04 00-33 00 24 00 1d 00 20 54   ..+.....3.$... T
0040 - cf b0 13 29 ec 24 88 3b-9c 46 fc 97 0e 31 f6 af   ...).$.;.F...1..
0050 - 08 33 33 86 ec ff 2e a6-bb e5 22 8d b4 17 49 14   .33......."...I.
0060 - 03 03 00 01 01 17 03 03-00 17 70 a5 ed a1 17 12   ..........p.....
0070 - 23 7b b4 cd 34 02 ce a6-9d 7b 39 8f 92 dc fc a8   #{..4....{9.....
0080 - 24 17 03 03 03 7e ca e2-d9 18 73 20 78 df 3f 0e   $....~....s x.?.
0090 - 68 d9 fd 5d 7a 43 dd 22-c8 f6 3e 07 5b 62 0e 25   h..]zC."..>.[b.%
00a0 - 18 63 5b f6 45 6e 38 d8-33 71 38 b0 af 6a 67 d1   .c[.En8.3q8..jg.
00b0 - dd ec 20 06 e5 2d a2 c9-a2 1d 4e a8 54 9b 35 82   .. ..-....N.T.5.
00c0 - 97 93 9e d0 14 07 f4 b5-ea 69 9d 06 b0 8b 77 98   .........i....w.
00d0 - 5e 4e 8f ef 29 a5 a7 95-0b 57 c4 19 a2 27 03 f5   ^N..)....W...'..
00e0 - 4c a1 24 3d ac a4 5e 90-0b 23 ca aa 07 b5 14 71   L.$=..^..#.....q
00f0 - 8c d7 0b b3 d6 ad 68 a5-4a 01 c4 bd df da 06 4a   ......h.J......J
0100 - a0 f6 38 a2 46 d8 c6 9a-f6 57 b0 89 e5 3a 8f a2   ..8.F....W...:..
0110 - 30 d9 ec bd be 73 c6 42-1a 42 04 b6 0c 5a 60 3e   0....s.B.B...Z`>
0120 - 31 de 7c 93 f2 18 cf 3e-18 b1 65 e2 46 5e bd 20   1.|....>..e.F^.
0130 - c8 f1 bb 12 ef a3 59 7e-3d 79 4b 08 57 9a 0a be   ......Y~=yK.W...
0140 - 10 d8 48 c0 4a db 22 8b-40 fc f6 17 45 5a 56 0e   ..H.J.".@...EZV.
0150 - 4c ca bc ff 87 d6 ee a4-4a e2 97 d0 ac 4a 6d 91   L.......J....Jm.
0160 - 02 ac e6 cb 16 a0 92 7b-97 28 2d 6c 79 84 29 aa   .......{.(-ly.).
0170 - ac 70 57 4d b4 ef bd 3c-69 f8 7a d0 39 28 67 4b   .pWM...<i.z.9(gK
0180 - 89 12 26 c9 41 d3 80 b2-96 90 b5 fd ce 09 a4 93   ..&.A...........
0190 - 89 0d a2 01 d6 5f e4 75-cb 76 8a bf c7 f1 63 fb   ....._.u.v....c.
01a0 - 58 5a 6e 9c aa a0 34 81-a5 07 90 6d ea c2 33 c4   XZn...4....m..3.
01b0 - 32 5f a1 b8 a8 42 6e 34-09 5c ec 31 0c e4 56 2e   2_...Bn4.\.1..V.
01c0 - 9b 8a 07 4c 2b 66 57 ee-0f a7 b8 5b 13 ae 84 6f   ...L+fW....[...o
01d0 - c1 2d 94 26 d4 47 eb 38-9f 2d c6 b1 dd 50 85 d7   .-.&.G.8.-...P..
01e0 - 9b 25 fa 85 0a 2b e1 29-a7 d0 36 21 0b 9b 89 70   .%...+.)..6!...p
01f0 - f9 f5 3d b9 58 c7 88 7c-98 cd 6c 0e 0f c8 e2 7e   ..=.X..|..l....~
0200 - f8 af 03 54 f2 24 71 96-02 92 5b 83 b5 38 71 b4   ...T.$q...[..8q.
0210 - 5d d1 3a b8 af 85 2a ae-35 e2 d0 f0 ea 30 96 ff   ].:...*.5....0..
0220 - 1a fd 09 f4 f8 78 54 0d-68 6d 71 49 35 01 c2 61   .....xT.hmqI5..a
0230 - 34 9d ee 1f 25 ff 72 13-8e cd c6 ce 72 38 5f 80   4...%.r.....r8_.
0240 - 73 d0 af 4a f4 f7 7f fb-66 54 bf f7 96 5b 0b 65   s..J....fT...[.e
0250 - 63 c6 20 aa aa 56 f8 b6-ac c1 8f 86 7a 06 b5 76   c. ..V......z..v
0260 - cb cf e4 5f b1 3b 21 37-1a f5 0a 6f a9 8d 25 79   ..._.;!7...o..%y
0270 - 9e 9f c9 3f b7 9f 3c ff-5d 88 05 70 3a dc de ea   ...?..<.]..p:...
0280 - f2 fd e9 8a b9 f4 bc bf-89 be f7 87 59 34 fb ab   ............Y4..
0290 - 57 d1 d8 23 3c 8f 59 f1-7f 67 1b 38 34 6f a0 7b   W..#<.Y..g.84o.{
02a0 - 63 a2 b0 bb 89 f9 a6 da-3d 32 75 09 45 25 2f b0   c.......=2u.E%/.
02b0 - 42 72 d0 18 a5 3d 52 58-2d 50 2c 51 b8 f7 31 9f   Br...=RX-P,Q..1.
02c0 - 7e d4 6c d2 19 2b 87 09-d7 97 dd e7 db 92 44 b0   ~.l..+........D.
02d0 - 12 b9 53 d3 99 84 2b ea-78 8d b0 9c dc b3 cd 35   ..S...+.x......5
02e0 - 93 7b ed 0a d5 28 92 45-7e d8 66 88 41 a8 82 64   .{...(.E~.f.A..d
02f0 - 37 75 ad 2c 51 c5 68 c2-84 53 e2 28 82 54 d8 62   7u.,Q.h..S.(.T.b
0300 - 9e 18 3b 2c d0 fd a8 13-24 74 de c0 d8 88 f8 fd   ..;,....$t......
0310 - 9e 5e a8 04 95 ef ac 86-35 91 fd 96 a5 bc 83 54   .^......5......T
0320 - 63 4b e1 19 74 eb fd ed-cb a1 87 3c 04 01 49 a1   cK..t......<..I.
0330 - 38 03 33 b3 b2 87 34 bc-a6 fb 69 4f a9 f6 5b 48   8.3...4...iO..[H
0340 - 91 0f c6 42 d5 8f 24 d4-75 29 26 0b d4 2b 63 a5   ...B..$.u)&..+c.
0350 - 5f ec 6f 4f 54 b9 b7 f2-66 06 ac ce 71 dc 96 a3   _.oOT...f...q...
0360 - 4b b5 5c b7 8a c4 4c d4-b8 d5 1e ab 46 aa 78 bd   K.\...L.....F.x.
0370 - 1e 2a 16 12 fd 25 fe 3d-4b 6f 45 dd 50 1b 7f a9   .*...%.=KoE.P...
0380 - fa d3 fb f6 1c 6d 7b 6d-b0 cb cb 02 e0 15 68 b2   .....m{m......h.
0390 - 31 31 c0 4e cc c9 6d 4b-8d de dc 86 32 17 ab 05   11.N..mK....2...
03a0 - 86 37 3d 85 09 2d e2 2d-79 52 f7 e4 3b 8d 6c 49   .7=..-.-yR..;.lI
03b0 - 2f db 5f 4b 4c 98 54 1f-61 ca ac d1 bf 1c 2b 87   /._KL.T.a.....+.
03c0 - 0d a5 47 a0 9f bc 30 e1-2c a9 da 5b 07 6e 39 eb   ..G...0.,..[.n9.
03d0 - ef bb 4a b0 65 92 16 77-4a 41 ac 2b bd 1f a9 3a   ..J.e..wJA.+...:
03e0 - cd 25 e6 99 1d d4 b6 e0-96 7a 25 01 9f f0 8c 1c   .%.......z%.....
03f0 - d8 18 5e 76 d7 4c 85 2b-61 ca 16 b3 03 e9 fe b0   ..^v.L.+a.......
0400 - c6 90 1d 63 17 03 03 01-19 60 ff da fa df 69 b9   ...c.....`....i.
0410 - eb e5 c8 7a 19 78 aa 2c-ec aa f7 05 8d 4a e2 b7   ...z.x.,.....J..
0420 - 15 a8 50 40 54 df f9 5a-ff 35 aa 07 2e 79 77 cc   ..P@T..Z.5...yw.
0430 - c3 41 de 38 bd d1 90 e6-3a a4 f5 0f 3a e3 03 f7   .A.8....:...:...
0440 - 01 9a 5f d6 e5 be f2 2d-ee 45 a4 de 61 29 60 64   .._....-.E..a)`d
0450 - a8 57 0c 96 eb ab ec 75-55 23 d5 e6 a1 4e 53 8d   .W.....uU#...NS.
0460 - b7 f9 c7 0c 26 6c 91 62-2f fb 12 34 c5 d5 7a d1   ....&l.b/..4..z.
0470 - e5 02 01 3b 0b 7a d8 28-6f f4 4d c7 60 80 6b d8   ...;.z.(o.M.`.k.
0480 - d7 19 dc 2c 14 81 29 bc-4e f4 bc 3f 47 16 39 50   ...,..).N..?G.9P
0490 - 42 27 24 d4 8b 65 08 b2-f7 06 de 22 b1 99 98 ba   B'$..e....."....
04a0 - 8f 9b 7e 27 28 03 9d f8-42 6c 35 13 b9 a3 66 11   ..~'(...Bl5...f.
04b0 - 86 12 fb d5 02 31 2a 8f-bd 8e 48 4f 9b 0a 85 4f   .....1*...HO...O
04c0 - 30 9f f6 6d ed d9 1d 3c-95 b3 6d 75 ef 04 63 15   0..m...<..mu..c.
04d0 - 6d af 4b 7e cb f1 7f 78-58 a2 38 9a 75 f2 1e 4c   m.K~...xX.8.u..L
04e0 - 1f 7e 9d 8c 7c c5 fc be-88 a5 e1 03 5c bf aa 76   .~..|.......\..v
04f0 - 8c 03 7a 2d ce 80 26 5f-13 ca 97 ed fb 8c 82 fd   ..z-..&_........
0500 - 45 d9 c6 85 d0 38 ba 46-cf a3 79 28 41 73 5c 51   E....8.F..y(As\Q
0510 - b7 ba 21 96 72 d0 6c 25-56 cf b6 5a 58 58 be 1c   ..!.r.l%V..ZXX..
0520 - b2 0b 17 03 03 00 35 9c-f1 55 89 2a 34 87 38 14   ......5..U.*4.8.
0530 - c3 b6 b0 67 85 3c ca 8a-6e c0 64 9a 62 1e 3a ea   ...g.<..n.d.b.:.
0540 - 9a 83 26 55 87 a8 78 94-a1 f6 09 c6 a0 53 0c a3   ..&U..x......S..
0550 - 03 d6 fc 6f 31 98 86 34-18 41 ee 4d               ...o1..4.A.M
SSL_accept:SSLv3/TLS write finished
SSL_accept:TLSv1.3 early data
read from 0x5561374426b0 [0x55613744dfd3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x5561374426b0 [0x55613744dfd8] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x5561374426b0 [0x55613744dfd3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 35                                    ....5
read from 0x5561374426b0 [0x55613744dfd8] (53 bytes => 53 (0x35))
0000 - eb 49 51 e9 56 a8 ce 96-bd b7 04 f5 a8 92 d3 f4   .IQ.V...........
0010 - b0 f7 9d ff 90 38 20 7a-73 b4 eb 92 03 b1 20 5c   .....8 zs..... \
0020 - 25 03 e5 7f ef bb 13 9e-a5 14 27 03 11 2f 27 62   %.........'../'b
0030 - 76 17 c7 c9 f7                                    v....
SSL_accept:TLSv1.3 early data
SSL_accept:SSLv3/TLS read finished
write to 0x5561374426b0 [0x5561374572e0] (239 bytes => 239 (0xEF))
0000 - 17 03 03 00 ea 8d eb 29-80 23 d6 8d 46 ea 9d 6d   .......).#..F..m
0010 - e0 6f 5f b0 96 27 e6 e2-89 1e c0 2a b0 22 11 29   .o_..'.....*.".)
0020 - 6a 0f 9e 44 0c 4d 8c 4b-1b 2f 3f ba 23 82 c7 0e   j..D.M.K./?.#...
0030 - 86 38 cf e7 aa c8 12 dc-bb e0 c9 cf 04 59 ff e5   .8...........Y..
0040 - 7b 00 9c 7d 2a 4d 50 3c-32 a4 7a 12 9c 61 5f 2a   {..}*MP<2.z..a_*
0050 - 2b a0 3e b8 d8 ac 54 a3-6b 62 f9 da a2 20 07 dd   +.>...T.kb... ..
0060 - 38 cf c1 d8 59 a4 a9 70-01 36 6f 46 24 1a d9 4b   8...Y..p.6oF$..K
0070 - 48 8b 65 4f b6 04 cb 4d-12 ae 58 64 9c da 20 4e   H.eO...M..Xd.. N
0080 - c5 43 22 50 42 c5 a4 ba-30 1f 7c bc 25 eb 64 1b   .C"PB...0.|.%.d.
0090 - 32 21 07 ed 40 d0 5c 71-db d8 25 dd 7c 2b ef b7   2!..@.\q..%.|+..
00a0 - f5 cf 90 99 bf 4b 99 af-37 a6 bb 56 85 12 4e a6   .....K..7..V..N.
00b0 - a5 52 65 22 85 b7 1d 37-6c 4e f5 ac 1c a1 ed 5b   .Re"...7lN.....[
00c0 - b8 64 ab 7f b2 65 2d d7-29 73 7e 63 ad 9e 56 83   .d...e-.)s~c..V.
00d0 - 3b 2f f2 16 8a c5 20 ca-ba 63 01 53 40 77 03 d9   ;/.... ..c.S@w..
00e0 - be 77 00 b5 ab b2 ef 3f-ec 3f 6b cb 1b cc f8      .w.....?.?k....
SSL_accept:SSLv3/TLS write session ticket
write to 0x5561374426b0 [0x5561374572e0] (223 bytes => 223 (0xDF))
0000 - 17 03 03 00 da ec 15 32-8b 08 dd 42 1f 41 da fc   .......2...B.A..
0010 - 02 62 e9 e1 f1 b3 2b 32-8d 0c 6c 43 8c 48 2b f8   .b....+2..lC.H+.
0020 - 89 a3 7e 69 8e 32 42 a8-b7 ba 26 60 83 39 94 cd   ..~i.2B...&`.9..
0030 - ae 92 a4 74 99 a2 8e bb-47 4f 16 f1 9f 4b 97 a5   ...t....GO...K..
0040 - 09 51 31 c9 59 fa 5f 44-51 41 78 a6 69 67 a2 8e   .Q1.Y._DQAx.ig..
0050 - ad 4b 32 8b e3 f6 7b 3a-69 a1 32 95 76 6e 46 b7   .K2...{:i.2.vnF.
0060 - a8 9d d0 56 42 ca 7f ca-e8 b4 af da 8a 10 d5 49   ...VB..........I
0070 - f1 b0 0b 0a 39 6f 9d 95-ae 53 90 06 9f 05 0d e2   ....9o...S......
0080 - 32 c7 cc c7 87 d8 ff f5-0e 49 99 03 88 8c 41 cf   2........I....A.
0090 - b4 18 5e bf 80 b3 ee 6f-0a b4 c9 9d fe c2 25 89   ..^....o......%.
00a0 - ca 7f 92 9f 07 e3 19 e6-6a 1c 43 3f 48 c7 07 e5   ........j.C?H...
00b0 - 07 43 9d bd a8 5d 14 fa-cd 0d 87 05 4c 39 66 64   .C...]......L9fd
00c0 - bd 20 f3 b2 81 53 03 33-17 e6 d4 54 6a ba 2b b2   . ...S.3...Tj.+.
00d0 - a7 4a 0f 55 3b 19 a1 d3-c4 b1 0d e5 3d 45 41      .J.U;.......=EA
SSL_accept:SSLv3/TLS write session ticket
-----BEGIN SSL SESSION PARAMETERS-----
MG0CAQECAgMEBAITAQQggVq8sRnhLVFR4axUfcSd0NE7HTm0tKLgGV6Ba6Wse2sE
IGAo41ehyxK/UvLTPweZR6rPA5GlHgaKrn+1+uoWYAXfoQYCBGgqaV2iBAICHCCk
BgQEAQAAAK4GAgRCmf0S
-----END SSL SESSION PARAMETERS-----
Shared ciphers:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA+SHA256:RSA+SHA384:RSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA+SHA256:RSA+SHA384:RSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512
Supported Elliptic Groups: X25519:P-256:X448:P-521:P-384
Shared Elliptic groups: X25519:P-256:X448:P-521:P-384
CIPHER is TLS_AES_128_GCM_SHA256
Secure Renegotiation IS NOT supported
read from 0x5561374426b0 [0x55613744dfd3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 16                                    .....
read from 0x5561374426b0 [0x55613744dfd8] (22 bytes => 22 (0x16))
0000 - f2 4c ec 4c d6 ca 28 af-17 74 08 0b f9 7a aa d7   .L.L..(..t...z..
0010 - f7 f1 39 d1 1b ba                                 ..9...
helloread from 0x5561374426b0 [0x55613744dfd3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 13                                    .....
read from 0x5561374426b0 [0x55613744dfd8] (19 bytes => 19 (0x13))
0000 - cc 96 ea ae dc 7a ba 3d-af 86 bd c5 5c 3f 37 8c   .....z.=....\?7.
0010 - cb ee ab                                          ...
SSL3 alert read:warning:close notify
DONE
shutting down SSL
CONNECTION CLOSED
SSL_accept:before SSL initialization
read from 0x5561374561e0 [0x55613744c2e3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 a4                                    .....
read from 0x5561374561e0 [0x55613744c2e8] (164 bytes => 164 (0xA4))
0000 - 01 00 00 a0 03 03 68 2a-69 63 67 a6 77 b6 71 62   ......h*icg.w.qb
0010 - cb c4 8c bf 9a 94 86 c1-49 ba fb d8 40 46 b7 21   ........I...@F.!
0020 - 29 08 1e 73 be 7a 00 00-36 13 01 13 02 13 03 13   )..s.z..6.......
0030 - 04 13 05 c0 23 c0 24 c0-27 c0 28 c0 2b c0 2c c0   ....#.$.'.(.+.,.
0040 - 2f c0 30 c0 5c c0 5d c0-60 c0 61 c0 72 c0 73 c0   /.0.\.].`.a.r.s.
0050 - 76 c0 77 c0 ac c0 ad c0-ae c0 af cc a8 cc a9 01   v.w.............
0060 - 00 00 41 00 0b 00 02 01-00 00 0a 00 0c 00 0a 00   ..A.............
0070 - 1d 00 17 00 1e 00 19 00-18 00 0d 00 1e 00 1c 04   ................
0080 - 03 05 03 06 03 08 07 08-08 04 01 05 01 06 01 08   ................
0090 - 09 08 0a 08 0b 08 04 08-05 08 06 00 23 00 00 ff   ............#...
00a0 - 01 00 01 00                                       ....
SSL_accept:before SSL initialization
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
SSL_accept:SSLv3/TLS write certificate
SSL_accept:SSLv3/TLS write key exchange
write to 0x5561374561e0 [0x55613745b9f0] (1259 bytes => 1259 (0x4EB))
0000 - 16 03 03 00 3d 02 00 00-39 03 03 de d5 2f 83 be   ....=...9..../..
0010 - e2 14 eb 1a c5 ea 81 f1-e4 da 4b d1 e6 5c c7 2e   ..........K..\..
0020 - 07 13 d0 44 4f 57 4e 47-52 44 01 00 c0 27 00 00   ...DOWNGRD...'..
0030 - 11 ff 01 00 01 00 00 0b-00 04 03 00 01 02 00 23   ...............#
0040 - 00 00 16 03 03 03 6a 0b-00 03 66 00 03 63 00 03   ......j...f..c..
0050 - 60 30 82 03 5c 30 82 02-44 a0 03 02 01 02 02 14   `0..\0..D.......
0060 - 63 a6 71 10 79 d6 a6 48-59 da 67 a9 04 e8 e3 5f   c.q.y..HY.g...._
0070 - e2 03 a3 26 30 0d 06 09-2a 86 48 86 f7 0d 01 01   ...&0...*.H.....
0080 - 0b 05 00 30 59 31 0b 30-09 06 03 55 04 06 13 02   ...0Y1.0...U....
0090 - 4b 52 31 0b 30 09 06 03-55 04 08 0c 02 47 47 31   KR1.0...U....GG1
00a0 - 0b 30 09 06 03 55 04 07-0c 02 59 49 31 0d 30 0b   .0...U....YI1.0.
00b0 - 06 03 55 04 0a 0c 04 54-65 73 74 31 0d 30 0b 06   ..U....Test1.0..
00c0 - 03 55 04 0b 0c 04 54 65-73 74 31 12 30 10 06 03   .U....Test1.0...
00d0 - 55 04 03 0c 09 54 65 73-74 20 52 6f 6f 74 30 1e   U....Test Root0.
00e0 - 17 0d 32 34 30 38 32 39-30 36 32 37 31 37 5a 17   ..240829062717Z.
00f0 - 0d 32 35 30 38 32 39 30-36 32 37 31 37 5a 30 54   .250829062717Z0T
0100 - 31 0b 30 09 06 03 55 04-06 13 02 4b 52 31 0b 30   1.0...U....KR1.0
0110 - 09 06 03 55 04 08 0c 02-47 47 31 0b 30 09 06 03   ...U....GG1.0...
0120 - 55 04 07 0c 02 59 49 31-0d 30 0b 06 03 55 04 0a   U....YI1.0...U..
0130 - 0c 04 54 65 73 74 31 0d-30 0b 06 03 55 04 0b 0c   ..Test1.0...U...
0140 - 04 54 65 73 74 31 0d 30-0b 06 03 55 04 03 0c 04   .Test1.0...U....
0150 - 54 65 73 74 30 82 01 22-30 0d 06 09 2a 86 48 86   Test0.."0...*.H.
0160 - f7 0d 01 01 01 05 00 03-82 01 0f 00 30 82 01 0a   ............0...
0170 - 02 82 01 01 00 ad 9a 29-67 5f f3 a4 79 b4 c6 e6   .......)g_..y...
0180 - 32 73 d8 d7 ed 88 94 15-83 e4 31 00 04 6c b5 8c   2s........1..l..
0190 - ac 87 ab 74 44 13 76 ca-0b 74 29 40 9e 97 2a 01   ...tD.v..t)@..*.
01a0 - d7 8b 46 26 6e 19 35 4d-c0 d3 b5 ea 0e 93 3a 06   ..F&n.5M......:.
01b0 - e8 e5 85 b5 27 05 63 db-28 b8 92 da 5a 14 39 0f   ....'.c.(...Z.9.
01c0 - da 68 6d 6f 0a fb 52 dc-08 0f 54 d3 e4 a2 28 9d   .hmo..R...T...(.
01d0 - a0 71 50 82 e0 db ca d1-94 dd 42 98 3a 09 33 a8   .qP.......B.:.3.
01e0 - d9 ef fb d2 35 43 b1 22-a2 be 41 6d ba 91 dc 0b   ....5C."..Am....
01f0 - 31 4e 88 f9 4d 9c 61 2d-ec b2 13 0a c2 91 8e a2   1N..M.a-........
0200 - d6 e9 40 b9 32 b9 80 8f-b3 18 a3 33 13 23 d5 d0   ..@.2......3.#..
0210 - 7e d9 d0 7f 93 e0 2d 4d-90 c5 58 24 56 d5 c9 10   ~.....-M..X$V...
0220 - 13 4a b2 99 23 7d 34 b9-8e 97 19 69 6f ce c6 3f   .J..#}4....io..?
0230 - d6 17 a7 d2 43 e0 36 cb-51 7b 2f 18 8b c2 33 f8   ....C.6.Q{/...3.
0240 - 57 cf d1 61 0b 7c ed 37-35 e3 13 7a 24 2e 77 08   W..a.|.75..z$.w.
0250 - c2 e3 d9 e6 17 d3 a5 c6-34 5a da 86 a7 f8 02 36   ........4Z.....6
0260 - 1d 66 63 cf e9 c0 3d 82-fb 39 a2 8d 92 01 4a 83   .fc...=..9....J.
0270 - cf e2 76 3d 87 02 03 01-00 01 a3 21 30 1f 30 1d   ..v=.......!0.0.
0280 - 06 03 55 1d 11 04 16 30-14 82 12 74 65 73 74 2e   ..U....0...test.
0290 - 70 72 69 6e 63 65 62 36-31 32 2e 70 65 30 0d 06   princeb612.pe0..
02a0 - 09 2a 86 48 86 f7 0d 01-01 0b 05 00 03 82 01 01   .*.H............
02b0 - 00 00 a5 f5 54 18 ab ad-36 38 c8 fc 0b 66 60 dd   ....T...68...f`.
02c0 - 9f 75 9d 86 5b 79 2f ee-57 f1 79 1c 15 a1 34 23   .u..[y/.W.y...4#
02d0 - d0 1c a9 58 51 a4 d0 08-f5 d8 f7 49 e9 c5 b5 65   ...XQ......I...e
02e0 - 91 51 2d 6d e4 3b 0e 77-02 1f 45 8e 34 e5 bb eb   .Q-m.;.w..E.4...
02f0 - f6 9d df 4a 40 60 21 b3-8e 16 33 3f f4 b6 90 d3   ...J@`!...3?....
0300 - 3c 34 ce e6 d9 47 07 a7-57 14 0c f9 78 0b 36 72   <4...G..W...x.6r
0310 - a9 88 07 07 93 b4 d7 fe-29 5e e8 41 37 20 a5 03   ........)^.A7 ..
0320 - c7 97 cb 82 ca db 14 e5-8b 96 1f a9 e9 20 3d 6b   ............. =k
0330 - 25 ae f4 89 4c 60 8d e9-14 33 47 4b 88 54 a2 47   %...L`...3GK.T.G
0340 - 19 81 c8 7b 0e 32 52 2b-91 88 ad 0f 6d 73 30 8c   ...{.2R+....ms0.
0350 - 00 af d5 fc 46 46 af 3a-c2 17 89 ec c8 83 ae da   ....FF.:........
0360 - e6 69 63 e0 9c 84 22 c5-7a de e8 23 6b 53 9d 6f   .ic...".z..#kS.o
0370 - 94 d2 7f 5c be 1d 0c de-0e 07 0d 52 a5 43 8c e8   ...\.......R.C..
0380 - 05 ef c0 ff f0 73 fa dc-5a 51 4c 24 09 65 45 7d   .....s..ZQL$.eE}
0390 - ab 52 8b 7e 5d f0 fb de-a7 3d 43 c5 af 76 e3 6e   .R.~]....=C..v.n
03a0 - f9 a1 dc 78 a2 bd 54 41-04 99 e5 56 32 ba 02 fd   ...x..TA...V2...
03b0 - 72 16 03 03 01 2c 0c 00-01 28 03 00 1d 20 b5 26   r....,...(... .&
03c0 - 7b db 89 9e fe 6c 72 51-ee df 9c 3f 4a 40 95 78   {....lrQ...?J@.x
03d0 - fe 22 32 77 21 f9 bc 67-c1 32 95 cc 3e 06 04 01   ."2w!..g.2..>...
03e0 - 01 00 a3 9b f5 8c f2 d8-98 4d 29 5a 2a 8c 64 42   .........M)Z*.dB
03f0 - 27 e2 3c f3 03 ba 11 8c-1e c2 2b 04 4a 85 09 24   '.<.......+.J..$
0400 - b0 4d e8 36 88 bb 07 98-07 cf dc cb d0 28 b4 8d   .M.6.........(..
0410 - 7f fd 6a b1 49 af 53 f3-dc 21 04 58 67 87 2a 3d   ..j.I.S..!.Xg.*=
0420 - 78 12 b7 ce f1 c1 d3 10-9a ef fc b9 21 4a 23 d8   x...........!J#.
0430 - 22 50 65 d1 bb 8f 05 a3-b0 2c 81 cc fe 7c ea ad   "Pe......,...|..
0440 - d9 3d e4 14 27 5f 63 48-21 dd b7 6c d9 3c cb b2   .=..'_cH!..l.<..
0450 - 7e 44 ee 26 87 44 6f fb-7a 61 36 6e 42 f1 e8 82   ~D.&.Do.za6nB...
0460 - 87 85 47 ad c4 a8 1b f7-da 17 23 f1 09 37 b2 b9   ..G.......#..7..
0470 - 00 8d de e6 cc 3f f0 fc-b2 fb 21 48 3a c5 39 55   .....?....!H:.9U
0480 - 59 7a 26 75 5e f6 7e cf-c7 76 ce 2e 32 a6 0d dc   Yz&u^.~..v..2...
0490 - fa 87 50 3e c2 83 60 1e-8b 19 e8 7a 1e 60 a1 6c   ..P>..`....z.`.l
04a0 - 5f b6 6b d5 3c 5d 9c 95-49 2f a3 96 94 3e 42 22   _.k.<]..I/...>B"
04b0 - 11 bc 45 3c af c2 a4 13-5a 61 4c 1e 53 39 23 38   ..E<....ZaL.S9#8
04c0 - 71 a5 94 3d e3 83 3a 54-fc 5a 29 9a e8 d8 02 21   q..=..:T.Z)....!
04d0 - d7 22 d5 7d 72 07 eb 1f-a0 9a 3f 9c cd 2c 8c ab   .".}r.....?..,..
04e0 - 70 85 16 03 03 00 04 0e-00 00 00                  p..........
SSL_accept:SSLv3/TLS write server done
read from 0x5561374561e0 [0x55613744c2e3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 25                                    ....%
read from 0x5561374561e0 [0x55613744c2e8] (37 bytes => 37 (0x25))
0000 - 10 00 00 21 20 aa f2 82-ef 3f 5d 4b 15 9e 16 75   ...! ....?]K...u
0010 - 9e 95 c7 cc 06 00 33 3f-52 4f b7 ad 26 01 59 ff   ......3?RO..&.Y.
0020 - f9 0c 55 fd 0b                                    ..U..
SSL_accept:SSLv3/TLS write server done
read from 0x5561374561e0 [0x55613744c2e3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x5561374561e0 [0x55613744c2e8] (1 bytes => 1 (0x1))
0000 - 01                                                .
SSL_accept:SSLv3/TLS read client key exchange
read from 0x5561374561e0 [0x55613744c2e3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 50                                    ....P
read from 0x5561374561e0 [0x55613744c2e8] (80 bytes => 80 (0x50))
0000 - 69 17 1b 67 bb 43 9c c1-e7 3b 0c 39 dc 82 a5 dd   i..g.C...;.9....
0010 - d4 7b d2 42 e0 da a8 03-c8 3c 13 c4 d4 b3 c9 09   .{.B.....<......
0020 - c5 b5 bc 71 b7 49 aa 0e-53 f0 87 07 84 25 e6 dc   ...q.I..S....%..
0030 - 71 fb fe 9e 69 c7 34 e0-6c 7b aa 2c d7 aa ca 4d   q...i.4.l{.,...M
0040 - 36 c6 81 67 27 ff 43 36-f5 b5 8a cd 54 0e 64 c9   6..g'.C6....T.d.
SSL_accept:SSLv3/TLS read change cipher spec
SSL_accept:SSLv3/TLS read finished
SSL_accept:SSLv3/TLS write session ticket
SSL_accept:SSLv3/TLS write change cipher spec
write to 0x5561374561e0 [0x55613745b9f0] (266 bytes => 266 (0x10A))
0000 - 16 03 03 00 aa 04 00 00-a6 00 00 1c 20 00 a0 1a   ............ ...
0010 - a1 d8 ae ed 51 4a 5e e7-ed 14 d6 4c 59 0d 90 41   ....QJ^....LY..A
0020 - 6c f0 7a 72 00 d5 90 45-89 d4 13 b5 4a 8f 65 59   l.zr...E....J.eY
0030 - e0 2c f4 0c 30 b8 6a 9e-73 07 3f de 58 42 af 02   .,..0.j.s.?.XB..
0040 - 05 d9 c3 b0 77 db 58 76-1a b7 e2 a6 00 89 38 af   ....w.Xv......8.
0050 - 82 77 f7 3f 03 73 b3 4a-fb 42 c7 e6 55 49 52 0e   .w.?.s.J.B..UIR.
0060 - 19 28 a6 a6 9c 7c 4d db-b7 f0 04 2c 89 3e e5 87   .(...|M....,.>..
0070 - 4a 41 e7 66 7b f3 0f 76-e9 61 aa c5 5a 89 54 3f   JA.f{..v.a..Z.T?
0080 - d7 2e 07 78 13 d1 ca 83-a6 c1 54 a9 88 01 4c 3e   ...x......T...L>
0090 - fc ca 4a 89 9f fb bd ab-2e 39 5e ab c7 d4 5a 47   ..J......9^...ZG
00a0 - 0e 04 81 02 78 70 08 99-91 81 db 35 20 69 c3 14   ....xp.....5 i..
00b0 - 03 03 00 01 01 16 03 03-00 50 21 c9 65 cb 87 ca   .........P!.e...
00c0 - 4a 1e e1 fe 1e 3a 49 ca-e5 a5 0d d9 3c ce 9b 23   J....:I.....<..#
00d0 - 7a 34 aa 7b d5 86 0e e2-01 51 99 20 8f 43 37 4e   z4.{.....Q. .C7N
00e0 - 65 63 3d 45 53 a3 6e d6-0c a2 32 d9 8f 7f de ca   ec=ES.n...2.....
00f0 - 72 ba 20 cd 5f 8a c6 d2-38 b6 8e 5d 91 19 35 9b   r. ._...8..]..5.
0100 - 79 7e b0 15 a4 42 97 47-1d 8b                     y~...B.G..
SSL_accept:SSLv3/TLS write finished
-----BEGIN SSL SESSION PARAMETERS-----
MFUCAQECAgMDBALAJwQABDBkg5hh7XzuePofJIfQLoSSLdbgNDgi+7jatqTIgpXc
Am14BO/uBzVtFz6z10x5OXyhBgIEaCppY6IEAgIcIKQGBAQBAAAA
-----END SSL SESSION PARAMETERS-----
Shared ciphers:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305
Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA+SHA256:RSA+SHA384:RSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512
Shared Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA+SHA256:RSA+SHA384:RSA+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512
Supported Elliptic Curve Point Formats: uncompressed
Supported Elliptic Groups: X25519:P-256:X448:P-521:P-384
Shared Elliptic groups: X25519:P-256:X448:P-521:P-384
CIPHER is ECDHE-RSA-AES128-SHA256
Secure Renegotiation IS supported
read from 0x5561374561e0 [0x55613744c2e3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 40                                    ....@
read from 0x5561374561e0 [0x55613744c2e8] (64 bytes => 64 (0x40))
0000 - 92 ba a8 c8 90 20 57 7b-2d b7 9e b4 96 ff 24 5d   ..... W{-.....$]
0010 - 44 be 31 d8 63 30 33 c9-55 ab c6 56 d8 af 77 1b   D.1.c03.U..V..w.
0020 - f8 9e c4 70 b9 b6 a7 8b-2b f4 95 a4 7d 0c 3b 45   ...p....+...}.;E
0030 - 68 27 eb b8 07 a4 26 e2-94 1d 18 7d 65 2f 8e 87   h'....&....}e/..
helloread from 0x5561374561e0 [0x55613744c2e3] (5 bytes => 5 (0x5))
0000 - 15 03 03 00 40                                    ....@
read from 0x5561374561e0 [0x55613744c2e8] (64 bytes => 64 (0x40))
0000 - 89 b4 9b a0 39 35 bf 24-c0 e9 6c cd 44 34 ec ec   ....95.$..l.D4..
0010 - 3d ed 58 68 5d 98 87 01-d2 18 26 e6 c0 3d c3 57   =.Xh].....&..=.W
0020 - d5 5d 95 d8 80 fe 23 66-1d d8 37 0c 1c a7 9b 48   .]....#f..7....H
0030 - ae ea ce dc 54 6f 21 e1-b9 4d 3e 0a 0d 4f 53 47   ....To!..M>..OSG
SSL3 alert read:warning:close notify
DONE
shutting down SSL
CONNECTION CLOSED
````

[TOC](README.md)
