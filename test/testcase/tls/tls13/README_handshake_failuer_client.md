#### client

$ openssl s_client -connect localhost:9000 -state -debug -keylogfile sslkeylog -tls1_3 -ciphersuites TLS_AES_128_CCM_SHA256
````
Connecting to ::1
CONNECTED(0000020C)
SSL_connect:before SSL initialization
write to 0x25d8aad8ac0 [0x25d8ab1cb20] (1452 bytes => 1452 (0x5AC))
0000 - 16 03 01 05 a7 01 00 05-a3 03 03 bb f3 3c 1a a2   .............<..
0010 - db 1a e6 fc 84 33 dc 00-31 69 35 3c 12 7e 96 fa   .....3..1i5<.~..
0020 - a0 df 36 bd f2 e9 e5 be-89 c3 b0 20 95 61 41 4b   ..6........ .aAK
0030 - 9c 3c ce 72 e8 bc a2 9a-b8 53 4d 41 47 a7 34 6f   .<.r.....SMAG.4o
0040 - 9b a3 99 c1 8a 1a 46 0e-9a 5a 7e 63 00 02 13 04   ......F..Z~c....
0050 - 01 00 05 58 00 0b 00 02-01 00 00 0a 00 12 00 10   ...X............
0060 - 11 ec 00 1d 00 17 00 1e-00 18 00 19 01 00 01 01   ................
0070 - 00 23 00 00 00 16 00 00-00 17 00 00 00 0d 00 2a   .#.............*
0080 - 00 28 09 05 09 06 09 04-04 03 05 03 06 03 08 07   .(..............
0090 - 08 08 08 1a 08 1b 08 1c-08 09 08 0a 08 0b 08 04   ................
00a0 - 08 05 08 06 04 01 05 01-06 01 00 2b 00 03 02 03   ...........+....
00b0 - 04 00 2d 00 02 01 01 00-33 04 ea 04 e8 11 ec 04   ..-.....3.......
00c0 - c0 13 eb 88 67 e9 c8 cf-43 b7 93 32 32 c0 21 ae   ....g...C..22.!.
00d0 - 81 bb b0 e1 c4 05 b6 d4-1c ff 35 a5 e6 81 72 4e   ..........5...rN
00e0 - 19 ac 91 21 7e 67 f4 09-ca 20 5f 5c 72 84 73 5a   ...!~g... _\r.sZ
00f0 - 96 ee e2 5f ab 2c c1 61-34 15 1a b1 a3 69 e7 cb   ..._.,.a4....i..
0100 - 63 43 b6 26 a4 50 2b 49-35 d7 83 72 b1 b5 0a 16   cC.&.P+I5..r....
0110 - c2 c6 50 f8 03 d8 48 c9-15 32 2b 4e 0c cb a9 3b   ..P...H..2+N...;
0120 - 14 72 3b b9 fb 42 a2 af-f9 19 9e 54 57 70 40 8d   .r;..B.....TWp@.
0130 - 1f d7 cd 87 51 bd e5 0b-2b 86 85 84 6e f1 96 e1   ....Q...+...n...
0140 - 72 05 3d 73 13 79 f8 5b-03 38 35 db 22 99 34 76   r.=s.y.[.85.".4v
0150 - 72 2d ba 83 c2 c0 46 63-e5 0c 6b 19 40 5b 16 8c   r-....Fc..k.@[..
0160 - bd a3 c6 fc 4b 52 6b 29-12 33 c2 64 2d 24 a9 de   ....KRk).3.d-$..
0170 - 4c 8f 33 8b 80 91 83 3e-78 1b 83 93 08 60 ec e2   L.3....>x....`..
0180 - 13 54 7c 88 ea 06 cc aa-f2 64 18 89 b5 00 c3 0b   .T|......d......
0190 - 97 bb 88 b8 e7 18 a1 c1-a4 26 88 68 3c 7b 98 5f   .........&.h<{._
01a0 - 6c 13 e1 8c 0c fb c4 64-c6 0b 48 40 73 8f d6 c5   l......d..H@s...
01b0 - 00 76 80 66 65 81 1c 2b-0a 0b 6b a4 2d dc 25 19   .v.fe..+..k.-.%.
01c0 - 55 3c c8 f1 79 a2 db 1c-a9 fe 9a 47 f1 80 bd f6   U<..y......G....
01d0 - d0 4f b2 e7 95 13 81 33-7b 69 45 9d d1 b5 3a 13   .O.....3{iE...:.
01e0 - 4f 2d d3 55 b2 ac 73 38-f0 2a bf 5b 3a c2 db 2a   O-.U..s8.*.[:..*
01f0 - cc a1 b6 d1 fc 7f 2f 42-ae 10 4a 15 b6 40 2f 00   ....../B..J..@/.
0200 - 72 7d 47 23 43 0d 63 9e-99 7a 40 95 e6 c5 19 d1   r}G#C.c..z@.....
0210 - 14 ea 5a 2a da 40 25 53-b4 4c f4 b1 6f 41 11 b9   ..Z*.@%S.L..oA..
0220 - 6f 55 55 ca e5 2a 31 e4-c9 b1 15 3f 6e 82 13 bc   oUU..*1....?n...
0230 - b2 5e 5d 35 a9 ff 33 5b-40 d1 2d 52 22 2b 86 1a   .^]5..3[@.-R"+..
0240 - 11 a9 45 1c e1 25 71 46-a1 95 54 03 58 f0 75 19   ..E..%qF..T.X.u.
0250 - 2c 29 3e 1f 5b 13 b5 4a-03 0c 6a 34 3a cc 3a ed   ,)>.[..J..j4:.:.
0260 - c4 5d 64 38 93 d4 07 b4-7f 14 c8 e1 96 bd 5e e6   .]d8..........^.
0270 - b8 da 28 6c 81 58 83 b8-c7 01 1d 30 bc ab 9c 48   ..(l.X.....0...H
0280 - a4 41 41 56 58 0d b4 b6-2c dd 84 98 a7 33 cf c5   .AAVX...,....3..
0290 - 89 43 b8 7b 08 bc d9 9a-c3 5b 61 cf 15 15 15 c0   .C.{.....[a.....
02a0 - 3e 57 fa 1d d1 84 b7 97-32 34 d4 fc 6b bb 72 57   >W......24..k.rW
02b0 - 10 37 50 a0 49 72 08 79-8f 4c 03 51 5a a4 43 26   .7P.Ir.y.L.QZ.C&
02c0 - 24 c3 0d d8 24 dd a2 44-59 c4 07 f4 88 25 ff 30   $...$..DY....%.0
02d0 - b0 cf e5 59 f8 ab 3a df-c1 c1 38 ab 3c fc f7 19   ...Y..:...8.<...
02e0 - 67 36 ad 19 87 35 4d a3-1b 0c b3 6b be 42 9e b1   g6...5M....k.B..
02f0 - 2b 91 31 04 aa 79 5c c8-c9 47 52 d7 02 07 cc a3   +.1..y\..GR.....
0300 - ba c8 9b 18 e6 fc b6 fd-c9 b4 c3 54 96 fe b6 93   ...........T....
0310 - 83 19 13 65 a1 87 b0 21-0f 01 82 b6 ca b3 a0 3d   ...e...!.......=
0320 - e7 a6 4a f3 42 25 48 52-6e b7 72 60 fc 4a fa 10   ..J.B%HRn.r`.J..
0330 - 62 02 29 46 4e 8c 6d 54-94 a2 d4 06 0f a6 41 b6   b.)FN.mT......A.
0340 - 21 a3 1e d3 c7 0e 69 f3-33 1d a0 20 d5 e1 17 c5   !.....i.3.. ....
0350 - 0a 12 2b ac 35 f3 46 2d-4b 54 90 49 c5 18 32 4b   ..+.5.F-KT.I..2K
0360 - 5a db 38 8b eb 49 14 d5-53 05 c6 41 7f c5 76 59   Z.8..I..S..A..vY
0370 - 27 81 c6 24 46 bc ff 9a-cd 9c 70 18 9f ab 2f f4   '..$F.....p.../.
0380 - 30 cc 96 9b 64 7b ec 24-04 b9 1a a5 1a 0f 75 71   0...d{.$......uq
0390 - 0f ec b0 2d d2 26 cf 7f-75 34 a0 85 5c 5c 4b 45   ...-.&..u4..\\KE
03a0 - f0 8b c8 50 36 9c 0d 72-7b c7 bb 9b 03 92 86 85   ...P6..r{.......
03b0 - c1 7b cf 41 79 4b b9 95-8c 90 2d 48 a7 0b ca 29   .{.AyK....-H...)
03c0 - 70 ba aa ab 56 15 7c a0-83 c7 0e 50 1f 58 32 1b   p...V.|....P.X2.
03d0 - 68 6c a4 f6 46 9c 53 83-12 90 90 ac 68 b2 36 17   hl..F.S.....h.6.
03e0 - 34 92 8c aa 43 b4 e8 48-09 d1 26 ae 1a 2f a7 13   4...C..H..&../..
03f0 - 93 87 a5 ad 60 53 7a 34-c8 cd f7 60 72 68 28 c2   ....`Sz4...`rh(.
0400 - 4b 1c cb 20 53 be e6 39-8d df 8b 53 cf e4 53 5b   K.. S..9...S..S[
0410 - 67 7b 23 fb 9b e9 e9 6f-f8 d1 14 4f a8 6c bb 81   g{#....o...O.l..
0420 - c0 c5 84 c4 a9 c7 65 95-91 c4 32 e8 7b 3c 7c 20   ......e...2.{<|
0430 - 55 85 36 40 f2 54 cf b1-29 d3 01 a1 99 48 ac 5b   U.6@.T..)....H.[
0440 - b4 a7 08 49 cd 08 c7 97-7e 04 6e 38 26 26 02 b5   ...I....~.n8&&..
0450 - 8e f8 93 56 b8 34 9e 37-e4 4a 82 98 0f 87 c8 88   ...V.4.7.J......
0460 - 93 25 c1 26 80 97 60 7a-4e 23 45 47 5f 89 38 56   .%.&..`zN#EG_.8V
0470 - 66 16 0a 28 c9 56 f4 10-38 20 27 bf f0 00 b6 52   f..(.V..8 '....R
0480 - 9d ed 57 24 7b b9 08 ab-65 61 25 e7 0d 56 1b bb   ..W${...ea%..V..
0490 - 12 e6 47 d4 91 70 a8 9a-b5 5d 11 4e 0c 86 1c d7   ..G..p...].N....
04a0 - 00 72 2b c5 cd a7 b2 05-20 3b 72 16 85 8b df 07   .r+..... ;r.....
04b0 - 02 96 26 10 88 1c 64 63-b9 0b 47 8a 6a ef e7 5a   ..&...dc..G.j..Z
04c0 - 9d 57 a3 b7 11 76 af b2-20 5a ac c9 66 e0 69 22   .W...v.. Z..f.i"
04d0 - a4 35 d6 f4 ac 2c 23 3f-e0 5a 30 b8 5b 71 cb d8   .5...,#?.Z0.[q..
04e0 - aa 87 e0 69 f3 f8 ad 77-52 1b 97 f5 09 60 52 35   ...i...wR....`R5
04f0 - 00 eb c0 0d e5 b9 42 82-7d 98 b3 b6 52 a0 39 ee   ......B.}...R.9.
0500 - 0c 7b 1a ba 5e 96 b1 c2-53 8b 3c 1a a4 59 a4 47   .{..^...S.<..Y.G
0510 - a1 c6 96 c7 76 38 8f a1-ec a2 71 45 4c 2d 21 c5   ....v8....qEL-!.
0520 - d3 93 2d 09 7c 7b 08 c6-8c 1b 82 80 71 e8 2a c3   ..-.|{......q.*.
0530 - 80 4c c6 65 c5 ff a2 24-17 c1 0b f7 62 28 95 eb   .L.e...$....b(..
0540 - 03 29 c4 d7 e2 d1 e8 ad-aa 23 58 9b b7 b0 c4 89   .).......#X.....
0550 - ab 11 7e 29 57 39 00 85-54 00 ba 79 38 95 87 0d   ..~)W9..T..y8...
0560 - 1d 52 14 e3 d5 fe 5d 52-d8 77 30 00 f2 06 6b 5b   .R....]R.w0...k[
0570 - 13 6c a2 a9 45 e7 c2 63-d5 16 30 8f 55 49 56 66   .l..E..c..0.UIVf
0580 - 44 00 1d 00 20 22 03 1f-16 d8 83 5b 51 03 f7 ed   D... ".....[Q...
0590 - 27 d0 be 72 85 89 5f 5c-b5 a3 ba f6 d4 b5 1e cd   '..r.._\........
05a0 - ae 02 78 c1 63 00 1b 00-03 02 00 01               ..x.c.......
SSL_connect:SSLv3/TLS write client hello
read from 0x25d8aad8ac0 [0x25d8ab241f3] (5 bytes => 5 (0x5))
0000 - 15 03 03 00 02                                    .....
read from 0x25d8aad8ac0 [0x25d8ab241f8] (2 bytes => 2 (0x2))
0000 - 02 28                                             .(
SSL3 alert read:fatal:handshake failure
SSL_connect:error in error
146E0000:error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake failure:../openssl-3.6.2/ssl/record/rec_layer_s3.c:918:SSL alert number 40
---
no peer certificate available
---
No client certificate CA names sent
Negotiated TLS1.3 group: <NULL>
---
SSL handshake has read 7 bytes and written 1452 bytes
Verification: OK
---
New, (NONE), Cipher is (NONE)
Protocol: TLSv1.3
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---
read from 0x25d8aad8ac0 [0x25d890748b0] (16384 bytes => 0)
146E0000:error:0A000197:SSL routines:SSL_shutdown:shutdown while in init:../openssl-3.6.2/ssl/ssl_lib.c:2804:
````

[TOC](README.md)
