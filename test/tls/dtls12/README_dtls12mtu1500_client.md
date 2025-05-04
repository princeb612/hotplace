#### dtls12mtu1500.pcapng - client

````
$ openssl s_client -connect localhost:9000 -state -debug -keylogfile client.keylog -mtu 1500 -dtls1_2
Connecting to ::1
CONNECTED(000001E0)
SSL_connect:before SSL initialization
write to 0x27fa3b12680 [0x27fa5852df0] (214 bytes => 214 (0xD6))
0000 - 16 fe ff 00 00 00 00 00-00 00 00 00 c9 01 00 00   ................
0010 - bd 00 00 00 00 00 00 00-bd fe fd 72 d4 34 26 a5   ...........r.4&.
0020 - 5a a0 09 5f f3 ac 7c 69-90 fe c0 00 8d ad 75 4d   Z.._..|i......uM
0030 - 09 7c f7 04 58 cb 9e 49-b2 89 27 00 00 00 36 c0   .|..X..I..'...6.
0040 - 2c c0 30 00 9f cc a9 cc-a8 cc aa c0 2b c0 2f 00   ,.0.........+./.
0050 - 9e c0 24 c0 28 00 6b c0-23 c0 27 00 67 c0 0a c0   ..$.(.k.#.'.g...
0060 - 14 00 39 c0 09 c0 13 00-33 00 9d 00 9c 00 3d 00   ..9.....3.....=.
0070 - 3c 00 35 00 2f 01 00 00-5d ff 01 00 01 00 00 0b   <.5./...].......
0080 - 00 04 03 00 01 02 00 0a-00 0c 00 0a 00 1d 00 17   ................
0090 - 00 1e 00 19 00 18 00 23-00 00 00 16 00 00 00 17   .......#........
00a0 - 00 00 00 0d 00 30 00 2e-04 03 05 03 06 03 08 07   .....0..........
00b0 - 08 08 08 1a 08 1b 08 1c-08 09 08 0a 08 0b 08 04   ................
00c0 - 08 05 08 06 04 01 05 01-06 01 03 03 03 01 03 02   ................
00d0 - 04 02 05 02 06 02                                 ......
SSL_connect:SSLv3/TLS write client hello
read from 0x27fa3b12680 [0x27fa5858283] (16717 bytes => 48 (0x30))
0000 - 16 fe ff 00 00 00 00 00-00 00 00 00 23 03 00 00   ............#...
0010 - 17 00 00 00 00 00 00 00-17 fe ff 14 b5 2e 26 56   ..............&V
0020 - f9 71 3d 40 97 4c 59 ec-e4 89 b3 2f 57 37 57 ce   .q=@.LY..../W7W.
SSL_connect:SSLv3/TLS write client hello
SSL_connect:DTLS1 read hello verify request
write to 0x27fa3b12680 [0x27fa5852df0] (234 bytes => 234 (0xEA))
0000 - 16 fe ff 00 00 00 00 00-00 00 01 00 dd 01 00 00   ................
0010 - d1 00 01 00 00 00 00 00-d1 fe fd 72 d4 34 26 a5   ...........r.4&.
0020 - 5a a0 09 5f f3 ac 7c 69-90 fe c0 00 8d ad 75 4d   Z.._..|i......uM
0030 - 09 7c f7 04 58 cb 9e 49-b2 89 27 00 14 b5 2e 26   .|..X..I..'....&
0040 - 56 f9 71 3d 40 97 4c 59-ec e4 89 b3 2f 57 37 57   V.q=@.LY..../W7W
0050 - ce 00 36 c0 2c c0 30 00-9f cc a9 cc a8 cc aa c0   ..6.,.0.........
0060 - 2b c0 2f 00 9e c0 24 c0-28 00 6b c0 23 c0 27 00   +./...$.(.k.#.'.
0070 - 67 c0 0a c0 14 00 39 c0-09 c0 13 00 33 00 9d 00   g.....9.....3...
0080 - 9c 00 3d 00 3c 00 35 00-2f 01 00 00 5d ff 01 00   ..=.<.5./...]...
0090 - 01 00 00 0b 00 04 03 00-01 02 00 0a 00 0c 00 0a   ................
00a0 - 00 1d 00 17 00 1e 00 19-00 18 00 23 00 00 00 16   ...........#....
00b0 - 00 00 00 17 00 00 00 0d-00 30 00 2e 04 03 05 03   .........0......
00c0 - 06 03 08 07 08 08 08 1a-08 1b 08 1c 08 09 08 0a   ................
00d0 - 08 0b 08 04 08 05 08 06-04 01 05 01 06 01 03 03   ................
00e0 - 03 01 03 02 04 02 05 02-06 02                     ..........
SSL_connect:SSLv3/TLS write client hello
read from 0x27fa3b12680 [0x27fa5858283] (16717 bytes => 1331 (0x533))
0000 - 16 fe fd 00 00 00 00 00-00 00 01 00 4d 02 00 00   ............M...
0010 - 41 00 01 00 00 00 00 00-41 fe fd c4 6f f0 c6 f8   A.......A...o...
0020 - f2 0e 8f 16 05 31 f2 85-b0 1a fb 36 ae a5 f0 1b   .....1.....6....
0030 - 2b 9b de 69 aa 08 99 84-45 61 b0 00 c0 27 00 00   +..i....Ea...'..
0040 - 19 ff 01 00 01 00 00 0b-00 04 03 00 01 02 00 23   ...............#
0050 - 00 00 00 16 00 00 00 17-00 00 16 fe fd 00 00 00   ................
0060 - 00 00 00 00 02 03 72 0b-00 03 66 00 02 00 00 00   ......r...f.....
0070 - 00 03 66 00 03 63 00 03-60 30 82 03 5c 30 82 02   ..f..c..`0..\0..
0080 - 44 a0 03 02 01 02 02 14-63 a6 71 10 79 d6 a6 48   D.......c.q.y..H
0090 - 59 da 67 a9 04 e8 e3 5f-e2 03 a3 26 30 0d 06 09   Y.g...._...&0...
00a0 - 2a 86 48 86 f7 0d 01 01-0b 05 00 30 59 31 0b 30   *.H........0Y1.0
00b0 - 09 06 03 55 04 06 13 02-4b 52 31 0b 30 09 06 03   ...U....KR1.0...
00c0 - 55 04 08 0c 02 47 47 31-0b 30 09 06 03 55 04 07   U....GG1.0...U..
00d0 - 0c 02 59 49 31 0d 30 0b-06 03 55 04 0a 0c 04 54   ..YI1.0...U....T
00e0 - 65 73 74 31 0d 30 0b 06-03 55 04 0b 0c 04 54 65   est1.0...U....Te
00f0 - 73 74 31 12 30 10 06 03-55 04 03 0c 09 54 65 73   st1.0...U....Tes
0100 - 74 20 52 6f 6f 74 30 1e-17 0d 32 34 30 38 32 39   t Root0...240829
0110 - 30 36 32 37 31 37 5a 17-0d 32 35 30 38 32 39 30   062717Z..2508290
0120 - 36 32 37 31 37 5a 30 54-31 0b 30 09 06 03 55 04   62717Z0T1.0...U.
0130 - 06 13 02 4b 52 31 0b 30-09 06 03 55 04 08 0c 02   ...KR1.0...U....
0140 - 47 47 31 0b 30 09 06 03-55 04 07 0c 02 59 49 31   GG1.0...U....YI1
0150 - 0d 30 0b 06 03 55 04 0a-0c 04 54 65 73 74 31 0d   .0...U....Test1.
0160 - 30 0b 06 03 55 04 0b 0c-04 54 65 73 74 31 0d 30   0...U....Test1.0
0170 - 0b 06 03 55 04 03 0c 04-54 65 73 74 30 82 01 22   ...U....Test0.."
0180 - 30 0d 06 09 2a 86 48 86-f7 0d 01 01 01 05 00 03   0...*.H.........
0190 - 82 01 0f 00 30 82 01 0a-02 82 01 01 00 ad 9a 29   ....0..........)
01a0 - 67 5f f3 a4 79 b4 c6 e6-32 73 d8 d7 ed 88 94 15   g_..y...2s......
01b0 - 83 e4 31 00 04 6c b5 8c-ac 87 ab 74 44 13 76 ca   ..1..l.....tD.v.
01c0 - 0b 74 29 40 9e 97 2a 01-d7 8b 46 26 6e 19 35 4d   .t)@..*...F&n.5M
01d0 - c0 d3 b5 ea 0e 93 3a 06-e8 e5 85 b5 27 05 63 db   ......:.....'.c.
01e0 - 28 b8 92 da 5a 14 39 0f-da 68 6d 6f 0a fb 52 dc   (...Z.9..hmo..R.
01f0 - 08 0f 54 d3 e4 a2 28 9d-a0 71 50 82 e0 db ca d1   ..T...(..qP.....
0200 - 94 dd 42 98 3a 09 33 a8-d9 ef fb d2 35 43 b1 22   ..B.:.3.....5C."
0210 - a2 be 41 6d ba 91 dc 0b-31 4e 88 f9 4d 9c 61 2d   ..Am....1N..M.a-
0220 - ec b2 13 0a c2 91 8e a2-d6 e9 40 b9 32 b9 80 8f   ..........@.2...
0230 - b3 18 a3 33 13 23 d5 d0-7e d9 d0 7f 93 e0 2d 4d   ...3.#..~.....-M
0240 - 90 c5 58 24 56 d5 c9 10-13 4a b2 99 23 7d 34 b9   ..X$V....J..#}4.
0250 - 8e 97 19 69 6f ce c6 3f-d6 17 a7 d2 43 e0 36 cb   ...io..?....C.6.
0260 - 51 7b 2f 18 8b c2 33 f8-57 cf d1 61 0b 7c ed 37   Q{/...3.W..a.|.7
0270 - 35 e3 13 7a 24 2e 77 08-c2 e3 d9 e6 17 d3 a5 c6   5..z$.w.........
0280 - 34 5a da 86 a7 f8 02 36-1d 66 63 cf e9 c0 3d 82   4Z.....6.fc...=.
0290 - fb 39 a2 8d 92 01 4a 83-cf e2 76 3d 87 02 03 01   .9....J...v=....
02a0 - 00 01 a3 21 30 1f 30 1d-06 03 55 1d 11 04 16 30   ...!0.0...U....0
02b0 - 14 82 12 74 65 73 74 2e-70 72 69 6e 63 65 62 36   ...test.princeb6
02c0 - 31 32 2e 70 65 30 0d 06-09 2a 86 48 86 f7 0d 01   12.pe0...*.H....
02d0 - 01 0b 05 00 03 82 01 01-00 00 a5 f5 54 18 ab ad   ............T...
02e0 - 36 38 c8 fc 0b 66 60 dd-9f 75 9d 86 5b 79 2f ee   68...f`..u..[y/.
02f0 - 57 f1 79 1c 15 a1 34 23-d0 1c a9 58 51 a4 d0 08   W.y...4#...XQ...
0300 - f5 d8 f7 49 e9 c5 b5 65-91 51 2d 6d e4 3b 0e 77   ...I...e.Q-m.;.w
0310 - 02 1f 45 8e 34 e5 bb eb-f6 9d df 4a 40 60 21 b3   ..E.4......J@`!.
0320 - 8e 16 33 3f f4 b6 90 d3-3c 34 ce e6 d9 47 07 a7   ..3?....<4...G..
0330 - 57 14 0c f9 78 0b 36 72-a9 88 07 07 93 b4 d7 fe   W...x.6r........
0340 - 29 5e e8 41 37 20 a5 03-c7 97 cb 82 ca db 14 e5   )^.A7 ..........
0350 - 8b 96 1f a9 e9 20 3d 6b-25 ae f4 89 4c 60 8d e9   ..... =k%...L`..
0360 - 14 33 47 4b 88 54 a2 47-19 81 c8 7b 0e 32 52 2b   .3GK.T.G...{.2R+
0370 - 91 88 ad 0f 6d 73 30 8c-00 af d5 fc 46 46 af 3a   ....ms0.....FF.:
0380 - c2 17 89 ec c8 83 ae da-e6 69 63 e0 9c 84 22 c5   .........ic...".
0390 - 7a de e8 23 6b 53 9d 6f-94 d2 7f 5c be 1d 0c de   z..#kS.o...\....
03a0 - 0e 07 0d 52 a5 43 8c e8-05 ef c0 ff f0 73 fa dc   ...R.C.......s..
03b0 - 5a 51 4c 24 09 65 45 7d-ab 52 8b 7e 5d f0 fb de   ZQL$.eE}.R.~]...
03c0 - a7 3d 43 c5 af 76 e3 6e-f9 a1 dc 78 a2 bd 54 41   .=C..v.n...x..TA
03d0 - 04 99 e5 56 32 ba 02 fd-72 16 fe fd 00 00 00 00   ...V2...r.......
03e0 - 00 00 00 03 01 34 0c 00-01 28 00 03 00 00 00 00   .....4...(......
03f0 - 01 28 03 00 1d 20 a8 7e-61 06 63 3a 42 0a c7 29   .(... .~a.c:B..)
0400 - 44 19 57 8b de a2 e9 83-04 c9 75 a8 ab 44 47 1f   D.W.......u..DG.
0410 - ce c1 66 d3 1a 1b 08 04-01 00 91 ab 4c e4 97 1f   ..f.........L...
0420 - 90 76 85 8d 7f 0b 56 64-45 9c d0 ec 2c fe 41 10   .v....VdE...,.A.
0430 - 91 76 a7 69 81 8c 56 9a-44 8f 55 40 b2 2b 60 64   .v.i..V.D.U@.+`d
0440 - c0 63 40 97 53 5f 38 c1-f5 b4 68 a6 6c 1a 4c 23   .c@.S_8...h.l.L#
0450 - e3 df 64 dc 18 77 d4 06-1d dc ab 97 2c d1 61 e3   ..d..w......,.a.
0460 - 4d 17 19 5b 2f 77 0b ec-1c 68 bd 54 4d 60 d3 da   M..[/w...h.TM`..
0470 - 1b 10 76 dc ad 99 4c ff-40 99 14 aa de 37 c6 ef   ..v...L.@....7..
0480 - 2a 90 f7 5a ef 3d b6 99-63 70 e4 e4 d8 6f f9 6a   *..Z.=..cp...o.j
0490 - 1f 5f 13 28 0e b5 ab 8b-d6 26 68 49 15 21 2b fb   ._.(.....&hI.!+.
04a0 - bf 53 19 53 d4 36 17 56-3e 57 b4 a8 d9 db 99 3f   .S.S.6.V>W.....?
04b0 - 0d 8d f8 1c 3e af 32 23-45 73 49 11 d6 5c fa bf   ....>.2#EsI..\..
04c0 - b3 af 1d 8c 05 2a 6c bb-74 c0 ea ad bb a1 e1 5c   .....*l.t......\
04d0 - e9 23 50 b6 29 37 82 8d-88 b4 36 aa 5c f6 82 ab   .#P.)7....6.\...
04e0 - 90 a7 30 e1 ce 92 02 2f-0d 5c 77 f1 b5 35 fb 48   ..0..../.\w..5.H
04f0 - f2 73 ab e5 00 0d f1 ce-70 7a 04 bc 18 79 7c 65   .s......pz...y|e
0500 - 08 ca e5 f3 a0 6c 9e 61-1c 99 64 84 0f 19 c9 c5   .....l.a..d.....
0510 - e3 dc 68 ba 1c 29 69 60-46 be 16 fe fd 00 00 00   ..h..)i`F.......
0520 - 00 00 00 00 04 00 0c 0e-00 00 00 00 04 00 00 00   ................
0530 - 00 00 00                                          ...
SSL_connect:SSLv3/TLS write client hello
Can't use SSL_get_servername
SSL_connect:SSLv3/TLS read server hello
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify return:1
SSL_connect:SSLv3/TLS read server certificate
SSL_connect:SSLv3/TLS read server key exchange
SSL_connect:SSLv3/TLS read server done
SSL_connect:SSLv3/TLS write client key exchange
SSL_connect:SSLv3/TLS write change cipher spec
write to 0x27fa3b12680 [0x27fa5852df0] (165 bytes => 165 (0xA5))
0000 - 16 fe fd 00 00 00 00 00-00 00 02 00 2d 10 00 00   ............-...
0010 - 21 00 02 00 00 00 00 00-21 20 b7 6b 26 2b 2a c4   !.......! .k&+*.
0020 - b6 a4 05 30 de 2d 61 8d-6f cc 0a 8a 3f ca 98 98   ...0.-a.o...?...
0030 - ec 0b 49 90 48 ce fb f8-b1 65 14 fe fd 00 00 00   ..I.H....e......
0040 - 00 00 00 00 03 00 01 01-16 fe fd 00 01 00 00 00   ................
0050 - 00 00 00 00 50 b4 64 b5-c5 c0 71 56 67 00 c2 9b   ....P.d...qVg...
0060 - d6 e4 74 b6 3a 31 0c 93-d8 4e e1 2c 20 66 b6 ce   ..t.:1...N., f..
0070 - 53 0d 02 6f fa a7 3c 69-73 57 2e f1 9c 30 8c 67   S..o..<isW...0.g
0080 - 6c 91 38 ee 2e f3 5f b9-d5 38 95 38 c8 0a 31 f9   l.8..._..8.8..1.
0090 - e1 3b cf 47 d7 be 98 cc-fb f5 40 7d f6 bb 40 86   .;.G......@}..@.
00a0 - f3 0c 47 08 34                                    ..G.4
SSL_connect:SSLv3/TLS write finished
read from 0x27fa3b12680 [0x27fa5858283] (16717 bytes => 314 (0x13A))
0000 - 16 fe fd 00 00 00 00 00-00 00 05 00 c2 04 00 00   ................
0010 - b6 00 05 00 00 00 00 00-b6 00 00 1c 20 00 b0 de   ............ ...
0020 - 9b 91 5c f3 4b 41 77 01-c8 51 9d 14 6e 19 41 69   ..\.KAw..Q..n.Ai
0030 - 68 b7 2f 43 52 5e fe a2-eb d9 4d df 89 50 21 0f   h./CR^....M..P!.
0040 - 99 29 f3 dd 91 db 16 5d-fb e2 38 6c fc 9b 47 01   .).....]..8l..G.
0050 - 9a 70 aa e4 28 42 46 0b-25 ba 5b 43 46 9b ed 43   .p..(BF.%.[CF..C
0060 - 47 3e 42 b7 30 1d 5a f4-2f 7c fe d5 9a ea af d9   G>B.0.Z./|......
0070 - 2c 14 93 30 10 2f cc 36-e8 7c 74 03 1f 05 d4 0d   ,..0./.6.|t.....
0080 - 52 e8 a3 8e 67 78 83 20-18 13 41 48 f8 c5 1e f7   R...gx. ..AH....
0090 - 19 32 86 31 61 b7 c1 53-04 f9 e7 c0 25 22 0a 83   .2.1a..S....%"..
00a0 - 7d f4 a8 f8 4f e2 a2 73-86 1f 80 70 c9 2f 0a 25   }...O..s...p./.%
00b0 - 0a b7 bd 9b 22 06 83 36-25 6a 1f 0f 93 01 eb 99   ...."..6%j......
00c0 - af 6b 38 0a 2b cd 45 2b-90 7e 34 84 6a be fa 14   .k8.+.E+.~4.j...
00d0 - fe fd 00 00 00 00 00 00-00 06 00 01 01 16 fe fd   ................
00e0 - 00 01 00 00 00 00 00 00-00 50 ac 08 4a 2f 53 fd   .........P..J/S.
00f0 - 0e 06 2d 47 78 84 de 0d-e7 77 d4 bd 2e 73 d1 b2   ..-Gx....w...s..
0100 - 0a c1 66 2a aa 74 15 ca-0b 07 f0 08 85 ec 47 ef   ..f*.t........G.
0110 - f4 a8 82 a1 fb ee ea 4a-67 9b 44 b4 7b 47 12 61   .......Jg.D.{G.a
0120 - 0d b1 0a 19 6f ba 7f 52-e8 c9 ef 53 59 ed b4 cf   ....o..R...SY...
0130 - 57 03 12 cf 61 92 cd 0f-9b 1a                     W...a.....
SSL_connect:SSLv3/TLS write finished
SSL_connect:SSLv3/TLS read server session ticket
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
SSL handshake has read 1693 bytes and written 613 bytes
Verification error: unable to verify the first certificate
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES128-SHA256
Protocol: DTLSv1.2
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : DTLSv1.2
    Cipher    : ECDHE-RSA-AES128-SHA256
    Session-ID: E2EBCC4A17CD403E19368BABDF99E3EED4CA2C43358F3D1EB9125AA17163011C
    Session-ID-ctx:
    Master-Key: CB07E6D5E5ABEF6D1C36BD39A5433B66F1932D485A40B0AA374C613F1630A91502DAEDA8F3A9C87007AA2D64C855BE24
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - de 9b 91 5c f3 4b 41 77-01 c8 51 9d 14 6e 19 41   ...\.KAw..Q..n.A
    0010 - 69 68 b7 2f 43 52 5e fe-a2 eb d9 4d df 89 50 21   ih./CR^....M..P!
    0020 - 0f 99 29 f3 dd 91 db 16-5d fb e2 38 6c fc 9b 47   ..).....]..8l..G
    0030 - 01 9a 70 aa e4 28 42 46-0b 25 ba 5b 43 46 9b ed   ..p..(BF.%.[CF..
    0040 - 43 47 3e 42 b7 30 1d 5a-f4 2f 7c fe d5 9a ea af   CG>B.0.Z./|.....
    0050 - d9 2c 14 93 30 10 2f cc-36 e8 7c 74 03 1f 05 d4   .,..0./.6.|t....
    0060 - 0d 52 e8 a3 8e 67 78 83-20 18 13 41 48 f8 c5 1e   .R...gx. ..AH...
    0070 - f7 19 32 86 31 61 b7 c1-53 04 f9 e7 c0 25 22 0a   ..2.1a..S....%".
    0080 - 83 7d f4 a8 f8 4f e2 a2-73 86 1f 80 70 c9 2f 0a   .}...O..s...p./.
    0090 - 25 0a b7 bd 9b 22 06 83-36 25 6a 1f 0f 93 01 eb   %...."..6%j.....
    00a0 - 99 af 6b 38 0a 2b cd 45-2b 90 7e 34 84 6a be fa   ..k8.+.E+.~4.j..

    Start Time: 1745722666
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: yes
---
hello
write to 0x27fa3b12680 [0x27fa586af63] (77 bytes => 77 (0x4D))
0000 - 17 fe fd 00 01 00 00 00-00 00 01 00 40 bb a3 af   ............@...
0010 - 1a 11 7d 47 21 6d 1c b9-99 26 ac 98 a9 97 33 3c   ..}G!m...&....3<
0020 - 97 25 d2 09 69 b1 38 1e-fd 06 01 82 b1 b0 be 3a   .%..i.8........:
0030 - 21 c2 9d 3f 99 68 00 7e-15 61 31 cd fe 83 fc 3e   !..?.h.~.a1....>
0040 - fa f5 b3 7b 77 76 37 56-0f b5 2a 60 9a            ...{wv7V..*`.
Q
DONE
write to 0x27fa3b12680 [0x27fa586af63] (77 bytes => 77 (0x4D))
0000 - 15 fe fd 00 01 00 00 00-00 00 02 00 40 c1 a0 84   ............@...
0010 - 7a 55 42 1f d9 3c 60 27-ab c0 f6 25 9d 7e ee c1   zUB..<`'...%.~..
0020 - e0 5b b4 1f d8 ca 29 6b-f0 ef 18 70 fd 92 02 4e   .[....)k...p...N
0030 - 70 0f 8e ad bf 5a f2 84-4c 8d 3e 87 21 1a ca e5   p....Z..L.>.!...
0040 - f0 72 75 f0 af c7 ff 00-1c 17 da 1c ae            .ru..........
SSL3 alert write:warning:close notify
read from 0x27fa3b12680 [0x27fa3a57c90] (16384 bytes => 77 (0x4D))
0000 - 15 fe fd 00 01 00 00 00-00 00 01 00 40 05 c7 30   ............@..0
0010 - 85 a8 64 57 52 91 f5 f3-26 42 6e 43 10 63 06 ed   ..dWR...&BnC.c..
0020 - a2 e0 8b 05 81 23 1c a8-1e 0c 76 69 67 c2 dc 04   .....#....vig...
0030 - 9b 88 f7 44 52 ae 3e 9c-f0 02 16 3a c8 ed 84 35   ...DR.>....:...5
0040 - 97 ec f7 27 03 a8 bd 51-f1 cc 48 60 6c            ...'...Q..H`l
````

[TOC](README.md)
