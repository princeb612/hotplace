#### tls13.pcapng - client

````
$ openssl s_client -connect localhost:9000 -state -debug -keylogfile sslkeylog -tls1_3
Connecting to ::1
CONNECTED(000001DC)
SSL_connect:before SSL initialization
write to 0x1b57b0afae0 [0x1b57ce45d20] (236 bytes => 236 (0xEC))
0000 - 16 03 01 00 e7 01 00 00-e3 03 03 b9 39 8c 3a f3   ............9.:.
0010 - 5d 14 01 fe 4a a6 2e a9-4b 26 43 37 f1 85 bc 84   ]...J...K&C7....
0020 - 4e 1b c2 dd ed 35 86 b8-da e2 25 20 43 9a cd c3   N....5....% C...
0030 - 2a 47 ca 3c 67 bf d9 ae-dc fa ee 66 3b 49 bc f8   *G.<g......f;I..
0040 - c7 da 1c 8e 36 ed 29 c9-d9 43 62 30 00 06 13 02   ....6.)..Cb0....
0050 - 13 03 13 01 01 00 00 94-00 0b 00 04 03 00 01 02   ................
0060 - 00 0a 00 16 00 14 00 1d-00 17 00 1e 00 19 00 18   ................
0070 - 01 00 01 01 01 02 01 03-01 04 00 23 00 00 00 16   ...........#....
0080 - 00 00 00 17 00 00 00 0d-00 24 00 22 04 03 05 03   .........$."....
0090 - 06 03 08 07 08 08 08 1a-08 1b 08 1c 08 09 08 0a   ................
00a0 - 08 0b 08 04 08 05 08 06-04 01 05 01 06 01 00 2b   ...............+
00b0 - 00 03 02 03 04 00 2d 00-02 01 01 00 33 00 26 00   ......-.....3.&.
00c0 - 24 00 1d 00 20 54 10 c0-fe 90 88 d2 f5 df 0f c5   $... T..........
00d0 - dc bf 60 75 9b 96 f5 75-f8 aa 91 14 37 5f d5 e6   ..`u...u....7_..
00e0 - d7 e9 b0 94 23 00 1b 00-03 02 00 01               ....#.......
SSL_connect:SSLv3/TLS write client hello
read from 0x1b57b0afae0 [0x1b57ce4adf3] (5 bytes => 5 (0x5))
0000 - 16 03 03 00 7a                                    ....z
read from 0x1b57b0afae0 [0x1b57ce4adf8] (122 bytes => 122 (0x7A))
0000 - 02 00 00 76 03 03 73 8a-10 e3 4d 0a d3 4b 5c 0c   ...v..s...M..K\.
0010 - 9b b5 6b 9b 20 f9 b6 1e-55 73 6e 35 ca cb a3 14   ..k. ...Usn5....
0020 - 7d ff 09 f8 5a 9a 20 43-9a cd c3 2a 47 ca 3c 67   }...Z. C...*G.<g
0030 - bf d9 ae dc fa ee 66 3b-49 bc f8 c7 da 1c 8e 36   ......f;I......6
0040 - ed 29 c9 d9 43 62 30 13-02 00 00 2e 00 2b 00 02   .)..Cb0......+..
0050 - 03 04 00 33 00 24 00 1d-00 20 60 63 09 ac 36 97   ...3.$... `c..6.
0060 - 58 a7 33 00 a4 68 13 ce-40 6f e8 3c 90 a0 0c 5b   X.3..h..@o.<...[
0070 - 9a be a2 52 64 00 2d 79-ec 00                     ...Rd.-y..
SSL_connect:SSLv3/TLS write client hello
read from 0x1b57b0afae0 [0x1b57ce4adf3] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
read from 0x1b57b0afae0 [0x1b57ce4adf8] (1 bytes => 1 (0x1))
0000 - 01                                                .
read from 0x1b57b0afae0 [0x1b57ce4adf3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
read from 0x1b57b0afae0 [0x1b57ce4adf8] (23 bytes => 23 (0x17))
0000 - a1 f9 36 57 36 ea 54 b8-3b 6f b2 eb 7b 3b 6e 1a   ..6W6.T.;o..{;n.
0010 - 2a e4 88 1b 24 64 03                              *...$d.
SSL_connect:SSLv3/TLS read server hello
Can't use SSL_get_servername
read from 0x1b57b0afae0 [0x1b57ce4adf3] (5 bytes => 5 (0x5))
0000 - 17 03 03 03 7e                                    ....~
read from 0x1b57b0afae0 [0x1b57ce4adf8] (894 bytes => 894 (0x37E))
0000 - 39 1a 84 b4 f7 2d 0b ee-0e 47 f1 9d 78 19 a5 bc   9....-...G..x...
0010 - 24 f8 02 51 48 1c 61 df-5d c0 2d d2 76 02 1f 39   $..QH.a.].-.v..9
0020 - 30 49 b9 66 72 67 d0 58-67 d3 25 f9 20 53 1c 31   0I.frg.Xg.%. S.1
0030 - 3b c2 a7 98 86 d7 20 1a-f1 bf 30 89 a4 d1 de f3   ;..... ...0.....
0040 - 1d ff 91 04 2f 6e d5 f8-97 69 ef 99 96 5e b7 7c   ..../n...i...^.|
0050 - 2f 9d 4c 79 2a 47 8a 75-11 65 ff c8 cf cb 24 eb   /.Ly*G.u.e....$.
0060 - b8 e1 10 36 b6 ec bd f1-19 cd bb 12 c0 e2 8b 7d   ...6...........}
0070 - db 8b 03 83 19 1c 6e 24-87 38 6c cb 2a 79 9b 89   ......n$.8l.*y..
0080 - f0 e2 4a 73 21 61 3d e2-45 19 99 bf 46 64 60 d5   ..Js!a=.E...Fd`.
0090 - 50 10 10 32 ec 3d 9b d3-4e 00 0c 28 47 9a f6 d7   P..2.=..N..(G...
00a0 - ca 7e 42 2b 6d 50 ca f3-56 8d 5f 6a 43 3f e7 2c   .~B+mP..V._jC?.,
00b0 - 81 57 7b 2a 27 db 2b 86-79 16 a3 04 6a 2f 1a 6d   .W{*'.+.y...j/.m
00c0 - a9 06 da 58 0a a2 c2 47-42 16 e5 81 1d b2 cf fe   ...X...GB.......
00d0 - 81 c9 d9 e0 bf 8b 11 49-86 33 13 be 57 78 7c 8f   .......I.3..Wx|.
00e0 - 8a 3e 06 06 75 b3 bc 8f-6b 0f f6 5a 58 be 49 d4   .>..u...k..ZX.I.
00f0 - d4 da 17 8a 89 5b c4 9c-6f c6 0a c9 15 9d 87 31   .....[..o......1
0100 - 0e c5 7b e3 a3 2d 13 2c-d9 9c 58 0b a5 1f f7 c1   ..{..-.,..X.....
0110 - ba ae b7 66 9a 90 09 11-f4 ba cc f1 84 79 e2 c7   ...f.........y..
0120 - bd 5c 9a cf 11 1d c1 7f-20 97 68 7f 87 8b 63 28   .\...... .h...c(
0130 - af 35 60 d1 ab c2 aa f8-cb 90 c3 69 7b 6f e4 c2   .5`........i{o..
0140 - a9 69 e5 fb e6 9f 39 9a-8b ff 07 4c ab a4 48 93   .i....9....L..H.
0150 - 1f 63 7e 3e e8 ae 86 26-0a 36 9a bd cb a6 9a 22   .c~>...&.6....."
0160 - 28 bc a3 d9 c9 16 ed e6-48 da 22 50 eb 17 75 52   (.......H."P..uR
0170 - fc 6e 95 eb d1 a2 e4 4e-e9 8e 49 37 e6 81 56 53   .n.....N..I7..VS
0180 - 19 ff e8 7d ac f1 fb e2-10 45 37 93 6a f4 39 d0   ...}.....E7.j.9.
0190 - 17 ea 30 0a c2 e6 7d 60-81 ab 02 32 6c aa a1 2e   ..0...}`...2l...
01a0 - 7c c4 ee 24 47 40 e5 2a-64 c4 f2 37 a9 9e 54 89   |..$G@.*d..7..T.
01b0 - 7a cd 74 22 6b 96 b8 e2-0d 1e 93 31 83 fe 63 06   z.t"k......1..c.
01c0 - 3d 20 e9 8f c7 cd 79 de-03 ca d3 37 c8 a7 f5 8b   = ....y....7....
01d0 - f1 aa c4 63 ef fa 2e d1-31 1b 04 1b ef e1 51 40   ...c....1.....Q@
01e0 - 8c c6 c7 38 c8 be 02 34-42 bf 66 a2 7f 1a f7 5f   ...8...4B.f...._
01f0 - c8 c9 47 90 91 9a 3f 9f-6b 1c 6b e0 3c 8c ed f9   ..G...?.k.k.<...
0200 - aa de bc 92 c9 26 2f f6-d3 e8 0e 04 77 b2 d0 cb   .....&/.....w...
0210 - 10 72 4a 9e 96 00 fd 5c-04 91 08 c7 05 d0 8f 00   .rJ....\........
0220 - 68 35 1e 6b 46 b8 66 f0-f9 62 46 59 cf a7 e2 15   h5.kF.f..bFY....
0230 - 7a 3c a2 47 a8 f4 8e e8-b5 90 95 4a 75 8d f5 5d   z<.G.......Ju..]
0240 - cb d0 7d 69 9f 0a 3c 34-a5 41 8c 99 6d e4 4b 66   ..}i..<4.A..m.Kf
0250 - d9 d1 18 8d 39 f1 19 25-43 1e 6e 1d a4 92 04 64   ....9..%C.n....d
0260 - f5 03 92 2d 75 e7 58 d0-f7 83 83 2e ca 39 f5 99   ...-u.X......9..
0270 - fc 2d 4b 7d 1b e7 f6 a0-32 ea 54 03 20 16 37 b2   .-K}....2.T. .7.
0280 - 65 c0 b6 51 a3 a8 d4 e2-8e 3a 97 83 86 4e ad 16   e..Q.....:...N..
0290 - fe d9 45 91 79 ce 84 f6-f7 40 4e 2e 61 c3 1d 04   ..E.y....@N.a...
02a0 - 7c 04 4e 99 d5 61 98 6a-bd 17 b8 2f 3a c9 e4 db   |.N..a.j.../:...
02b0 - 43 02 6a 28 63 cc 12 19-e0 5f 18 62 31 c9 c3 93   C.j(c...._.b1...
02c0 - fd e4 79 d6 f2 6c c0 fc-18 1e 31 6f 1b 9d 72 f0   ..y..l....1o..r.
02d0 - 91 f5 b7 89 20 79 cb 0e-1d d2 70 3a a5 dd bc 5a   .... y....p:...Z
02e0 - 60 a3 0d 01 4b a7 d9 68-d9 32 58 6a db 0d 67 6f   `...K..h.2Xj..go
02f0 - 9a 54 5f 97 c2 02 87 07-30 2e 38 15 33 a5 90 d1   .T_.....0.8.3...
0300 - 1e 75 fe 9d e3 97 e5 b9-80 d4 7d b0 33 13 53 6a   .u........}.3.Sj
0310 - 8d e7 a1 7d 8c d8 bc 05-3f ac 0a d4 07 d4 d1 00   ...}....?.......
0320 - 45 be 97 ec a0 a1 3a d1-c1 c6 48 48 5a ff b2 4a   E.....:...HHZ..J
0330 - 9e 00 f9 a8 09 b0 08 86-9a ca d0 5d 79 dc 20 5b   ...........]y. [
0340 - a5 87 5c 68 45 e2 52 31-22 36 0f cf 98 45 9c b0   ..\hE.R1"6...E..
0350 - 81 ee e0 2f eb 02 8e b0-7b 21 58 a0 d2 02 12 c2   .../....{!X.....
0360 - 99 82 bf 15 b1 93 cb 3a-df 88 88 9e 44 a5 4a dc   .......:....D.J.
0370 - 12 35 2f 77 95 04 44 9d-90 b2 d5 c2 29 a0         .5/w..D.....).
SSL_connect:TLSv1.3 read encrypted extensions
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify return:1
read from 0x1b57b0afae0 [0x1b57ce4adf3] (5 bytes => 5 (0x5))
0000 - 17 03 03 01 19                                    .....
read from 0x1b57b0afae0 [0x1b57ce4adf8] (281 bytes => 281 (0x119))
0000 - ed 30 de 7c 10 91 7d 7d-38 0a 9b cf 9c ed 40 d8   .0.|..}}8.....@.
0010 - c0 30 3e 01 ed 3f 2a a8-c0 b1 a1 3c 1f 88 a4 fb   .0>..?*....<....
0020 - 9e 77 2e 9a b9 78 ed 22-82 4c c4 7f 65 74 ba b4   .w...x.".L..et..
0030 - 5f 90 91 35 0a f8 16 41-ef 5f 83 a1 a5 fd 78 e7   _..5...A._....x.
0040 - 9f f0 10 79 f4 e7 5c 2c-50 e1 6b 22 ff c3 62 03   ...y..\,P.k"..b.
0050 - e9 b8 7f 67 79 3b bd b4-0d f1 83 89 2e f4 fa 99   ...gy;..........
0060 - 41 a4 1b 6f d0 ee b2 db-56 1c 5d 24 80 6f 1e 03   A..o....V.]$.o..
0070 - be 13 1d 4d 17 70 d2 27-81 72 31 34 e4 cf cf 3c   ...M.p.'.r14...<
0080 - 60 fb 07 60 18 a8 92 17-61 95 be b7 f4 e9 1f 16   `..`....a.......
0090 - 9a ae 41 2c 35 d8 71 7c-62 2a 42 17 70 eb e9 c4   ..A,5.q|b*B.p...
00a0 - ee cc 42 4c 6b 4d 3a c4-2a 5c c6 df ff 11 45 6a   ..BLkM:.*\....Ej
00b0 - b8 61 2b 84 eb 3b 37 ae-a7 ff b5 4b 5a 3b c7 83   .a+..;7....KZ;..
00c0 - 32 6a e1 76 4d c6 78 10-9b be e7 85 90 5d 80 b6   2j.vM.x......]..
00d0 - ff e7 04 77 e6 28 41 f6-69 a8 17 1d 02 8e 6d eb   ...w.(A.i.....m.
00e0 - 79 f9 34 8b bf 9c 10 2b-5d 51 6e 61 e5 2a e7 7c   y.4....+]Qna.*.|
00f0 - db d7 ea 2d e9 28 5f 0d-07 6d e1 05 8d 2e 71 f0   ...-.(_..m....q.
0100 - 7d 53 87 ba 7e 31 11 d8-38 93 83 05 f2 95 7b 58   }S..~1..8.....{X
0110 - 99 89 df 82 2c 2d 74 82-40                        ....,-t.@
SSL_connect:SSLv3/TLS read server certificate
read from 0x1b57b0afae0 [0x1b57ce4adf3] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 45                                    ....E
read from 0x1b57b0afae0 [0x1b57ce4adf8] (69 bytes => 69 (0x45))
0000 - 9b df d7 61 a6 0d 5d b2-76 7c f2 ae c5 b6 c4 ee   ...a..].v|......
0010 - 63 21 23 6a 56 0d 9e c8-c4 69 36 2a e1 1c 52 a7   c!#jV....i6*..R.
0020 - 9d e0 64 75 60 04 94 c9-6a bf 43 e0 0e 36 17 ca   ..du`...j.C..6..
0030 - a9 93 39 c9 d7 59 d2 9e-37 d1 47 b5 dd ca 40 69   ..9..Y..7.G...@i
0040 - 4a 7d 48 8b ad                                    J}H..
SSL_connect:TLSv1.3 read server certificate verify
SSL_connect:SSLv3/TLS read finished
SSL_connect:SSLv3/TLS write change cipher spec
write to 0x1b57b0afae0 [0x1b57ce45d20] (80 bytes => 80 (0x50))
0000 - 14 03 03 00 01 01 17 03-03 00 45 3e 55 2d be a4   ..........E>U-..
0010 - 88 ba 1f 12 73 73 f8 84-75 05 d9 9f d2 1a 84 aa   ....ss..u.......
0020 - b7 7c e4 3f f4 ea 4e de-fa 94 da c7 3c 66 fc 29   .|.?..N.....<f.)
0030 - 95 13 f1 23 48 a0 20 68-d5 db 44 d8 99 df 30 45   ...#H. h..D...0E
0040 - ea f9 f1 f5 ed 8e 39 5a-d6 d8 ae 3a 21 6e ac b1   ......9Z...:!n..
SSL_connect:SSLv3/TLS write finished
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
SSL handshake has read 1420 bytes and written 316 bytes
Verification error: unable to verify the first certificate
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
Server public key is 2048 bit
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 21 (unable to verify the first certificate)
---
read from 0x1b57b0afae0 [0x1b57ce3f513] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 fa                                    .....
read from 0x1b57b0afae0 [0x1b57ce3f518] (250 bytes => 250 (0xFA))
0000 - e1 f5 d3 d5 fc 93 f7 11-d4 e9 0c dc 95 00 2d 83   ..............-.
0010 - 56 34 e6 dc 11 98 7f 89-ad 9c 36 95 e0 52 f4 59   V4........6..R.Y
0020 - 4a a7 96 c9 69 63 1c b7-68 79 f6 58 86 84 91 00   J...ic..hy.X....
0030 - bb 22 e6 58 ac 03 3f 87-58 08 fa 16 ce 29 fc d4   .".X..?.X....)..
0040 - 1a 67 df 21 8e 4d b7 0f-48 86 46 66 2d fe d8 cd   .g.!.M..H.Ff-...
0050 - 13 16 f5 95 53 0d f2 f9-3b 24 0e c7 fd 5d 9e 56   ....S...;$...].V
0060 - 88 ce 8b f0 45 a1 bc 7e-18 8e f9 ab 94 8b 6e fb   ....E..~......n.
0070 - c6 4a 1d d6 3d ca 7d cb-30 30 83 4d cc 17 0d b6   .J..=.}.00.M....
0080 - 47 b1 32 4f c7 49 c8 f6-d9 b8 4f d1 83 f1 e8 d4   G.2O.I....O.....
0090 - 0d fb d0 6f 44 f5 da db-a2 05 7e 4d 5a 62 81 e8   ...oD.....~MZb..
00a0 - 38 0b ba f5 58 c4 5c b4-3a 14 0c b6 fe 34 c2 c3   8...X.\.:....4..
00b0 - 9a f2 9e ee 36 66 84 be-af fb 8d 4a 4f 1e ec f9   ....6f.....JO...
00c0 - b6 73 84 7e 51 5a d8 23-f1 a4 0c 9b ee a8 c8 32   .s.~QZ.#.......2
00d0 - 52 68 64 d5 92 2d a4 ed-b2 ed fd 2c be a4 ff 71   Rhd..-.....,...q
00e0 - 5b 8f 79 7e a0 d5 69 a1-33 65 e4 d1 ef 20 be 29   [.y~..i.3e... .)
00f0 - 1f f9 56 15 be 2a f8 12-25 9c                     ..V..*..%.
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 9A25E7C9284F877CE930D9BACCAA97B0DB4C5B49DF9932B79E86C30A1203166F
    Session-ID-ctx:
    Resumption PSK: 6288F978E9D0A5DC2DE3A66B6C3D02B0AD70B731500AD7D9E3F14DF121FE4E3EDE8200240B857C497501B678649FF62C
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - aa 8d 83 7c 67 5a 9e ba-3a 64 e2 e7 85 b8 9d 33   ...|gZ..:d.....3
    0010 - b1 93 ab 0b 32 22 aa f3-cf 3c 68 da ad 06 6e 37   ....2"...<h...n7
    0020 - 98 27 1b c1 b3 20 9f a8-82 74 7b 42 be 86 f3 60   .'... ...t{B...`
    0030 - 94 7e 03 b5 86 40 7d 4e-d7 8a cf 2f 74 9e 19 90   .~...@}N.../t...
    0040 - 37 b2 e1 68 0e 4d 5d 24-bc 0c 31 f1 b1 cb c3 dd   7..h.M]$..1.....
    0050 - 26 ca 2f ad e5 b7 7c d6-94 97 92 f1 66 58 ab 52   &./...|.....fX.R
    0060 - 8d 3e a6 29 61 4f 98 08-0e 14 4d f8 12 09 fd 8d   .>.)aO....M.....
    0070 - fc 33 1a 29 d3 c7 94 92-59 40 63 e3 68 b6 40 96   .3.)....Y@c.h.@.
    0080 - 7d 8c 7c d2 59 c2 09 b9-d9 41 78 5b f7 7d 53 b7   }.|.Y....Ax[.}S.
    0090 - ba 9e 80 c7 85 36 e5 58-02 9e b5 66 c0 0d c4 42   .....6.X...f...B
    00a0 - 89 1e 78 59 51 df 0e c6-c9 e6 a1 db 37 77 e4 4a   ..xYQ.......7w.J
    00b0 - b0 e0 6c 0c 27 30 17 66-7d 2f 55 e4 e4 b4 3d b2   ..l.'0.f}/U...=.
    00c0 - 6b 28 78 d4 1f 4a 21 5a-43 aa 14 02 32 33 8a 23   k(x..J!ZC...23.#

    Start Time: 1744902754
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
read from 0x1b57b0afae0 [0x1b57ce3f513] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 fa                                    .....
read from 0x1b57b0afae0 [0x1b57ce3f518] (250 bytes => 250 (0xFA))
0000 - 73 0c 72 9b 71 6d b8 a1-02 19 32 1d bf fa 05 89   s.r.qm....2.....
0010 - 82 b6 bb 0c c5 fd 9c 00-14 20 5c 2c e7 2a cb d5   ......... \,.*..
0020 - f9 a5 b2 e7 68 d5 76 e3-ca 0c 71 ca 7e 83 1c 1f   ....h.v...q.~...
0030 - fa 62 da b8 fb e7 58 9f-2a 81 92 d9 73 82 a5 9d   .b....X.*...s...
0040 - dc 21 4b 1e c0 27 52 63-03 b3 83 15 bc 2b c8 08   .!K..'Rc.....+..
0050 - 8a 94 09 95 f2 49 ba 60-92 eb 3d 8a a9 eb eb b8   .....I.`..=.....
0060 - eb 42 08 e0 32 17 c3 ad-63 5c 2b fa e5 68 47 32   .B..2...c\+..hG2
0070 - 19 a5 d3 15 26 2b 1c d2-48 b3 7b f4 a5 c2 2c 3e   ....&+..H.{...,>
0080 - 61 0e b3 c1 81 c7 5e 87-5c 6b da 14 65 9e 3d 1f   a.....^.\k..e.=.
0090 - c1 f7 56 9b 08 f2 af cc-f6 d8 c6 7f 94 c8 f1 5a   ..V............Z
00a0 - 1b 6a 1e 57 0e 07 f2 2c-dc 78 88 76 7b e7 95 6c   .j.W...,.x.v{..l
00b0 - 00 9d 76 5e 4e 62 9c e7-45 31 66 cf 84 eb bc 77   ..v^Nb..E1f....w
00c0 - a5 4d 31 61 91 49 c1 a5-70 a7 c4 99 1d 1e 05 9e   .M1a.I..p.......
00d0 - 96 e2 e4 7d d6 f6 4b 56-ac 24 87 9c 33 22 62 08   ...}..KV.$..3"b.
00e0 - 1c ac d6 34 85 0e 08 81-ea 48 1b cd 41 31 35 a4   ...4.....H..A15.
00f0 - 28 34 c8 d9 43 06 9c c9-e3 1c                     (4..C.....
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 252E29EDADCD6E242F276D802092D61CEC857E7DFF3579276208A5D969806ED0
    Session-ID-ctx:
    Resumption PSK: 313BC19423A03770899FCAB3ABAD36F32CA654B7584D15185203A5BEC2A596CF9D6F94A8B6C7954CCFE28B0B4879DC9C
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - aa 8d 83 7c 67 5a 9e ba-3a 64 e2 e7 85 b8 9d 33   ...|gZ..:d.....3
    0010 - 1a 7c 20 23 b3 01 f3 e6-0b d3 fa 31 94 ae 27 6f   .| #.......1..'o
    0020 - 67 a0 03 cc d6 d4 dd b9-5a e6 54 f1 d0 62 72 89   g.......Z.T..br.
    0030 - 7e be 5a e6 78 51 e2 58-00 1e 01 1e 1d 29 8c de   ~.Z.xQ.X.....)..
    0040 - 7b ce 6d 30 b0 20 b7 c0-36 4b 1a 41 87 de 36 41   {.m0. ..6K.A..6A
    0050 - 64 ed 07 9f aa f7 d2 f6-1a 27 cc a4 09 a4 4d e3   d........'....M.
    0060 - 2f 42 e3 b6 9b 89 8d 06-2f ed 4e 71 54 30 b7 a9   /B....../.NqT0..
    0070 - 92 7f a3 6c 18 9d be f7-a7 3b ad 93 76 fb 06 b0   ...l.....;..v...
    0080 - db 33 c0 be 26 b8 8b 0f-df 9f cf b4 de b6 3f 39   .3..&.........?9
    0090 - cd cd c9 46 80 a9 a6 35-2f cd e4 3b 2f 3a cb 85   ...F...5/..;/:..
    00a0 - 81 38 42 fc cb 3a 9f 02-5b 1f 68 2a 04 8c b3 73   .8B..:..[.h*...s
    00b0 - 0e bf 22 2d 35 75 9e c9-cb 81 e4 ef 85 b2 20 a5   .."-5u........ .
    00c0 - ae 0f 26 56 dc fe 42 6f-20 7d 07 fd 88 a2 5e 5b   ..&V..Bo }....^[

    Start Time: 1744902754
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
hello
write to 0x1b57b0afae0 [0x1b57ce43663] (29 bytes => 29 (0x1D))
0000 - 17 03 03 00 18 f1 40 f0-3b 33 67 09 18 be 0a 57   ......@.;3g....W
0010 - fc 94 64 08 ae b5 4f 02-20 fe 01 46 ec            ..d...O. ..F.
Q
DONE
write to 0x1b57b0afae0 [0x1b57ce43663] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 a0 d4 71-0a 7a 11 44 63 97 ff 63   .......q.z.Dc..c
0010 - 2c 0c b5 b1 23 cb a9 01-                          ,...#...
SSL3 alert write:warning:close notify
read from 0x1b57b0afae0 [0x1b57aff7cf0] (16384 bytes => 24 (0x18))
0000 - 17 03 03 00 13 6e ca 59-6f 00 37 ca bd 87 17 10   .....n.Yo.7.....
0010 - 1a ab 9c d9 1c 38 23 9d-                          .....8#.
read from 0x1b57b0afae0 [0x1b57aff7cf0] (16384 bytes => 0)
````

[TOC](README.md)
