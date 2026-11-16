#### client

````
$ openssl s_client -connect localhost:9000 -state -debug -trace -keylogfile sslkeylog -tls1_3
Connecting to ::1
CONNECTED(00000214)
SSL_connect:before SSL initialization
Sent TLS Record
Header:
  Version = TLS 1.0 (0x301)
  Content Type = Handshake (22)
  Length = 1451
    ClientHello, Length=1447
      client_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0x1EF0C3F2
        random_bytes (len=28): 64995610803EB0A1D140D70A8052E950CC9B0C5A716318AF6BD2EF88
      session_id (len=32): C9679CB307C2D35BFF3415FAD3131C4C6EE186CC2BF7C98796FCEF4E5D7C5C2F
      cipher_suites (len=6)
        {0x13, 0x02} TLS_AES_256_GCM_SHA384
        {0x13, 0x03} TLS_CHACHA20_POLY1305_SHA256
        {0x13, 0x01} TLS_AES_128_GCM_SHA256
      compression_methods (len=1)
        No Compression (0x00)
      extensions, length = 1368
        extension_type=ec_point_formats(11), length=2
          uncompressed (0)
        extension_type=supported_groups(10), length=18
          X25519MLKEM768 (4588)
          ecdh_x25519 (29)
          secp256r1 (P-256) (23)
          ecdh_x448 (30)
          secp384r1 (P-384) (24)
          secp521r1 (P-521) (25)
          ffdhe2048 (256)
          ffdhe3072 (257)
        extension_type=session_ticket(35), length=0
        extension_type=encrypt_then_mac(22), length=0
        extension_type=extended_master_secret(23), length=0
        extension_type=signature_algorithms(13), length=42
          mldsa65 (0x0905)
          mldsa87 (0x0906)
          mldsa44 (0x0904)
          ecdsa_secp256r1_sha256 (0x0403)
          ecdsa_secp384r1_sha384 (0x0503)
          ecdsa_secp521r1_sha512 (0x0603)
          ed25519 (0x0807)
          ed448 (0x0808)
          ecdsa_brainpoolP256r1tls13_sha256 (0x081a)
          ecdsa_brainpoolP384r1tls13_sha384 (0x081b)
          ecdsa_brainpoolP512r1tls13_sha512 (0x081c)
          rsa_pss_pss_sha256 (0x0809)
          rsa_pss_pss_sha384 (0x080a)
          rsa_pss_pss_sha512 (0x080b)
          rsa_pss_rsae_sha256 (0x0804)
          rsa_pss_rsae_sha384 (0x0805)
          rsa_pss_rsae_sha512 (0x0806)
          rsa_pkcs1_sha256 (0x0401)
          rsa_pkcs1_sha384 (0x0501)
          rsa_pkcs1_sha512 (0x0601)
        extension_type=supported_versions(43), length=3
          TLS 1.3 (772)
        extension_type=psk_key_exchange_modes(45), length=2
          psk_dhe_ke (1)
        extension_type=key_share(51), length=1258
            NamedGroup: X25519MLKEM768 (4588)
            key_exchange:  (len=1216): 9262C13473325E47CCCC36482DD229DCB22A794C4391BACABEA61EE335BF4C1B20E09B8E6D00CD17C5C297ECBE4706295AA4509B58852544CC972037517142FF5143C660AD329565570794AF4A6A5A98B3F27A83B2E45BBE369457D3A811393D1E2071D7B18DE10BBEF3F664E478A9DAF5243200097788655405A0A39526464C7A97513DC51CC304D1C9F6D6888433649A6C22A9266E1FABA635782E8BC70F09923B7B38B8E219B02C343D0BE9243C6B1C41F85CFB0986C1265816C200023CC5E025781BBB687AE2446D3941E1FC0DF6813DD55050E2BA97B3F6B3C0A92D3F0C4DFF2948705231B62A75562117F0996D17C01723494171353B50D053C9939DC579B250382DF64C6896A5A09EBB2D99685575FC35968694D9F0696FD0CB3B6BA0BDAC871E9298DEAC7467C04276B85E2903746149350487684C37A767B36A8ECB2BB556CD7F92BF1BAACA91686F3AC261D7A68393157B1A7CC34C2B06A7C23A6C1AA801007F6C5028C4E274882A478A362FEA717E8B2A74899C3E8CB308368BCD80B206A9FC138E78B3B010A0ECC97C98BA4BBAC4CE08A7852A90A575D83015E4A2AF04AF137C2D6352245F05ABB5235244FB68F6442FB627C7924A5EF27A92A716C177CBC7568BBCBB93496E37816E56088318357D54AD48B2345A291699303F504A4880E65D9F9538885BBA13278362A11CAB391170F376A4B39440201C7F91C65CC712CD17649BC344D9C60E142BC111410A946B7D1CB456BDB36790068D12E614267B806DC47A8C6A897E70912EB7C297E885B6070E871B2630129E872743F48304160C66493919E9325E06900736B184A1780BC689520EF63E14F28068F367AF2BA5B8759C02F33537279B8774126FB14FBC55724FE772E7A9A193435F1EA897B973BF488C595BE354F32B4EDE6289A2991D1195C42224C7A5F72B168852223997F77792C3C1653B5C7C3BCC7194C1682D7974766CA0F145A0065C9314BB6EF558980CA97FC5F67DE63103B576B370E11144CB5BE53B8DEE01A6487B6CD278A443C1BC5BDA469768184D772FC3168F75D96BA5FC2BAFE10C1DC0507167C072906F3156B87D846CCB11B5F3DBCC56F6BA6D1238A52C4134119E3F94BF8DE827AED530FD2366291238C0E3B245135FAAC40F4C2B2254DC2700EC9536AB23CF89CEA7A28A7E10CC78914E30D9391DD96CA59004CBA7A20BD99803199FE547C7B9551DF8D80DC0B08AF61A946E682C4F5753FBF2603D88C51F826839A5151420BDD40063618A70C38C207C20B798E33754E9807514AE141B3391A0C12895C989905ECBEC74095615D9C996370CBD4A2ACE61B4A3C9246DFE7B6AD869B96005462ED8CFFE481EA2A8C13B7101135496522A27F6C61162DB7C7E7C245B00AC0ED7B689FC4007067196D0B98A60210C12A39157AA6830C6BFF093E3B850701CB1FAD2CC5EBBC69FBBA5AA14091130B8A42CA29D742234B8A67AC42B34005D82900344F9ACD75595E4BCC85073B9C1384F81A6BBA3A79DE8C638B87A800D9A7FAAD596CE017390C10EC638AD9CE717870A344CC06149C63078473DC3E27B5CE2277817C1DCA0A008052015C338CF1CBA5765B7E9170A827A3494076FD3319535B964EC59D6844DD94B09522B4BC2D91D20544216F95CB74613DF2487BBF6CB8AB31612593799F509E24228FF6C8118FAD2DDFE0F4D424111130DB8F591B685DD797A
            NamedGroup: ecdh_x25519 (29)
            key_exchange:  (len=32): 847E2FABDEED01A51650D2D12C28096A8A5BAE5BB1AE73A034941333AB7DDF77
        extension_type=compress_certificate(27), length=3
          zlib (1)

write to 0x214124ee7a0 [0x2141250bd70] (1456 bytes => 1456 (0x5B0))
0000 - 16 03 01 05 ab 01 00 05-a7 03 03 1e f0 c3 f2 64   ...............d
0010 - 99 56 10 80 3e b0 a1 d1-40 d7 0a 80 52 e9 50 cc   .V..>...@...R.P.
0020 - 9b 0c 5a 71 63 18 af 6b-d2 ef 88 20 c9 67 9c b3   ..Zqc..k... .g..
0030 - 07 c2 d3 5b ff 34 15 fa-d3 13 1c 4c 6e e1 86 cc   ...[.4.....Ln...
0040 - 2b f7 c9 87 96 fc ef 4e-5d 7c 5c 2f 00 06 13 02   +......N]|\/....
0050 - 13 03 13 01 01 00 05 58-00 0b 00 02 01 00 00 0a   .......X........
0060 - 00 12 00 10 11 ec 00 1d-00 17 00 1e 00 18 00 19   ................
0070 - 01 00 01 01 00 23 00 00-00 16 00 00 00 17 00 00   .....#..........
0080 - 00 0d 00 2a 00 28 09 05-09 06 09 04 04 03 05 03   ...*.(..........
0090 - 06 03 08 07 08 08 08 1a-08 1b 08 1c 08 09 08 0a   ................
00a0 - 08 0b 08 04 08 05 08 06-04 01 05 01 06 01 00 2b   ...............+
00b0 - 00 03 02 03 04 00 2d 00-02 01 01 00 33 04 ea 04   ......-.....3...
00c0 - e8 11 ec 04 c0 92 62 c1-34 73 32 5e 47 cc cc 36   ......b.4s2^G..6
00d0 - 48 2d d2 29 dc b2 2a 79-4c 43 91 ba ca be a6 1e   H-.)..*yLC......
00e0 - e3 35 bf 4c 1b 20 e0 9b-8e 6d 00 cd 17 c5 c2 97   .5.L. ...m......
00f0 - ec be 47 06 29 5a a4 50-9b 58 85 25 44 cc 97 20   ..G.)Z.P.X.%D..
0100 - 37 51 71 42 ff 51 43 c6-60 ad 32 95 65 57 07 94   7QqB.QC.`.2.eW..
0110 - af 4a 6a 5a 98 b3 f2 7a-83 b2 e4 5b be 36 94 57   .JjZ...z...[.6.W
0120 - d3 a8 11 39 3d 1e 20 71-d7 b1 8d e1 0b be f3 f6   ...9=. q........
0130 - 64 e4 78 a9 da f5 24 32-00 09 77 88 65 54 05 a0   d.x...$2..w.eT..
0140 - a3 95 26 46 4c 7a 97 51-3d c5 1c c3 04 d1 c9 f6   ..&FLz.Q=.......
0150 - d6 88 84 33 64 9a 6c 22-a9 26 6e 1f ab a6 35 78   ...3d.l".&n...5x
0160 - 2e 8b c7 0f 09 92 3b 7b-38 b8 e2 19 b0 2c 34 3d   ......;{8....,4=
0170 - 0b e9 24 3c 6b 1c 41 f8-5c fb 09 86 c1 26 58 16   ..$<k.A.\....&X.
0180 - c2 00 02 3c c5 e0 25 78-1b bb 68 7a e2 44 6d 39   ...<..%x..hz.Dm9
0190 - 41 e1 fc 0d f6 81 3d d5-50 50 e2 ba 97 b3 f6 b3   A.....=.PP......
01a0 - c0 a9 2d 3f 0c 4d ff 29-48 70 52 31 b6 2a 75 56   ..-?.M.)HpR1.*uV
01b0 - 21 17 f0 99 6d 17 c0 17-23 49 41 71 35 3b 50 d0   !...m...#IAq5;P.
01c0 - 53 c9 93 9d c5 79 b2 50-38 2d f6 4c 68 96 a5 a0   S....y.P8-.Lh...
01d0 - 9e bb 2d 99 68 55 75 fc-35 96 86 94 d9 f0 69 6f   ..-.hUu.5.....io
01e0 - d0 cb 3b 6b a0 bd ac 87-1e 92 98 de ac 74 67 c0   ..;k.........tg.
01f0 - 42 76 b8 5e 29 03 74 61-49 35 04 87 68 4c 37 a7   Bv.^).taI5..hL7.
0200 - 67 b3 6a 8e cb 2b b5 56-cd 7f 92 bf 1b aa ca 91   g.j..+.V........
0210 - 68 6f 3a c2 61 d7 a6 83-93 15 7b 1a 7c c3 4c 2b   ho:.a.....{.|.L+
0220 - 06 a7 c2 3a 6c 1a a8 01-00 7f 6c 50 28 c4 e2 74   ...:l.....lP(..t
0230 - 88 2a 47 8a 36 2f ea 71-7e 8b 2a 74 89 9c 3e 8c   .*G.6/.q~.*t..>.
0240 - b3 08 36 8b cd 80 b2 06-a9 fc 13 8e 78 b3 b0 10   ..6.........x...
0250 - a0 ec c9 7c 98 ba 4b ba-c4 ce 08 a7 85 2a 90 a5   ...|..K......*..
0260 - 75 d8 30 15 e4 a2 af 04-af 13 7c 2d 63 52 24 5f   u.0.......|-cR$_
0270 - 05 ab b5 23 52 44 fb 68-f6 44 2f b6 27 c7 92 4a   ...#RD.h.D/.'..J
0280 - 5e f2 7a 92 a7 16 c1 77-cb c7 56 8b bc bb 93 49   ^.z....w..V....I
0290 - 6e 37 81 6e 56 08 83 18-35 7d 54 ad 48 b2 34 5a   n7.nV...5}T.H.4Z
02a0 - 29 16 99 30 3f 50 4a 48-80 e6 5d 9f 95 38 88 5b   )..0?PJH..]..8.[
02b0 - ba 13 27 83 62 a1 1c ab-39 11 70 f3 76 a4 b3 94   ..'.b...9.p.v...
02c0 - 40 20 1c 7f 91 c6 5c c7-12 cd 17 64 9b c3 44 d9   @ ....\....d..D.
02d0 - c6 0e 14 2b c1 11 41 0a-94 6b 7d 1c b4 56 bd b3   ...+..A..k}..V..
02e0 - 67 90 06 8d 12 e6 14 26-7b 80 6d c4 7a 8c 6a 89   g......&{.m.z.j.
02f0 - 7e 70 91 2e b7 c2 97 e8-85 b6 07 0e 87 1b 26 30   ~p............&0
0300 - 12 9e 87 27 43 f4 83 04-16 0c 66 49 39 19 e9 32   ...'C.....fI9..2
0310 - 5e 06 90 07 36 b1 84 a1-78 0b c6 89 52 0e f6 3e   ^...6...x...R..>
0320 - 14 f2 80 68 f3 67 af 2b-a5 b8 75 9c 02 f3 35 37   ...h.g.+..u...57
0330 - 27 9b 87 74 12 6f b1 4f-bc 55 72 4f e7 72 e7 a9   '..t.o.O.UrO.r..
0340 - a1 93 43 5f 1e a8 97 b9-73 bf 48 8c 59 5b e3 54   ..C_....s.H.Y[.T
0350 - f3 2b 4e de 62 89 a2 99-1d 11 95 c4 22 24 c7 a5   .+N.b......."$..
0360 - f7 2b 16 88 52 22 39 97-f7 77 92 c3 c1 65 3b 5c   .+..R"9..w...e;\
0370 - 7c 3b cc 71 94 c1 68 2d-79 74 76 6c a0 f1 45 a0   |;.q..h-ytvl..E.
0380 - 06 5c 93 14 bb 6e f5 58-98 0c a9 7f c5 f6 7d e6   .\...n.X......}.
0390 - 31 03 b5 76 b3 70 e1 11-44 cb 5b e5 3b 8d ee 01   1..v.p..D.[.;...
03a0 - a6 48 7b 6c d2 78 a4 43-c1 bc 5b da 46 97 68 18   .H{l.x.C..[.F.h.
03b0 - 4d 77 2f c3 16 8f 75 d9-6b a5 fc 2b af e1 0c 1d   Mw/...u.k..+....
03c0 - c0 50 71 67 c0 72 90 6f-31 56 b8 7d 84 6c cb 11   .Pqg.r.o1V.}.l..
03d0 - b5 f3 db cc 56 f6 ba 6d-12 38 a5 2c 41 34 11 9e   ....V..m.8.,A4..
03e0 - 3f 94 bf 8d e8 27 ae d5-30 fd 23 66 29 12 38 c0   ?....'..0.#f).8.
03f0 - e3 b2 45 13 5f aa c4 0f-4c 2b 22 54 dc 27 00 ec   ..E._...L+"T.'..
0400 - 95 36 ab 23 cf 89 ce a7-a2 8a 7e 10 cc 78 91 4e   .6.#......~..x.N
0410 - 30 d9 39 1d d9 6c a5 90-04 cb a7 a2 0b d9 98 03   0.9..l..........
0420 - 19 9f e5 47 c7 b9 55 1d-f8 d8 0d c0 b0 8a f6 1a   ...G..U.........
0430 - 94 6e 68 2c 4f 57 53 fb-f2 60 3d 88 c5 1f 82 68   .nh,OWS..`=....h
0440 - 39 a5 15 14 20 bd d4 00-63 61 8a 70 c3 8c 20 7c   9... ...ca.p.. |
0450 - 20 b7 98 e3 37 54 e9 80-75 14 ae 14 1b 33 91 a0    ...7T..u....3..
0460 - c1 28 95 c9 89 90 5e cb-ec 74 09 56 15 d9 c9 96   .(....^..t.V....
0470 - 37 0c bd 4a 2a ce 61 b4-a3 c9 24 6d fe 7b 6a d8   7..J*.a...$m.{j.
0480 - 69 b9 60 05 46 2e d8 cf-fe 48 1e a2 a8 c1 3b 71   i.`.F....H....;q
0490 - 01 13 54 96 52 2a 27 f6-c6 11 62 db 7c 7e 7c 24   ..T.R*'...b.|~|$
04a0 - 5b 00 ac 0e d7 b6 89 fc-40 07 06 71 96 d0 b9 8a   [.......@..q....
04b0 - 60 21 0c 12 a3 91 57 aa-68 30 c6 bf f0 93 e3 b8   `!....W.h0......
04c0 - 50 70 1c b1 fa d2 cc 5e-bb c6 9f bb a5 aa 14 09   Pp.....^........
04d0 - 11 30 b8 a4 2c a2 9d 74-22 34 b8 a6 7a c4 2b 34   .0..,..t"4..z.+4
04e0 - 00 5d 82 90 03 44 f9 ac-d7 55 95 e4 bc c8 50 73   .]...D...U....Ps
04f0 - b9 c1 38 4f 81 a6 bb a3-a7 9d e8 c6 38 b8 7a 80   ..8O........8.z.
0500 - 0d 9a 7f aa d5 96 ce 01-73 90 c1 0e c6 38 ad 9c   ........s....8..
0510 - e7 17 87 0a 34 4c c0 61-49 c6 30 78 47 3d c3 e2   ....4L.aI.0xG=..
0520 - 7b 5c e2 27 78 17 c1 dc-a0 a0 08 05 20 15 c3 38   {\.'x....... ..8
0530 - cf 1c ba 57 65 b7 e9 17-0a 82 7a 34 94 07 6f d3   ...We.....z4..o.
0540 - 31 95 35 b9 64 ec 59 d6-84 4d d9 4b 09 52 2b 4b   1.5.d.Y..M.K.R+K
0550 - c2 d9 1d 20 54 42 16 f9-5c b7 46 13 df 24 87 bb   ... TB..\.F..$..
0560 - f6 cb 8a b3 16 12 59 37-99 f5 09 e2 42 28 ff 6c   ......Y7....B(.l
0570 - 81 18 fa d2 dd fe 0f 4d-42 41 11 13 0d b8 f5 91   .......MBA......
0580 - b6 85 dd 79 7a 00 1d 00-20 84 7e 2f ab de ed 01   ...yz... .~/....
0590 - a5 16 50 d2 d1 2c 28 09-6a 8a 5b ae 5b b1 ae 73   ..P..,(.j.[.[..s
05a0 - a0 34 94 13 33 ab 7d df-77 00 1b 00 03 02 00 01   .4..3.}.w.......
SSL_connect:SSLv3/TLS write client hello
read from 0x214124ee7a0 [0x21412512653] (5 bytes => 5 (0x5))
0000 - 16 03 03 04 ba                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 1210
read from 0x214124ee7a0 [0x21412512658] (1210 bytes => 1210 (0x4BA))
0000 - 02 00 04 b6 03 03 6a 4c-a7 d2 76 c3 08 cd 77 41   ......jL..v...wA
0010 - 13 57 44 31 92 7b 59 fa-1e c7 cc 70 a9 4a bb aa   .WD1.{Y....p.J..
0020 - ed 7b 53 7a d3 c9 20 c9-67 9c b3 07 c2 d3 5b ff   .{Sz.. .g.....[.
0030 - 34 15 fa d3 13 1c 4c 6e-e1 86 cc 2b f7 c9 87 96   4.....Ln...+....
0040 - fc ef 4e 5d 7c 5c 2f 13-02 00 04 6e 00 2b 00 02   ..N]|\/....n.+..
0050 - 03 04 00 33 04 64 11 ec-04 60 3a 55 ed 7d c0 9c   ...3.d...`:U.}..
0060 - eb 11 b5 a5 4e a9 9f 77-52 f1 d2 54 3d 69 df 76   ....N..wR..T=i.v
0070 - e4 9d 96 c5 52 b2 80 b5-9a a6 88 fd 25 69 f9 aa   ....R.......%i..
0080 - 4c e0 57 30 7b 96 fe 4b-bd af 42 79 28 ee d0 31   L.W0{..K..By(..1
0090 - a7 5b dd 51 60 61 d3 f6-01 fa 7c 0c 3a b6 90 27   .[.Q`a....|.:..'
00a0 - bb 9a d1 bb 73 85 f7 8c-59 a7 72 b5 e8 38 e6 46   ....s...Y.r..8.F
00b0 - 0a c1 4e b1 90 f6 75 01-d3 67 ad 62 50 50 f1 7c   ..N...u..g.bPP.|
00c0 - be 29 9e 9e 9d 8b 53 a4-d3 3a 58 e6 db 16 93 29   .)....S..:X....)
00d0 - 8a 0a e4 53 c4 66 f5 4b-30 25 d2 b8 4c c9 83 a7   ...S.f.K0%..L...
00e0 - 13 26 eb 5f ca cd 98 cf-e1 98 4c ef db aa 63 5f   .&._......L...c_
00f0 - fe bd 82 5d 6e 82 cb 49-a0 36 4c bb 1b e2 de 9d   ...]n..I.6L.....
0100 - 86 c3 96 db 2b 9b fe ae-44 16 d0 a3 76 48 90 4a   ....+...D...vH.J
0110 - 54 f1 0b 8c 29 37 51 b8-3c 9a c8 11 a9 67 ac 02   T...)7Q.<....g..
0120 - 94 c2 d7 cd 63 23 9f 99-b9 b7 c4 ab b4 d0 53 d8   ....c#........S.
0130 - e9 73 9b e1 ad 14 e0 f3-28 7c 57 ab be e4 f5 43   .s......(|W....C
0140 - d7 0b 47 ce 67 d5 53 fc-b3 4b ad 05 8e c2 67 4f   ..G.g.S..K....gO
0150 - 1a d2 26 c0 02 70 b8 0c-3d b5 5d 0b a1 a7 dd a2   ..&..p..=.].....
0160 - 67 09 9f 8b 7a 29 cb bf-e1 81 3c 2b b9 87 36 f9   g...z)....<+..6.
0170 - 7e 34 46 3a 3b c6 71 5a-c8 2b 85 87 5d a8 a7 2d   ~4F:;.qZ.+..]..-
0180 - 30 0f 6f 97 f3 a6 7b ab-a7 6c c5 d2 e5 dd b2 c2   0.o...{..l......
0190 - 44 70 a4 0b 75 9f c8 fe-bc 27 d8 60 97 10 9e 36   Dp..u....'.`...6
01a0 - d6 c2 2c d8 0f ec 48 e6-b3 c7 52 69 cf 22 8a cd   ..,...H...Ri."..
01b0 - 6c fb 8e 41 ca 11 e8 66-0e e8 38 17 81 cd 7a f2   l..A...f..8...z.
01c0 - 74 a9 48 0b f1 03 b6 00-ec 0a cd c9 e8 25 e6 06   t.H..........%..
01d0 - db c5 61 68 67 35 11 fa-b8 2f 81 42 69 61 4c 27   ..ahg5.../.BiaL'
01e0 - 5c 23 ad 42 c9 f7 ac 4e-a9 0d 27 75 87 c6 0c bd   \#.B...N..'u....
01f0 - 5c 03 ef 2b 71 66 53 68-4c 47 bf cf b5 c9 23 2c   \..+qfShLG....#,
0200 - 13 bf 13 34 e9 3e 4e b4-de 84 29 d3 b9 59 fa 82   ...4.>N...)..Y..
0210 - 37 01 4d 00 a6 88 ad 56-9d 8d 9b 19 7d 78 2b 01   7.M....V....}x+.
0220 - e3 d8 bb 13 30 65 e4 b8-9d d0 57 6f 92 10 e0 88   ....0e....Wo....
0230 - 29 01 fb a6 a9 5f 79 0d-f8 a9 e5 7a 5e e8 a5 3a   )...._y....z^..:
0240 - 7a f0 37 26 91 41 9d 5e-ad c6 e5 4a 4e 36 3e 13   z.7&.A.^...JN6>.
0250 - 65 67 fb c4 74 9b 62 ce-9b aa 42 b8 a1 5a b8 90   eg..t.b...B..Z..
0260 - 09 f8 57 20 60 2f 3e 57-fd 87 99 b5 00 cb c2 0c   ..W `/>W........
0270 - 2c 1f 59 3f 36 f0 3b 57-67 9c 57 ba 65 0c c9 03   ,.Y?6.;Wg.W.e...
0280 - df c7 39 8f 38 c1 40 12-35 e5 b0 30 fc 20 98 5b   ..9.8.@.5..0. .[
0290 - 3a d9 d7 b7 f1 72 17 86-ae b7 d3 ae 3e 63 fc 9a   :....r......>c..
02a0 - ac ba c6 00 a4 a1 a0 ab-89 a9 71 4d fa 2f 3a 71   ..........qM./:q
02b0 - 6f 37 ec 49 1a ee 91 c2-52 b5 bc 94 5c fd 4d 69   o7.I....R...\.Mi
02c0 - 92 94 8b 15 ea b3 aa 1f-90 08 78 d1 30 f7 cc ff   ..........x.0...
02d0 - 42 ec 6b 12 ba c3 bc fa-ce 50 14 d5 7f da d2 58   B.k......P.....X
02e0 - ea 8e 60 69 96 01 a4 79-a8 b1 08 7e c1 1c 58 d7   ..`i...y...~..X.
02f0 - 55 e5 52 44 33 dc c3 97-1a 6e df fd 2d c8 79 5f   U.RD3....n..-.y_
0300 - 78 8e 29 de 9e 36 b9 77-08 a8 be 25 57 44 97 63   x.)..6.w...%WD.c
0310 - 5b 99 2c 17 fa 4b d0 75-bc 7f 77 1a 68 4c 67 86   [.,..K.u..w.hLg.
0320 - 17 19 6c 01 5b 94 f5 e4-23 7f 1c 68 06 27 ec 83   ..l.[...#..h.'..
0330 - f9 80 ac 8f d9 5b ff 3f-dd 40 fa 30 35 8d 16 73   .....[.?.@.05..s
0340 - 86 0a 33 22 ca 8c 93 f7-dd 50 ae 1f 47 9a 07 21   ..3".....P..G..!
0350 - cb ce 39 8d f4 77 4b 8d-0a 7d a7 68 ad 48 de c8   ..9..wK..}.h.H..
0360 - a0 93 53 c1 56 1c bf e8-d8 39 4b 5c b5 8b c9 bb   ..S.V....9K\....
0370 - 1f f7 c3 58 72 5b db 6b-47 1c 08 16 62 04 c9 f5   ...Xr[.kG...b...
0380 - 50 f4 a6 d1 36 67 d9 9c-01 17 45 84 19 83 21 25   P...6g....E...!%
0390 - fa b7 f1 32 06 15 2e 25-07 38 c3 5d 4c 01 35 c5   ...2...%.8.]L.5.
03a0 - 8d e1 83 53 73 51 b1 e0-05 1b 1f 2a 9c b4 c3 47   ...SsQ.....*...G
03b0 - 4c a3 2a d9 84 65 34 8a-d6 d6 e2 59 4c e1 e8 cb   L.*..e4....YL...
03c0 - 98 35 14 5f c4 af fa 12-c6 6f f3 32 66 23 0f 10   .5._.....o.2f#..
03d0 - f6 b8 93 5f a2 fc b5 d3-68 89 68 20 b0 15 b0 f0   ..._....h.h ....
03e0 - 49 95 db ab 1d a4 13 c2-76 bb c0 33 e7 eb fa bf   I.......v..3....
03f0 - c6 a1 b6 10 47 7f 10 b2-7e 2f 5e 45 cc fe ff d9   ....G...~/^E....
0400 - dc e5 d9 31 06 0b 7f 93-9f 12 03 f8 a9 65 0b 58   ...1.........e.X
0410 - 90 6c e8 4e b4 65 29 e9-ea de 85 37 fc 35 68 89   .l.N.e)....7.5h.
0420 - e3 9a 10 f9 5d cb 37 e3-46 c2 d9 28 c3 9e 88 4f   ....].7.F..(...O
0430 - 0a 1d 05 63 e5 a8 53 d1-3c c1 72 4d df 1c 64 18   ...c..S.<.rM..d.
0440 - c1 cf 5a c7 42 76 23 52-c2 26 9d d6 9a ed 0d c0   ..Z.Bv#R.&......
0450 - ef 4e 1b ba 91 16 1c 11-c1 84 de e6 c7 16 8f bb   .N..............
0460 - 46 32 b0 a0 62 95 d8 40-d1 4f 35 20 c9 48 fe e0   F2..b..@.O5 .H..
0470 - 8b e2 16 d2 0c 31 07 4a-72 5f ce eb 4f a8 6c e0   .....1.Jr_..O.l.
0480 - 4a 1c 01 84 d6 6d d4 32-10 a3 9b ec e1 8d a7 8a   J....m.2........
0490 - ae b3 d6 30 2e 63 6b 3c-4f ee d0 db a7 77 f4 5a   ...0.ck<O....w.Z
04a0 - 7d e5 6e 52 86 11 d0 82-13 de 9e fd 2a 46 b6 4b   }.nR........*F.K
04b0 - 97 cc d6 e6 42 e3 43 3c-12 3e                     ....B.C<.>
SSL_connect:SSLv3/TLS write client hello
    ServerHello, Length=1206
      server_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0x6A4CA7D2
        random_bytes (len=28): 76C308CD774113574431927B59FA1EC7CC70A94ABBAAED7B537AD3C9
      session_id (len=32): C9679CB307C2D35BFF3415FAD3131C4C6EE186CC2BF7C98796FCEF4E5D7C5C2F
      cipher_suite {0x13, 0x02} TLS_AES_256_GCM_SHA384
      compression_method: No Compression (0x00)
      extensions, length = 1134
        extension_type=supported_versions(43), length=2
            TLS 1.3 (772)
        extension_type=key_share(51), length=1124
            NamedGroup: X25519MLKEM768 (4588)
            key_exchange:  (len=1120): 3A55ED7DC09CEB11B5A54EA99F7752F1D2543D69DF76E49D96C552B280B59AA688FD2569F9AA4CE057307B96FE4BBDAF427928EED031A75BDD516061D3F601FA7C0C3AB69027BB9AD1BB7385F78C59A772B5E838E6460AC14EB190F67501D367AD625050F17CBE299E9E9D8B53A4D33A58E6DB1693298A0AE453C466F54B3025D2B84CC983A71326EB5FCACD98CFE1984CEFDBAA635FFEBD825D6E82CB49A0364CBB1BE2DE9D86C396DB2B9BFEAE4416D0A37648904A54F10B8C293751B83C9AC811A967AC0294C2D7CD63239F99B9B7C4ABB4D053D8E9739BE1AD14E0F3287C57ABBEE4F543D70B47CE67D553FCB34BAD058EC2674F1AD226C00270B80C3DB55D0BA1A7DDA267099F8B7A29CBBFE1813C2BB98736F97E34463A3BC6715AC82B85875DA8A72D300F6F97F3A67BABA76CC5D2E5DDB2C24470A40B759FC8FEBC27D86097109E36D6C22CD80FEC48E6B3C75269CF228ACD6CFB8E41CA11E8660EE8381781CD7AF274A9480BF103B600EC0ACDC9E825E606DBC56168673511FAB82F814269614C275C23AD42C9F7AC4EA90D277587C60CBD5C03EF2B716653684C47BFCFB5C9232C13BF1334E93E4EB4DE8429D3B959FA8237014D00A688AD569D8D9B197D782B01E3D8BB133065E4B89DD0576F9210E0882901FBA6A95F790DF8A9E57A5EE8A53A7AF0372691419D5EADC6E54A4E363E136567FBC4749B62CE9BAA42B8A15AB89009F85720602F3E57FD8799B500CBC20C2C1F593F36F03B57679C57BA650CC903DFC7398F38C1401235E5B030FC20985B3AD9D7B7F1721786AEB7D3AE3E63FC9AACBAC600A4A1A0AB89A9714DFA2F3A716F37EC491AEE91C252B5BC945CFD4D6992948B15EAB3AA1F900878D130F7CCFF42EC6B12BAC3BCFACE5014D57FDAD258EA8E60699601A479A8B1087EC11C58D755E5524433DCC3971A6EDFFD2DC8795F788E29DE9E36B97708A8BE25574497635B992C17FA4BD075BC7F771A684C678617196C015B94F5E4237F1C680627EC83F980AC8FD95BFF3FDD40FA30358D1673860A3322CA8C93F7DD50AE1F479A0721CBCE398DF4774B8D0A7DA768AD48DEC8A09353C1561CBFE8D8394B5CB58BC9BB1FF7C358725BDB6B471C08166204C9F550F4A6D13667D99C0117458419832125FAB7F13206152E250738C35D4C0135C58DE183537351B1E0051B1F2A9CB4C3474CA32AD98465348AD6D6E2594CE1E8CB9835145FC4AFFA12C66FF33266230F10F6B8935FA2FCB5D368896820B015B0F04995DBAB1DA413C276BBC033E7EBFABFC6A1B610477F10B27E2F5E45CCFEFFD9DCE5D931060B7F939F1203F8A9650B58906CE84EB46529E9EADE8537FC356889E39A10F95DCB37E346C2D928C39E884F0A1D0563E5A853D13CC1724DDF1C6418C1CF5AC742762352C2269DD69AED0DC0EF4E1BBA91161C11C184DEE6C7168FBB4632B0A06295D840D14F3520C948FEE08BE216D20C31074A725FCEEB4FA86CE04A1C0184D66DD43210A39BECE18DA78AAEB3D6302E636B3C4FEED0DBA777F45A7DE56E528611D08213DE9EFD2A46B64B97CCD6E642E3433C123E

read from 0x214124ee7a0 [0x21412512653] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ChangeCipherSpec (20)
  Length = 1
read from 0x214124ee7a0 [0x21412512658] (1 bytes => 1 (0x1))
0000 - 01                                                .
    change_cipher_spec (1)

read from 0x214124ee7a0 [0x21412512653] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 23
read from 0x214124ee7a0 [0x21412512658] (23 bytes => 23 (0x17))
0000 - 4c 3f 60 6d 34 e1 a6 bc-78 94 87 31 3f 07 89 6b   L?`m4...x..1?..k
0010 - c8 b0 90 87 4e 19 74                              ....N.t
  Inner Content Type = Handshake (22)
SSL_connect:SSLv3/TLS read server hello
    EncryptedExtensions, Length=2
      No extensions

Can't use SSL_get_servername
read from 0x214124ee7a0 [0x21412512653] (5 bytes => 5 (0x5))
0000 - 17 03 03 02 a9                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 681
read from 0x214124ee7a0 [0x21412512658] (681 bytes => 681 (0x2A9))
0000 - 88 d8 9b 30 90 87 da 60-17 3f 1f 7a 79 68 2b 8f   ...0...`.?.zyh+.
0010 - 60 6f 40 07 20 82 48 0f-eb 8f 32 74 4f 3c 85 6d   `o@. .H...2tO<.m
0020 - 40 29 47 bc ce 95 43 18-f0 4e 36 86 2f 16 ca ba   @)G...C..N6./...
0030 - 9f db 95 36 40 5a 8b c5-3c b9 99 5d 55 0d a2 24   ...6@Z..<..]U..$
0040 - a4 31 19 c9 7a 71 d6 9f-49 a9 e0 cb 2f a3 bc db   .1..zq..I.../...
0050 - b2 e9 27 55 dd 44 23 42-f8 44 c2 76 50 1a a2 a5   ..'U.D#B.D.vP...
0060 - a0 a7 23 02 fe 44 4e 95-48 7d 0e fe 7b 65 c1 d4   ..#..DN.H}..{e..
0070 - 9a a3 eb f0 c9 07 2f 05-7a 44 fc 0f a0 27 7e 9e   ....../.zD...'~.
0080 - 65 3b 25 22 c1 60 e2 35-3e 61 f3 d1 73 9c 62 b9   e;%".`.5>a..s.b.
0090 - e6 7b b8 c5 48 d3 49 99-a2 d5 17 04 2a b2 29 5d   .{..H.I.....*.)]
00a0 - 8a c5 dc 42 60 1f 8f b6-15 b8 cc 9f 0c 4c 23 2b   ...B`........L#+
00b0 - 8f 47 0b 91 e5 4a 50 44-33 aa 28 03 c9 56 f3 10   .G...JPD3.(..V..
00c0 - 3c 9e ac cb b0 c3 ff ae-2d f2 19 0d e0 87 47 42   <.......-.....GB
00d0 - 4c d7 b3 ef 1a a1 fa d9-5d 55 92 4e 46 96 23 eb   L.......]U.NF.#.
00e0 - cf be 62 62 e6 e9 c3 bb-b1 e1 c7 7e 07 5b f9 bb   ..bb.......~.[..
00f0 - 4c 3e 37 b2 a5 05 3e 92-09 a1 b7 74 9e 96 ad 2c   L>7...>....t...,
0100 - ee 3f d4 b6 37 e6 ee ad-cf 2e 00 0f c4 ac f8 63   .?..7..........c
0110 - 27 89 e4 f1 4c 5c 99 7b-ce b5 ea 98 bd 81 69 cc   '...L\.{......i.
0120 - 16 d7 e9 59 38 65 79 bf-ec 7b dd b5 6e 03 17 ac   ...Y8ey..{..n...
0130 - b8 d4 df 9c ff f7 b7 62-86 d0 d7 91 55 1c 0d a0   .......b....U...
0140 - 1d 17 4d 4e 99 29 54 f9-34 f5 14 65 45 97 c5 5e   ..MN.)T.4..eE..^
0150 - 96 fe d0 9c dd 44 1d e2-d7 96 3f a5 7e 4d 0a eb   .....D....?.~M..
0160 - 90 da b6 5e 5d 2f a6 4b-c9 6a 24 82 95 4e f0 c3   ...^]/.K.j$..N..
0170 - 7c f4 51 b3 da a1 5e 39-04 e2 b4 83 14 73 2e 5b   |.Q...^9.....s.[
0180 - 4f b7 aa 2d 49 de da 5d-bd 03 b2 4f e1 2b 3e 84   O..-I..]...O.+>.
0190 - a0 53 65 2f 4f a1 c1 b0-49 20 50 0e 36 ac b8 16   .Se/O...I P.6...
01a0 - 51 37 fd 38 8c 8f 3d f8-a3 6e 1f bf d1 db bd 4c   Q7.8..=..n.....L
01b0 - af aa b7 44 2b 3d 5c 78-13 db 82 7e 88 97 27 59   ...D+=\x...~..'Y
01c0 - 55 5a f1 1d c7 7e 9f 82-b3 cd 49 8a d7 8d 28 bb   UZ...~....I...(.
01d0 - 4e a7 25 8c d3 0f 17 82-bc 34 8a 20 dc 77 7a e9   N.%......4. .wz.
01e0 - a4 11 ca 2d 05 db ea 2b-c4 14 4f 07 54 99 b9 e7   ...-...+..O.T...
01f0 - 3e 95 db 62 27 46 30 41-5c a1 10 76 61 f8 48 0c   >..b'F0A\..va.H.
0200 - d4 05 85 fc 3a 86 c8 9c-34 d7 c2 c4 65 78 a0 71   ....:...4...ex.q
0210 - 66 b5 2e 77 15 8b ec 8f-b6 ae a4 a1 26 4a f3 21   f..w........&J.!
0220 - f3 2b 89 2e 90 f6 9e 3b-32 a0 bd fc 2a 46 f7 5d   .+.....;2...*F.]
0230 - 1d 8e 5a b4 da b2 be 3c-5c 63 2b 5f ba 74 f7 11   ..Z....<\c+_.t..
0240 - 1a 20 3f fd 97 43 08 95-04 9c 41 bf 51 cf ab 5b   . ?..C....A.Q..[
0250 - d2 bc e9 cf 69 41 60 23-47 b7 ca 6f 63 91 48 59   ....iA`#G..oc.HY
0260 - 9d d1 71 0f bd f3 0d 62-75 99 fe 82 d6 63 63 52   ..q....bu....ccR
0270 - 24 c7 95 89 43 f2 26 8e-28 43 1d eb 40 0d b5 3d   $...C.&.(C..@..=
0280 - dd 02 28 e1 59 e2 bb 6f-b0 d7 59 65 8f fb e8 c8   ..(.Y..o..Ye....
0290 - d2 f1 86 5b d2 6c 90 c9-16 b8 68 40 39 4f 69 71   ...[.l....h@9Oiq
02a0 - 42 9b d0 10 f1 dd 5a 7a-4f                        B.....ZzO
  Inner Content Type = Handshake (22)
SSL_connect:TLSv1.3 read encrypted extensions
    Certificate, Length=660
      context (len=0):
      certificate_list, length=656
        ASN.1Cert, length=651
------details-----
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            54:62:ff:be:6d:4b:20:ec:20:48:3b:13:c7:73:6a:d5:ad:af:ae:96
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C = KR, ST = KN, L = GJ, O = Test, OU = Test, CN = Test Root
        Validity
            Not Before: May 13 22:20:02 2026 GMT
            Not After : May 13 22:20:02 2027 GMT
        Subject: C = KR, ST = KN, L = GJ, O = Test, OU = Test, CN = test.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:b2:7f:4a:c8:e3:26:69:39:f4:28:1d:d9:02:d4:
                    27:4a:40:09:74:f4:7a:29:e4:8b:36:64:2e:67:33:
                    98:0c:59:06:e4:fb:ce:12:b6:4e:87:7a:f0:66:b2:
                    4e:db:c6:d7:19:2c:be:21:74:f8:fa:9f:cb:4d:8f:
                    7b:07:72:59:50:a1:1e:a4:60:d1:27:b6:16:71:06:
                    1f:e1:e1:7a:a7:cd:00:47:d9:b8:3a:d0:ed:b7:c2:
                    75:5e:1d:15:1e:cc:5b
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        X509v3 extensions:
            X509v3 Basic Constraints:
                CA:FALSE
            X509v3 Key Usage:
                Digital Signature
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Subject Alternative Name:
                DNS:test.com, DNS:localhost, IP Address:127.0.0.1
            X509v3 Subject Key Identifier:
                F0:6A:54:51:F4:17:33:FC:37:7F:66:B1:94:D7:C5:6A:78:E2:F0:32
            X509v3 Authority Key Identifier:
                6C:B3:F5:87:BF:38:EE:DF:DC:86:97:57:C6:91:69:EA:01:23:13:4E
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:65:02:30:4c:34:05:3f:7c:d0:34:15:f9:d2:35:53:68:0c:
        78:0d:db:13:e7:0c:dc:c8:86:1f:a9:cc:87:67:e7:71:11:9d:
        0a:91:29:a8:8b:b5:aa:14:00:4c:a1:a9:ea:ec:43:d9:02:31:
        00:ac:f1:ef:2f:d5:dd:2f:e9:a1:74:b1:7a:51:38:46:c3:fc:
        6c:30:f1:12:3f:47:ce:ff:fc:94:a3:5e:80:51:6b:77:8c:fc:
        94:2d:3d:45:1a:a7:5e:e2:93:41:7d:1b:57
-----BEGIN CERTIFICATE-----
MIIChzCCAg2gAwIBAgIUVGL/vm1LIOwgSDsTx3Nq1a2vrpYwCgYIKoZIzj0EAwIw
WTELMAkGA1UEBhMCS1IxCzAJBgNVBAgMAktOMQswCQYDVQQHDAJHSjENMAsGA1UE
CgwEVGVzdDENMAsGA1UECwwEVGVzdDESMBAGA1UEAwwJVGVzdCBSb290MB4XDTI2
MDUxMzIyMjAwMloXDTI3MDUxMzIyMjAwMlowWDELMAkGA1UEBhMCS1IxCzAJBgNV
BAgMAktOMQswCQYDVQQHDAJHSjENMAsGA1UECgwEVGVzdDENMAsGA1UECwwEVGVz
dDERMA8GA1UEAwwIdGVzdC5jb20wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASyf0rI
4yZpOfQoHdkC1CdKQAl09Hop5Is2ZC5nM5gMWQbk+84Stk6HevBmsk7bxtcZLL4h
dPj6n8tNj3sHcllQoR6kYNEnthZxBh/h4XqnzQBH2bg60O23wnVeHRUezFujgZYw
gZMwCQYDVR0TBAIwADALBgNVHQ8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEw
JAYDVR0RBB0wG4IIdGVzdC5jb22CCWxvY2FsaG9zdIcEfwAAATAdBgNVHQ4EFgQU
8GpUUfQXM/w3f2axlNfFanji8DIwHwYDVR0jBBgwFoAUbLP1h7847t/chpdXxpFp
6gEjE04wCgYIKoZIzj0EAwIDaAAwZQIwTDQFP3zQNBX50jVTaAx4DdsT5wzcyIYf
qcyHZ+dxEZ0KkSmoi7WqFABMoanq7EPZAjEArPHvL9XdL+mhdLF6UThGw/xsMPES
P0fO//yUo16AUWt3jPyULT1FGqde4pNBfRtX
-----END CERTIFICATE-----
------------------
        No extensions

depth=0 C=KR, ST=KN, L=GJ, O=Test, OU=Test, CN=test.com
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 C=KR, ST=KN, L=GJ, O=Test, OU=Test, CN=test.com
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 C=KR, ST=KN, L=GJ, O=Test, OU=Test, CN=test.com
verify return:1
read from 0x214124ee7a0 [0x21412512653] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 81                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 129
read from 0x214124ee7a0 [0x21412512658] (129 bytes => 129 (0x81))
0000 - 1d c2 25 1a f9 2b bb d0-56 83 d5 7c 8c 5d 78 95   ..%..+..V..|.]x.
0010 - a9 fe 63 93 04 cc d4 22-ae 5d b7 b2 de dd 15 b4   ..c....".]......
0020 - 07 6d 68 41 d9 60 28 da-b8 98 6f 9d 03 ec 2e db   .mhA.`(...o.....
0030 - a9 e1 bf 13 75 26 8c 65-82 20 8f 00 f9 d3 17 40   ....u&.e. .....@
0040 - 3f a3 98 a1 00 a4 c3 66-fc e7 74 82 04 10 ec 3d   ?......f..t....=
0050 - 84 7d 95 d0 40 a9 69 7c-62 62 cd f2 74 cb f7 cb   .}..@.i|bb..t...
0060 - ef e4 b2 86 57 f6 59 a1-33 03 2a 97 c3 8c 8b 63   ....W.Y.3.*....c
0070 - bb 1b 90 69 44 31 5b ef-56 34 37 84 57 d8 a7 e2   ...iD1[.V47.W...
0080 - ff                                                .
  Inner Content Type = Handshake (22)
SSL_connect:SSLv3/TLS read server certificate
    CertificateVerify, Length=108
      Signature Algorithm: ecdsa_secp384r1_sha384 (0x0503)
      Signature (len=104): 3066023100E772D13002D0487D8AA5DDD42DF96B06E5F0F7EDE7A2EA17F1573BACB78EDE0F9269DBB184A25100CED10E88DAB9EDED023100D9BF61BC9C1E118972A309D4DEAC56CA908EFCA13C51C007D87D30047CCE5F50E91E74B2EFBF10CF3100A07827E60994

read from 0x214124ee7a0 [0x21412512653] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 45                                    ....E
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 69
read from 0x214124ee7a0 [0x21412512658] (69 bytes => 69 (0x45))
0000 - 23 dc 18 16 45 03 3c a0-e6 fd 91 cb 87 e6 75 54   #...E.<.......uT
0010 - ec 74 63 da 15 38 c1 33-3a 96 2d 2f 43 9f 8d d1   .tc..8.3:.-/C...
0020 - 7c ea 00 ca 38 57 4a e3-5c e9 68 44 89 31 a9 1f   |...8WJ.\.hD.1..
0030 - 8a 02 6d 69 ea af 29 ae-7d dd 52 3b b9 70 e4 ac   ..mi..).}.R;.p..
0040 - 11 c9 0a 9f 5f                                    ...._
  Inner Content Type = Handshake (22)
SSL_connect:TLSv1.3 read server certificate verify
    Finished, Length=48
      verify_data (len=48): D0580D69CF894DC1599EDAB54CFA6F53D8135533AFB3F1DAC4CA0CD67D422DC86078B988B548E4F472B570A01A8B03F1

SSL_connect:SSLv3/TLS read finished
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ChangeCipherSpec (20)
  Length = 1
    change_cipher_spec (1)

SSL_connect:SSLv3/TLS write change cipher spec
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 69
  Inner Content Type = Handshake (22)
    Finished, Length=48
      verify_data (len=48): B4E9E37E37DF8C61610F8459F981385DDEEE287AF3C28A1788F603C35DFB13048C75CB1381A142D9DCBA34D80ADDF133

write to 0x214124ee7a0 [0x2141250bd70] (80 bytes => 80 (0x50))
0000 - 14 03 03 00 01 01 17 03-03 00 45 b6 41 aa 8e 58   ..........E.A..X
0010 - 22 41 c5 ef 08 bf 02 19-22 25 29 c0 7c c7 ef 7d   "A......"%).|..}
0020 - 5e d6 14 29 49 13 b9 6f-0d bb 9b aa cd b3 f5 8f   ^..)I..o........
0030 - 4d 12 fb e6 03 e2 f7 a9-ce a4 76 7f 5f a6 4b 0d   M.........v._.K.
0040 - ce 9a 4e c0 24 cd 94 ca-95 75 f9 0d 6b f6 a4 fc   ..N.$....u..k...
SSL_connect:SSLv3/TLS write finished
---
Certificate chain
 0 s:C=KR, ST=KN, L=GJ, O=Test, OU=Test, CN=test.com
   i:C=KR, ST=KN, L=GJ, O=Test, OU=Test, CN=Test Root
   a:PKEY: EC, (secp384r1); sigalg: ecdsa-with-SHA256
   v:NotBefore: May 13 22:20:02 2026 GMT; NotAfter: May 13 22:20:02 2027 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIChzCCAg2gAwIBAgIUVGL/vm1LIOwgSDsTx3Nq1a2vrpYwCgYIKoZIzj0EAwIw
WTELMAkGA1UEBhMCS1IxCzAJBgNVBAgMAktOMQswCQYDVQQHDAJHSjENMAsGA1UE
CgwEVGVzdDENMAsGA1UECwwEVGVzdDESMBAGA1UEAwwJVGVzdCBSb290MB4XDTI2
MDUxMzIyMjAwMloXDTI3MDUxMzIyMjAwMlowWDELMAkGA1UEBhMCS1IxCzAJBgNV
BAgMAktOMQswCQYDVQQHDAJHSjENMAsGA1UECgwEVGVzdDENMAsGA1UECwwEVGVz
dDERMA8GA1UEAwwIdGVzdC5jb20wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASyf0rI
4yZpOfQoHdkC1CdKQAl09Hop5Is2ZC5nM5gMWQbk+84Stk6HevBmsk7bxtcZLL4h
dPj6n8tNj3sHcllQoR6kYNEnthZxBh/h4XqnzQBH2bg60O23wnVeHRUezFujgZYw
gZMwCQYDVR0TBAIwADALBgNVHQ8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEw
JAYDVR0RBB0wG4IIdGVzdC5jb22CCWxvY2FsaG9zdIcEfwAAATAdBgNVHQ4EFgQU
8GpUUfQXM/w3f2axlNfFanji8DIwHwYDVR0jBBgwFoAUbLP1h7847t/chpdXxpFp
6gEjE04wCgYIKoZIzj0EAwIDaAAwZQIwTDQFP3zQNBX50jVTaAx4DdsT5wzcyIYf
qcyHZ+dxEZ0KkSmoi7WqFABMoanq7EPZAjEArPHvL9XdL+mhdLF6UThGw/xsMPES
P0fO//yUo16AUWt3jPyULT1FGqde4pNBfRtX
-----END CERTIFICATE-----
subject=C=KR, ST=KN, L=GJ, O=Test, OU=Test, CN=test.com
issuer=C=KR, ST=KN, L=GJ, O=Test, OU=Test, CN=Test Root
---
No client certificate CA names sent
Peer signing digest: SHA384
Peer signature type: ecdsa_secp384r1_sha384
Negotiated TLS1.3 group: X25519MLKEM768
---
SSL handshake has read 2143 bytes and written 1536 bytes
Verification error: unable to verify the first certificate
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
Server public key is 384 bit
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 21 (unable to verify the first certificate)
---
read from 0x214124ee7a0 [0x21412505803] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 fa                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 250
read from 0x214124ee7a0 [0x21412505808] (250 bytes => 250 (0xFA))
0000 - 25 5f da 09 71 21 5d d0-f5 4c 93 2f 52 f6 23 12   %_..q!]..L./R.#.
0010 - 73 11 41 31 09 dc 9a 26-fe 33 bd 9a 18 af bd 3a   s.A1...&.3.....:
0020 - 05 9f 50 c4 6d c1 41 46-ac e7 9c 59 d1 aa 8f c9   ..P.m.AF...Y....
0030 - c6 98 fa 3e 4d 03 b2 d6-23 16 b2 95 b5 bb fb fc   ...>M...#.......
0040 - 7c 14 84 89 1b ac f9 08-fa b8 15 af c5 0d 5b 63   |.............[c
0050 - 29 78 ca 1f a4 0c f7 cb-4e 87 71 87 6b 47 13 88   )x......N.q.kG..
0060 - 39 59 95 9a 75 57 42 bf-8d 7a 48 01 08 83 39 f0   9Y..uWB..zH...9.
0070 - a7 74 4e 7d 64 0c 48 01-0b 85 8a f0 ff 22 6c c7   .tN}d.H......"l.
0080 - 17 c2 cf 57 76 cc 31 d1-61 02 59 8c 08 2d 25 d1   ...Wv.1.a.Y..-%.
0090 - 47 52 67 23 0d 8f c3 a8-b9 b2 35 64 51 e1 8f c1   GRg#......5dQ...
00a0 - c1 e8 90 d8 18 d0 0d 61-47 36 f1 0d ae d2 49 d9   .......aG6....I.
00b0 - d2 42 69 f1 f1 22 01 18-59 86 45 75 b0 ac 2e 89   .Bi.."..Y.Eu....
00c0 - 6c c7 3e 8a 4f 3b 8d 70-3e a4 5c de af fb 3c 98   l.>.O;.p>.\...<.
00d0 - ef 4b 1f 3a b1 32 7a e4-ba b9 10 31 07 f3 2e 6f   .K.:.2z....1...o
00e0 - 3a ab 3d 7c d0 7e bc 18-33 1b cb be 74 a7 cf d9   :.=|.~..3...t...
00f0 - 5c f3 b7 5d e2 2a ba 25-f2 ea                     \..].*.%..
  Inner Content Type = Handshake (22)
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
    NewSessionTicket, Length=229
        ticket_lifetime_hint=7200
        ticket_age_add=2947272170
        ticket_nonce (len=8): 0000000000000000
        ticket (len=208): F4BB630D43E7AAE90000A33207501202FAE7C84890AC670310324806FD1B44197337EF501165F6B2D6D0C5F328CCA5FEE02ED3F0C9F94C87E831F25A29F376B4BC309F7102099773957270C58A07974916C2FBA31FFE0F2E2E059991D93CBE3EC4D3A9FBBA9B34697F81DB003D25E5192971E4A0BB23FD51769E6A596BFABAB97873CEF2D511EE85E14843B49167E6DBE08E0D2D5E2567AE8DE4486CE3F22736A6B6468DBA36F681E2885BC4E49D0D08E5E0F821FCFC8314999AAFD034E6492F1345B904ABE54A62A57CB627BA3328B8
        No extensions

---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 65CA4704918EB42AAD27BB8207BE0BFBD46974039AE8C4A1A885E7795260F79A
    Session-ID-ctx:
    Resumption PSK: B3507475CC533AB4A7E718F660EBCE579353C021F5ED62494B28410EA81465C8CF49CD85587A8FB24DE3912206832334
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - f4 bb 63 0d 43 e7 aa e9-00 00 a3 32 07 50 12 02   ..c.C......2.P..
    0010 - fa e7 c8 48 90 ac 67 03-10 32 48 06 fd 1b 44 19   ...H..g..2H...D.
    0020 - 73 37 ef 50 11 65 f6 b2-d6 d0 c5 f3 28 cc a5 fe   s7.P.e......(...
    0030 - e0 2e d3 f0 c9 f9 4c 87-e8 31 f2 5a 29 f3 76 b4   ......L..1.Z).v.
    0040 - bc 30 9f 71 02 09 97 73-95 72 70 c5 8a 07 97 49   .0.q...s.rp....I
    0050 - 16 c2 fb a3 1f fe 0f 2e-2e 05 99 91 d9 3c be 3e   .............<.>
    0060 - c4 d3 a9 fb ba 9b 34 69-7f 81 db 00 3d 25 e5 19   ......4i....=%..
    0070 - 29 71 e4 a0 bb 23 fd 51-76 9e 6a 59 6b fa ba b9   )q...#.Qv.jYk...
    0080 - 78 73 ce f2 d5 11 ee 85-e1 48 43 b4 91 67 e6 db   xs.......HC..g..
    0090 - e0 8e 0d 2d 5e 25 67 ae-8d e4 48 6c e3 f2 27 36   ...-^%g...Hl..'6
    00a0 - a6 b6 46 8d ba 36 f6 81-e2 88 5b c4 e4 9d 0d 08   ..F..6....[.....
    00b0 - e5 e0 f8 21 fc fc 83 14-99 9a af d0 34 e6 49 2f   ...!........4.I/
    00c0 - 13 45 b9 04 ab e5 4a 62-a5 7c b6 27 ba 33 28 b8   .E....Jb.|.'.3(.

    Start Time: 1794782273
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
read from 0x214124ee7a0 [0x21412505803] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 fa                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 250
read from 0x214124ee7a0 [0x21412505808] (250 bytes => 250 (0xFA))
0000 - e9 46 67 01 30 bf e4 a0-43 3a 2a 6f 18 ec 60 d9   .Fg.0...C:*o..`.
0010 - 61 79 14 9f f5 5a a5 8b-e2 b3 6e 28 d6 c9 f2 64   ay...Z....n(...d
0020 - ca 1b 56 d6 f1 f6 43 d9-d9 2a 88 1e 10 88 6d 90   ..V...C..*....m.
0030 - 66 75 77 83 92 80 77 43-2d 4e af 01 ed 56 87 2c   fuw...wC-N...V.,
0040 - c0 5b dd 6a ec d8 5a a3-bf d0 80 8f a4 db 25 89   .[.j..Z.......%.
0050 - f7 ad bb c8 99 07 c4 8d-b9 13 ed 03 c8 e9 92 54   ...............T
0060 - e2 77 40 4e da e3 a0 f2-a6 fe 85 0f ef 3b d0 1b   .w@N.........;..
0070 - d3 8c f1 45 93 e7 88 6a-0b 75 db 49 ca 81 41 18   ...E...j.u.I..A.
0080 - e7 a6 0c 11 dd f2 a4 f3-43 6e d0 82 a2 75 fc 69   ........Cn...u.i
0090 - e0 a8 3c 98 2e 77 20 d5-39 4c 11 fb a2 b0 83 dc   ..<..w .9L......
00a0 - 4e 1a 55 ea b0 4e 8f b9-53 6b cd 40 33 64 18 c2   N.U..N..Sk.@3d..
00b0 - 57 07 49 64 22 63 c7 ca-e7 0a b4 71 45 9c e6 11   W.Id"c.....qE...
00c0 - be a3 a9 c5 64 98 1c 5b-51 10 89 02 cb ba 3e 1e   ....d..[Q.....>.
00d0 - 8b 18 fa ad c5 e5 57 dc-89 58 c6 6d bd 51 00 c7   ......W..X.m.Q..
00e0 - b5 c8 59 d4 b8 ad cb d5-d3 b9 a0 81 ae 19 e9 2c   ..Y............,
00f0 - 42 c2 a5 68 27 ff f4 cb-ae 19                     B..h'.....
  Inner Content Type = Handshake (22)
SSL_connect:SSL negotiation finished successfully
SSL_connect:SSL negotiation finished successfully
    NewSessionTicket, Length=229
        ticket_lifetime_hint=7200
        ticket_age_add=707350052
        ticket_nonce (len=8): 0000000000000001
        ticket (len=208): F4BB630D43E7AAE90000A3320750120242F1745B292D8416AF1FE32A1C2AB2807327374BDC616C7B1CD32CAB46313F6B3C0696C5F5CC7A5D81BDE16515CF8A30725A8B946A016486429FB0CEF8BBE362D4588EA01F21E8075F5AFB73B0F313B680CF260E0EBB1295B9178547002C999855097760E3468992542C3FE1D41DB87AF25CB4E0170D70CF61700A5D20B91CBA9F18C94A40723FA05C3C00C6B6A51D13B8F88048B7B8336E31F67BB98A1D2552E69FE8835BA0DCFAF9A2D9272FB23054C6E7ED08FD45DCD17C930037CA4D0EC9
        No extensions

---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 44495277C9A38B54B3A41FF8FE44E51ED8BE5FB440175BBFD5189CEDBD8F460E
    Session-ID-ctx:
    Resumption PSK: 36E4F00B26BD50410B67881E4738FA59E572E95F48EB20E0450ECC114CFEF1504578795BDCB5DB8C94C58ED72FA43B40
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - f4 bb 63 0d 43 e7 aa e9-00 00 a3 32 07 50 12 02   ..c.C......2.P..
    0010 - 42 f1 74 5b 29 2d 84 16-af 1f e3 2a 1c 2a b2 80   B.t[)-.....*.*..
    0020 - 73 27 37 4b dc 61 6c 7b-1c d3 2c ab 46 31 3f 6b   s'7K.al{..,.F1?k
    0030 - 3c 06 96 c5 f5 cc 7a 5d-81 bd e1 65 15 cf 8a 30   <.....z]...e...0
    0040 - 72 5a 8b 94 6a 01 64 86-42 9f b0 ce f8 bb e3 62   rZ..j.d.B......b
    0050 - d4 58 8e a0 1f 21 e8 07-5f 5a fb 73 b0 f3 13 b6   .X...!.._Z.s....
    0060 - 80 cf 26 0e 0e bb 12 95-b9 17 85 47 00 2c 99 98   ..&........G.,..
    0070 - 55 09 77 60 e3 46 89 92-54 2c 3f e1 d4 1d b8 7a   U.w`.F..T,?....z
    0080 - f2 5c b4 e0 17 0d 70 cf-61 70 0a 5d 20 b9 1c ba   .\....p.ap.] ...
    0090 - 9f 18 c9 4a 40 72 3f a0-5c 3c 00 c6 b6 a5 1d 13   ...J@r?.\<......
    00a0 - b8 f8 80 48 b7 b8 33 6e-31 f6 7b b9 8a 1d 25 52   ...H..3n1.{...%R
    00b0 - e6 9f e8 83 5b a0 dc fa-f9 a2 d9 27 2f b2 30 54   ....[......'/.0T
    00c0 - c6 e7 ed 08 fd 45 dc d1-7c 93 00 37 ca 4d 0e c9   .....E..|..7.M..

    Start Time: 1794782273
    Timeout   : 7200 (sec)
    Verify return code: 21 (unable to verify the first certificate)
    Extended master secret: no
    Max Early Data: 0
---
SSL_connect:SSLv3/TLS read server session ticket
read R BLOCK
test
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 23
  Inner Content Type = ApplicationData (23)
write to 0x214124ee7a0 [0x2141250e593] (28 bytes => 28 (0x1C))
0000 - 17 03 03 00 17 0b 15 ee-3f 57 21 29 e6 f3 30 d8   ........?W!)..0.
0010 - 6e 06 25 97 52 bd 58 29-17 8d f7 a3               n.%.R.X)....
k
KEYUPDATE
SSL_connect:SSL negotiation finished successfully
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 22
  Inner Content Type = Handshake (22)
    KeyUpdate, Length=1
      update_not_requested (0)

write to 0x214124ee7a0 [0x21412552990] (27 bytes => 27 (0x1B))
0000 - 17 03 03 00 16 3e ba 81-fd 2d e7 5f df 5e b7 7b   .....>...-._.^.{
0010 - b5 ef 13 a3 c8 96 40 16-3b d2 bf                  ......@.;..
SSL_connect:TLSv1.3 write client key update
test
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 23
  Inner Content Type = ApplicationData (23)
write to 0x214124ee7a0 [0x2141254d063] (28 bytes => 28 (0x1C))
0000 - 17 03 03 00 17 d5 29 bf-bf 2f 6c a5 f0 40 61 fc   ......)../l..@a.
0010 - 64 70 a4 5b 7c ad 7e f3-bf 55 24 53               dp.[|.~..U$S
K
KEYUPDATE
SSL_connect:SSL negotiation finished successfully
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 22
  Inner Content Type = Handshake (22)
    KeyUpdate, Length=1
      update_requested (1)

write to 0x214124ee7a0 [0x214125046b0] (27 bytes => 27 (0x1B))
0000 - 17 03 03 00 16 35 d0 a7-df 56 0a 96 7e e2 ce e6   .....5...V..~...
0010 - 04 71 c8 1b 3a c8 30 5b-64 8e 67                  .q..:.0[d.g
SSL_connect:TLSv1.3 write client key update
test
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 23
  Inner Content Type = ApplicationData (23)
write to 0x214124ee7a0 [0x2141254d063] (28 bytes => 28 (0x1C))
0000 - 17 03 03 00 17 4d 6e 18-28 e8 a4 64 0a 03 1d 56   .....Mn.(..d...V
0010 - c3 d5 cf a7 7a a9 da 02-38 c0 7d 5a               ....z...8.}Z
Q
DONE
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 19
  Inner Content Type = Alert (21)
write to 0x214124ee7a0 [0x2141254d063] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 98 3a 84-04 33 08 6a 46 09 67 da   ......:..3.jF.g.
0010 - 5c eb 10 e3 20 61 ad 73-                          \... a.s
    Level=warning(1), description=close notify(0)

SSL3 alert write:warning:close notify
read from 0x214124ee7a0 [0x21410b94890] (16384 bytes => 24 (0x18))
0000 - 17 03 03 00 13 1b b3 4d-64 f3 8f 2e 76 b3 e7 a8   .......Md...v...
0010 - 93 2c 04 b5 bd cc 76 41-                          .,....vA
read from 0x214124ee7a0 [0x21410b94890] (16384 bytes => 0)
````

[TOC](README.md)
