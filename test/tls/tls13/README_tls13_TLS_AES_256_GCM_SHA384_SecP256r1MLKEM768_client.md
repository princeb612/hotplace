#### client

````
$ openssl s_client -connect localhost:9000 -state -debug -trace -keylogfile sslkeylog -tls1_3 --curves SecP256r1MLKEM768
Connecting to ::1
CONNECTED(00000170)
SSL_connect:before SSL initialization
Sent TLS Record
Header:
  Version = TLS 1.0 (0x301)
  Content Type = Handshake (22)
  Length = 1428
    ClientHello, Length=1424
      client_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0x84896616
        random_bytes (len=28): 8F6D2421B7F2107AD342D89341B37FF00EB5BC22CB1F4D4DF8993EE8
      session_id (len=32): 8AAAD716C2AD4EC00A953548F62CFA19075E0C95D84DF1BCE8836C5A3DD370B6
      cipher_suites (len=6)
        {0x13, 0x02} TLS_AES_256_GCM_SHA384
        {0x13, 0x03} TLS_CHACHA20_POLY1305_SHA256
        {0x13, 0x01} TLS_AES_128_GCM_SHA256
      compression_methods (len=1)
        No Compression (0x00)
      extensions, length = 1345
        extension_type=supported_groups(10), length=4
          SecP256r1MLKEM768 (4587)
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
        extension_type=key_share(51), length=1255
            NamedGroup: SecP256r1MLKEM768 (4587)
            key_exchange:  (len=1249): 043C2EFE313B835D2F91308C02B85AB298E1DBEB41F4358D3DC0380D2D94B5D417EB7F2938AD579E3FBF4D1046FB5F6311506C9FA0BE612D0C9D4748358395664ABA9825E666371FCC0C8E95141FF5BD257858F4A2568E8160C1C01A73AAC9C32813D78C9DDDD9C8A10B675E737B57156CAE8069AAB1A8E1341BADC27A2052B361387C66D15B249B9B15457723D00D82F0738138BB14907407511B96752054F930FEE153F46CA7741B5D74046E30F8A08D01134865CEC3F2B0DE8BA5DE948CDA7BBBCB38990FB06B1BA50E34364981DB55CC0270CA76CAF8AA510A6736B5D312B5EB5D92904DE57C3B956C275BCB8985F9ADFDE96AF72324D4856209AB2477290E11206646919E07D8A0EAD63ACB4A49924B7803DAC7FD2C6314830623D584140A91A4B94F8B7B52BB0661DE942B0DBC18ADF49852A3BAA425BDF2AB5EEE56916406AE22B70A09023EEF937D641304FDC516AAB9ABA9FA40EDFB2DEA986E0F922FF6F720535BC791301D15216D51261F07B48C0CD2757C0C6B12C9B485F25B66B25F31077963E97B34F51C4B7546B640C099C5020961CD555767F09821B8436E700B356899CF7184A9DD9432FEF361003D43ED5007C3EC4154E0CCF05BC3435A2439335743F343633838620880E7A381E7602565494BD405B7FA041CC449B2F1750DB9429A7A5118FDB53738611F063492ED7765C59704B6C51B0AE1B00D187030910D16A8C17B195D10B92072C046050B914AF87C337710F1864D4B694FD710434B765D34A223AA712AFC209C0A499F9E409A6CA4C7A98C6A9BFA726BE1BFB286B47428C05B583C08915190ECC1DA5AA213CA7708FA855EB5923F518557D72BDA665B3B689EAE07364042266E9307CBA1767C371EB2F8C92188B91AA946C360A5F4C243D8D972458366F7344131D207DCD7C76319125D0763FB15C7970213ED974C55F8BA410B5857935F58D119BEC7BBB8561B2FE7B3F22C9E71C7431E33C6BE29673DBA30F8820A0F52122FEA56A20658A3AC5F0B6029ACB0CE269A36362306E2B63E7A6296F42B3017E5C98EF9CFF11682C6331177D95B28B1B0B6F6A2F3616D9F8B719FFC3F27290DC1DACFE22A9C4C66BE32B1C4BFEAA748B8581F49B68DA2C24BFAA6BCFC9598DAAAC41BAF32D67EF9D00BF9A81F474889133C7C2B9363B2F8155447603D0AB421D35C2E253CDB896C6FA217295C12A4C6089B07B35B6B4E59A68D9F40042899624FE83347E52215A2C167C022DAE3C2BBA2469D250E65FC47EB55641BF8CD2594726C077440A75F56047DB82AC25EE5561E80403BBC9599F98B59827089BC0DCDA193E074B46FF6C669DA5C11D360C3F0056A165F65E8BCDBA2A11772C365F55193D9B614C1868F9029198B3F141B2D7A5B5A9CE2C0A97952A4B8A85589CD7AB82816B89359C8312B3364B2600F7913A75E241702028276EB063CF60096341B0F4A8B621A368E0C5DCED872DF702637793BE250778C373A0FDC5B8187267C56265B934F7DAB8A963B0A6273447B65635AA2882F7A82FB199081111AC6F15BDCD172FB9A315D526B31A5CD1E4950E00A1CD6744DC3D6AFFE1A9CF2A0BE3FD10821AB9DD4E883ED475AD7F7B42C1031E8B31B44581C735A2A06438AD65184DE2892469CB5CD3B63567C6D1D188602E29E6606B1AAC296AB6C3B80D83BC23C16F9B036D1321BB5F7C2ED079E7BC62B4C5B4B8635100294696A080B88FBCB2079B5FBAF097FAB3572A2EDFE7CAB151AB43A5AC4F9B3EECB21
        extension_type=compress_certificate(27), length=3
          zlib (1)

write to 0x22ec0da5e10 [0x22ec11c5910] (1433 bytes => 1433 (0x599))
0000 - 16 03 01 05 94 01 00 05-90 03 03 84 89 66 16 8f   .............f..
0010 - 6d 24 21 b7 f2 10 7a d3-42 d8 93 41 b3 7f f0 0e   m$!...z.B..A....
0020 - b5 bc 22 cb 1f 4d 4d f8-99 3e e8 20 8a aa d7 16   .."..MM..>. ....
0030 - c2 ad 4e c0 0a 95 35 48-f6 2c fa 19 07 5e 0c 95   ..N...5H.,...^..
0040 - d8 4d f1 bc e8 83 6c 5a-3d d3 70 b6 00 06 13 02   .M....lZ=.p.....
0050 - 13 03 13 01 01 00 05 41-00 0a 00 04 00 02 11 eb   .......A........
0060 - 00 23 00 00 00 16 00 00-00 17 00 00 00 0d 00 2a   .#.............*
0070 - 00 28 09 05 09 06 09 04-04 03 05 03 06 03 08 07   .(..............
0080 - 08 08 08 1a 08 1b 08 1c-08 09 08 0a 08 0b 08 04   ................
0090 - 08 05 08 06 04 01 05 01-06 01 00 2b 00 03 02 03   ...........+....
00a0 - 04 00 2d 00 02 01 01 00-33 04 e7 04 e5 11 eb 04   ..-.....3.......
00b0 - e1 04 3c 2e fe 31 3b 83-5d 2f 91 30 8c 02 b8 5a   ..<..1;.]/.0...Z
00c0 - b2 98 e1 db eb 41 f4 35-8d 3d c0 38 0d 2d 94 b5   .....A.5.=.8.-..
00d0 - d4 17 eb 7f 29 38 ad 57-9e 3f bf 4d 10 46 fb 5f   ....)8.W.?.M.F._
00e0 - 63 11 50 6c 9f a0 be 61-2d 0c 9d 47 48 35 83 95   c.Pl...a-..GH5..
00f0 - 66 4a ba 98 25 e6 66 37-1f cc 0c 8e 95 14 1f f5   fJ..%.f7........
0100 - bd 25 78 58 f4 a2 56 8e-81 60 c1 c0 1a 73 aa c9   .%xX..V..`...s..
0110 - c3 28 13 d7 8c 9d dd d9-c8 a1 0b 67 5e 73 7b 57   .(.........g^s{W
0120 - 15 6c ae 80 69 aa b1 a8-e1 34 1b ad c2 7a 20 52   .l..i....4...z R
0130 - b3 61 38 7c 66 d1 5b 24-9b 9b 15 45 77 23 d0 0d   .a8|f.[$...Ew#..
0140 - 82 f0 73 81 38 bb 14 90-74 07 51 1b 96 75 20 54   ..s.8...t.Q..u T
0150 - f9 30 fe e1 53 f4 6c a7-74 1b 5d 74 04 6e 30 f8   .0..S.l.t.]t.n0.
0160 - a0 8d 01 13 48 65 ce c3-f2 b0 de 8b a5 de 94 8c   ....He..........
0170 - da 7b bb cb 38 99 0f b0-6b 1b a5 0e 34 36 49 81   .{..8...k...46I.
0180 - db 55 cc 02 70 ca 76 ca-f8 aa 51 0a 67 36 b5 d3   .U..p.v...Q.g6..
0190 - 12 b5 eb 5d 92 90 4d e5-7c 3b 95 6c 27 5b cb 89   ...]..M.|;.l'[..
01a0 - 85 f9 ad fd e9 6a f7 23-24 d4 85 62 09 ab 24 77   .....j.#$..b..$w
01b0 - 29 0e 11 20 66 46 91 9e-07 d8 a0 ea d6 3a cb 4a   ).. fF.......:.J
01c0 - 49 92 4b 78 03 da c7 fd-2c 63 14 83 06 23 d5 84   I.Kx....,c...#..
01d0 - 14 0a 91 a4 b9 4f 8b 7b-52 bb 06 61 de 94 2b 0d   .....O.{R..a..+.
01e0 - bc 18 ad f4 98 52 a3 ba-a4 25 bd f2 ab 5e ee 56   .....R...%...^.V
01f0 - 91 64 06 ae 22 b7 0a 09-02 3e ef 93 7d 64 13 04   .d.."....>..}d..
0200 - fd c5 16 aa b9 ab a9 fa-40 ed fb 2d ea 98 6e 0f   ........@..-..n.
0210 - 92 2f f6 f7 20 53 5b c7-91 30 1d 15 21 6d 51 26   ./.. S[..0..!mQ&
0220 - 1f 07 b4 8c 0c d2 75 7c-0c 6b 12 c9 b4 85 f2 5b   ......u|.k.....[
0230 - 66 b2 5f 31 07 79 63 e9-7b 34 f5 1c 4b 75 46 b6   f._1.yc.{4..KuF.
0240 - 40 c0 99 c5 02 09 61 cd-55 57 67 f0 98 21 b8 43   @.....a.UWg..!.C
0250 - 6e 70 0b 35 68 99 cf 71-84 a9 dd 94 32 fe f3 61   np.5h..q....2..a
0260 - 00 3d 43 ed 50 07 c3 ec-41 54 e0 cc f0 5b c3 43   .=C.P...AT...[.C
0270 - 5a 24 39 33 57 43 f3 43-63 38 38 62 08 80 e7 a3   Z$93WC.Cc88b....
0280 - 81 e7 60 25 65 49 4b d4-05 b7 fa 04 1c c4 49 b2   ..`%eIK.......I.
0290 - f1 75 0d b9 42 9a 7a 51-18 fd b5 37 38 61 1f 06   .u..B.zQ...78a..
02a0 - 34 92 ed 77 65 c5 97 04-b6 c5 1b 0a e1 b0 0d 18   4..we...........
02b0 - 70 30 91 0d 16 a8 c1 7b-19 5d 10 b9 20 72 c0 46   p0.....{.].. r.F
02c0 - 05 0b 91 4a f8 7c 33 77-10 f1 86 4d 4b 69 4f d7   ...J.|3w...MKiO.
02d0 - 10 43 4b 76 5d 34 a2 23-aa 71 2a fc 20 9c 0a 49   .CKv]4.#.q*. ..I
02e0 - 9f 9e 40 9a 6c a4 c7 a9-8c 6a 9b fa 72 6b e1 bf   ..@.l....j..rk..
02f0 - b2 86 b4 74 28 c0 5b 58-3c 08 91 51 90 ec c1 da   ...t(.[X<..Q....
0300 - 5a a2 13 ca 77 08 fa 85-5e b5 92 3f 51 85 57 d7   Z...w...^..?Q.W.
0310 - 2b da 66 5b 3b 68 9e ae-07 36 40 42 26 6e 93 07   +.f[;h...6@B&n..
0320 - cb a1 76 7c 37 1e b2 f8-c9 21 88 b9 1a a9 46 c3   ..v|7....!....F.
0330 - 60 a5 f4 c2 43 d8 d9 72-45 83 66 f7 34 41 31 d2   `...C..rE.f.4A1.
0340 - 07 dc d7 c7 63 19 12 5d-07 63 fb 15 c7 97 02 13   ....c..].c......
0350 - ed 97 4c 55 f8 ba 41 0b-58 57 93 5f 58 d1 19 be   ..LU..A.XW._X...
0360 - c7 bb b8 56 1b 2f e7 b3-f2 2c 9e 71 c7 43 1e 33   ...V./...,.q.C.3
0370 - c6 be 29 67 3d ba 30 f8-82 0a 0f 52 12 2f ea 56   ..)g=.0....R./.V
0380 - a2 06 58 a3 ac 5f 0b 60-29 ac b0 ce 26 9a 36 36   ..X.._.`)...&.66
0390 - 23 06 e2 b6 3e 7a 62 96-f4 2b 30 17 e5 c9 8e f9   #...>zb..+0.....
03a0 - cf f1 16 82 c6 33 11 77-d9 5b 28 b1 b0 b6 f6 a2   .....3.w.[(.....
03b0 - f3 61 6d 9f 8b 71 9f fc-3f 27 29 0d c1 da cf e2   .am..q..?').....
03c0 - 2a 9c 4c 66 be 32 b1 c4-bf ea a7 48 b8 58 1f 49   *.Lf.2.....H.X.I
03d0 - b6 8d a2 c2 4b fa a6 bc-fc 95 98 da aa c4 1b af   ....K...........
03e0 - 32 d6 7e f9 d0 0b f9 a8-1f 47 48 89 13 3c 7c 2b   2.~......GH..<|+
03f0 - 93 63 b2 f8 15 54 47 60-3d 0a b4 21 d3 5c 2e 25   .c...TG`=..!.\.%
0400 - 3c db 89 6c 6f a2 17 29-5c 12 a4 c6 08 9b 07 b3   <..lo..)\.......
0410 - 5b 6b 4e 59 a6 8d 9f 40-04 28 99 62 4f e8 33 47   [kNY...@.(.bO.3G
0420 - e5 22 15 a2 c1 67 c0 22-da e3 c2 bb a2 46 9d 25   ."...g.".....F.%
0430 - 0e 65 fc 47 eb 55 64 1b-f8 cd 25 94 72 6c 07 74   .e.G.Ud...%.rl.t
0440 - 40 a7 5f 56 04 7d b8 2a-c2 5e e5 56 1e 80 40 3b   @._V.}.*.^.V..@;
0450 - bc 95 99 f9 8b 59 82 70-89 bc 0d cd a1 93 e0 74   .....Y.p.......t
0460 - b4 6f f6 c6 69 da 5c 11-d3 60 c3 f0 05 6a 16 5f   .o..i.\..`...j._
0470 - 65 e8 bc db a2 a1 17 72-c3 65 f5 51 93 d9 b6 14   e......r.e.Q....
0480 - c1 86 8f 90 29 19 8b 3f-14 1b 2d 7a 5b 5a 9c e2   ....)..?..-z[Z..
0490 - c0 a9 79 52 a4 b8 a8 55-89 cd 7a b8 28 16 b8 93   ..yR...U..z.(...
04a0 - 59 c8 31 2b 33 64 b2 60-0f 79 13 a7 5e 24 17 02   Y.1+3d.`.y..^$..
04b0 - 02 82 76 eb 06 3c f6 00-96 34 1b 0f 4a 8b 62 1a   ..v..<...4..J.b.
04c0 - 36 8e 0c 5d ce d8 72 df-70 26 37 79 3b e2 50 77   6..]..r.p&7y;.Pw
04d0 - 8c 37 3a 0f dc 5b 81 87-26 7c 56 26 5b 93 4f 7d   .7:..[..&|V&[.O}
04e0 - ab 8a 96 3b 0a 62 73 44-7b 65 63 5a a2 88 2f 7a   ...;.bsD{ecZ../z
04f0 - 82 fb 19 90 81 11 1a c6-f1 5b dc d1 72 fb 9a 31   .........[..r..1
0500 - 5d 52 6b 31 a5 cd 1e 49-50 e0 0a 1c d6 74 4d c3   ]Rk1...IP....tM.
0510 - d6 af fe 1a 9c f2 a0 be-3f d1 08 21 ab 9d d4 e8   ........?..!....
0520 - 83 ed 47 5a d7 f7 b4 2c-10 31 e8 b3 1b 44 58 1c   ..GZ...,.1...DX.
0530 - 73 5a 2a 06 43 8a d6 51-84 de 28 92 46 9c b5 cd   sZ*.C..Q..(.F...
0540 - 3b 63 56 7c 6d 1d 18 86-02 e2 9e 66 06 b1 aa c2   ;cV|m......f....
0550 - 96 ab 6c 3b 80 d8 3b c2-3c 16 f9 b0 36 d1 32 1b   ..l;..;.<...6.2.
0560 - b5 f7 c2 ed 07 9e 7b c6-2b 4c 5b 4b 86 35 10 02   ......{.+L[K.5..
0570 - 94 69 6a 08 0b 88 fb cb-20 79 b5 fb af 09 7f ab   .ij..... y......
0580 - 35 72 a2 ed fe 7c ab 15-1a b4 3a 5a c4 f9 b3 ee   5r...|....:Z....
0590 - cb 21 00 1b 00 03 02 00-01                        .!.......
SSL_connect:SSLv3/TLS write client hello
read from 0x22ec0da5e10 [0x22ec11ccfb3] (5 bytes => 5 (0x5))
0000 - 16 03 03 04 db                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 1243
read from 0x22ec0da5e10 [0x22ec11ccfb8] (1243 bytes => 1243 (0x4DB))
0000 - 02 00 04 d7 03 03 69 22-ef 64 e7 c9 3b 97 3a b4   ......i".d..;.:.
0010 - 91 6d 02 23 9c 10 3b d8-cc 41 c7 48 f6 f5 48 b3   .m.#..;..A.H..H.
0020 - 13 ca 93 6d 03 08 20 8a-aa d7 16 c2 ad 4e c0 0a   ...m.. ......N..
0030 - 95 35 48 f6 2c fa 19 07-5e 0c 95 d8 4d f1 bc e8   .5H.,...^...M...
0040 - 83 6c 5a 3d d3 70 b6 13-02 00 04 8f 00 2b 00 02   .lZ=.p.......+..
0050 - 03 04 00 33 04 85 11 eb-04 81 04 46 e1 78 dc 5b   ...3.......F.x.[
0060 - cc 6d db ef e1 5f ca d6-d5 4f 04 93 06 3c 32 41   .m..._...O...<2A
0070 - 2d 7f 3d 9e 23 cf 20 ce-e3 59 30 ce 3e 81 b1 a1   -.=.#. ..Y0.>...
0080 - 2b 82 67 7b b6 26 3d 43-8b a0 bb 4a b2 23 59 30   +.g{.&=C...J.#Y0
0090 - 6c 4a 44 5e ae ec 4d 34-d1 4b 7c f8 bb 15 17 49   lJD^..M4.K|....I
00a0 - 4a 8e 7c b6 64 49 57 e2-bc f5 f8 57 6a b6 d7 c3   J.|.dIW....Wj...
00b0 - 0a 0e 3b 68 d9 f0 ed fd-b3 0f e5 f2 67 bb a4 61   ..;h........g..a
00c0 - 8f 2c d3 ac 71 9e 6a ef-03 c1 c6 47 b2 e4 5b cf   .,..q.j....G..[.
00d0 - d2 04 cd b2 98 bb 62 a9-16 f6 26 e5 0d 55 cf 6c   ......b...&..U.l
00e0 - d0 08 79 90 60 43 69 16-6a 44 2d f8 3b c7 35 43   ..y.`Ci.jD-.;.5C
00f0 - 3f 6c 0a 33 fc a1 53 fe-c8 c8 bf b6 57 c0 71 25   ?l.3..S.....W.q%
0100 - 84 25 e1 6f 88 f7 0e ea-a9 e7 f7 d2 58 f6 8d 4e   .%.o........X..N
0110 - 1e a3 fc 86 45 f1 65 d2-e8 ee b7 09 2c 05 53 88   ....E.e.....,.S.
0120 - f2 15 cf d6 2a 70 e2 b5-73 e2 26 d3 a7 36 c2 cd   ....*p..s.&..6..
0130 - f8 90 c0 d2 7c 4f 27 ef-0f e7 01 9b c0 f6 62 61   ....|O'.......ba
0140 - 52 97 b1 9a e9 8c cb c4-58 86 a2 ec a8 66 a6 39   R.......X....f.9
0150 - 68 3e 42 23 84 0a fa f7-4c 49 35 f3 a1 4d 67 57   h>B#....LI5..MgW
0160 - da 27 56 d9 93 26 7c 48-37 68 d8 90 56 7b 10 c0   .'V..&|H7h..V{..
0170 - 08 97 89 1e 5c 4d 58 51-a0 06 cf 55 a2 2c c6 91   ....\MXQ...U.,..
0180 - 79 6f ff 67 88 0d 41 e6-31 fe e7 ea f0 f4 70 11   yo.g..A.1.....p.
0190 - 87 07 ea f2 d0 fd 6e 42-29 81 f4 98 30 77 7d 2a   ......nB)...0w}*
01a0 - 39 6b 8d 56 08 bf de 0d-24 f8 27 12 b1 f8 bb d1   9k.V....$.'.....
01b0 - e5 48 3f 02 04 5a b3 ea-cf e1 32 73 2a de d6 50   .H?..Z....2s*..P
01c0 - 45 77 aa d8 84 e1 82 bc-f1 7d ab af 10 fa ad 73   Ew.......}.....s
01d0 - d3 5f 59 53 6d b9 ad b7-69 06 ea 04 7f e1 09 e8   ._YSm...i.......
01e0 - 55 62 4c 97 fe 65 b2 ca-3f ab 35 2f 0b b8 28 95   UbL..e..?.5/..(.
01f0 - c3 38 93 2f 0c 72 e5 ca-d8 b0 af 0e c7 eb 8c cb   .8./.r..........
0200 - ef 25 15 68 f1 6d 5c 1c-1d 64 3f 6e 03 15 e0 4e   .%.h.m\..d?n...N
0210 - 30 6b 3b b7 05 a4 73 1f-00 59 58 13 f3 5f ed 16   0k;...s..YX.._..
0220 - 03 f2 3f 3e 27 c1 7a 08-7e f4 42 20 6a b6 4b 5d   ..?>'.z.~.B j.K]
0230 - 97 b3 ce 98 e2 5c 62 ea-0c 03 b6 81 74 49 1a f6   .....\b.....tI..
0240 - cc a5 be 61 e8 63 a9 02-46 10 cc df fa c9 49 67   ...a.c..F.....Ig
0250 - 18 bb 17 32 ec 3e 60 af-56 12 cf 2a 16 00 c2 60   ...2.>`.V..*...`
0260 - 7a 2a c0 30 57 28 d7 0b-e4 6a 81 aa 30 2e ad d3   z*.0W(...j..0...
0270 - 69 3b 40 38 df 53 7f 4e-02 39 9e b3 f1 e3 65 b6   i;@8.S.N.9....e.
0280 - 51 79 80 56 28 9b 90 51-8a 8a 4f 5c ef c5 36 ca   Qy.V(..Q..O\..6.
0290 - 3d 3c cd 29 cb a6 c6 6b-83 a1 1a 77 71 52 df 26   =<.)...k...wqR.&
02a0 - 93 29 ec 22 8a 6d 70 b0-a7 6d e2 d5 19 0f e3 46   .).".mp..m.....F
02b0 - 64 d5 17 58 44 fe 2e 5f-b5 5d d3 8d 4f 3f 0f 79   d..XD.._.]..O?.y
02c0 - a6 07 ec 2f 7d 35 4a b3-dd 2f 1c ba 05 03 e0 7b   .../}5J../.....{
02d0 - 4c 7c d8 f7 9b cf 76 eb-05 6d d5 cb a2 9d 35 57   L|....v..m....5W
02e0 - f3 c6 2c 3d 19 56 75 12-1a de 53 eb 9a ba 7e 90   ..,=.Vu...S...~.
02f0 - 1f cd bc 11 af 33 01 07-48 71 35 90 d6 5e 85 23   .....3..Hq5..^.#
0300 - 88 d3 31 9b e3 7c c2 b9-4b f0 28 ca c5 38 1f d7   ..1..|..K.(..8..
0310 - fa 65 8f a0 b6 c4 8e 35-47 51 2f 6e 1c 40 24 94   .e.....5GQ/n.@$.
0320 - b0 ad 18 80 a4 39 37 5d-26 80 ad 73 f1 0f f1 25   .....97]&..s...%
0330 - e0 1f 38 d6 c8 44 f8 db-fd ad 63 53 b8 5d 7f 22   ..8..D....cS.]."
0340 - 2d 63 5d 78 1c d3 e4 8c-08 7d 79 ff fd 7e d7 20   -c]x.....}y..~.
0350 - 32 5d 88 25 53 1e f7 35-b1 af 77 1f 41 61 03 e3   2].%S..5..w.Aa..
0360 - c9 4e aa d1 d3 4c 6f cc-a6 6b 2e 26 d9 85 b7 90   .N...Lo..k.&....
0370 - 2b 9a 24 ff 35 27 32 b4-f6 47 7c 03 fe 75 2f fe   +.$.5'2..G|..u/.
0380 - 02 12 ff c3 32 f6 f7 5c-2d b6 f3 12 1a 6b 23 32   ....2..\-....k#2
0390 - e4 a4 c4 ce bb e5 61 a3-cc 00 27 eb a6 2b e0 fc   ......a...'..+..
03a0 - 42 48 74 2c 82 c8 60 fd-c5 a3 94 60 98 00 e9 e0   BHt,..`....`....
03b0 - 84 43 26 a3 3b 33 3c 0f-eb 95 27 96 6c b5 f2 e7   .C&.;3<...'.l...
03c0 - d7 0a fb 7f 42 76 bc 8f-72 0d a3 29 6a f3 ca 46   ....Bv..r..)j..F
03d0 - d2 a8 3a 59 a2 46 23 2c-e0 c2 50 0d b9 07 4f cb   ..:Y.F#,..P...O.
03e0 - 10 10 ca d2 6c 32 fc 18-eb 1d 97 3c f5 22 cc ba   ....l2.....<."..
03f0 - d7 a0 48 ed 2e 8e 12 df-27 e2 9e c4 50 e9 8c d4   ..H.....'...P...
0400 - 80 b1 08 ce 0a e1 dc 53-7a f1 62 ee ce 35 b7 d0   .......Sz.b..5..
0410 - 10 a0 da 91 18 39 68 cc-c2 27 9e 8a 2e 22 87 1c   .....9h..'..."..
0420 - 1c 6e a4 48 07 5a 38 9d-e9 01 e3 84 94 36 23 06   .n.H.Z8......6#.
0430 - 89 21 ba 93 c7 d4 6d 97-50 99 e3 b9 6d c4 0d f0   .!....m.P...m...
0440 - ae f0 fa 7b d2 53 24 df-72 f6 37 3f da e7 72 55   ...{.S$.r.7?..rU
0450 - b2 b7 11 87 5f 98 c7 02-42 9f 37 27 81 e2 31 f3   ...._...B.7'..1.
0460 - 19 b3 aa 68 93 93 ea c3-d5 6d f2 56 5c c6 b0 97   ...h.....m.V\...
0470 - ce 86 6c 77 49 e3 c4 41-39 f9 c9 63 fb 97 8d b9   ..lwI..A9..c....
0480 - 59 10 79 08 7b 64 2d 68-da 63 70 21 f0 23 37 51   Y.y.{d-h.cp!.#7Q
0490 - 0d 61 74 de e2 ef b8 93-99 5a 74 01 93 6a da c5   .at......Zt..j..
04a0 - 2c a3 57 46 23 cf b1 78-20 68 ec f0 68 2c f8 58   ,.WF#..x h..h,.X
04b0 - 7e b0 90 dd 16 97 2e 5c-a4 61 49 72 8f 09 07 de   ~......\.aIr....
04c0 - 4f 59 cb d6 52 f9 f7 0f-dc b5 2b 81 ad f4 ad cc   OY..R.....+.....
04d0 - 42 45 fa 02 9d 3e 37 5b-2e 28 c5                  BE...>7[.(.
SSL_connect:SSLv3/TLS write client hello
    ServerHello, Length=1239
      server_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0x6922EF64
        random_bytes (len=28): E7C93B973AB4916D02239C103BD8CC41C748F6F548B313CA936D0308
      session_id (len=32): 8AAAD716C2AD4EC00A953548F62CFA19075E0C95D84DF1BCE8836C5A3DD370B6
      cipher_suite {0x13, 0x02} TLS_AES_256_GCM_SHA384
      compression_method: No Compression (0x00)
      extensions, length = 1167
        extension_type=supported_versions(43), length=2
            TLS 1.3 (772)
        extension_type=key_share(51), length=1157
            NamedGroup: SecP256r1MLKEM768 (4587)
            key_exchange:  (len=1153): 0446E178DC5BCC6DDBEFE15FCAD6D54F0493063C32412D7F3D9E23CF20CEE35930CE3E81B1A12B82677BB6263D438BA0BB4AB22359306C4A445EAEEC4D34D14B7CF8BB1517494A8E7CB6644957E2BCF5F8576AB6D7C30A0E3B68D9F0EDFDB30FE5F267BBA4618F2CD3AC719E6AEF03C1C647B2E45BCFD204CDB298BB62A916F626E50D55CF6CD0087990604369166A442DF83BC735433F6C0A33FCA153FEC8C8BFB657C071258425E16F88F70EEAA9E7F7D258F68D4E1EA3FC8645F165D2E8EEB7092C055388F215CFD62A70E2B573E226D3A736C2CDF890C0D27C4F27EF0FE7019BC0F662615297B19AE98CCBC45886A2ECA866A639683E4223840AFAF74C4935F3A14D6757DA2756D993267C483768D890567B10C00897891E5C4D5851A006CF55A22CC691796FFF67880D41E631FEE7EAF0F470118707EAF2D0FD6E422981F49830777D2A396B8D5608BFDE0D24F82712B1F8BBD1E5483F02045AB3EACFE132732ADED6504577AAD884E182BCF17DABAF10FAAD73D35F59536DB9ADB76906EA047FE109E855624C97FE65B2CA3FAB352F0BB82895C338932F0C72E5CAD8B0AF0EC7EB8CCBEF251568F16D5C1C1D643F6E0315E04E306B3BB705A4731F00595813F35FED1603F23F3E27C17A087EF442206AB64B5D97B3CE98E25C62EA0C03B68174491AF6CCA5BE61E863A9024610CCDFFAC9496718BB1732EC3E60AF5612CF2A1600C2607A2AC0305728D70BE46A81AA302EADD3693B4038DF537F4E02399EB3F1E365B651798056289B90518A8A4F5CEFC536CA3D3CCD29CBA6C66B83A11A777152DF269329EC228A6D70B0A76DE2D5190FE34664D5175844FE2E5FB55DD38D4F3F0F79A607EC2F7D354AB3DD2F1CBA0503E07B4C7CD8F79BCF76EB056DD5CBA29D3557F3C62C3D195675121ADE53EB9ABA7E901FCDBC11AF33010748713590D65E852388D3319BE37CC2B94BF028CAC5381FD7FA658FA0B6C48E3547512F6E1C402494B0AD1880A439375D2680AD73F10FF125E01F38D6C844F8DBFDAD6353B85D7F222D635D781CD3E48C087D79FFFD7ED720325D8825531EF735B1AF771F416103E3C94EAAD1D34C6FCCA66B2E26D985B7902B9A24FF352732B4F6477C03FE752FFE0212FFC332F6F75C2DB6F3121A6B2332E4A4C4CEBBE561A3CC0027EBA62BE0FC4248742C82C860FDC5A394609800E9E0844326A33B333C0FEB9527966CB5F2E7D70AFB7F4276BC8F720DA3296AF3CA46D2A83A59A246232CE0C2500DB9074FCB1010CAD26C32FC18EB1D973CF522CCBAD7A048ED2E8E12DF27E29EC450E98CD480B108CE0AE1DC537AF162EECE35B7D010A0DA91183968CCC2279E8A2E22871C1C6EA448075A389DE901E384943623068921BA93C7D46D975099E3B96DC40DF0AEF0FA7BD25324DF72F6373FDAE77255B2B711875F98C702429F372781E231F319B3AA689393EAC3D56DF2565CC6B097CE866C7749E3C44139F9C963FB978DB9591079087B642D68DA637021F02337510D6174DEE2EFB893995A7401936ADAC52CA3574623CFB1782068ECF0682CF8587EB090DD16972E5CA46149728F0907DE4F59CBD652F9F70FDCB52B81ADF4ADCC4245FA029D3E375B2E28C5

read from 0x22ec0da5e10 [0x22ec11ccc03] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ChangeCipherSpec (20)
  Length = 1
read from 0x22ec0da5e10 [0x22ec11ccc08] (1 bytes => 1 (0x1))
0000 - 01                                                .
    change_cipher_spec (1)

read from 0x22ec0da5e10 [0x22ec11ccc03] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 23
read from 0x22ec0da5e10 [0x22ec11ccc08] (23 bytes => 23 (0x17))
0000 - 48 ca 48 fa 51 ff 1c 51-33 db d2 e1 5f ea b9 56   H.H.Q..Q3..._..V
0010 - 4a 19 f9 82 00 9b dd                              J......
  Inner Content Type = Handshake (22)
SSL_connect:SSLv3/TLS read server hello
    EncryptedExtensions, Length=2
      No extensions

Can't use SSL_get_servername
read from 0x22ec0da5e10 [0x22ec11ccc03] (5 bytes => 5 (0x5))
0000 - 17 03 03 03 7e                                    ....~
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 894
read from 0x22ec0da5e10 [0x22ec11ccc08] (894 bytes => 894 (0x37E))
0000 - 6c 61 5c 8a be b1 68 6d-74 9a 3f b6 c3 82 e0 52   la\...hmt.?....R
0010 - 4d bd 78 e6 b6 03 52 c8-ce c6 e1 a0 b5 09 74 78   M.x...R.......tx
0020 - 15 cf 03 51 14 7a 50 90-87 5b fd b1 9b b7 ad a7   ...Q.zP..[......
0030 - de 50 f7 57 72 5d 80 57-60 e5 38 1c 3d 6c 80 3f   .P.Wr].W`.8.=l.?
0040 - 8e 3f d3 f2 2f 2d b3 40-11 40 83 87 53 bb c0 dc   .?../-.@.@..S...
0050 - 6d f3 06 82 63 32 eb 09-09 33 00 2f 75 56 7a 45   m...c2...3./uVzE
0060 - a2 c2 ea 41 50 5f ea 80-9a 32 64 6a f4 1c 8a eb   ...AP_...2dj....
0070 - 40 0d 75 3a ef c6 66 ff-7b 75 b1 f2 0a 0c 77 42   @.u:..f.{u....wB
0080 - c9 07 16 5a 3b 43 73 f5-ad 09 07 19 87 b9 67 b6   ...Z;Cs.......g.
0090 - c9 4c 2a 34 8b c9 4c 47-88 15 0b b0 dc 08 2b 75   .L*4..LG......+u
00a0 - d3 3d 0e 00 8c b0 44 1d-ab 76 3d bc df 88 ce 49   .=....D..v=....I
00b0 - ba 94 e8 ec 5a cf e7 14-e4 b2 97 e5 4f 48 d6 d0   ....Z.......OH..
00c0 - e5 c7 f9 7c bf d2 ee 01-ba 35 05 be 3f 4a a2 ca   ...|.....5..?J..
00d0 - cd ae 25 33 c1 01 ba f7-4e 0b 1e b8 94 01 97 13   ..%3....N.......
00e0 - 15 16 4f 8a 25 46 21 aa-16 19 47 a9 64 d3 f9 4b   ..O.%F!...G.d..K
00f0 - dc ee 1f 86 5b 21 37 c7-75 5a 69 70 a1 61 c7 38   ....[!7.uZip.a.8
0100 - 3f c6 4e 47 4c 93 40 dd-5f 0f a0 6f 3c 63 98 13   ?.NGL.@._..o<c..
0110 - f1 e1 b6 6d 27 72 c9 50-77 1a e4 3a 08 47 30 a3   ...m'r.Pw..:.G0.
0120 - ec c0 7b 25 4b 22 fc 8d-e9 21 88 9a 71 bc 95 72   ..{%K"...!..q..r
0130 - 73 2d 4b d4 77 2f 45 90-5c 62 46 10 a8 a6 10 32   s-K.w/E.\bF....2
0140 - db df 95 67 06 fc 6e 04-74 4c 00 0a 3a d9 35 43   ...g..n.tL..:.5C
0150 - 4f 3a 45 21 af b3 9b 5f-df d0 6f 06 77 42 9a 67   O:E!..._..o.wB.g
0160 - 87 92 32 06 39 dc ec c8-3e ff 0a 1b 65 43 70 27   ..2.9...>...eCp'
0170 - 28 47 a9 34 92 d5 18 36-82 5b 24 bc 64 8e 00 ca   (G.4...6.[$.d...
0180 - c6 86 a6 17 df e7 4f 34-83 d9 71 df 64 e1 14 f2   ......O4..q.d...
0190 - 4b 70 69 70 eb 58 36 ff-87 36 45 a1 42 66 83 e6   Kpip.X6..6E.Bf..
01a0 - 0e cd f5 8f e5 db 99 7c-a6 19 44 ee 8e 6d cc 58   .......|..D..m.X
01b0 - 48 0b 96 cd ed a9 0a de-0c 1a f8 34 32 83 08 cd   H..........42...
01c0 - 9a 74 c2 ec cd 0f 01 ee-11 a5 da 8c 54 21 49 18   .t..........T!I.
01d0 - ec 05 e6 c5 2c 7f b0 2b-db 25 79 29 a8 07 9a 52   ....,..+.%y)...R
01e0 - 54 ee 3b 18 44 e8 83 e9-65 75 a9 55 46 98 b7 b0   T.;.D...eu.UF...
01f0 - c1 b0 99 d1 7c a2 00 99-9a 3f 8d 19 b7 5e 9b 9c   ....|....?...^..
0200 - 01 11 29 b2 79 9b 69 0e-35 be 14 2f 35 18 c9 8f   ..).y.i.5../5...
0210 - 7b 65 f8 11 4c da 95 a2-41 ee 3e 75 d9 08 a1 a5   {e..L...A.>u....
0220 - 75 08 f2 a5 f4 39 1e 93-d2 12 6c 78 dd 21 c1 c1   u....9....lx.!..
0230 - d3 b2 fc 31 75 22 96 7c-b7 c4 f6 59 b2 8f 18 16   ...1u".|...Y....
0240 - 75 54 3e 34 ec 61 9b 07-ad b9 ee a3 c6 0d b6 ac   uT>4.a..........
0250 - ed 55 1e a1 8f 67 62 55-81 db 04 06 43 f6 bf f5   .U...gbU....C...
0260 - 26 29 d6 5c 9d 1e e8 e5-e3 22 11 f0 74 8f c4 b3   &).\....."..t...
0270 - 41 4d 04 43 55 1f 00 1f-84 f6 b1 25 30 fc de 66   AM.CU......%0..f
0280 - 01 2b d2 88 5c 85 a8 53-4f 66 6c 5d f9 1b 7a d5   .+..\..SOfl]..z.
0290 - cd 76 21 79 69 fa 70 9b-08 48 87 54 d3 76 12 fc   .v!yi.p..H.T.v..
02a0 - f8 b0 48 ff c5 6f 46 6e-7d 10 b3 24 b7 39 d7 1d   ..H..oFn}..$.9..
02b0 - d6 63 bb 4c 81 2d 8d bb-dc 68 4f fe af c2 95 ae   .c.L.-...hO.....
02c0 - 7d 93 d0 ab cb c8 6d 3b-bb 6a a7 cb ae 92 2a 1f   }.....m;.j....*.
02d0 - bf dc 48 18 01 69 86 ab-02 e2 46 8e 6b b3 9e dd   ..H..i....F.k...
02e0 - aa 44 a7 0d 95 b8 81 6e-2c 6d bf 2c f1 1d a4 2a   .D.....n,m.,...*
02f0 - 85 df 81 44 5d 88 c9 01-90 90 77 4e ef 71 12 4b   ...D].....wN.q.K
0300 - 2e aa 73 bb d1 89 bd e2-2c d0 ca d3 c2 fb c3 b2   ..s.....,.......
0310 - 0a e2 67 e8 69 7b 8d ed-0f 78 36 02 30 43 7d b4   ..g.i{...x6.0C}.
0320 - 1f 8a a1 29 90 7f e9 9c-c0 ca 6c 14 81 80 31 d9   ...)......l...1.
0330 - b4 73 50 c8 33 e0 31 87-e5 65 c9 2b be a5 35 c8   .sP.3.1..e.+..5.
0340 - 01 c5 1d c0 43 87 31 fb-c2 d9 b0 97 3d 1b c5 13   ....C.1.....=...
0350 - 78 ea 54 c8 b0 18 de f6-5e e4 d4 87 ce 61 0f 35   x.T.....^....a.5
0360 - 1f 0b b1 36 10 ad 44 fb-c7 78 5d c8 93 b9 85 58   ...6..D..x]....X
0370 - 3c ce 29 c5 4e 77 2b d2-90 b4 f0 64 0e ba         <.).Nw+....d..
  Inner Content Type = Handshake (22)
SSL_connect:TLSv1.3 read encrypted extensions
    Certificate, Length=873
      context (len=0):
      certificate_list, length=869
        ASN.1Cert, length=864
------details-----
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            63:a6:71:10:79:d6:a6:48:59:da:67:a9:04:e8:e3:5f:e2:03:a3:26
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = KR, ST = GG, L = YI, O = Test, OU = Test, CN = Test Root
        Validity
            Not Before: Aug 29 06:27:17 2024 GMT
            Not After : Aug 29 06:27:17 2025 GMT
        Subject: C = KR, ST = GG, L = YI, O = Test, OU = Test, CN = Test
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ad:9a:29:67:5f:f3:a4:79:b4:c6:e6:32:73:d8:
                    d7:ed:88:94:15:83:e4:31:00:04:6c:b5:8c:ac:87:
                    ab:74:44:13:76:ca:0b:74:29:40:9e:97:2a:01:d7:
                    8b:46:26:6e:19:35:4d:c0:d3:b5:ea:0e:93:3a:06:
                    e8:e5:85:b5:27:05:63:db:28:b8:92:da:5a:14:39:
                    0f:da:68:6d:6f:0a:fb:52:dc:08:0f:54:d3:e4:a2:
                    28:9d:a0:71:50:82:e0:db:ca:d1:94:dd:42:98:3a:
                    09:33:a8:d9:ef:fb:d2:35:43:b1:22:a2:be:41:6d:
                    ba:91:dc:0b:31:4e:88:f9:4d:9c:61:2d:ec:b2:13:
                    0a:c2:91:8e:a2:d6:e9:40:b9:32:b9:80:8f:b3:18:
                    a3:33:13:23:d5:d0:7e:d9:d0:7f:93:e0:2d:4d:90:
                    c5:58:24:56:d5:c9:10:13:4a:b2:99:23:7d:34:b9:
                    8e:97:19:69:6f:ce:c6:3f:d6:17:a7:d2:43:e0:36:
                    cb:51:7b:2f:18:8b:c2:33:f8:57:cf:d1:61:0b:7c:
                    ed:37:35:e3:13:7a:24:2e:77:08:c2:e3:d9:e6:17:
                    d3:a5:c6:34:5a:da:86:a7:f8:02:36:1d:66:63:cf:
                    e9:c0:3d:82:fb:39:a2:8d:92:01:4a:83:cf:e2:76:
                    3d:87
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Alternative Name:
                DNS:test.princeb612.pe
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        00:a5:f5:54:18:ab:ad:36:38:c8:fc:0b:66:60:dd:9f:75:9d:
        86:5b:79:2f:ee:57:f1:79:1c:15:a1:34:23:d0:1c:a9:58:51:
        a4:d0:08:f5:d8:f7:49:e9:c5:b5:65:91:51:2d:6d:e4:3b:0e:
        77:02:1f:45:8e:34:e5:bb:eb:f6:9d:df:4a:40:60:21:b3:8e:
        16:33:3f:f4:b6:90:d3:3c:34:ce:e6:d9:47:07:a7:57:14:0c:
        f9:78:0b:36:72:a9:88:07:07:93:b4:d7:fe:29:5e:e8:41:37:
        20:a5:03:c7:97:cb:82:ca:db:14:e5:8b:96:1f:a9:e9:20:3d:
        6b:25:ae:f4:89:4c:60:8d:e9:14:33:47:4b:88:54:a2:47:19:
        81:c8:7b:0e:32:52:2b:91:88:ad:0f:6d:73:30:8c:00:af:d5:
        fc:46:46:af:3a:c2:17:89:ec:c8:83:ae:da:e6:69:63:e0:9c:
        84:22:c5:7a:de:e8:23:6b:53:9d:6f:94:d2:7f:5c:be:1d:0c:
        de:0e:07:0d:52:a5:43:8c:e8:05:ef:c0:ff:f0:73:fa:dc:5a:
        51:4c:24:09:65:45:7d:ab:52:8b:7e:5d:f0:fb:de:a7:3d:43:
        c5:af:76:e3:6e:f9:a1:dc:78:a2:bd:54:41:04:99:e5:56:32:
        ba:02:fd:72
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
------------------
        No extensions

depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
verify error:num=10:certificate has expired
notAfter=Aug 29 06:27:17 2025 GMT
verify return:1
depth=0 C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
notAfter=Aug 29 06:27:17 2025 GMT
verify return:1
read from 0x22ec0da5e10 [0x22ec11ccc03] (5 bytes => 5 (0x5))
0000 - 17 03 03 01 19                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 281
read from 0x22ec0da5e10 [0x22ec11ccc08] (281 bytes => 281 (0x119))
0000 - 50 bd 9c 79 0c 36 6a ea-4a 18 1c 88 d7 89 8c 65   P..y.6j.J......e
0010 - ad b7 a3 00 03 69 42 d1-49 e7 31 78 7f b3 22 1e   .....iB.I.1x..".
0020 - 7c 35 9e 31 9d 7f a4 84-21 ec e9 f7 f0 59 5a e5   |5.1....!....YZ.
0030 - d7 53 e6 3c 49 8f 8a dc-0f 18 cd e5 7c 2f 01 38   .S.<I.......|/.8
0040 - 61 85 2f 22 c7 8d 39 fd-05 39 ca 14 8b b9 cd 27   a./"..9..9.....'
0050 - 1f 0c b2 c0 21 53 cf d3-34 33 96 d4 75 e1 1f 5d   ....!S..43..u..]
0060 - 25 c9 d1 d5 10 ea f1 0a-ea 34 e3 47 5c bd 78 3a   %........4.G\.x:
0070 - 2d fd 54 02 96 dc ea 6f-21 05 d7 02 8b e6 c6 83   -.T....o!.......
0080 - 08 4e 19 52 ab 15 88 82-06 00 33 96 fe 28 96 a1   .N.R......3..(..
0090 - 56 80 a3 78 c5 0f 72 72-8b 73 9f d8 a0 ca 9f 38   V..x..rr.s.....8
00a0 - 5d 4a 49 44 1d fb 34 ee-38 4f f0 cb 86 28 04 3a   ]JID..4.8O...(.:
00b0 - 87 59 9e df 3e 37 d4 3a-58 53 77 e4 c4 fb 10 ad   .Y..>7.:XSw.....
00c0 - fa e3 c1 e8 7e 44 a9 78-bb be a2 fa a1 1d 73 76   ....~D.x......sv
00d0 - 58 72 42 5b 42 5a 91 11-2c 77 bc f8 34 79 5a 2c   XrB[BZ..,w..4yZ,
00e0 - 18 04 09 80 8b 4e 1a 76-bc a0 a8 1f f1 77 72 f0   .....N.v.....wr.
00f0 - 9e 30 92 ae d0 b6 54 15-b3 88 7d 0d 8e e2 4c 8a   .0....T...}...L.
0100 - 4f b5 b0 20 da 78 b6 fa-86 a4 4a ba f7 25 e8 48   O.. .x....J..%.H
0110 - 99 75 52 dc ae cf 08 95-bc                        .uR......
  Inner Content Type = Handshake (22)
SSL_connect:SSLv3/TLS read server certificate
    CertificateVerify, Length=260
      Signature Algorithm: rsa_pss_rsae_sha256 (0x0804)
      Signature (len=256): 0E64E6E06F5E40629B9FA7F6F3C723A65A17B38EBE7CB8D470B0B00DC5EA4B5FCCAC51C5593490144B941086741F6E51AE02B895E062489C7155C9D1998DE3C27308DD9C1D8194C88CB10CACDF08D40DA516C2E800CDA5B808592D5E5C1632A94434B81DC5C05A81F4A4DC70C1817050AA2455C8EBF1BC4C507F0C68168DB3E7B225B67989D2B158677B1B13E0099E2EBE76BBA3E080C08BD9A7C1FE8DDD5BBFE4D471D2B941EA947F7D557AD7E2AE410E552E9537AAFAD5D43FF431957B45B7696F728BC5C48BD0C7F1A177A9CDD2505B8AC9AE036A7CB6D0F32C15021A232B34276DECB8669EDDC87A0A037EB89EE00A695414FC1AB076C0E986571F847A7D

read from 0x22ec0da5e10 [0x22ec11ccc03] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 45                                    ....E
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 69
read from 0x22ec0da5e10 [0x22ec11ccc08] (69 bytes => 69 (0x45))
0000 - c9 25 77 b2 fa bb 61 8b-5a fd 59 b7 1d e6 ca c8   .%w...a.Z.Y.....
0010 - 97 07 99 d5 64 6d ca 49-7a 3f 58 e2 ea 30 b4 18   ....dm.Iz?X..0..
0020 - 30 79 67 c3 e5 a1 c5 4d-9f 4d 28 13 ca 19 52 2a   0yg....M.M(...R*
0030 - 45 1d 53 36 06 77 92 d0-74 99 22 02 d5 07 36 71   E.S6.w..t."...6q
0040 - 16 d6 a5 28 1c                                    ...(.
  Inner Content Type = Handshake (22)
SSL_connect:TLSv1.3 read server certificate verify
    Finished, Length=48
      verify_data (len=48): D16D1C7AB80D63C4D7256208201C6BA422422BF2EC36BD02CBC8A3F0AC6BD615FD928796BB632A5CA72CEC9A400747BC

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
      verify_data (len=48): D667ABCA5A0AA167B0868089F3B22DCD06E9BABE08B8C8D782D8B0DA0E803A88C84B6E6B6FFE78A315A47FA7DD2B2A71

write to 0x22ec0da5e10 [0x22ec11c5910] (80 bytes => 80 (0x50))
0000 - 14 03 03 00 01 01 17 03-03 00 45 19 46 01 31 38   ..........E.F.18
0010 - fd a7 02 ae c0 e3 a5 1c-39 9c 4e 5a 6c ad 88 fc   ........9.NZl...
0020 - 80 bc b0 13 d8 b6 f1 3c-3a 15 e6 14 89 71 a2 d4   .......<:....q..
0030 - 2c b9 60 8a 1a 67 41 35-bf 9e f4 dc df 45 81 07   ,.`..gA5.....E..
0040 - 94 95 53 9d 31 c4 e5 93-39 3e b0 dd e3 12 e1 e7   ..S.1...9>......
SSL_connect:SSLv3/TLS write finished
---
Certificate chain
 0 s:C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test
   i:C=KR, ST=GG, L=YI, O=Test, OU=Test, CN=Test Root
   a:PKEY: RSA, 2048 (bit); sigalg: sha256WithRSAEncryption
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
Peer signature type: rsa_pss_rsae_sha256
Negotiated TLS1.3 group: SecP256r1MLKEM768
---
SSL handshake has read 2541 bytes and written 1513 bytes
Verification error: certificate has expired
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
Server public key is 2048 bit
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 10 (certificate has expired)
---
test
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 23
  Inner Content Type = ApplicationData (23)
write to 0x22ec0da5e10 [0x22ec11bf3a3] (28 bytes => 28 (0x1C))
0000 - 17 03 03 00 17 cb 90 27-2e 4f 2f 1d e5 c3 2b 36   .......'.O/...+6
0010 - eb 47 3a 5e 44 ec 2d 27-76 28 60 b9               .G:^D.-'v(`.
read from 0x22ec0da5e10 [0x22ec11c8773] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 23
read from 0x22ec0da5e10 [0x22ec11c8778] (23 bytes => 23 (0x17))
0000 - 9c 9b 73 d3 80 92 fc c3-ab 42 bd 9c b6 86 9a ba   ..s......B......
0010 - aa c7 1b 13 f5 96 3f                              ......?
  Inner Content Type = ApplicationData (23)
test
Q
DONE
Sent TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 19
  Inner Content Type = Alert (21)
write to 0x22ec0da5e10 [0x22ec11bf3a3] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 03 71 3e-d4 6b 29 97 00 36 36 38   ......q>.k)..668
0010 - f5 01 e6 07 ca 4a 89 2e-                          .....J..
    Level=warning(1), description=close notify(0)

SSL3 alert write:warning:close notify
read from 0x22ec0da5e10 [0x22ec0ccfcd0] (16384 bytes => 0)
````

[TOC](README.md)
