#### client

````
$ openssl s_client -connect localhost:9000 -state -debug -trace -keylogfile sslkeylog -tls1_3 --curves SecP384r1MLKEM1024
Connecting to ::1
CONNECTED(000001DC)
SSL_connect:before SSL initialization
Sent TLS Record
Header:
  Version = TLS 1.0 (0x301)
  Content Type = Handshake (22)
  Length = 1844
    ClientHello, Length=1840
      client_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0xA7731D19
        random_bytes (len=28): D7C400C193C55E68633EC3A87912106D6DC1CFD17706162A6F6540B0
      session_id (len=32): BB2538F8F71FC8C39379822E2BA6DEECA89713C68C07FBD2FBA6F12AAF5B7AF0
      cipher_suites (len=6)
        {0x13, 0x02} TLS_AES_256_GCM_SHA384
        {0x13, 0x03} TLS_CHACHA20_POLY1305_SHA256
        {0x13, 0x01} TLS_AES_128_GCM_SHA256
      compression_methods (len=1)
        No Compression (0x00)
      extensions, length = 1761
        extension_type=supported_groups(10), length=4
          UNKNOWN (4589)
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
        extension_type=key_share(51), length=1671
            NamedGroup: UNKNOWN (4589)
            key_exchange:  (len=1665): 04035D2C7D4912CBE06E780F88357980FAB5198384168948024644A73F4197BC17DA7C23D9677724A15CFD41AC0C8BD747AC4D4D938E4B04DE316618317083BAE548A42A63C4D757E87DA7E94AC152B60F0350EE8A91A634230877DBA431837E06C441ACEE8912EDDAC9B3883A4025CD269127A4E09BE7F5586EBB7474B95A0F094B5B626EF57846F4D687D8100DAB94041038738DE6485D040C758921F21572AAE45C40DAC49BFAB69DF83DE718B87A5597EF1A48C4A49DBC772482C3878D6724DFB61B8C81BAF79C5C095A6243340893A40F46AA159222440135B321E23051B572DF1867219572F027154E0C6B1DA0603AF5A0CBFAB89F64518F732E439905DCF953F1318A4725643521740879618003324C879288E550403A2E8580B135109FDE73CE6EB81E0FA8C22B8B37BB878F901A1DF100199B26ACF981071BDCC5303C75EDC404A1017ED4B8252C049D364C5EA5C087850B1E4546A91FB2B0647348729461E9883A39A3782169237FB609203272E2C57871645E5488B26883CF744658A6E076FDEC0382241195E107D9B09410DB14D4DB2F8F22AFAD2A5CBAC75D722700C3C02567238626237CBD7B61E488928C3A049655743C1C44F2ACB38DA3480B4B2122C21E932834222AB162052F2E238D44AB21F67715D615CB3F68A5AC85A4824785E78672103245E2D667501B8E5F66CB240C76A5183E7E2514BC2C138F35A9BA9981EE978FD19011A8B055BB675B670779320237D544148678722D390E939B6994E632FDD35DD419B921D458F5307180E9404AA42FCD917C1A27440F665231A7297A7445BFA06D6F28010E1A6A4396CB71EBA55A509F37E063E4F96CC3B53A63C12DE34CBF6CAB676280BE1B28276BA037EBEC05C985A7EB634B7C482501181C31C512CB6C1B51DC4E1DE57A9432743FA2A0C0CBABF7CCB231DB8D9B775DF9841AF3E4CA722AAAB9CA77DEB4561063074B835A3C4A86D241C47440626618B1B9A39BB14C86973160BAE16911C390E873BD8324B0A213A6C0C936CD16A685C556A63A3419F13D2188C4DB74CE330A9187EAB46F522BBC5217B67012D978C57851BE1321628895008F2ACA1CA3BA2678C38131071901B6EBA32DB865A71577278B431E4B286F375B87DFA848F2526C06F8A627C82E53E290A1F94E30676E6B96A3E2445B23A810AE7C0F5AF648FD25666BEBB48D6718AC687B2924C66A6A1B5696BC1FD6B220E637CBCB3DE4869FA7F46972E9495820867CA4C6C087CD81014E00129680B631FDA06657742C1D1519F94BCA898C5D0BC3185C68ACBEAC14AF4589CDC16EF82C71658886191C82B71B0F817289D2398DD74677783639FA6A493D34B3D9F7C5DF7833EB7859B776CA0A8A6E6C39904AB3466A40AF460078F87BA6C6F25B3E114B9179C302243ECCDC0324784E83A2CD556C45B74623424137147A8580C7BC8FF06641C942DEC2139D9C2AE460C9F9714663D52E9A5146051417626A84E471367A75576704781887A55B6C6910782252F52F100A85C5EBBAA708231CD6B8016818785B097922702C177940CA75D9EB97F515453D89486B9433C0BCA745B34DDEF4A77CF49324DA9E60F5BDDE7A4A6E8719D94385413B7771818169E07DB9D52010A983191297E1D1535FA411A34CA11F392D6E542B51E21089C53C6715447FB03A38641C1DA4B873C04F4BF2BBDBD8057214AFF86878DA91BBA090B0F96B59DA9696CA034FF2B53CBE628034E560B1FB8AE545B4CA437F8A7B7AEC9A6B4AE476AEF8AF5352A3FD1248BA51BFCDAA8D57826D6B99B631A7B23C00BDC8314BF5948C8D4ACDBF170E6FFB807603BCE923420BA1A0DB46CBDA84CCD8BCC1BAE144E3B468A42A7AD94598F040170F574B98A4AF626518C4E196E2C09E68E2873E4A490AB19B2699C32621984D850E2739B1BD84C9E99B30B36365E770BCD6B9908D61CC68F94A08112088F894B53C21E8620F89D3CE4359549E3125AF2712AA3C15B5D0132DBC9D21808803DB4EE0B92257853FCBB159A7294118FB6569937056C19562E955BC9B387652C97EA878B7A22CA41012A631091D5214072B1CF6EA70C9B8556F5A25B675B52D544758BC2C39EBC66003C90B87AF8FB674651A57C37557728072798641840A181341CE8DBBB598262A38677B1C27B93419135414CBE13123150759F394AF245B86D0F369C437B106072359A2C928E172D3A70ED0E588A3A40C98B651B148B39CF731FF691394615231C58FED21067DC73F12A50AA1A619B9F97364A45829E73DF4728ED1DA0721882F0DF0C41A80ADECA806C8FCB660209520A473E1FA3981C671EC1F8BFED2BA541289E9ABB331A5AA654B
        extension_type=compress_certificate(27), length=3
          zlib (1)

write to 0x1a988f876d0 [0x1a989455910] (1849 bytes => 1849 (0x739))
0000 - 16 03 01 07 34 01 00 07-30 03 03 a7 73 1d 19 d7   ....4...0...s...
0010 - c4 00 c1 93 c5 5e 68 63-3e c3 a8 79 12 10 6d 6d   .....^hc>..y..mm
0020 - c1 cf d1 77 06 16 2a 6f-65 40 b0 20 bb 25 38 f8   ...w..*oe@. .%8.
0030 - f7 1f c8 c3 93 79 82 2e-2b a6 de ec a8 97 13 c6   .....y..+.......
0040 - 8c 07 fb d2 fb a6 f1 2a-af 5b 7a f0 00 06 13 02   .......*.[z.....
0050 - 13 03 13 01 01 00 06 e1-00 0a 00 04 00 02 11 ed   ................
0060 - 00 23 00 00 00 16 00 00-00 17 00 00 00 0d 00 2a   .#.............*
0070 - 00 28 09 05 09 06 09 04-04 03 05 03 06 03 08 07   .(..............
0080 - 08 08 08 1a 08 1b 08 1c-08 09 08 0a 08 0b 08 04   ................
0090 - 08 05 08 06 04 01 05 01-06 01 00 2b 00 03 02 03   ...........+....
00a0 - 04 00 2d 00 02 01 01 00-33 06 87 06 85 11 ed 06   ..-.....3.......
00b0 - 81 04 03 5d 2c 7d 49 12-cb e0 6e 78 0f 88 35 79   ...],}I...nx..5y
00c0 - 80 fa b5 19 83 84 16 89-48 02 46 44 a7 3f 41 97   ........H.FD.?A.
00d0 - bc 17 da 7c 23 d9 67 77-24 a1 5c fd 41 ac 0c 8b   ...|#.gw$.\.A...
00e0 - d7 47 ac 4d 4d 93 8e 4b-04 de 31 66 18 31 70 83   .G.MM..K..1f.1p.
00f0 - ba e5 48 a4 2a 63 c4 d7-57 e8 7d a7 e9 4a c1 52   ..H.*c..W.}..J.R
0100 - b6 0f 03 50 ee 8a 91 a6-34 23 08 77 db a4 31 83   ...P....4#.w..1.
0110 - 7e 06 c4 41 ac ee 89 12-ed da c9 b3 88 3a 40 25   ~..A.........:@%
0120 - cd 26 91 27 a4 e0 9b e7-f5 58 6e bb 74 74 b9 5a   .&.'.....Xn.tt.Z
0130 - 0f 09 4b 5b 62 6e f5 78-46 f4 d6 87 d8 10 0d ab   ..K[bn.xF.......
0140 - 94 04 10 38 73 8d e6 48-5d 04 0c 75 89 21 f2 15   ...8s..H]..u.!..
0150 - 72 aa e4 5c 40 da c4 9b-fa b6 9d f8 3d e7 18 b8   r..\@.......=...
0160 - 7a 55 97 ef 1a 48 c4 a4-9d bc 77 24 82 c3 87 8d   zU...H....w$....
0170 - 67 24 df b6 1b 8c 81 ba-f7 9c 5c 09 5a 62 43 34   g$........\.ZbC4
0180 - 08 93 a4 0f 46 aa 15 92-22 44 01 35 b3 21 e2 30   ....F..."D.5.!.0
0190 - 51 b5 72 df 18 67 21 95-72 f0 27 15 4e 0c 6b 1d   Q.r..g!.r.'.N.k.
01a0 - a0 60 3a f5 a0 cb fa b8-9f 64 51 8f 73 2e 43 99   .`:......dQ.s.C.
01b0 - 05 dc f9 53 f1 31 8a 47-25 64 35 21 74 08 79 61   ...S.1.G%d5!t.ya
01c0 - 80 03 32 4c 87 92 88 e5-50 40 3a 2e 85 80 b1 35   ..2L....P@:....5
01d0 - 10 9f de 73 ce 6e b8 1e-0f a8 c2 2b 8b 37 bb 87   ...s.n.....+.7..
01e0 - 8f 90 1a 1d f1 00 19 9b-26 ac f9 81 07 1b dc c5   ........&.......
01f0 - 30 3c 75 ed c4 04 a1 01-7e d4 b8 25 2c 04 9d 36   0<u.....~..%,..6
0200 - 4c 5e a5 c0 87 85 0b 1e-45 46 a9 1f b2 b0 64 73   L^......EF....ds
0210 - 48 72 94 61 e9 88 3a 39-a3 78 21 69 23 7f b6 09   Hr.a..:9.x!i#...
0220 - 20 32 72 e2 c5 78 71 64-5e 54 88 b2 68 83 cf 74    2r..xqd^T..h..t
0230 - 46 58 a6 e0 76 fd ec 03-82 24 11 95 e1 07 d9 b0   FX..v....$......
0240 - 94 10 db 14 d4 db 2f 8f-22 af ad 2a 5c ba c7 5d   ....../."..*\..]
0250 - 72 27 00 c3 c0 25 67 23-86 26 23 7c bd 7b 61 e4   r'...%g#.&#|.{a.
0260 - 88 92 8c 3a 04 96 55 74-3c 1c 44 f2 ac b3 8d a3   ...:..Ut<.D.....
0270 - 48 0b 4b 21 22 c2 1e 93-28 34 22 2a b1 62 05 2f   H.K!"...(4"*.b./
0280 - 2e 23 8d 44 ab 21 f6 77-15 d6 15 cb 3f 68 a5 ac   .#.D.!.w....?h..
0290 - 85 a4 82 47 85 e7 86 72-10 32 45 e2 d6 67 50 1b   ...G...r.2E..gP.
02a0 - 8e 5f 66 cb 24 0c 76 a5-18 3e 7e 25 14 bc 2c 13   ._f.$.v..>~%..,.
02b0 - 8f 35 a9 ba 99 81 ee 97-8f d1 90 11 a8 b0 55 bb   .5............U.
02c0 - 67 5b 67 07 79 32 02 37-d5 44 14 86 78 72 2d 39   g[g.y2.7.D..xr-9
02d0 - 0e 93 9b 69 94 e6 32 fd-d3 5d d4 19 b9 21 d4 58   ...i..2..]...!.X
02e0 - f5 30 71 80 e9 40 4a a4-2f cd 91 7c 1a 27 44 0f   .0q..@J./..|.'D.
02f0 - 66 52 31 a7 29 7a 74 45-bf a0 6d 6f 28 01 0e 1a   fR1.)ztE..mo(...
0300 - 6a 43 96 cb 71 eb a5 5a-50 9f 37 e0 63 e4 f9 6c   jC..q..ZP.7.c..l
0310 - c3 b5 3a 63 c1 2d e3 4c-bf 6c ab 67 62 80 be 1b   ..:c.-.L.l.gb...
0320 - 28 27 6b a0 37 eb ec 05-c9 85 a7 eb 63 4b 7c 48   ('k.7.......cK|H
0330 - 25 01 18 1c 31 c5 12 cb-6c 1b 51 dc 4e 1d e5 7a   %...1...l.Q.N..z
0340 - 94 32 74 3f a2 a0 c0 cb-ab f7 cc b2 31 db 8d 9b   .2t?........1...
0350 - 77 5d f9 84 1a f3 e4 ca-72 2a aa b9 ca 77 de b4   w]......r*...w..
0360 - 56 10 63 07 4b 83 5a 3c-4a 86 d2 41 c4 74 40 62   V.c.K.Z<J..A.t@b
0370 - 66 18 b1 b9 a3 9b b1 4c-86 97 31 60 ba e1 69 11   f......L..1`..i.
0380 - c3 90 e8 73 bd 83 24 b0-a2 13 a6 c0 c9 36 cd 16   ...s..$......6..
0390 - a6 85 c5 56 a6 3a 34 19-f1 3d 21 88 c4 db 74 ce   ...V.:4..=!...t.
03a0 - 33 0a 91 87 ea b4 6f 52-2b bc 52 17 b6 70 12 d9   3.....oR+.R..p..
03b0 - 78 c5 78 51 be 13 21 62-88 95 00 8f 2a ca 1c a3   x.xQ..!b....*...
03c0 - ba 26 78 c3 81 31 07 19-01 b6 eb a3 2d b8 65 a7   .&x..1......-.e.
03d0 - 15 77 27 8b 43 1e 4b 28-6f 37 5b 87 df a8 48 f2   .w'.C.K(o7[...H.
03e0 - 52 6c 06 f8 a6 27 c8 2e-53 e2 90 a1 f9 4e 30 67   Rl...'..S....N0g
03f0 - 6e 6b 96 a3 e2 44 5b 23-a8 10 ae 7c 0f 5a f6 48   nk...D[#...|.Z.H
0400 - fd 25 66 6b eb b4 8d 67-18 ac 68 7b 29 24 c6 6a   .%fk...g..h{)$.j
0410 - 6a 1b 56 96 bc 1f d6 b2-20 e6 37 cb cb 3d e4 86   j.V..... .7..=..
0420 - 9f a7 f4 69 72 e9 49 58-20 86 7c a4 c6 c0 87 cd   ...ir.IX .|.....
0430 - 81 01 4e 00 12 96 80 b6-31 fd a0 66 57 74 2c 1d   ..N.....1..fWt,.
0440 - 15 19 f9 4b ca 89 8c 5d-0b c3 18 5c 68 ac be ac   ...K...]...\h...
0450 - 14 af 45 89 cd c1 6e f8-2c 71 65 88 86 19 1c 82   ..E...n.,qe.....
0460 - b7 1b 0f 81 72 89 d2 39-8d d7 46 77 78 36 39 fa   ....r..9..Fwx69.
0470 - 6a 49 3d 34 b3 d9 f7 c5-df 78 33 eb 78 59 b7 76   jI=4.....x3.xY.v
0480 - ca 0a 8a 6e 6c 39 90 4a-b3 46 6a 40 af 46 00 78   ...nl9.J.Fj@.F.x
0490 - f8 7b a6 c6 f2 5b 3e 11-4b 91 79 c3 02 24 3e cc   .{...[>.K.y..$>.
04a0 - dc 03 24 78 4e 83 a2 cd-55 6c 45 b7 46 23 42 41   ..$xN...UlE.F#BA
04b0 - 37 14 7a 85 80 c7 bc 8f-f0 66 41 c9 42 de c2 13   7.z......fA.B...
04c0 - 9d 9c 2a e4 60 c9 f9 71-46 63 d5 2e 9a 51 46 05   ..*.`..qFc...QF.
04d0 - 14 17 62 6a 84 e4 71 36-7a 75 57 67 04 78 18 87   ..bj..q6zuWg.x..
04e0 - a5 5b 6c 69 10 78 22 52-f5 2f 10 0a 85 c5 eb ba   .[li.x"R./......
04f0 - a7 08 23 1c d6 b8 01 68-18 78 5b 09 79 22 70 2c   ..#....h.x[.y"p,
0500 - 17 79 40 ca 75 d9 eb 97-f5 15 45 3d 89 48 6b 94   .y@.u.....E=.Hk.
0510 - 33 c0 bc a7 45 b3 4d de-f4 a7 7c f4 93 24 da 9e   3...E.M...|..$..
0520 - 60 f5 bd de 7a 4a 6e 87-19 d9 43 85 41 3b 77 71   `...zJn...C.A;wq
0530 - 81 81 69 e0 7d b9 d5 20-10 a9 83 19 12 97 e1 d1   ..i.}.. ........
0540 - 53 5f a4 11 a3 4c a1 1f-39 2d 6e 54 2b 51 e2 10   S_...L..9-nT+Q..
0550 - 89 c5 3c 67 15 44 7f b0-3a 38 64 1c 1d a4 b8 73   ..<g.D..:8d....s
0560 - c0 4f 4b f2 bb db d8 05-72 14 af f8 68 78 da 91   .OK.....r...hx..
0570 - bb a0 90 b0 f9 6b 59 da-96 96 ca 03 4f f2 b5 3c   .....kY.....O..<
0580 - be 62 80 34 e5 60 b1 fb-8a e5 45 b4 ca 43 7f 8a   .b.4.`....E..C..
0590 - 7b 7a ec 9a 6b 4a e4 76-ae f8 af 53 52 a3 fd 12   {z..kJ.v...SR...
05a0 - 48 ba 51 bf cd aa 8d 57-82 6d 6b 99 b6 31 a7 b2   H.Q....W.mk..1..
05b0 - 3c 00 bd c8 31 4b f5 94-8c 8d 4a cd bf 17 0e 6f   <...1K....J....o
05c0 - fb 80 76 03 bc e9 23 42-0b a1 a0 db 46 cb da 84   ..v...#B....F...
05d0 - cc d8 bc c1 ba e1 44 e3-b4 68 a4 2a 7a d9 45 98   ......D..h.*z.E.
05e0 - f0 40 17 0f 57 4b 98 a4-af 62 65 18 c4 e1 96 e2   .@..WK...be.....
05f0 - c0 9e 68 e2 87 3e 4a 49-0a b1 9b 26 99 c3 26 21   ..h..>JI...&..&!
0600 - 98 4d 85 0e 27 39 b1 bd-84 c9 e9 9b 30 b3 63 65   .M..'9......0.ce
0610 - e7 70 bc d6 b9 90 8d 61-cc 68 f9 4a 08 11 20 88   .p.....a.h.J.. .
0620 - f8 94 b5 3c 21 e8 62 0f-89 d3 ce 43 59 54 9e 31   ...<!.b....CYT.1
0630 - 25 af 27 12 aa 3c 15 b5-d0 13 2d bc 9d 21 80 88   %.'..<....-..!..
0640 - 03 db 4e e0 b9 22 57 85-3f cb b1 59 a7 29 41 18   ..N.."W.?..Y.)A.
0650 - fb 65 69 93 70 56 c1 95-62 e9 55 bc 9b 38 76 52   .ei.pV..b.U..8vR
0660 - c9 7e a8 78 b7 a2 2c a4-10 12 a6 31 09 1d 52 14   .~.x..,....1..R.
0670 - 07 2b 1c f6 ea 70 c9 b8-55 6f 5a 25 b6 75 b5 2d   .+...p..UoZ%.u.-
0680 - 54 47 58 bc 2c 39 eb c6-60 03 c9 0b 87 af 8f b6   TGX.,9..`.......
0690 - 74 65 1a 57 c3 75 57 72-80 72 79 86 41 84 0a 18   te.W.uWr.ry.A...
06a0 - 13 41 ce 8d bb b5 98 26-2a 38 67 7b 1c 27 b9 34   .A.....&*8g{.'.4
06b0 - 19 13 54 14 cb e1 31 23-15 07 59 f3 94 af 24 5b   ..T...1#..Y...$[
06c0 - 86 d0 f3 69 c4 37 b1 06-07 23 59 a2 c9 28 e1 72   ...i.7...#Y..(.r
06d0 - d3 a7 0e d0 e5 88 a3 a4-0c 98 b6 51 b1 48 b3 9c   ...........Q.H..
06e0 - f7 31 ff 69 13 94 61 52-31 c5 8f ed 21 06 7d c7   .1.i..aR1...!.}.
06f0 - 3f 12 a5 0a a1 a6 19 b9-f9 73 64 a4 58 29 e7 3d   ?........sd.X).=
0700 - f4 72 8e d1 da 07 21 88-2f 0d f0 c4 1a 80 ad ec   .r....!./.......
0710 - a8 06 c8 fc b6 60 20 95-20 a4 73 e1 fa 39 81 c6   .....` . .s..9..
0720 - 71 ec 1f 8b fe d2 ba 54-12 89 e9 ab b3 31 a5 aa   q......T.....1..
0730 - 65 4b 00 1b 00 03 02 00-01                        eK.......
SSL_connect:SSLv3/TLS write client hello
read from 0x1a988f876d0 [0x1a98945e3e3] (5 bytes => 5 (0x5))
0000 - 16 03 03 06 db                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = Handshake (22)
  Length = 1755
read from 0x1a988f876d0 [0x1a98945e3e8] (1755 bytes => 1755 (0x6DB))
0000 - 02 00 06 d7 03 03 69 22-ef d3 d5 5e ce 62 b2 40   ......i"...^.b.@
0010 - da 5a 3a 98 0b 57 a3 68-3c 1d 16 64 6e 3d 43 95   .Z:..W.h<..dn=C.
0020 - 1c 83 f0 e5 35 a0 20 bb-25 38 f8 f7 1f c8 c3 93   ....5. .%8......
0030 - 79 82 2e 2b a6 de ec a8-97 13 c6 8c 07 fb d2 fb   y..+............
0040 - a6 f1 2a af 5b 7a f0 13-02 00 06 8f 00 2b 00 02   ..*.[z.......+..
0050 - 03 04 00 33 06 85 11 ed-06 81 04 d0 ec c1 57 9c   ...3..........W.
0060 - 2f a2 48 3c 18 72 61 99-68 07 75 b9 79 28 33 65   /.H<.ra.h.u.y(3e
0070 - 23 44 d2 ed fe 48 f4 de-61 1e 8d c7 6e e8 ed ff   #D...H..a...n...
0080 - c0 e6 3b 69 d9 66 1f 9b-34 57 41 8a 00 f8 fb e9   ..;i.f..4WA.....
0090 - 69 d2 aa 2b f8 be 9a df-4c 23 a1 fd 95 7c 5c e5   i..+....L#...|\.
00a0 - ae bd 22 87 51 c1 a5 e0-be fd f4 da 99 6b cd 1e   ..".Q........k..
00b0 - 2e ae aa 16 36 11 03 3c-55 f8 21 76 38 f7 0c 8f   ....6..<U.!v8...
00c0 - d0 72 99 5a 70 e0 65 a9-ab 5e 0e 91 e8 ad d3 5c   .r.Zp.e..^.....\
00d0 - 08 7a aa bd f2 da 0d c0-b4 4e bb 2e f8 58 c5 7c   .z.......N...X.|
00e0 - f9 5f 9d d6 88 d2 89 d9-a6 b6 b5 7c 8d ac 69 0e   ._.........|..i.
00f0 - 4a 78 f6 a7 27 d8 72 a0-3c 67 42 51 2d 15 d7 29   Jx..'.r.<gBQ-..)
0100 - 92 76 34 3c 83 66 39 ac-60 c0 12 d4 cc 8d 43 d1   .v4<.f9.`.....C.
0110 - d9 64 cd f8 91 6b 4e 83-92 7f e9 83 eb f6 c6 a7   .d...kN.........
0120 - 38 b7 6d 5f c8 99 21 b6-41 92 96 c7 f1 9a 62 d3   8.m_..!.A.....b.
0130 - 4a 4d f5 0b f3 a9 26 86-a0 b5 2e ed 76 1e 6f bf   JM....&.....v.o.
0140 - a0 87 de aa c7 ed 6c 74-57 f3 4e de c8 98 cf 96   ......ltW.N.....
0150 - e3 3f 91 fe 25 2d 35 90-1e 4f af 8f bd b1 cf 92   .?..%-5..O......
0160 - 37 af 7a 77 83 ab a8 97-37 83 a3 9a d8 b9 2a a2   7.zw....7.....*.
0170 - d1 8b 25 36 96 e6 76 c2-b2 05 18 68 c7 11 d4 49   ..%6..v....h...I
0180 - 1c 5b 95 26 a7 90 77 0f-cb 2d fc fc 2f 27 e3 84   .[.&..w..-../'..
0190 - cc ea fd 74 14 72 a3 6f-c6 dc d7 66 4d 83 e1 21   ...t.r.o...fM..!
01a0 - 9f d0 41 b5 72 82 b1 57-83 0d 3b f4 e4 58 82 28   ..A.r..W..;..X.(
01b0 - 29 8c 9f 76 36 cf 11 3a-b2 53 29 d7 82 2d 42 c7   )..v6..:.S)..-B.
01c0 - 79 c6 6e 36 30 03 c5 67-8a bb 5b 3f a9 3f 28 54   y.n60..g..[?.?(T
01d0 - a1 a3 3a cf 59 57 72 5b-3e 0f c1 e5 50 65 03 79   ..:.YWr[>...Pe.y
01e0 - 54 e9 6f 35 ca c9 f5 3c-71 d9 85 9f d1 49 48 20   T.o5...<q....IH
01f0 - 09 4b a6 ad 8d a4 29 7f-e6 3f 86 d3 ad 99 79 c1   .K....)..?....y.
0200 - 96 02 87 60 30 82 30 48-93 20 5d dd 2f 02 d9 7e   ...`0.0H. ]./..~
0210 - 32 81 b0 a8 cb a0 45 aa-90 ad 29 b6 cc 01 7e df   2.....E...)...~.
0220 - 71 5c c2 5f 46 bf ca 32-72 7f b8 9e ea 54 c5 c2   q\._F..2r....T..
0230 - 91 76 59 6d 30 43 60 87-63 11 a5 57 c7 e8 4c 2f   .vYm0C`.c..W..L/
0240 - 47 86 b8 f4 3c c2 c0 e1-1f 08 7e e7 1b 47 4c 33   G...<.....~..GL3
0250 - 3f 10 ce 35 02 4f 5c 1d-8d 24 62 af 5e af 42 b4   ?..5.O\..$b.^.B.
0260 - 71 d7 77 0b cf 90 9b eb-27 83 4f 58 c9 30 36 1d   q.w.....'.OX.06.
0270 - a6 8d 2e 69 d7 b6 1f 1c-8a dd 57 8c 94 ca 79 aa   ...i......W...y.
0280 - 54 f3 a4 02 5a 0d a5 17-6d f5 cc e7 80 3e bd ae   T...Z...m....>..
0290 - 76 98 3a 18 96 5f 31 a9-dc f5 fe 2d 6e 4c e4 c9   v.:.._1....-nL..
02a0 - 16 99 1a df 0d e1 69 1e-1c 8a 29 4d 49 0b 91 ad   ......i...)MI...
02b0 - d2 b3 d1 5d 49 9c 97 c5-c8 9c f9 08 75 94 5a 64   ...]I.......u.Zd
02c0 - 72 a2 f6 ea 65 3a d9 5b-30 08 46 37 ae 2b ae 54   r...e:.[0.F7.+.T
02d0 - c8 0e 75 88 c5 55 bf d9-6d 4d 03 ae 37 68 a9 6c   ..u..U..mM..7h.l
02e0 - 61 21 e3 a4 b6 70 86 a7-c7 c3 97 56 7e d2 52 5d   a!...p.....V~.R]
02f0 - 9e 44 1b 1d 45 04 7e 52-68 f5 34 c9 21 e4 d1 32   .D..E.~Rh.4.!..2
0300 - a3 8e b6 4c 8d 1d 18 94-8a ac 2a d1 58 b1 2c 49   ...L......*.X.,I
0310 - c5 7e 20 a6 a4 88 e8 42-1c b7 6d 44 34 07 42 84   .~ ....B..mD4.B.
0320 - b9 b1 ed bb 33 c3 4f 8e-11 97 f3 07 73 14 03 4d   ....3.O.....s..M
0330 - fe c9 e4 27 53 b9 9f c7-eb 5b 4a 08 b5 8b 40 bd   ...'S....[J...@.
0340 - 77 27 f6 24 6d 0f f9 43-6d cb 10 42 b0 a4 f9 23   w'.$m..Cm..B...#
0350 - 8c 66 5a 4f 9e 64 5a e4-57 8c 33 70 41 64 af 38   .fZO.dZ.W.3pAd.8
0360 - ff d2 f1 fb 69 cf 0d 0d-be fe 7a c7 20 6a a7 fb   ....i.....z. j..
0370 - 49 61 cf c5 2f db 0d 13-00 7c 2b af ef f5 ad 4b   Ia../....|+....K
0380 - 87 57 1d d5 45 5d 7c 92-e4 48 9a be d7 28 00 8e   .W..E]|..H...(..
0390 - f9 8c 19 b3 83 5b 55 9b-89 a1 4c 03 bc 16 da 78   .....[U...L....x
03a0 - b4 42 69 40 7c d3 76 98-1a 80 19 8c 7a 7e ab 8c   .Bi@|.v.....z~..
03b0 - bf cd e4 51 23 ff f0 cc-c1 66 19 6f 6b 55 6e a7   ...Q#....f.okUn.
03c0 - 31 a5 26 01 b9 0d ab fc-83 bb 13 68 c8 26 69 6d   1.&........h.&im
03d0 - f4 87 45 66 05 9c 13 d0-d0 ad 91 c6 c2 0c f9 d2   ..Ef............
03e0 - 83 3d 11 37 9b 47 12 81-2b 10 ab aa a2 10 cf 80   .=.7.G..+.......
03f0 - 74 2a f6 e4 f1 10 d2 34-a6 c5 13 70 49 ad 66 81   t*.....4...pI.f.
0400 - f1 a8 0e d7 79 29 29 da-12 7c ff 60 34 a0 64 89   ....y))..|.`4.d.
0410 - e6 22 1a bf ea 9c c6 fc-1b 7c 86 28 15 4e 2a 9d   .".......|.(.N*.
0420 - 3e 46 d9 b3 79 e0 00 6d-05 93 5d 07 bc c4 49 24   >F..y..m..]...I$
0430 - 10 61 c7 9e 60 66 5b 74-22 8f fe cc f7 93 e2 c3   .a..`f[t".......
0440 - 25 97 f0 01 0b 5f 6d 53-34 4d fc 0f 5a 0c c3 20   %...._mS4M..Z..
0450 - ed 9e c7 75 f0 18 79 72-d7 d0 5b b1 23 45 7e fa   ...u..yr..[.#E~.
0460 - af ca a4 68 13 39 b0 80-14 9d 81 a5 4a d3 ab e1   ...h.9......J...
0470 - 73 2c ef df ea 04 25 2c-05 88 0a d6 d1 c5 e4 34   s,....%,.......4
0480 - d2 a1 b7 f2 a1 c5 1b 49-d3 89 68 49 e1 66 60 ad   .......I..hI.f`.
0490 - 5f 87 24 2f e9 97 fc 4d-00 c4 86 82 e5 0a a5 1a   _.$/...M........
04a0 - 47 b3 18 b2 52 04 5a 3e-15 98 e3 0a 3d 58 41 27   G...R.Z>....=XA'
04b0 - c1 e1 60 5f cd 2e 81 64-81 93 90 bf e9 10 72 b7   ..`_...d......r.
04c0 - 5a a0 d2 af 58 71 91 fc-bf ac 05 ce d2 36 b1 83   Z...Xq.......6..
04d0 - dc 79 29 93 b7 96 ed 43-ae 85 d6 2e eb df da 67   .y)....C.......g
04e0 - 78 5c d7 19 8d 9f bd 08-56 be 45 d5 ae 46 e8 d0   x\......V.E..F..
04f0 - b4 ec af a9 e2 fa c6 ef-5a be e1 84 34 39 99 c1   ........Z...49..
0500 - 55 6f 82 c6 d1 2f 96 c1-34 f8 c6 41 84 d5 80 cf   Uo.../..4..A....
0510 - 99 32 9f de d9 d6 bd 8e-39 72 1c 1a 88 21 da 38   .2......9r...!.8
0520 - fb 41 ec 6b a0 9d 20 27-d2 43 55 38 4d 10 5c 02   .A.k.. '.CU8M.\.
0530 - a0 3d f4 1d fb 3e 76 29-ee 21 37 d2 27 4f 2b 7f   .=...>v).!7.'O+.
0540 - f8 8f 2a 0c fe a0 4e 0c-ff 33 24 84 3d 60 56 6e   ..*...N..3$.=`Vn
0550 - 8b ae 63 f3 dc b1 a2 2c-c9 5e 89 2d 57 51 70 55   ..c....,.^.-WQpU
0560 - 22 32 cc 50 a9 d4 cd 55-87 0b c1 0c e5 7d b0 de   "2.P...U.....}..
0570 - 9a 9f 10 5a 0a bf d7 65-98 df ab 9f 91 94 73 bb   ...Z...e......s.
0580 - a7 1e 8f bd 01 66 fd 16-b3 48 10 05 29 d2 6b 93   .....f...H..).k.
0590 - 98 7d 16 4d f3 23 1a 0d-78 7a 88 a4 83 74 1e 71   .}.M.#..xz...t.q
05a0 - c5 26 66 66 61 09 70 77-c1 a7 7c 44 94 e8 fe bd   .&ffa.pw..|D....
05b0 - 22 81 e0 2b e3 ea 1d 88-29 09 27 50 30 0c cb 39   "..+....).'P0..9
05c0 - 63 ec 71 e8 ca 97 7e 4b-43 19 2e d6 08 e6 a2 52   c.q...~KC......R
05d0 - 9f 97 48 76 82 8e 75 d4-cd ff c6 9a 19 51 e6 5f   ..Hv..u......Q._
05e0 - a5 d6 b7 fc 77 75 ae db-49 8c ea d6 12 2d c1 18   ....wu..I....-..
05f0 - ef eb 5f b4 52 12 1e 47-e5 ee 94 48 f0 26 e7 56   .._.R..G...H.&.V
0600 - a5 8a 4d 99 d3 2e 3f 74-9e b5 70 98 53 26 4b 00   ..M...?t..p.S&K.
0610 - bb 39 72 cb e1 4d cb 69-34 97 ce 7e 11 94 75 73   .9r..M.i4..~..us
0620 - c0 5a c8 06 5a 4d c1 2c-0a 2b 48 ce cb a6 f7 fd   .Z..ZM.,.+H.....
0630 - e7 4e e0 19 3a 4d ef c1-92 7d 5a 46 7c 90 d3 06   .N..:M...}ZF|...
0640 - 04 84 26 a9 5d 7c c9 2f-bc fc 18 27 e1 45 af 8e   ..&.]|./...'.E..
0650 - d5 be 45 7b b8 c0 c1 45-a2 c4 6b 85 ca 01 24 5b   ..E{...E..k...$[
0660 - 36 66 21 70 13 95 72 0e-7b 4d 55 96 6a bb 4c 76   6f!p..r.{MU.j.Lv
0670 - 0b fd 49 25 0e 0c ec ab-13 10 17 8d 29 c2 0e be   ..I%........)...
0680 - e8 13 0d a2 33 d3 44 99-56 eb 11 c3 f8 3d 81 84   ....3.D.V....=..
0690 - e7 a5 a0 30 0d 1a 76 35-a9 9c 5c 55 37 63 7c 81   ...0..v5..\U7c|.
06a0 - a8 7e 92 a0 32 00 4c 1a-09 ce 53 c4 5c a0 72 f8   .~..2.L...S.\.r.
06b0 - 52 01 cd c0 38 8f 4d 5c-d3 2a ca f0 ab 9c c2 16   R...8.M\.*......
06c0 - bf 3a 17 bb 01 53 48 43-e1 6b 4a 30 78 c9 fb dd   .:...SHC.kJ0x...
06d0 - 09 fa cd 13 f9 e1 be 44-75 5c 34                  .......Du\4
SSL_connect:SSLv3/TLS write client hello
    ServerHello, Length=1751
      server_version=0x303 (TLS 1.2)
      Random:
        gmt_unix_time=0x6922EFD3
        random_bytes (len=28): D55ECE62B240DA5A3A980B57A3683C1D16646E3D43951C83F0E535A0
      session_id (len=32): BB2538F8F71FC8C39379822E2BA6DEECA89713C68C07FBD2FBA6F12AAF5B7AF0
      cipher_suite {0x13, 0x02} TLS_AES_256_GCM_SHA384
      compression_method: No Compression (0x00)
      extensions, length = 1679
        extension_type=supported_versions(43), length=2
            TLS 1.3 (772)
        extension_type=key_share(51), length=1669
            NamedGroup: UNKNOWN (4589)
            key_exchange:  (len=1665): 04D0ECC1579C2FA2483C18726199680775B9792833652344D2EDFE48F4DE611E8DC76EE8EDFFC0E63B69D9661F9B3457418A00F8FBE969D2AA2BF8BE9ADF4C23A1FD957C5CE5AEBD228751C1A5E0BEFDF4DA996BCD1E2EAEAA163611033C55F8217638F70C8FD072995A70E065A9AB5E0E91E8ADD35C087AAABDF2DA0DC0B44EBB2EF858C57CF95F9DD688D289D9A6B6B57C8DAC690E4A78F6A727D872A03C6742512D15D7299276343C836639AC60C012D4CC8D43D1D964CDF8916B4E83927FE983EBF6C6A738B76D5FC89921B6419296C7F19A62D34A4DF50BF3A92686A0B52EED761E6FBFA087DEAAC7ED6C7457F34EDEC898CF96E33F91FE252D35901E4FAF8FBDB1CF9237AF7A7783ABA8973783A39AD8B92AA2D18B253696E676C2B2051868C711D4491C5B9526A790770FCB2DFCFC2F27E384CCEAFD741472A36FC6DCD7664D83E1219FD041B57282B157830D3BF4E4588228298C9F7636CF113AB25329D7822D42C779C66E363003C5678ABB5B3FA93F2854A1A33ACF5957725B3E0FC1E55065037954E96F35CAC9F53C71D9859FD1494820094BA6AD8DA4297FE63F86D3AD9979C1960287603082304893205DDD2F02D97E3281B0A8CBA045AA90AD29B6CC017EDF715CC25F46BFCA32727FB89EEA54C5C29176596D304360876311A557C7E84C2F4786B8F43CC2C0E11F087EE71B474C333F10CE35024F5C1D8D2462AF5EAF42B471D7770BCF909BEB27834F58C930361DA68D2E69D7B61F1C8ADD578C94CA79AA54F3A4025A0DA5176DF5CCE7803EBDAE76983A18965F31A9DCF5FE2D6E4CE4C916991ADF0DE1691E1C8A294D490B91ADD2B3D15D499C97C5C89CF90875945A6472A2F6EA653AD95B30084637AE2BAE54C80E7588C555BFD96D4D03AE3768A96C6121E3A4B67086A7C7C397567ED2525D9E441B1D45047E5268F534C921E4D132A38EB64C8D1D18948AAC2AD158B12C49C57E20A6A488E8421CB76D4434074284B9B1EDBB33C34F8E1197F3077314034DFEC9E42753B99FC7EB5B4A08B58B40BD7727F6246D0FF9436DCB1042B0A4F9238C665A4F9E645AE4578C33704164AF38FFD2F1FB69CF0D0DBEFE7AC7206AA7FB4961CFC52FDB0D13007C2BAFEFF5AD4B87571DD5455D7C92E4489ABED728008EF98C19B3835B559B89A14C03BC16DA78B44269407CD376981A80198C7A7EAB8CBFCDE45123FFF0CCC166196F6B556EA731A52601B90DABFC83BB1368C826696DF4874566059C13D0D0AD91C6C20CF9D2833D11379B4712812B10ABAAA210CF80742AF6E4F110D234A6C5137049AD6681F1A80ED7792929DA127CFF6034A06489E6221ABFEA9CC6FC1B7C8628154E2A9D3E46D9B379E0006D05935D07BCC449241061C79E60665B74228FFECCF793E2C32597F0010B5F6D53344DFC0F5A0CC320ED9EC775F0187972D7D05BB123457EFAAFCAA4681339B080149D81A54AD3ABE1732CEFDFEA04252C05880AD6D1C5E434D2A1B7F2A1C51B49D3896849E16660AD5F87242FE997FC4D00C48682E50AA51A47B318B252045A3E1598E30A3D584127C1E1605FCD2E8164819390BFE91072B75AA0D2AF587191FCBFAC05CED236B183DC792993B796ED43AE85D62EEBDFDA67785CD7198D9FBD0856BE45D5AE46E8D0B4ECAFA9E2FAC6EF5ABEE184343999C1556F82C6D12F96C134F8C64184D580CF99329FDED9D6BD8E39721C1A8821DA38FB41EC6BA09D2027D24355384D105C02A03DF41DFB3E7629EE2137D2274F2B7FF88F2A0CFEA04E0CFF3324843D60566E8BAE63F3DCB1A22CC95E892D575170552232CC50A9D4CD55870BC10CE57DB0DE9A9F105A0ABFD76598DFAB9F919473BBA71E8FBD0166FD16B348100529D26B93987D164DF3231A0D787A88A483741E71C526666661097077C1A77C4494E8FEBD2281E02BE3EA1D8829092750300CCB3963EC71E8CA977E4B43192ED608E6A2529F974876828E75D4CDFFC69A1951E65FA5D6B7FC7775AEDB498CEAD6122DC118EFEB5FB452121E47E5EE9448F026E756A58A4D99D32E3F749EB5709853264B00BB3972CBE14DCB693497CE7E11947573C05AC8065A4DC12C0A2B48CECBA6F7FDE74EE0193A4DEFC1927D5A467C90D306048426A95D7CC92FBCFC1827E145AF8ED5BE457BB8C0C145A2C46B85CA01245B366621701395720E7B4D55966ABB4C760BFD49250E0CECAB1310178D29C20EBEE8130DA233D3449956EB11C3F83D8184E7A5A0300D1A7635A99C5C5537637C81A87E92A032004C1A09CE53C45CA072F85201CDC0388F4D5CD32ACAF0AB9CC216BF3A17BB01534843E16B4A3078C9FBDD09FACD13F9E1BE44755C34

read from 0x1a988f876d0 [0x1a98945de03] (5 bytes => 5 (0x5))
0000 - 14 03 03 00 01                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ChangeCipherSpec (20)
  Length = 1
read from 0x1a988f876d0 [0x1a98945de08] (1 bytes => 1 (0x1))
0000 - 01                                                .
    change_cipher_spec (1)

read from 0x1a988f876d0 [0x1a98945de03] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 23
read from 0x1a988f876d0 [0x1a98945de08] (23 bytes => 23 (0x17))
0000 - 51 a8 5f 76 db 8f ed c8-30 9b 6f ee d5 3b df c1   Q._v....0.o..;..
0010 - 4e a6 5a 59 36 07 9b                              N.ZY6..
  Inner Content Type = Handshake (22)
SSL_connect:SSLv3/TLS read server hello
    EncryptedExtensions, Length=2
      No extensions

Can't use SSL_get_servername
read from 0x1a988f876d0 [0x1a98945de03] (5 bytes => 5 (0x5))
0000 - 17 03 03 03 7e                                    ....~
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 894
read from 0x1a988f876d0 [0x1a98945de08] (894 bytes => 894 (0x37E))
0000 - 58 23 92 d4 35 40 9b 02-47 c7 5a d5 84 08 30 77   X#..5@..G.Z...0w
0010 - cb 14 f6 de db 63 df 73-f8 ec 2b 1b 9f 7a 5b 28   .....c.s..+..z[(
0020 - c1 b8 0c a7 ad 3f bd 64-96 0a f0 a4 d9 92 71 bd   .....?.d......q.
0030 - ca 2d 7d 04 f1 a9 13 3d-ed c2 c6 c5 90 0e 6f fe   .-}....=......o.
0040 - f6 4d 97 16 c1 52 ed 1d-0e 4d 32 1e 44 bd 6c c3   .M...R...M2.D.l.
0050 - fc f9 f5 6d ad 63 de 44-4e 06 74 db 8b 9d e7 05   ...m.c.DN.t.....
0060 - 69 b2 01 de 3c d1 f8 a5-49 46 64 8c b3 01 c7 79   i...<...IFd....y
0070 - d2 1e 5d a7 d3 db 67 76-09 25 0c d4 03 13 04 c3   ..]...gv.%......
0080 - 10 6a e9 37 00 52 70 d8-07 ed 0f 9b b2 19 11 e5   .j.7.Rp.........
0090 - 64 f0 18 34 58 e6 c9 e5-18 a4 6e 43 19 1e 03 03   d..4X.....nC....
00a0 - 9c 92 6c 0d 10 fc 77 4d-12 9e 2b dd 09 bc 6d 47   ..l...wM..+...mG
00b0 - f7 0e f9 6e d4 64 b9 03-af b6 59 7b 26 ef d7 d5   ...n.d....Y{&...
00c0 - 46 83 95 97 42 85 35 e2-18 2a 30 11 23 69 48 7d   F...B.5..*0.#iH}
00d0 - a9 4f 2e 30 f7 ae bf 1b-8a 67 a7 fe 94 91 b9 5b   .O.0.....g.....[
00e0 - 2f 53 88 d3 72 ec 8b 33-7b bc b0 e9 b3 db 6c d4   /S..r..3{.....l.
00f0 - 4f d7 fa 5b b0 f6 88 c0-d6 cb bc 98 77 ae e7 c0   O..[........w...
0100 - 21 17 92 4e 14 f7 fa 48-15 19 0a 43 2e 60 0d 4e   !..N...H...C.`.N
0110 - 4a 9b 8d a9 ed 5b d6 35-b5 81 44 fc fc 1a 06 35   J....[.5..D....5
0120 - 08 8f e3 e1 50 68 18 7e-45 5f 4d d7 0f df 21 12   ....Ph.~E_M...!.
0130 - 8c 02 16 b5 56 fc a7 de-40 71 da a7 13 ae df e2   ....V...@q......
0140 - d5 c5 60 9f 7a 03 67 fb-e6 1e a4 61 73 f7 e8 25   ..`.z.g....as..%
0150 - 59 bf 5d fe 9d 79 2f 2e-28 10 3e c8 35 af 9b 23   Y.]..y/.(.>.5..#
0160 - d1 e0 d8 e2 8e 76 29 63-50 64 29 a4 45 05 1c c2   .....v)cPd).E...
0170 - e1 84 b6 e1 08 32 15 ec-9f f5 ec d7 dc 33 e9 d0   .....2.......3..
0180 - 37 39 16 e1 13 0a f5 4c-00 0b 5e 4e 27 88 0c 6b   79.....L..^N'..k
0190 - 82 55 f4 6a 18 d4 e0 d4-c3 34 7b fa 8e f9 37 ad   .U.j.....4{...7.
01a0 - 63 a7 0e 21 f3 c3 57 c1-d8 d5 1f 0b 9e 34 0c 87   c..!..W......4..
01b0 - 2c 32 5d e3 56 a4 06 04-5d 2d 4d 17 7a 62 08 8e   ,2].V...]-M.zb..
01c0 - 92 98 8d a7 1d 21 4b 71-e3 06 ff fb 53 e4 67 71   .....!Kq....S.gq
01d0 - 6a 91 fe 96 c7 d0 57 9e-79 66 bd cd 2e 0d 69 a0   j.....W.yf....i.
01e0 - 42 dd 92 80 3e 0c 78 c3-b7 64 94 dd 23 74 5f b8   B...>.x..d..#t_.
01f0 - b1 31 e8 7c fa 4b b4 75-8c 28 1c d7 62 1b 0e e7   .1.|.K.u.(..b...
0200 - 92 c1 a8 3b 8c a7 95 25-58 d0 c4 8d fd 15 b3 6c   ...;...%X......l
0210 - bc 41 7c 4c d6 98 67 87-f0 6f b3 c6 6c 20 05 14   .A|L..g..o..l ..
0220 - 5b 4a d8 48 68 2e 63 d5-7b 83 50 a2 44 49 bd c5   [J.Hh.c.{.P.DI..
0230 - 19 06 47 2a bc 93 c1 a3-21 03 d8 f5 99 a3 a6 58   ..G*....!......X
0240 - be 13 b9 9f 3c 61 7f 1c-75 81 11 5a de da 1c e8   ....<a..u..Z....
0250 - 00 2d 97 c7 6c 59 5d ec-bc bc d5 48 fa e7 62 09   .-..lY]....H..b.
0260 - 10 67 0c 9b ba 97 1a 3e-f3 44 e0 49 fc 11 7a bc   .g.....>.D.I..z.
0270 - e0 1b 3a ae 8f cb 70 8b-84 6d a6 15 58 e5 24 8d   ..:...p..m..X.$.
0280 - 87 d7 09 c6 1b f1 29 3f-ff 37 e6 3b 25 60 90 38   ......)?.7.;%`.8
0290 - f1 a8 7c ff 26 27 b8 e2-a4 95 ed 49 f9 1e ad d8   ..|.&'.....I....
02a0 - af 53 f3 b8 12 bf 75 33-2d 15 88 73 36 f4 d7 6c   .S....u3-..s6..l
02b0 - 62 80 55 fa f7 ed 4d 96-ce 39 1c bf 0b db 08 ff   b.U...M..9......
02c0 - 47 a7 08 0a 34 4d ca c9-40 63 f3 53 ea 4b 04 7c   G...4M..@c.S.K.|
02d0 - 7a 9b bd e6 34 e5 a7 36-82 82 8c bb 81 71 1e 90   z...4..6.....q..
02e0 - ff 3b e5 b6 fe 70 19 6d-f4 c3 c6 4a 91 cf 2f ba   .;...p.m...J../.
02f0 - 01 f3 a4 64 39 8a 8d d8-5e 69 cb 6d 0d bb f5 c9   ...d9...^i.m....
0300 - 7f 56 92 c8 af 17 86 61-02 c9 df 8b 88 16 c1 62   .V.....a.......b
0310 - d3 99 6c 68 6d 61 12 55-d5 7a bf 69 6d cc b1 7f   ..lhma.U.z.im...
0320 - 39 27 5d 3c d3 9d 1c a1-28 8a fa 14 0d 8e da 14   9']<....(.......
0330 - b9 db 6f 9c ff 20 62 6f-74 b7 9e 85 bb 7f 4c 90   ..o.. bot.....L.
0340 - f5 25 98 be 01 c4 b2 89-77 25 8c ba e4 20 1c 45   .%......w%... .E
0350 - 7d 4c d6 1c 4f b3 cf 5a-0f 53 b9 4f 2b d4 74 83   }L..O..Z.S.O+.t.
0360 - 15 6b b6 6b 12 c1 4c 0a-89 ca 5a 8f ff 21 7e 06   .k.k..L...Z..!~.
0370 - 60 12 14 98 4f b1 78 8c-dd c1 34 97 c4 78         `...O.x...4..x
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
read from 0x1a988f876d0 [0x1a98945de03] (5 bytes => 5 (0x5))
0000 - 17 03 03 01 19                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 281
read from 0x1a988f876d0 [0x1a98945de08] (281 bytes => 281 (0x119))
0000 - 39 a0 87 7f 9c c2 2a 24-9b e1 f9 16 1c b7 1c 85   9.....*$........
0010 - 91 26 e9 c7 b0 ea 3a 49-1f ae 55 b5 b1 e5 ed ad   .&....:I..U.....
0020 - e6 33 17 af 1c ac 5d 4a-19 7d 92 4b 1e de c3 87   .3....]J.}.K....
0030 - 98 c7 cc 2b e9 ad cb 56-d3 19 2c 51 ca 05 84 e4   ...+...V..,Q....
0040 - c1 53 d0 a1 77 fc 82 ad-0c 97 72 d2 74 5d 52 8b   .S..w.....r.t]R.
0050 - 7e af 61 e0 76 6f 3f c5-b9 54 b4 fb ad 1d 0d 45   ~.a.vo?..T.....E
0060 - df 3c 8c 3d 42 b4 ef 92-f8 be 3c 67 e2 37 0d 05   .<.=B.....<g.7..
0070 - 98 8a e6 e8 71 80 f2 dd-f3 28 70 ee 62 bc 76 b7   ....q....(p.b.v.
0080 - 4c 6c 25 0a 6b ae 21 65-18 a8 98 0a b6 40 68 5b   Ll%.k.!e.....@h[
0090 - 39 da 0a 6b 11 6c 80 20-c3 41 7f 08 b5 0c 35 69   9..k.l. .A....5i
00a0 - aa 36 5e ea e1 16 eb 21-4c f6 01 d0 9e b5 7c 37   .6^....!L.....|7
00b0 - 3b 31 f5 a7 49 f0 29 f0-58 ba 0a ac 7d f0 de f6   ;1..I.).X...}...
00c0 - b5 39 aa b9 08 f0 d3 90-98 95 98 46 a8 99 2e e2   .9.........F....
00d0 - 22 43 f2 37 14 4e 9a 91-3a 3a 4e 0c d3 f7 78 c2   "C.7.N..::N...x.
00e0 - 30 49 cc 8f ae d5 37 e0-92 d8 d3 c2 58 8a c0 69   0I....7.....X..i
00f0 - c7 9a f6 1a 04 44 a0 68-00 6b 9f 9d 36 14 ae d0   .....D.h.k..6...
0100 - 67 ff 2d b3 86 33 b4 3d-51 7b 46 cb e4 02 92 99   g.-..3.=Q{F.....
0110 - 45 ed 1f 3b ff f3 1c 7b-b8                        E..;...{.
  Inner Content Type = Handshake (22)
SSL_connect:SSLv3/TLS read server certificate
    CertificateVerify, Length=260
      Signature Algorithm: rsa_pss_rsae_sha256 (0x0804)
      Signature (len=256): 76C18EA462B37C806043951A38788D4E56FB42E217729FFE3EDA44949CD5A1F8FA6FF205EF394072C7FD82117A0371C7DA1582275700E659E7DF28F9903E347FDD2C5121DED9B5C3EF0FB2FA77F6DAE330087AD479FDF5AB6BF541510B4ACEE2CBFBC5447BFED30678C8BE72B1142800D3C1D336C35B247C883086D9D7AC46E6851074E7659D649CC4B646CC270C2F81BF24E3E6964B65D693BDD0302B134B4E109DAC4E0C5E5CAE36996DAAF838ACCD6BCA4C011F2C339DDD393BAAB35BD952B93A1C32B79F0F6101DDB0D132D404F6B920EBEF718F9C1894BD4FFAC94CB77980B00BC86E4391D1CE085C87DFE0A8B82A95444C2B123BB3C2DD48B3D8358B66

read from 0x1a988f876d0 [0x1a98945de03] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 45                                    ....E
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 69
read from 0x1a988f876d0 [0x1a98945de08] (69 bytes => 69 (0x45))
0000 - 53 ee af 15 2f 9f a2 47-d5 9d 92 7f 90 7a 3b 45   S.../..G.....z;E
0010 - 81 61 75 14 65 32 cf 2c-15 0e 99 9c cb a0 5d ff   .au.e2.,......].
0020 - e0 4a 8e e9 33 ae ca aa-27 ec fe c0 59 a0 28 9d   .J..3...'...Y.(.
0030 - 75 fd e7 5b 9d 3e ca 8b-fc 85 12 c3 e8 69 42 75   u..[.>.......iBu
0040 - 60 9e 7e 51 1c                                    `.~Q.
  Inner Content Type = Handshake (22)
SSL_connect:TLSv1.3 read server certificate verify
    Finished, Length=48
      verify_data (len=48): 50AC1D7CF27C8E3B8E8E8E6C6B640F370B08B5B8014518D682DD7DC369B16718A3446BE3DCAB0EEEEFB6B8F4AFC62FF7

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
      verify_data (len=48): DCE01D55C5530069E37A12A5EFBD136E921860AFD041DE63BC3CDC88A75542505796120EA5A12063171D6C3EB2D79803

write to 0x1a988f876d0 [0x1a989455910] (80 bytes => 80 (0x50))
0000 - 14 03 03 00 01 01 17 03-03 00 45 da 81 f2 ca fa   ..........E.....
0010 - f4 ca 6c 8a f4 3d 0a c3-ab 5a 08 45 37 01 ed 49   ..l..=...Z.E7..I
0020 - 49 44 68 98 d3 cc 29 70-f7 cc 7d 0d 89 80 4c 2c   IDh...)p..}...L,
0030 - cd b5 ae fb 40 a3 7f be-ad a9 b9 4b b7 41 d4 f0   ....@......K.A..
0040 - 57 61 99 78 4b 70 97 bd-08 71 4a d0 62 0d bc 88   Wa.xKp...qJ.b...
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
Negotiated TLS1.3 group: SecP384r1MLKEM1024
---
SSL handshake has read 3053 bytes and written 1929 bytes
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
write to 0x1a988f876d0 [0x1a98944f3a3] (28 bytes => 28 (0x1C))
0000 - 17 03 03 00 17 5d 38 e3-eb 51 c2 ce 99 ce 25 fc   .....]8..Q....%.
0010 - cd 54 93 40 78 ba 09 e2-99 58 d2 d5               .T.@x....X..
read from 0x1a988f876d0 [0x1a989459973] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 17                                    .....
Received TLS Record
Header:
  Version = TLS 1.2 (0x303)
  Content Type = ApplicationData (23)
  Length = 23
read from 0x1a988f876d0 [0x1a989459978] (23 bytes => 23 (0x17))
0000 - 04 7c cf 69 df f7 78 31-97 71 02 9a ee 51 78 7f   .|.i..x1.q...Qx.
0010 - 7b 59 ca a6 16 97 49                              {Y....I
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
write to 0x1a988f876d0 [0x1a98944f3a3] (24 bytes => 24 (0x18))
0000 - 17 03 03 00 13 33 73 68-ca 5d 81 dd 36 1e e2 99   .....3sh.]..6...
0010 - d8 45 97 cc 8d df ce b4-                          .E......
    Level=warning(1), description=close notify(0)

SSL3 alert write:warning:close notify
read from 0x1a988f876d0 [0x1a988eafcd0] (16384 bytes => 0)

````


