#### tls12mte.pcapng - client

````
$ ./test-netclient.exe -v -d -i -P tls12
socket 464 created family 2(AF_INET) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 000001e4 created
iocp handle 000001e4 bind 464
- event_loop_new tid 0000660c
# write record content type 0x16(22) (handshake)
# write handshake type 0x01(1) (client_hello)
# record constructed
   00000000 : 16 03 03 00 CC 01 00 00 C8 03 03 88 06 AA F3 BA | ................
   00000010 : B7 CF A0 06 49 7E F5 06 20 DD AE 53 20 BF 15 41 | ....I~.. ..S ..A
   00000020 : D2 D2 A9 7A FB 85 14 5A A1 D2 75 20 B4 81 AC D6 | ...z...Z..u ....
   00000030 : E0 A2 2E 0F A5 D6 0D B9 FD 2D 02 3C 32 FB 20 89 | .........-.<2. .
   00000040 : 4A 64 AF 87 4E 7A 68 4F DF 4F 6F 5A 00 10 C0 23 | Jd..NzhO.OoZ...#
   00000050 : C0 24 C0 27 C0 28 C0 2B C0 2C C0 2F C0 30 01 00 | .$.'.(.+.,./.0..
   00000060 : 00 6F 00 0B 00 02 01 00 00 0A 00 0C 00 0A 00 1D | .o..............
   00000070 : 00 17 00 1E 00 19 00 18 00 0D 00 1E 00 1C 04 03 | ................
   00000080 : 05 03 06 03 08 07 08 08 04 01 05 01 06 01 08 09 | ................
   00000090 : 08 0A 08 0B 08 04 08 05 08 06 00 2B 00 03 02 03 | ...........+....
   000000A0 : 03 00 2D 00 02 01 01 00 33 00 26 00 24 00 1D 00 | ..-.....3.&.$...
   000000B0 : 20 AB A4 8C AB AB 5B E5 92 54 CC 25 C8 B3 67 AE |  .....[..T.%..g.
   000000C0 : 0D 35 8B 69 1F 3B 98 D0 4B 5C 67 3B 55 F0 D2 91 | .5.i.;..K\g;U...
   000000D0 : 57 -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- | W
[ns] read 0x502
   00000000 : 16 03 03 00 54 02 00 00 50 03 03 E7 36 BE 0B F5 | ....T...P...6...
   00000010 : E6 D9 FF EC 34 8B 1D 22 2E 5E 5F 0D D2 D4 A4 6C | ....4..".^_....l
   00000020 : 99 AE 52 1D E3 54 08 88 72 CA AB 20 37 9E F9 6B | ..R..T..r.. 7..k
   00000030 : 1C 03 10 52 81 88 10 C9 2B 67 F0 B7 F9 E0 5F 7B | ...R....+g...._{
   00000040 : D4 E2 E8 AA ED FF 4D 55 D8 7D A7 77 C0 27 00 00 | ......MU.}.w.'..
   00000050 : 08 00 0B 00 04 03 00 01 02 16 03 03 03 6A 0B 00 | .............j..
   00000060 : 03 66 00 03 63 00 03 60 30 82 03 5C 30 82 02 44 | .f..c..`0..\0..D
   00000070 : A0 03 02 01 02 02 14 63 A6 71 10 79 D6 A6 48 59 | .......c.q.y..HY
   00000080 : DA 67 A9 04 E8 E3 5F E2 03 A3 26 30 0D 06 09 2A | .g...._...&0...*
   00000090 : 86 48 86 F7 0D 01 01 0B 05 00 30 59 31 0B 30 09 | .H........0Y1.0.
   000000A0 : 06 03 55 04 06 13 02 4B 52 31 0B 30 09 06 03 55 | ..U....KR1.0...U
   000000B0 : 04 08 0C 02 47 47 31 0B 30 09 06 03 55 04 07 0C | ....GG1.0...U...
   000000C0 : 02 59 49 31 0D 30 0B 06 03 55 04 0A 0C 04 54 65 | .YI1.0...U....Te
   000000D0 : 73 74 31 0D 30 0B 06 03 55 04 0B 0C 04 54 65 73 | st1.0...U....Tes
   000000E0 : 74 31 12 30 10 06 03 55 04 03 0C 09 54 65 73 74 | t1.0...U....Test
   000000F0 : 20 52 6F 6F 74 30 1E 17 0D 32 34 30 38 32 39 30 |  Root0...2408290
   00000100 : 36 32 37 31 37 5A 17 0D 32 35 30 38 32 39 30 36 | 62717Z..25082906
   00000110 : 32 37 31 37 5A 30 54 31 0B 30 09 06 03 55 04 06 | 2717Z0T1.0...U..
   00000120 : 13 02 4B 52 31 0B 30 09 06 03 55 04 08 0C 02 47 | ..KR1.0...U....G
   00000130 : 47 31 0B 30 09 06 03 55 04 07 0C 02 59 49 31 0D | G1.0...U....YI1.
   00000140 : 30 0B 06 03 55 04 0A 0C 04 54 65 73 74 31 0D 30 | 0...U....Test1.0
   00000150 : 0B 06 03 55 04 0B 0C 04 54 65 73 74 31 0D 30 0B | ...U....Test1.0.
   00000160 : 06 03 55 04 03 0C 04 54 65 73 74 30 82 01 22 30 | ..U....Test0.."0
   00000170 : 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00 03 82 | ...*.H..........
   00000180 : 01 0F 00 30 82 01 0A 02 82 01 01 00 AD 9A 29 67 | ...0..........)g
   00000190 : 5F F3 A4 79 B4 C6 E6 32 73 D8 D7 ED 88 94 15 83 | _..y...2s.......
   000001A0 : E4 31 00 04 6C B5 8C AC 87 AB 74 44 13 76 CA 0B | .1..l.....tD.v..
   000001B0 : 74 29 40 9E 97 2A 01 D7 8B 46 26 6E 19 35 4D C0 | t)@..*...F&n.5M.
   000001C0 : D3 B5 EA 0E 93 3A 06 E8 E5 85 B5 27 05 63 DB 28 | .....:.....'.c.(
   000001D0 : B8 92 DA 5A 14 39 0F DA 68 6D 6F 0A FB 52 DC 08 | ...Z.9..hmo..R..
   000001E0 : 0F 54 D3 E4 A2 28 9D A0 71 50 82 E0 DB CA D1 94 | .T...(..qP......
   000001F0 : DD 42 98 3A 09 33 A8 D9 EF FB D2 35 43 B1 22 A2 | .B.:.3.....5C.".
   00000200 : BE 41 6D BA 91 DC 0B 31 4E 88 F9 4D 9C 61 2D EC | .Am....1N..M.a-.
   00000210 : B2 13 0A C2 91 8E A2 D6 E9 40 B9 32 B9 80 8F B3 | .........@.2....
   00000220 : 18 A3 33 13 23 D5 D0 7E D9 D0 7F 93 E0 2D 4D 90 | ..3.#..~.....-M.
   00000230 : C5 58 24 56 D5 C9 10 13 4A B2 99 23 7D 34 B9 8E | .X$V....J..#}4..
   00000240 : 97 19 69 6F CE C6 3F D6 17 A7 D2 43 E0 36 CB 51 | ..io..?....C.6.Q
   00000250 : 7B 2F 18 8B C2 33 F8 57 CF D1 61 0B 7C ED 37 35 | {/...3.W..a.|.75
   00000260 : E3 13 7A 24 2E 77 08 C2 E3 D9 E6 17 D3 A5 C6 34 | ..z$.w.........4
   00000270 : 5A DA 86 A7 F8 02 36 1D 66 63 CF E9 C0 3D 82 FB | Z.....6.fc...=..
   00000280 : 39 A2 8D 92 01 4A 83 CF E2 76 3D 87 02 03 01 00 | 9....J...v=.....
   00000290 : 01 A3 21 30 1F 30 1D 06 03 55 1D 11 04 16 30 14 | ..!0.0...U....0.
   000002A0 : 82 12 74 65 73 74 2E 70 72 69 6E 63 65 62 36 31 | ..test.princeb61
   000002B0 : 32 2E 70 65 30 0D 06 09 2A 86 48 86 F7 0D 01 01 | 2.pe0...*.H.....
   000002C0 : 0B 05 00 03 82 01 01 00 00 A5 F5 54 18 AB AD 36 | ...........T...6
   000002D0 : 38 C8 FC 0B 66 60 DD 9F 75 9D 86 5B 79 2F EE 57 | 8...f`..u..[y/.W
   000002E0 : F1 79 1C 15 A1 34 23 D0 1C A9 58 51 A4 D0 08 F5 | .y...4#...XQ....
   000002F0 : D8 F7 49 E9 C5 B5 65 91 51 2D 6D E4 3B 0E 77 02 | ..I...e.Q-m.;.w.
   00000300 : 1F 45 8E 34 E5 BB EB F6 9D DF 4A 40 60 21 B3 8E | .E.4......J@`!..
   00000310 : 16 33 3F F4 B6 90 D3 3C 34 CE E6 D9 47 07 A7 57 | .3?....<4...G..W
   00000320 : 14 0C F9 78 0B 36 72 A9 88 07 07 93 B4 D7 FE 29 | ...x.6r........)
   00000330 : 5E E8 41 37 20 A5 03 C7 97 CB 82 CA DB 14 E5 8B | ^.A7 ...........
   00000340 : 96 1F A9 E9 20 3D 6B 25 AE F4 89 4C 60 8D E9 14 | .... =k%...L`...
   00000350 : 33 47 4B 88 54 A2 47 19 81 C8 7B 0E 32 52 2B 91 | 3GK.T.G...{.2R+.
   00000360 : 88 AD 0F 6D 73 30 8C 00 AF D5 FC 46 46 AF 3A C2 | ...ms0.....FF.:.
   00000370 : 17 89 EC C8 83 AE DA E6 69 63 E0 9C 84 22 C5 7A | ........ic...".z
   00000380 : DE E8 23 6B 53 9D 6F 94 D2 7F 5C BE 1D 0C DE 0E | ..#kS.o...\.....
   00000390 : 07 0D 52 A5 43 8C E8 05 EF C0 FF F0 73 FA DC 5A | ..R.C.......s..Z
   000003A0 : 51 4C 24 09 65 45 7D AB 52 8B 7E 5D F0 FB DE A7 | QL$.eE}.R.~]....
   000003B0 : 3D 43 C5 AF 76 E3 6E F9 A1 DC 78 A2 BD 54 41 04 | =C..v.n...x..TA.
   000003C0 : 99 E5 56 32 BA 02 FD 72 16 03 03 01 2C 0C 00 01 | ..V2...r....,...
   000003D0 : 28 03 00 1D 20 F4 29 00 FF 3D 69 88 1D A1 44 60 | (... .)..=i...D`
   000003E0 : 74 0F AC 51 A0 4C B5 EF 3F FD EB FF 76 63 6E 9C | t..Q.L..?...vcn.
   000003F0 : 5D FE 3D 31 2B 04 01 01 00 4D 94 81 0F DD 66 C6 | ].=1+....M....f.
   00000400 : 7A FD 9B B4 22 EB 76 B7 DB 28 4B AD 39 00 D5 F7 | z...".v..(K.9...
   00000410 : E5 7A 41 DB D9 30 72 B4 C5 B9 09 ED 75 C1 ED 72 | .zA..0r.....u..r
   00000420 : E2 15 6F 3F D0 4B 81 46 FB 7A AE 8C C3 C3 10 16 | ..o?.K.F.z......
   00000430 : F2 71 69 CE 4E D2 84 49 2C 40 37 0E B9 60 60 36 | .qi.N..I,@7..``6
   00000440 : CE 66 2C 05 F1 A3 59 E5 6D 4D 06 BD 72 7D EB C2 | .f,...Y.mM..r}..
   00000450 : 72 2E 1B 55 85 51 1F 03 55 68 6D 6D A8 EA 96 BE | r..U.Q..Uhmm....
   00000460 : A6 20 EB 08 24 E5 A8 86 18 0A 06 58 37 DA 81 E0 | . ..$......X7...
   00000470 : EA 9E 05 6C 2C CF 76 4B 29 FE 52 F4 6A A6 FA B8 | ...l,.vK).R.j...
   00000480 : D9 81 DB EB 08 DB C4 80 C2 1D 04 B1 FB 7C 5C B2 | .............|\.
   00000490 : 73 BF 06 C8 61 7D 18 BB F8 2B 02 68 9B 52 E2 FA | s...a}...+.h.R..
   000004A0 : CA 74 3D 07 DD EB 0C 59 24 61 C2 21 5E 09 12 4E | .t=....Y$a.!^..N
   000004B0 : DB 7E 2E D4 D7 BC D6 2B 21 B7 D7 CE B1 65 F8 0E | .~.....+!....e..
   000004C0 : 2F EC 8C 36 C4 5A 03 3A 13 57 6D 2B 15 DF 65 29 | /..6.Z.:.Wm+..e)
   000004D0 : 75 41 E0 1D A0 82 BA EE 12 45 8A E8 57 75 6D 85 | uA.......E..Wum.
   000004E0 : 3E C2 D3 DC 5A 69 F7 D5 34 12 51 67 98 2D A0 F1 | >...Zi..4.Qg.-..
   000004F0 : 81 41 12 1C F6 41 F1 A0 09 16 03 03 00 04 0E 00 | .A...A..........
   00000500 : 00 00 -- -- -- -- -- -- -- -- -- -- -- -- -- -- | ..
# record (server) [size 0x502 pos 0x0]
   00000000 : 16 03 03 00 54 02 00 00 50 03 03 E7 36 BE 0B F5 | ....T...P...6...
   00000010 : E6 D9 FF EC 34 8B 1D 22 2E 5E 5F 0D D2 D4 A4 6C | ....4..".^_....l
   00000020 : 99 AE 52 1D E3 54 08 88 72 CA AB 20 37 9E F9 6B | ..R..T..r.. 7..k
   00000030 : 1C 03 10 52 81 88 10 C9 2B 67 F0 B7 F9 E0 5F 7B | ...R....+g...._{
   00000040 : D4 E2 E8 AA ED FF 4D 55 D8 7D A7 77 C0 27 00 00 | ......MU.}.w.'..
   00000050 : 08 00 0B 00 04 03 00 01 02 -- -- -- -- -- -- -- | .........
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x0054(84)
 > handshake type 0x02(2) (server_hello)
  > length 0x000050(80)
  > version 0x0303 (TLS v1.2)
  > random
    e736be0bf5e6d9ffec348b1d222e5e5f0dd2d4a46c99ae521de354088872caab
  > session id
    379ef96b1c031052818810c92b67f0b7f9e05f7bd4e2e8aaedff4d55d87da777
  > cipher suite 0xc027 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  > compression method 0 null
  > extension len 0x08(8)
  > extension - 000b ec_point_formats
    00000000 : 00 0B 00 04 03 00 01 02 -- -- -- -- -- -- -- -- | ........
   > extension len 0x0004(4)
   > formats 3
     [0] 0x00(0) uncompressed
     [1] 0x01(1) ansiX962_compressed_prime
     [2] 0x02(2) ansiX962_compressed_char2
# starting transcript_hash
 > cipher suite 0xc027 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
 > sha256
# record (server) [size 0x502 pos 0x59]
   00000000 : 16 03 03 03 6A 0B 00 03 66 00 03 63 00 03 60 30 | ....j...f..c..`0
   00000010 : 82 03 5C 30 82 02 44 A0 03 02 01 02 02 14 63 A6 | ..\0..D.......c.
   00000020 : 71 10 79 D6 A6 48 59 DA 67 A9 04 E8 E3 5F E2 03 | q.y..HY.g...._..
   00000030 : A3 26 30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 05 | .&0...*.H.......
   00000040 : 00 30 59 31 0B 30 09 06 03 55 04 06 13 02 4B 52 | .0Y1.0...U....KR
   00000050 : 31 0B 30 09 06 03 55 04 08 0C 02 47 47 31 0B 30 | 1.0...U....GG1.0
   00000060 : 09 06 03 55 04 07 0C 02 59 49 31 0D 30 0B 06 03 | ...U....YI1.0...
   00000070 : 55 04 0A 0C 04 54 65 73 74 31 0D 30 0B 06 03 55 | U....Test1.0...U
   00000080 : 04 0B 0C 04 54 65 73 74 31 12 30 10 06 03 55 04 | ....Test1.0...U.
   00000090 : 03 0C 09 54 65 73 74 20 52 6F 6F 74 30 1E 17 0D | ...Test Root0...
   000000A0 : 32 34 30 38 32 39 30 36 32 37 31 37 5A 17 0D 32 | 240829062717Z..2
   000000B0 : 35 30 38 32 39 30 36 32 37 31 37 5A 30 54 31 0B | 50829062717Z0T1.
   000000C0 : 30 09 06 03 55 04 06 13 02 4B 52 31 0B 30 09 06 | 0...U....KR1.0..
   000000D0 : 03 55 04 08 0C 02 47 47 31 0B 30 09 06 03 55 04 | .U....GG1.0...U.
   000000E0 : 07 0C 02 59 49 31 0D 30 0B 06 03 55 04 0A 0C 04 | ...YI1.0...U....
   000000F0 : 54 65 73 74 31 0D 30 0B 06 03 55 04 0B 0C 04 54 | Test1.0...U....T
   00000100 : 65 73 74 31 0D 30 0B 06 03 55 04 03 0C 04 54 65 | est1.0...U....Te
   00000110 : 73 74 30 82 01 22 30 0D 06 09 2A 86 48 86 F7 0D | st0.."0...*.H...
   00000120 : 01 01 01 05 00 03 82 01 0F 00 30 82 01 0A 02 82 | ..........0.....
   00000130 : 01 01 00 AD 9A 29 67 5F F3 A4 79 B4 C6 E6 32 73 | .....)g_..y...2s
   00000140 : D8 D7 ED 88 94 15 83 E4 31 00 04 6C B5 8C AC 87 | ........1..l....
   00000150 : AB 74 44 13 76 CA 0B 74 29 40 9E 97 2A 01 D7 8B | .tD.v..t)@..*...
   00000160 : 46 26 6E 19 35 4D C0 D3 B5 EA 0E 93 3A 06 E8 E5 | F&n.5M......:...
   00000170 : 85 B5 27 05 63 DB 28 B8 92 DA 5A 14 39 0F DA 68 | ..'.c.(...Z.9..h
   00000180 : 6D 6F 0A FB 52 DC 08 0F 54 D3 E4 A2 28 9D A0 71 | mo..R...T...(..q
   00000190 : 50 82 E0 DB CA D1 94 DD 42 98 3A 09 33 A8 D9 EF | P.......B.:.3...
   000001A0 : FB D2 35 43 B1 22 A2 BE 41 6D BA 91 DC 0B 31 4E | ..5C."..Am....1N
   000001B0 : 88 F9 4D 9C 61 2D EC B2 13 0A C2 91 8E A2 D6 E9 | ..M.a-..........
   000001C0 : 40 B9 32 B9 80 8F B3 18 A3 33 13 23 D5 D0 7E D9 | @.2......3.#..~.
   000001D0 : D0 7F 93 E0 2D 4D 90 C5 58 24 56 D5 C9 10 13 4A | ....-M..X$V....J
   000001E0 : B2 99 23 7D 34 B9 8E 97 19 69 6F CE C6 3F D6 17 | ..#}4....io..?..
   000001F0 : A7 D2 43 E0 36 CB 51 7B 2F 18 8B C2 33 F8 57 CF | ..C.6.Q{/...3.W.
   00000200 : D1 61 0B 7C ED 37 35 E3 13 7A 24 2E 77 08 C2 E3 | .a.|.75..z$.w...
   00000210 : D9 E6 17 D3 A5 C6 34 5A DA 86 A7 F8 02 36 1D 66 | ......4Z.....6.f
   00000220 : 63 CF E9 C0 3D 82 FB 39 A2 8D 92 01 4A 83 CF E2 | c...=..9....J...
   00000230 : 76 3D 87 02 03 01 00 01 A3 21 30 1F 30 1D 06 03 | v=.......!0.0...
   00000240 : 55 1D 11 04 16 30 14 82 12 74 65 73 74 2E 70 72 | U....0...test.pr
   00000250 : 69 6E 63 65 62 36 31 32 2E 70 65 30 0D 06 09 2A | inceb612.pe0...*
   00000260 : 86 48 86 F7 0D 01 01 0B 05 00 03 82 01 01 00 00 | .H..............
   00000270 : A5 F5 54 18 AB AD 36 38 C8 FC 0B 66 60 DD 9F 75 | ..T...68...f`..u
   00000280 : 9D 86 5B 79 2F EE 57 F1 79 1C 15 A1 34 23 D0 1C | ..[y/.W.y...4#..
   00000290 : A9 58 51 A4 D0 08 F5 D8 F7 49 E9 C5 B5 65 91 51 | .XQ......I...e.Q
   000002A0 : 2D 6D E4 3B 0E 77 02 1F 45 8E 34 E5 BB EB F6 9D | -m.;.w..E.4.....
   000002B0 : DF 4A 40 60 21 B3 8E 16 33 3F F4 B6 90 D3 3C 34 | .J@`!...3?....<4
   000002C0 : CE E6 D9 47 07 A7 57 14 0C F9 78 0B 36 72 A9 88 | ...G..W...x.6r..
   000002D0 : 07 07 93 B4 D7 FE 29 5E E8 41 37 20 A5 03 C7 97 | ......)^.A7 ....
   000002E0 : CB 82 CA DB 14 E5 8B 96 1F A9 E9 20 3D 6B 25 AE | ........... =k%.
   000002F0 : F4 89 4C 60 8D E9 14 33 47 4B 88 54 A2 47 19 81 | ..L`...3GK.T.G..
   00000300 : C8 7B 0E 32 52 2B 91 88 AD 0F 6D 73 30 8C 00 AF | .{.2R+....ms0...
   00000310 : D5 FC 46 46 AF 3A C2 17 89 EC C8 83 AE DA E6 69 | ..FF.:.........i
   00000320 : 63 E0 9C 84 22 C5 7A DE E8 23 6B 53 9D 6F 94 D2 | c...".z..#kS.o..
   00000330 : 7F 5C BE 1D 0C DE 0E 07 0D 52 A5 43 8C E8 05 EF | .\.......R.C....
   00000340 : C0 FF F0 73 FA DC 5A 51 4C 24 09 65 45 7D AB 52 | ...s..ZQL$.eE}.R
   00000350 : 8B 7E 5D F0 FB DE A7 3D 43 C5 AF 76 E3 6E F9 A1 | .~]....=C..v.n..
   00000360 : DC 78 A2 BD 54 41 04 99 E5 56 32 BA 02 FD 72 -- | .x..TA...V2...r
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x036a(874)
 > handshake type 0x0b(11) (certificate)
  > length 0x000366(870)
  > request context len 0
  > certifcates len 0x0363(867)
  > certifcate len 0x0360(864)
    00000000 : 30 82 03 5C 30 82 02 44 A0 03 02 01 02 02 14 63 | 0..\0..D.......c
    00000010 : A6 71 10 79 D6 A6 48 59 DA 67 A9 04 E8 E3 5F E2 | .q.y..HY.g...._.
    00000020 : 03 A3 26 30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B | ..&0...*.H......
    00000030 : 05 00 30 59 31 0B 30 09 06 03 55 04 06 13 02 4B | ..0Y1.0...U....K
    00000040 : 52 31 0B 30 09 06 03 55 04 08 0C 02 47 47 31 0B | R1.0...U....GG1.
    00000050 : 30 09 06 03 55 04 07 0C 02 59 49 31 0D 30 0B 06 | 0...U....YI1.0..
    00000060 : 03 55 04 0A 0C 04 54 65 73 74 31 0D 30 0B 06 03 | .U....Test1.0...
    00000070 : 55 04 0B 0C 04 54 65 73 74 31 12 30 10 06 03 55 | U....Test1.0...U
    00000080 : 04 03 0C 09 54 65 73 74 20 52 6F 6F 74 30 1E 17 | ....Test Root0..
    00000090 : 0D 32 34 30 38 32 39 30 36 32 37 31 37 5A 17 0D | .240829062717Z..
    000000A0 : 32 35 30 38 32 39 30 36 32 37 31 37 5A 30 54 31 | 250829062717Z0T1
    000000B0 : 0B 30 09 06 03 55 04 06 13 02 4B 52 31 0B 30 09 | .0...U....KR1.0.
    000000C0 : 06 03 55 04 08 0C 02 47 47 31 0B 30 09 06 03 55 | ..U....GG1.0...U
    000000D0 : 04 07 0C 02 59 49 31 0D 30 0B 06 03 55 04 0A 0C | ....YI1.0...U...
    000000E0 : 04 54 65 73 74 31 0D 30 0B 06 03 55 04 0B 0C 04 | .Test1.0...U....
    000000F0 : 54 65 73 74 31 0D 30 0B 06 03 55 04 03 0C 04 54 | Test1.0...U....T
    00000100 : 65 73 74 30 82 01 22 30 0D 06 09 2A 86 48 86 F7 | est0.."0...*.H..
    00000110 : 0D 01 01 01 05 00 03 82 01 0F 00 30 82 01 0A 02 | ...........0....
    00000120 : 82 01 01 00 AD 9A 29 67 5F F3 A4 79 B4 C6 E6 32 | ......)g_..y...2
    00000130 : 73 D8 D7 ED 88 94 15 83 E4 31 00 04 6C B5 8C AC | s........1..l...
    00000140 : 87 AB 74 44 13 76 CA 0B 74 29 40 9E 97 2A 01 D7 | ..tD.v..t)@..*..
    00000150 : 8B 46 26 6E 19 35 4D C0 D3 B5 EA 0E 93 3A 06 E8 | .F&n.5M......:..
    00000160 : E5 85 B5 27 05 63 DB 28 B8 92 DA 5A 14 39 0F DA | ...'.c.(...Z.9..
    00000170 : 68 6D 6F 0A FB 52 DC 08 0F 54 D3 E4 A2 28 9D A0 | hmo..R...T...(..
    00000180 : 71 50 82 E0 DB CA D1 94 DD 42 98 3A 09 33 A8 D9 | qP.......B.:.3..
    00000190 : EF FB D2 35 43 B1 22 A2 BE 41 6D BA 91 DC 0B 31 | ...5C."..Am....1
    000001A0 : 4E 88 F9 4D 9C 61 2D EC B2 13 0A C2 91 8E A2 D6 | N..M.a-.........
    000001B0 : E9 40 B9 32 B9 80 8F B3 18 A3 33 13 23 D5 D0 7E | .@.2......3.#..~
    000001C0 : D9 D0 7F 93 E0 2D 4D 90 C5 58 24 56 D5 C9 10 13 | .....-M..X$V....
    000001D0 : 4A B2 99 23 7D 34 B9 8E 97 19 69 6F CE C6 3F D6 | J..#}4....io..?.
    000001E0 : 17 A7 D2 43 E0 36 CB 51 7B 2F 18 8B C2 33 F8 57 | ...C.6.Q{/...3.W
    000001F0 : CF D1 61 0B 7C ED 37 35 E3 13 7A 24 2E 77 08 C2 | ..a.|.75..z$.w..
    00000200 : E3 D9 E6 17 D3 A5 C6 34 5A DA 86 A7 F8 02 36 1D | .......4Z.....6.
    00000210 : 66 63 CF E9 C0 3D 82 FB 39 A2 8D 92 01 4A 83 CF | fc...=..9....J..
    00000220 : E2 76 3D 87 02 03 01 00 01 A3 21 30 1F 30 1D 06 | .v=.......!0.0..
    00000230 : 03 55 1D 11 04 16 30 14 82 12 74 65 73 74 2E 70 | .U....0...test.p
    00000240 : 72 69 6E 63 65 62 36 31 32 2E 70 65 30 0D 06 09 | rinceb612.pe0...
    00000250 : 2A 86 48 86 F7 0D 01 01 0B 05 00 03 82 01 01 00 | *.H.............
    00000260 : 00 A5 F5 54 18 AB AD 36 38 C8 FC 0B 66 60 DD 9F | ...T...68...f`..
    00000270 : 75 9D 86 5B 79 2F EE 57 F1 79 1C 15 A1 34 23 D0 | u..[y/.W.y...4#.
    00000280 : 1C A9 58 51 A4 D0 08 F5 D8 F7 49 E9 C5 B5 65 91 | ..XQ......I...e.
    00000290 : 51 2D 6D E4 3B 0E 77 02 1F 45 8E 34 E5 BB EB F6 | Q-m.;.w..E.4....
    000002A0 : 9D DF 4A 40 60 21 B3 8E 16 33 3F F4 B6 90 D3 3C | ..J@`!...3?....<
    000002B0 : 34 CE E6 D9 47 07 A7 57 14 0C F9 78 0B 36 72 A9 | 4...G..W...x.6r.
    000002C0 : 88 07 07 93 B4 D7 FE 29 5E E8 41 37 20 A5 03 C7 | .......)^.A7 ...
    000002D0 : 97 CB 82 CA DB 14 E5 8B 96 1F A9 E9 20 3D 6B 25 | ............ =k%
    000002E0 : AE F4 89 4C 60 8D E9 14 33 47 4B 88 54 A2 47 19 | ...L`...3GK.T.G.
    000002F0 : 81 C8 7B 0E 32 52 2B 91 88 AD 0F 6D 73 30 8C 00 | ..{.2R+....ms0..
    00000300 : AF D5 FC 46 46 AF 3A C2 17 89 EC C8 83 AE DA E6 | ...FF.:.........
    00000310 : 69 63 E0 9C 84 22 C5 7A DE E8 23 6B 53 9D 6F 94 | ic...".z..#kS.o.
    00000320 : D2 7F 5C BE 1D 0C DE 0E 07 0D 52 A5 43 8C E8 05 | ..\.......R.C...
    00000330 : EF C0 FF F0 73 FA DC 5A 51 4C 24 09 65 45 7D AB | ....s..ZQL$.eE}.
    00000340 : 52 8B 7E 5D F0 FB DE A7 3D 43 C5 AF 76 E3 6E F9 | R.~]....=C..v.n.
    00000350 : A1 DC 78 A2 BD 54 41 04 99 E5 56 32 BA 02 FD 72 | ..x..TA...V2...r
  > certificate extensions 0x0000(0)
 RSA (public key)
   modulus (00:n)
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
     rZopZ1_zpHm0xuYyc9jX7YiUFYPkMQAEbLWMrIerdEQTdsoLdClAnpcqAdeLRiZuGTVNwNO16g6TOgbo5YW1JwVj2yi4ktpaFDkP2mhtbwr7UtwID1TT5KIonaBxUILg28rRlN1CmDoJM6jZ7_vSNUOxIqK-QW26kdwLMU6I-U2cYS3sshMKwpGOotbpQLkyuYCPsxijMxMj1dB-2dB_k-AtTZDFWCRW1ckQE0qymSN9NLmOlxlpb87GP9YXp9JD4DbLUXsvGIvCM_hXz9FhC3ztNzXjE3okLncIwuPZ5hfTpcY0WtqGp_gCNh1mY8_pwD2C-zmijZIBSoPP4nY9hw
     h'ad9a29675ff3a479b4c6e63273d8d7ed88941583e43100046cb58cac87ab74441376ca0b7429409e972a01d78b46266e19354dc0d3b5ea0e933a06e8e585b5270563db28b892da5a14390fda686d6f0afb52dc080f54d3e4a2289da0715082e0dbcad194dd42983a0933a8d9effbd23543b122a2be416dba91dc0b314e88f94d9c612decb2130ac2918ea2d6e940b932b9808fb318a3331323d5d07ed9d07f93e02d4d90c5582456d5c910134ab299237d34b98e9719696fcec63fd617a7d243e036cb517b2f188bc233f857cfd1610b7ced3735e3137a242e7708c2e3d9e617d3a5c6345ada86a7f802361d6663cfe9c03d82fb39a28d92014a83cfe2763d87'
   public exponent (e)
     01:00:01
     AQAB
     h'010001'
 -----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEArZopZ1/zpHm0xuYyc9jX7YiUFYPkMQAEbLWMrIerdEQTdsoLdClA
npcqAdeLRiZuGTVNwNO16g6TOgbo5YW1JwVj2yi4ktpaFDkP2mhtbwr7UtwID1TT
5KIonaBxUILg28rRlN1CmDoJM6jZ7/vSNUOxIqK+QW26kdwLMU6I+U2cYS3sshMK
wpGOotbpQLkyuYCPsxijMxMj1dB+2dB/k+AtTZDFWCRW1ckQE0qymSN9NLmOlxlp
b87GP9YXp9JD4DbLUXsvGIvCM/hXz9FhC3ztNzXjE3okLncIwuPZ5hfTpcY0WtqG
p/gCNh1mY8/pwD2C+zmijZIBSoPP4nY9hwIDAQAB
-----END RSA PUBLIC KEY-----

# record (server) [size 0x502 pos 0x3c8]
   00000000 : 16 03 03 01 2C 0C 00 01 28 03 00 1D 20 F4 29 00 | ....,...(... .).
   00000010 : FF 3D 69 88 1D A1 44 60 74 0F AC 51 A0 4C B5 EF | .=i...D`t..Q.L..
   00000020 : 3F FD EB FF 76 63 6E 9C 5D FE 3D 31 2B 04 01 01 | ?...vcn.].=1+...
   00000030 : 00 4D 94 81 0F DD 66 C6 7A FD 9B B4 22 EB 76 B7 | .M....f.z...".v.
   00000040 : DB 28 4B AD 39 00 D5 F7 E5 7A 41 DB D9 30 72 B4 | .(K.9....zA..0r.
   00000050 : C5 B9 09 ED 75 C1 ED 72 E2 15 6F 3F D0 4B 81 46 | ....u..r..o?.K.F
   00000060 : FB 7A AE 8C C3 C3 10 16 F2 71 69 CE 4E D2 84 49 | .z.......qi.N..I
   00000070 : 2C 40 37 0E B9 60 60 36 CE 66 2C 05 F1 A3 59 E5 | ,@7..``6.f,...Y.
   00000080 : 6D 4D 06 BD 72 7D EB C2 72 2E 1B 55 85 51 1F 03 | mM..r}..r..U.Q..
   00000090 : 55 68 6D 6D A8 EA 96 BE A6 20 EB 08 24 E5 A8 86 | Uhmm..... ..$...
   000000A0 : 18 0A 06 58 37 DA 81 E0 EA 9E 05 6C 2C CF 76 4B | ...X7......l,.vK
   000000B0 : 29 FE 52 F4 6A A6 FA B8 D9 81 DB EB 08 DB C4 80 | ).R.j...........
   000000C0 : C2 1D 04 B1 FB 7C 5C B2 73 BF 06 C8 61 7D 18 BB | .....|\.s...a}..
   000000D0 : F8 2B 02 68 9B 52 E2 FA CA 74 3D 07 DD EB 0C 59 | .+.h.R...t=....Y
   000000E0 : 24 61 C2 21 5E 09 12 4E DB 7E 2E D4 D7 BC D6 2B | $a.!^..N.~.....+
   000000F0 : 21 B7 D7 CE B1 65 F8 0E 2F EC 8C 36 C4 5A 03 3A | !....e../..6.Z.:
   00000100 : 13 57 6D 2B 15 DF 65 29 75 41 E0 1D A0 82 BA EE | .Wm+..e)uA......
   00000110 : 12 45 8A E8 57 75 6D 85 3E C2 D3 DC 5A 69 F7 D5 | .E..Wum.>...Zi..
   00000120 : 34 12 51 67 98 2D A0 F1 81 41 12 1C F6 41 F1 A0 | 4.Qg.-...A...A..
   00000130 : 09 -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- | .
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x012c(300)
 > handshake type 0x0c(12) (server_key_exchange)
  > length 0x000128(296)
  > curve info 3 (named_curve)
  > curve 0x001d x25519
  > public key
   > public key len 32
      00000000 : F4 29 00 FF 3D 69 88 1D A1 44 60 74 0F AC 51 A0 | .)..=i...D`t..Q.
      00000010 : 4C B5 EF 3F FD EB FF 76 63 6E 9C 5D FE 3D 31 2B | L..?...vcn.].=1+
  > signature
   > 0x0401 rsa_pkcs1_sha256
   > signature len 256
     00000000 : 4D 94 81 0F DD 66 C6 7A FD 9B B4 22 EB 76 B7 DB | M....f.z...".v..
     00000010 : 28 4B AD 39 00 D5 F7 E5 7A 41 DB D9 30 72 B4 C5 | (K.9....zA..0r..
     00000020 : B9 09 ED 75 C1 ED 72 E2 15 6F 3F D0 4B 81 46 FB | ...u..r..o?.K.F.
     00000030 : 7A AE 8C C3 C3 10 16 F2 71 69 CE 4E D2 84 49 2C | z.......qi.N..I,
     00000040 : 40 37 0E B9 60 60 36 CE 66 2C 05 F1 A3 59 E5 6D | @7..``6.f,...Y.m
     00000050 : 4D 06 BD 72 7D EB C2 72 2E 1B 55 85 51 1F 03 55 | M..r}..r..U.Q..U
     00000060 : 68 6D 6D A8 EA 96 BE A6 20 EB 08 24 E5 A8 86 18 | hmm..... ..$....
     00000070 : 0A 06 58 37 DA 81 E0 EA 9E 05 6C 2C CF 76 4B 29 | ..X7......l,.vK)
     00000080 : FE 52 F4 6A A6 FA B8 D9 81 DB EB 08 DB C4 80 C2 | .R.j............
     00000090 : 1D 04 B1 FB 7C 5C B2 73 BF 06 C8 61 7D 18 BB F8 | ....|\.s...a}...
     000000A0 : 2B 02 68 9B 52 E2 FA CA 74 3D 07 DD EB 0C 59 24 | +.h.R...t=....Y$
     000000B0 : 61 C2 21 5E 09 12 4E DB 7E 2E D4 D7 BC D6 2B 21 | a.!^..N.~.....+!
     000000C0 : B7 D7 CE B1 65 F8 0E 2F EC 8C 36 C4 5A 03 3A 13 | ....e../..6.Z.:.
     000000D0 : 57 6D 2B 15 DF 65 29 75 41 E0 1D A0 82 BA EE 12 | Wm+..e)uA.......
     000000E0 : 45 8A E8 57 75 6D 85 3E C2 D3 DC 5A 69 F7 D5 34 | E..Wum.>...Zi..4
     000000F0 : 12 51 67 98 2D A0 F1 81 41 12 1C F6 41 F1 A0 09 | .Qg.-...A...A...
# record (server) [size 0x502 pos 0x4f9]
   00000000 : 16 03 03 00 04 0E 00 00 00 -- -- -- -- -- -- -- | .........
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x0004(4)
 > handshake type 0x0e(14) (server_hello_done)
  > length 0x000000(0)
# write record content type 0x16(22) (handshake)
# write handshake type 0x10(16) (client_key_exchange)
> SKE
X25519 (public key)
curve X25519
 x
   00:f4:29:00:ff:3d:69:88:1d:a1:44:60:74:0f:ac:51:
   a0:4c:b5:ef:3f:fd:eb:ff:76:63:6e:9c:5d:fe:3d:31:
   2b
   9CkA_z1piB2hRGB0D6xRoEy17z_96_92Y26cXf49MSs
   h'f42900ff3d69881da14460740fac51a04cb5ef3ffdebff76636e9c5dfe3d312b'

> CKE
X25519 (private key)
curve X25519
 x
   00:c7:34:68:18:ac:64:38:c9:5a:9a:50:38:1d:70:0e:
   21:ca:a9:0c:91:22:ea:8e:15:e6:bf:cc:aa:dd:7e:80:
   23
   xzRoGKxkOMlamlA4HXAOIcqpDJEi6o4V5r_Mqt1-gCM
   h'c7346818ac6438c95a9a50381d700e21caa90c9122ea8e15e6bfccaadd7e8023'
 d (private)
   00:30:07:dc:49:4a:42:fa:ff:0b:58:a2:72:a9:da:4c:
   d9:54:32:e0:a0:c2:9d:33:39:7a:18:b8:98:3b:c1:b8:
   6f
   MAfcSUpC-v8LWKJyqdpM2VQy4KDCnTM5ehi4mDvBuG8
   h'3007dc494a42faff0b58a272a9da4cd95432e0a0c29d33397a18b8983bc1b86f'

> hmac alg 5
> client hello random 8806aaf3bab7cfa006497ef50620ddae5320bf1541d2d2a97afb85145aa1d275
> server hello random e736be0bf5e6d9ffec348b1d222e5e5f0dd2d4a46c99ae521de354088872caab
> pre master secret 823fb60b83460ee2575f75fdd2ca9743f870f5c8aaba1bd3c141db7660a1fb11
# CLIENT_RANDOM 8806aaf3bab7cfa006497ef50620ddae5320bf1541d2d2a97afb85145aa1d275 1598a9701b35936119d3b114b9b4df696d3d0fbcd92ee122612b59cdf0752f392e3ff27b38b9b585aa60e09408833a36
> secret_client_mac_key[00000102] d5e395deabd848cf72cb35fb271ae3c0fc359713df2310c15fe411ee2e168648
> secret_server_mac_key[00000103] 8700692ad8d830958ed756828a79a5a63a692cff6cb52c0b33f4e87463eb3779
> secret_client_key[00000108] 8dbce7ce8a9e60e9483a2160aa155bbb
> secret_server_key[0000010b] dd12fd12e3f2592cf8c0ee55739eb163
> secret_client_iv[00000109] ec0e5d7d436c674d96af8b4f3d5fa78c
> secret_server_iv[0000010c] 6d628e23d17b7b8cd0f355611a6c22cf
# record constructed
   00000000 : 16 03 03 00 25 10 00 00 21 20 C7 34 68 18 AC 64 | ....%...! .4h..d
   00000010 : 38 C9 5A 9A 50 38 1D 70 0E 21 CA A9 0C 91 22 EA | 8.Z.P8.p.!....".
   00000020 : 8E 15 E6 BF CC AA DD 7E 80 23 -- -- -- -- -- -- | .......~.#
# write record content type 0x14(20) (change_cipher_spec)
# record constructed
   00000000 : 16 03 03 00 25 10 00 00 21 20 C7 34 68 18 AC 64 | ....%...! .4h..d
   00000010 : 38 C9 5A 9A 50 38 1D 70 0E 21 CA A9 0C 91 22 EA | 8.Z.P8.p.!....".
   00000020 : 8E 15 E6 BF CC AA DD 7E 80 23 14 03 03 00 01 01 | .......~.#......
# write record content type 0x16(22) (handshake)
# write handshake type 0x14(20) (finished)
> verify data
   00000000 : 01 51 3C 99 95 DB 12 DE 88 A8 4C AB -- -- -- -- | .Q<.......L.
  > secret (internal) 0x00000106
  > algorithm sha256 size 12
  > verify data 01513c9995db12de88a84cab
> encrypt
 > aad 0000000000000000160303
 > enc aes-128-cbc
 > enckey[00000108] 8dbce7ce8a9e60e9483a2160aa155bbb
 > iv 03b679086ab01161c3db151d62b77550
 > mac sha256
 > mackey[00000102] d5e395deabd848cf72cb35fb271ae3c0fc359713df2310c15fe411ee2e168648
 > record no 0
 > plaintext
   00000000 : 14 00 00 0C 01 51 3C 99 95 DB 12 DE 88 A8 4C AB | .....Q<.......L.
 > ciphertext
   00000000 : F1 E8 2E E2 82 85 1B 22 73 B6 05 DF E8 C4 40 F8 | ......."s.....@.
   00000010 : 86 B1 4D CE 29 32 F6 74 35 2F F5 3A F5 8C 60 0B | ..M.)2.t5/.:..`.
   00000020 : BB 8E AF 45 57 BD 31 66 3B 55 33 D1 59 57 3B 50 | ...EW.1f;U3.YW;P
   00000030 : 94 DC C4 9D 51 98 15 6B 9E 49 72 76 59 EB 23 F7 | ....Q..k.IrvY.#.
# record constructed
   00000000 : 16 03 03 00 25 10 00 00 21 20 C7 34 68 18 AC 64 | ....%...! .4h..d
   00000010 : 38 C9 5A 9A 50 38 1D 70 0E 21 CA A9 0C 91 22 EA | 8.Z.P8.p.!....".
   00000020 : 8E 15 E6 BF CC AA DD 7E 80 23 14 03 03 00 01 01 | .......~.#......
   00000030 : 16 03 03 00 50 03 B6 79 08 6A B0 11 61 C3 DB 15 | ....P..y.j..a...
   00000040 : 1D 62 B7 75 50 F1 E8 2E E2 82 85 1B 22 73 B6 05 | .b.uP......."s..
   00000050 : DF E8 C4 40 F8 86 B1 4D CE 29 32 F6 74 35 2F F5 | ...@...M.)2.t5/.
   00000060 : 3A F5 8C 60 0B BB 8E AF 45 57 BD 31 66 3B 55 33 | :..`....EW.1f;U3
   00000070 : D1 59 57 3B 50 94 DC C4 9D 51 98 15 6B 9E 49 72 | .YW;P....Q..k.Ir
   00000080 : 76 59 EB 23 F7 -- -- -- -- -- -- -- -- -- -- -- | vY.#.
[ns] read 0x5b
   00000000 : 14 03 03 00 01 01 16 03 03 00 50 CB 3A 05 2D 43 | ..........P.:.-C
   00000010 : 3E E8 BB 9F 8A 50 D8 3D 97 B9 0F 44 E1 06 B3 E4 | >....P.=...D....
   00000020 : 26 87 A7 37 14 D9 B4 E7 80 69 60 B0 C7 17 CE CB | &..7.....i`.....
   00000030 : AA 8E E9 3D A0 08 E3 8E 59 B7 52 67 96 C6 9F F2 | ...=....Y.Rg....
   00000040 : F5 C7 C0 18 32 D2 27 9D CC 44 E1 B1 56 A8 1A 17 | ....2.'..D..V...
   00000050 : AE 8B 55 7E C2 B7 1B 3F 03 E2 CA -- -- -- -- -- | ..U~...?...
# record (server) [size 0x5b pos 0x0]
   00000000 : 14 03 03 00 01 01 -- -- -- -- -- -- -- -- -- -- | ......
> record content type 0x14(20) (change_cipher_spec)
 > record version 0x0303 (TLS v1.2)
 > len 0x0001(1)
# record (server) [size 0x5b pos 0x6]
   00000000 : 16 03 03 00 50 CB 3A 05 2D 43 3E E8 BB 9F 8A 50 | ....P.:.-C>....P
   00000010 : D8 3D 97 B9 0F 44 E1 06 B3 E4 26 87 A7 37 14 D9 | .=...D....&..7..
   00000020 : B4 E7 80 69 60 B0 C7 17 CE CB AA 8E E9 3D A0 08 | ...i`........=..
   00000030 : E3 8E 59 B7 52 67 96 C6 9F F2 F5 C7 C0 18 32 D2 | ..Y.Rg........2.
   00000040 : 27 9D CC 44 E1 B1 56 A8 1A 17 AE 8B 55 7E C2 B7 | '..D..V.....U~..
   00000050 : 1B 3F 03 E2 CA -- -- -- -- -- -- -- -- -- -- -- | .?...
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x0050(80)
> tag
   00000000 : D0 3F 70 B5 CC 61 B7 FF CB 4B 9D 16 D9 6E 60 84 | .?p..a...K...n`.
   00000010 : 38 E8 CD DC AA C5 2D 06 5D 54 26 51 79 B0 F9 0A | 8.....-.]T&Qy...
> decrypt
 > aad 0000000000000000160303
 > enc aes-128-cbc
 > enckey[0000010b] dd12fd12e3f2592cf8c0ee55739eb163
 > iv cb3a052d433ee8bb9f8a50d83d97b90f
 > mac sha256
 > mackey[00000103] 8700692ad8d830958ed756828a79a5a63a692cff6cb52c0b33f4e87463eb3779
 > record no 0
 > ciphertext
   00000000 : 44 E1 06 B3 E4 26 87 A7 37 14 D9 B4 E7 80 69 60 | D....&..7.....i`
   00000010 : B0 C7 17 CE CB AA 8E E9 3D A0 08 E3 8E 59 B7 52 | ........=....Y.R
   00000020 : 67 96 C6 9F F2 F5 C7 C0 18 32 D2 27 9D CC 44 E1 | g........2.'..D.
   00000030 : B1 56 A8 1A 17 AE 8B 55 7E C2 B7 1B 3F 03 E2 CA | .V.....U~...?...
 > plaintext 0x0(0)
   00000000 : 14 00 00 0C F5 78 03 22 92 BE B2 B3 69 F6 72 DB | .....x."....i.r.
 > handshake type 0x14(20) (finished)
  > length 0x00000c(12)
 > verify data true
    00000000 : F5 78 03 22 92 BE B2 B3 69 F6 72 DB -- -- -- -- | .x."....i.r.
   > secret (internal) 0x00000106
   > algorithm sha256 size 12
   > verify data f578032292beb2b369f672db
   > maced       f578032292beb2b369f672db
[00000000][async_tls_client] connect
# write record content type 0x17(23) (application_data)
> encrypt
 > aad 0000000000000001170303
 > enc aes-128-cbc
 > enckey[00000108] 8dbce7ce8a9e60e9483a2160aa155bbb
 > iv a7993ad145c18e6f25141671a356d681
 > mac sha256
 > mackey[00000102] d5e395deabd848cf72cb35fb271ae3c0fc359713df2310c15fe411ee2e168648
 > record no 1
 > plaintext
   00000000 : 68 65 6C 6C 6F 17 -- -- -- -- -- -- -- -- -- -- | hello.
 > ciphertext
   00000000 : DF 39 1E 62 10 68 9A 8E 7E BD 5A 4C 67 FA FA F4 | .9.b.h..~.ZLg...
   00000010 : 9D 1E 9F 91 4D 11 D2 01 FF AC B6 08 97 91 45 AC | ....M.........E.
   00000020 : 88 78 AF BE 99 AF 03 A8 81 D2 2C A4 FB AC 35 C8 | .x........,...5.
# record constructed
   00000000 : 17 03 03 00 40 A7 99 3A D1 45 C1 8E 6F 25 14 16 | ....@..:.E..o%..
   00000010 : 71 A3 56 D6 81 DF 39 1E 62 10 68 9A 8E 7E BD 5A | q.V...9.b.h..~.Z
   00000020 : 4C 67 FA FA F4 9D 1E 9F 91 4D 11 D2 01 FF AC B6 | Lg.......M......
   00000030 : 08 97 91 45 AC 88 78 AF BE 99 AF 03 A8 81 D2 2C | ...E..x........,
   00000040 : A4 FB AC 35 C8 -- -- -- -- -- -- -- -- -- -- -- | ...5.
received response: [464][len 0]
# write record content type 0x15(21) (alert)
> encrypt
 > aad 0000000000000002150303
 > enc aes-128-cbc
 > enckey[00000108] 8dbce7ce8a9e60e9483a2160aa155bbb
 > iv 4861456ba1a0c27a29d52e1326539b13
 > mac sha256
 > mackey[00000102] d5e395deabd848cf72cb35fb271ae3c0fc359713df2310c15fe411ee2e168648
 > record no 2
 > plaintext
   00000000 : 01 00 -- -- -- -- -- -- -- -- -- -- -- -- -- -- | ..
 > ciphertext
   00000000 : CC A1 5D EE CA EA AF BB A6 15 7C F7 0F D2 C0 38 | ..].......|....8
   00000010 : C5 A1 BE 8A 39 63 BE AF DA B1 1A 61 20 62 7C D4 | ....9c.....a b|.
   00000020 : 29 3B 0B 14 45 96 7E 5D 4F 21 24 2F 19 2E 34 23 | );..E.~]O!$/..4#
# record constructed
   00000000 : 15 03 03 00 40 48 61 45 6B A1 A0 C2 7A 29 D5 2E | ....@HaEk...z)..
   00000010 : 13 26 53 9B 13 CC A1 5D EE CA EA AF BB A6 15 7C | .&S....].......|
   00000020 : F7 0F D2 C0 38 C5 A1 BE 8A 39 63 BE AF DA B1 1A | ....8....9c.....
   00000030 : 61 20 62 7C D4 29 3B 0B 14 45 96 7E 5D 4F 21 24 | a b|.);..E.~]O!$
   00000040 : 2F 19 2E 34 23 -- -- -- -- -- -- -- -- -- -- -- | /..4#
- event_loop_break_concurrent : break 1/1
[ns] read 0x45
   00000000 : 15 03 03 00 40 06 EF 55 B7 23 A5 C9 61 8C 0E 76 | ....@..U.#..a..v
   00000010 : 89 3F 14 4F E3 E6 29 0C 39 99 F2 BE A2 32 A8 F4 | .?.O..).9....2..
   00000020 : D0 FC 79 38 EF 2F E6 2D D8 9F C2 82 19 A5 04 95 | ..y8./.-........
   00000030 : 31 04 B5 28 7F 4E 36 7C 74 40 4A EB FA FE C6 98 | 1..(.N6|t@J.....
   00000040 : 60 0C F4 A4 D6 -- -- -- -- -- -- -- -- -- -- -- | `....
# record (server) [size 0x45 pos 0x0]
   00000000 : 15 03 03 00 40 06 EF 55 B7 23 A5 C9 61 8C 0E 76 | ....@..U.#..a..v
   00000010 : 89 3F 14 4F E3 E6 29 0C 39 99 F2 BE A2 32 A8 F4 | .?.O..).9....2..
   00000020 : D0 FC 79 38 EF 2F E6 2D D8 9F C2 82 19 A5 04 95 | ..y8./.-........
   00000030 : 31 04 B5 28 7F 4E 36 7C 74 40 4A EB FA FE C6 98 | 1..(.N6|t@J.....
   00000040 : 60 0C F4 A4 D6 -- -- -- -- -- -- -- -- -- -- -- | `....
> record content type 0x15(21) (alert)
 > record version 0x0303 (TLS v1.2)
 > len 0x0040(64)
> tag
   00000000 : D8 A2 55 A0 C6 2A 84 52 20 45 F2 A2 0F EB 8B AF | ..U..*.R E......
   00000010 : 83 0C A8 2B 62 EC A5 89 C5 92 9D 2C 4F 85 2A E5 | ...+b......,O.*.
> decrypt
 > aad 0000000000000001150303
 > enc aes-128-cbc
 > enckey[0000010b] dd12fd12e3f2592cf8c0ee55739eb163
 > iv 06ef55b723a5c9618c0e76893f144fe3
 > mac sha256
 > mackey[00000103] 8700692ad8d830958ed756828a79a5a63a692cff6cb52c0b33f4e87463eb3779
 > record no 1
 > ciphertext
   00000000 : E6 29 0C 39 99 F2 BE A2 32 A8 F4 D0 FC 79 38 EF | .).9....2....y8.
   00000010 : 2F E6 2D D8 9F C2 82 19 A5 04 95 31 04 B5 28 7F | /.-........1..(.
   00000020 : 4E 36 7C 74 40 4A EB FA FE C6 98 60 0C F4 A4 D6 | N6|t@J.....`....
 > plaintext 0x0(0)
   00000000 : 01 00 -- -- -- -- -- -- -- -- -- -- -- -- -- -- | ..
 > alert
 > alert level 1 warning
 > alert desc  0 close_notify
- event_loop_test_broken : broken detected
[00000000][async_tls_client] client 127.0.0.1:9000
````

[TOC](README.md)
