#### tls12etm_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384.pcapng - client

````
$ ./test-netclient.exe -v -d -i -P tls12 -etm
socket 472 created family 2(AF_INET) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 000001ec created
iocp handle 000001ec bind 472
- event_loop_new tid 00003dd8
# write record content type 0x16(22) (handshake)
# write handshake type 0x01(1) (client_hello)
# record constructed
   00000000 : 16 03 03 00 B9 01 00 00 B5 03 03 5B D8 10 FC 94 | ...........[....
   00000010 : E2 3F 4E 88 98 DB 26 77 17 85 0C F6 85 C6 89 34 | .?N...&w.......4
   00000020 : 58 24 FB 91 85 E6 42 8F DA 1A 83 00 00 10 C0 23 | X$....B........#
   00000030 : C0 24 C0 27 C0 28 C0 72 C0 73 C0 76 C0 77 01 00 | .$.'.(.r.s.v.w..
   00000040 : 00 7C FF 01 00 01 00 00 23 00 00 00 16 00 00 00 | .|......#.......
   00000050 : 0B 00 02 01 00 00 0A 00 0C 00 0A 00 1D 00 17 00 | ................
   00000060 : 1E 00 19 00 18 00 0D 00 1E 00 1C 04 03 05 03 06 | ................
   00000070 : 03 08 07 08 08 04 01 05 01 06 01 08 09 08 0A 08 | ................
   00000080 : 0B 08 04 08 05 08 06 00 2B 00 03 02 03 03 00 2D | ........+......-
   00000090 : 00 02 01 01 00 33 00 26 00 24 00 1D 00 20 81 AD | .....3.&.$... ..
   000000A0 : D9 D4 28 F7 37 9A 1C 02 2F 6C CC D4 B2 1D 98 85 | ..(.7.../l......
   000000B0 : D4 D5 C0 D4 0A 44 16 93 00 2A E8 BA 55 4C -- -- | .....D...*..UL
[ns] read 0x4ef
   00000000 : 16 03 03 00 41 02 00 00 3D 03 03 BE F4 8E 83 C5 | ....A...=.......
   00000010 : DA 09 AB A6 C2 99 30 3E 2B 7A 33 1C 1D 72 6E 61 | ......0>+z3..rna
   00000020 : 2E 3C 9B 44 4F 57 4E 47 52 44 01 00 C0 28 00 00 | .<.DOWNGRD...(..
   00000030 : 15 FF 01 00 01 00 00 0B 00 04 03 00 01 02 00 23 | ...............#
   00000040 : 00 00 00 16 00 00 16 03 03 03 6A 0B 00 03 66 00 | ..........j...f.
   00000050 : 03 63 00 03 60 30 82 03 5C 30 82 02 44 A0 03 02 | .c..`0..\0..D...
   00000060 : 01 02 02 14 63 A6 71 10 79 D6 A6 48 59 DA 67 A9 | ....c.q.y..HY.g.
   00000070 : 04 E8 E3 5F E2 03 A3 26 30 0D 06 09 2A 86 48 86 | ..._...&0...*.H.
   00000080 : F7 0D 01 01 0B 05 00 30 59 31 0B 30 09 06 03 55 | .......0Y1.0...U
   00000090 : 04 06 13 02 4B 52 31 0B 30 09 06 03 55 04 08 0C | ....KR1.0...U...
   000000A0 : 02 47 47 31 0B 30 09 06 03 55 04 07 0C 02 59 49 | .GG1.0...U....YI
   000000B0 : 31 0D 30 0B 06 03 55 04 0A 0C 04 54 65 73 74 31 | 1.0...U....Test1
   000000C0 : 0D 30 0B 06 03 55 04 0B 0C 04 54 65 73 74 31 12 | .0...U....Test1.
   000000D0 : 30 10 06 03 55 04 03 0C 09 54 65 73 74 20 52 6F | 0...U....Test Ro
   000000E0 : 6F 74 30 1E 17 0D 32 34 30 38 32 39 30 36 32 37 | ot0...2408290627
   000000F0 : 31 37 5A 17 0D 32 35 30 38 32 39 30 36 32 37 31 | 17Z..25082906271
   00000100 : 37 5A 30 54 31 0B 30 09 06 03 55 04 06 13 02 4B | 7Z0T1.0...U....K
   00000110 : 52 31 0B 30 09 06 03 55 04 08 0C 02 47 47 31 0B | R1.0...U....GG1.
   00000120 : 30 09 06 03 55 04 07 0C 02 59 49 31 0D 30 0B 06 | 0...U....YI1.0..
   00000130 : 03 55 04 0A 0C 04 54 65 73 74 31 0D 30 0B 06 03 | .U....Test1.0...
   00000140 : 55 04 0B 0C 04 54 65 73 74 31 0D 30 0B 06 03 55 | U....Test1.0...U
   00000150 : 04 03 0C 04 54 65 73 74 30 82 01 22 30 0D 06 09 | ....Test0.."0...
   00000160 : 2A 86 48 86 F7 0D 01 01 01 05 00 03 82 01 0F 00 | *.H.............
   00000170 : 30 82 01 0A 02 82 01 01 00 AD 9A 29 67 5F F3 A4 | 0..........)g_..
   00000180 : 79 B4 C6 E6 32 73 D8 D7 ED 88 94 15 83 E4 31 00 | y...2s........1.
   00000190 : 04 6C B5 8C AC 87 AB 74 44 13 76 CA 0B 74 29 40 | .l.....tD.v..t)@
   000001A0 : 9E 97 2A 01 D7 8B 46 26 6E 19 35 4D C0 D3 B5 EA | ..*...F&n.5M....
   000001B0 : 0E 93 3A 06 E8 E5 85 B5 27 05 63 DB 28 B8 92 DA | ..:.....'.c.(...
   000001C0 : 5A 14 39 0F DA 68 6D 6F 0A FB 52 DC 08 0F 54 D3 | Z.9..hmo..R...T.
   000001D0 : E4 A2 28 9D A0 71 50 82 E0 DB CA D1 94 DD 42 98 | ..(..qP.......B.
   000001E0 : 3A 09 33 A8 D9 EF FB D2 35 43 B1 22 A2 BE 41 6D | :.3.....5C."..Am
   000001F0 : BA 91 DC 0B 31 4E 88 F9 4D 9C 61 2D EC B2 13 0A | ....1N..M.a-....
   00000200 : C2 91 8E A2 D6 E9 40 B9 32 B9 80 8F B3 18 A3 33 | ......@.2......3
   00000210 : 13 23 D5 D0 7E D9 D0 7F 93 E0 2D 4D 90 C5 58 24 | .#..~.....-M..X$
   00000220 : 56 D5 C9 10 13 4A B2 99 23 7D 34 B9 8E 97 19 69 | V....J..#}4....i
   00000230 : 6F CE C6 3F D6 17 A7 D2 43 E0 36 CB 51 7B 2F 18 | o..?....C.6.Q{/.
   00000240 : 8B C2 33 F8 57 CF D1 61 0B 7C ED 37 35 E3 13 7A | ..3.W..a.|.75..z
   00000250 : 24 2E 77 08 C2 E3 D9 E6 17 D3 A5 C6 34 5A DA 86 | $.w.........4Z..
   00000260 : A7 F8 02 36 1D 66 63 CF E9 C0 3D 82 FB 39 A2 8D | ...6.fc...=..9..
   00000270 : 92 01 4A 83 CF E2 76 3D 87 02 03 01 00 01 A3 21 | ..J...v=.......!
   00000280 : 30 1F 30 1D 06 03 55 1D 11 04 16 30 14 82 12 74 | 0.0...U....0...t
   00000290 : 65 73 74 2E 70 72 69 6E 63 65 62 36 31 32 2E 70 | est.princeb612.p
   000002A0 : 65 30 0D 06 09 2A 86 48 86 F7 0D 01 01 0B 05 00 | e0...*.H........
   000002B0 : 03 82 01 01 00 00 A5 F5 54 18 AB AD 36 38 C8 FC | ........T...68..
   000002C0 : 0B 66 60 DD 9F 75 9D 86 5B 79 2F EE 57 F1 79 1C | .f`..u..[y/.W.y.
   000002D0 : 15 A1 34 23 D0 1C A9 58 51 A4 D0 08 F5 D8 F7 49 | ..4#...XQ......I
   000002E0 : E9 C5 B5 65 91 51 2D 6D E4 3B 0E 77 02 1F 45 8E | ...e.Q-m.;.w..E.
   000002F0 : 34 E5 BB EB F6 9D DF 4A 40 60 21 B3 8E 16 33 3F | 4......J@`!...3?
   00000300 : F4 B6 90 D3 3C 34 CE E6 D9 47 07 A7 57 14 0C F9 | ....<4...G..W...
   00000310 : 78 0B 36 72 A9 88 07 07 93 B4 D7 FE 29 5E E8 41 | x.6r........)^.A
   00000320 : 37 20 A5 03 C7 97 CB 82 CA DB 14 E5 8B 96 1F A9 | 7 ..............
   00000330 : E9 20 3D 6B 25 AE F4 89 4C 60 8D E9 14 33 47 4B | . =k%...L`...3GK
   00000340 : 88 54 A2 47 19 81 C8 7B 0E 32 52 2B 91 88 AD 0F | .T.G...{.2R+....
   00000350 : 6D 73 30 8C 00 AF D5 FC 46 46 AF 3A C2 17 89 EC | ms0.....FF.:....
   00000360 : C8 83 AE DA E6 69 63 E0 9C 84 22 C5 7A DE E8 23 | .....ic...".z..#
   00000370 : 6B 53 9D 6F 94 D2 7F 5C BE 1D 0C DE 0E 07 0D 52 | kS.o...\.......R
   00000380 : A5 43 8C E8 05 EF C0 FF F0 73 FA DC 5A 51 4C 24 | .C.......s..ZQL$
   00000390 : 09 65 45 7D AB 52 8B 7E 5D F0 FB DE A7 3D 43 C5 | .eE}.R.~]....=C.
   000003A0 : AF 76 E3 6E F9 A1 DC 78 A2 BD 54 41 04 99 E5 56 | .v.n...x..TA...V
   000003B0 : 32 BA 02 FD 72 16 03 03 01 2C 0C 00 01 28 03 00 | 2...r....,...(..
   000003C0 : 1D 20 AF 57 28 C9 9D 2D 3A 2E DE 89 53 7D 85 D1 | . .W(..-:...S}..
   000003D0 : 82 37 A2 D5 92 45 26 A0 C1 EA B7 51 63 46 35 B6 | .7...E&....QcF5.
   000003E0 : 22 75 04 01 01 00 93 A8 14 F7 C4 61 B6 DF D4 DE | "u.........a....
   000003F0 : 30 BF 41 CA 40 1C B3 57 5F 60 93 9E D0 BA 72 8B | 0.A.@..W_`....r.
   00000400 : 67 09 5E 23 DA E8 65 56 C7 09 2F 66 64 9E 1D D2 | g.^#..eV../fd...
   00000410 : DA 7B D0 07 35 81 6F 70 F6 5A 75 24 67 7B 58 66 | .{..5.op.Zu$g{Xf
   00000420 : 61 26 35 F0 2F 8A C1 32 3D E1 65 F0 26 52 07 BC | a&5./..2=.e.&R..
   00000430 : 63 0C A3 60 E1 00 64 58 71 35 B1 3A 1E 2E 8B 96 | c..`..dXq5.:....
   00000440 : 7A A5 E3 1E 5A B4 F7 79 A0 89 CE EE 47 80 5E E8 | z...Z..y....G.^.
   00000450 : 8B 37 D2 56 A3 8E DF 3A 90 76 95 D0 BE A5 39 49 | .7.V...:.v....9I
   00000460 : 07 5F 50 88 FB 9D CE 3B 00 60 4E 0B B5 34 57 B4 | ._P....;.`N..4W.
   00000470 : D3 2A 31 5F 09 B6 44 91 B0 E9 5A 34 0A FD 7D 45 | .*1_..D...Z4..}E
   00000480 : DC 32 78 3C 56 5C 4E A7 1C A6 3C 93 86 FC 63 88 | .2x<V\N...<...c.
   00000490 : EB 9D A6 B9 86 BF 20 D7 A9 34 A8 27 89 C9 9B 8A | ...... ..4.'....
   000004A0 : A0 63 A9 DD 24 D2 15 40 76 49 0B 26 D9 3A 5B FE | .c..$..@vI.&.:[.
   000004B0 : 11 8B DC 3A 74 80 E8 10 AA 6F ED 00 62 4A 34 96 | ...:t....o..bJ4.
   000004C0 : 4E F6 C5 0C 3B B4 FE AA DA 30 4F 2C 33 93 B9 BC | N...;....0O,3...
   000004D0 : 00 07 BD B3 A2 F4 0C 5E 33 6C 2A C7 11 B8 CC E1 | .......^3l*.....
   000004E0 : 04 D3 BC 37 C3 6B 16 03 03 00 04 0E 00 00 00 -- | ...7.k.........
# record (server) [size 0x4ef pos 0x0]
   00000000 : 16 03 03 00 41 02 00 00 3D 03 03 BE F4 8E 83 C5 | ....A...=.......
   00000010 : DA 09 AB A6 C2 99 30 3E 2B 7A 33 1C 1D 72 6E 61 | ......0>+z3..rna
   00000020 : 2E 3C 9B 44 4F 57 4E 47 52 44 01 00 C0 28 00 00 | .<.DOWNGRD...(..
   00000030 : 15 FF 01 00 01 00 00 0B 00 04 03 00 01 02 00 23 | ...............#
   00000040 : 00 00 00 16 00 00 -- -- -- -- -- -- -- -- -- -- | ......
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x0041(65)
 > handshake type 0x02(2) (server_hello)
  > length 0x00003d(61)
  > version 0x0303 (TLS v1.2)
  > random
    bef48e83c5da09aba6c299303e2b7a331c1d726e612e3c9b444f574e47524401
  > session id
  > cipher suite 0xc028 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
  > compression method 0 null
  > extension len 0x15(21)
  > extension - ff01 renegotiation_info
    00000000 : FF 01 00 01 00 -- -- -- -- -- -- -- -- -- -- -- | .....
   > extension len 0x0001(1)
   > renegotiation_info len 0
  > extension - 000b ec_point_formats
    00000000 : 00 0B 00 04 03 00 01 02 -- -- -- -- -- -- -- -- | ........
   > extension len 0x0004(4)
   > formats 3
     [0] 0x00(0) uncompressed
     [1] 0x01(1) ansiX962_compressed_prime
     [2] 0x02(2) ansiX962_compressed_char2
  > extension - 0023 session_ticket
    00000000 : 00 23 00 00 -- -- -- -- -- -- -- -- -- -- -- -- | .#..
   > extension len 0x0000(0)
  > extension - 0016 encrypt_then_mac
    00000000 : 00 16 00 00 -- -- -- -- -- -- -- -- -- -- -- -- | ....
   > extension len 0x0000(0)
# starting transcript_hash
 > cipher suite 0xc028 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
 > sha384
# record (server) [size 0x4ef pos 0x46]
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

# record (server) [size 0x4ef pos 0x3b5]
   00000000 : 16 03 03 01 2C 0C 00 01 28 03 00 1D 20 AF 57 28 | ....,...(... .W(
   00000010 : C9 9D 2D 3A 2E DE 89 53 7D 85 D1 82 37 A2 D5 92 | ..-:...S}...7...
   00000020 : 45 26 A0 C1 EA B7 51 63 46 35 B6 22 75 04 01 01 | E&....QcF5."u...
   00000030 : 00 93 A8 14 F7 C4 61 B6 DF D4 DE 30 BF 41 CA 40 | ......a....0.A.@
   00000040 : 1C B3 57 5F 60 93 9E D0 BA 72 8B 67 09 5E 23 DA | ..W_`....r.g.^#.
   00000050 : E8 65 56 C7 09 2F 66 64 9E 1D D2 DA 7B D0 07 35 | .eV../fd....{..5
   00000060 : 81 6F 70 F6 5A 75 24 67 7B 58 66 61 26 35 F0 2F | .op.Zu$g{Xfa&5./
   00000070 : 8A C1 32 3D E1 65 F0 26 52 07 BC 63 0C A3 60 E1 | ..2=.e.&R..c..`.
   00000080 : 00 64 58 71 35 B1 3A 1E 2E 8B 96 7A A5 E3 1E 5A | .dXq5.:....z...Z
   00000090 : B4 F7 79 A0 89 CE EE 47 80 5E E8 8B 37 D2 56 A3 | ..y....G.^..7.V.
   000000A0 : 8E DF 3A 90 76 95 D0 BE A5 39 49 07 5F 50 88 FB | ..:.v....9I._P..
   000000B0 : 9D CE 3B 00 60 4E 0B B5 34 57 B4 D3 2A 31 5F 09 | ..;.`N..4W..*1_.
   000000C0 : B6 44 91 B0 E9 5A 34 0A FD 7D 45 DC 32 78 3C 56 | .D...Z4..}E.2x<V
   000000D0 : 5C 4E A7 1C A6 3C 93 86 FC 63 88 EB 9D A6 B9 86 | \N...<...c......
   000000E0 : BF 20 D7 A9 34 A8 27 89 C9 9B 8A A0 63 A9 DD 24 | . ..4.'.....c..$
   000000F0 : D2 15 40 76 49 0B 26 D9 3A 5B FE 11 8B DC 3A 74 | ..@vI.&.:[....:t
   00000100 : 80 E8 10 AA 6F ED 00 62 4A 34 96 4E F6 C5 0C 3B | ....o..bJ4.N...;
   00000110 : B4 FE AA DA 30 4F 2C 33 93 B9 BC 00 07 BD B3 A2 | ....0O,3........
   00000120 : F4 0C 5E 33 6C 2A C7 11 B8 CC E1 04 D3 BC 37 C3 | ..^3l*........7.
   00000130 : 6B -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- | k
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x012c(300)
 > handshake type 0x0c(12) (server_key_exchange)
  > length 0x000128(296)
  > curve info 3 (named_curve)
  > curve 0x001d x25519
  > public key
   > public key len 32
      00000000 : AF 57 28 C9 9D 2D 3A 2E DE 89 53 7D 85 D1 82 37 | .W(..-:...S}...7
      00000010 : A2 D5 92 45 26 A0 C1 EA B7 51 63 46 35 B6 22 75 | ...E&....QcF5."u
  > signature
   > 0x0401 rsa_pkcs1_sha256
   > signature len 256
     00000000 : 93 A8 14 F7 C4 61 B6 DF D4 DE 30 BF 41 CA 40 1C | .....a....0.A.@.
     00000010 : B3 57 5F 60 93 9E D0 BA 72 8B 67 09 5E 23 DA E8 | .W_`....r.g.^#..
     00000020 : 65 56 C7 09 2F 66 64 9E 1D D2 DA 7B D0 07 35 81 | eV../fd....{..5.
     00000030 : 6F 70 F6 5A 75 24 67 7B 58 66 61 26 35 F0 2F 8A | op.Zu$g{Xfa&5./.
     00000040 : C1 32 3D E1 65 F0 26 52 07 BC 63 0C A3 60 E1 00 | .2=.e.&R..c..`..
     00000050 : 64 58 71 35 B1 3A 1E 2E 8B 96 7A A5 E3 1E 5A B4 | dXq5.:....z...Z.
     00000060 : F7 79 A0 89 CE EE 47 80 5E E8 8B 37 D2 56 A3 8E | .y....G.^..7.V..
     00000070 : DF 3A 90 76 95 D0 BE A5 39 49 07 5F 50 88 FB 9D | .:.v....9I._P...
     00000080 : CE 3B 00 60 4E 0B B5 34 57 B4 D3 2A 31 5F 09 B6 | .;.`N..4W..*1_..
     00000090 : 44 91 B0 E9 5A 34 0A FD 7D 45 DC 32 78 3C 56 5C | D...Z4..}E.2x<V\
     000000A0 : 4E A7 1C A6 3C 93 86 FC 63 88 EB 9D A6 B9 86 BF | N...<...c.......
     000000B0 : 20 D7 A9 34 A8 27 89 C9 9B 8A A0 63 A9 DD 24 D2 |  ..4.'.....c..$.
     000000C0 : 15 40 76 49 0B 26 D9 3A 5B FE 11 8B DC 3A 74 80 | .@vI.&.:[....:t.
     000000D0 : E8 10 AA 6F ED 00 62 4A 34 96 4E F6 C5 0C 3B B4 | ...o..bJ4.N...;.
     000000E0 : FE AA DA 30 4F 2C 33 93 B9 BC 00 07 BD B3 A2 F4 | ...0O,3.........
     000000F0 : 0C 5E 33 6C 2A C7 11 B8 CC E1 04 D3 BC 37 C3 6B | .^3l*........7.k
# record (server) [size 0x4ef pos 0x4e6]
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
   00:af:57:28:c9:9d:2d:3a:2e:de:89:53:7d:85:d1:82:
   37:a2:d5:92:45:26:a0:c1:ea:b7:51:63:46:35:b6:22:
   75
   r1coyZ0tOi7eiVN9hdGCN6LVkkUmoMHqt1FjRjW2InU
   h'af5728c99d2d3a2ede89537d85d18237a2d5924526a0c1eab751634635b62275'

> CKE
X25519 (private key)
curve X25519
 x
   00:1a:15:b0:3f:91:f5:a1:40:74:bb:f2:5b:cd:f3:13:
   9e:6d:9d:ef:2b:b8:79:76:4b:be:f1:a0:f6:4a:6a:f4:
   70
   GhWwP5H1oUB0u_JbzfMTnm2d7yu4eXZLvvGg9kpq9HA
   h'1a15b03f91f5a14074bbf25bcdf3139e6d9def2bb879764bbef1a0f64a6af470'
 d (private)
   00:70:c5:cf:36:cb:1e:61:ce:f1:01:e9:08:ad:8e:9c:
   a1:34:d8:42:05:d9:56:d5:03:77:29:53:0c:cf:62:c5:
   41
   cMXPNsseYc7xAekIrY6coTTYQgXZVtUDdylTDM9ixUE
   h'70c5cf36cb1e61cef101e908ad8e9ca134d84205d956d5037729530ccf62c541'

> hmac alg 6
> client hello random 5bd810fc94e23f4e8898db267717850cf685c689345824fb9185e6428fda1a83
> server hello random bef48e83c5da09aba6c299303e2b7a331c1d726e612e3c9b444f574e47524401
> pre master secret 0931765d6b17100fb547f15ee5c0dc0f03fc6aa454ae8e93fe0199e31920e428
# CLIENT_RANDOM 5bd810fc94e23f4e8898db267717850cf685c689345824fb9185e6428fda1a83 1c3539884706c10602a1c8321b408b7eac0a66ff3a7005a3fa45dd895be411ee1a0c7eee5b267e0744b5bdb739a99990
> secret_client_mac_key[00000102] adec776cba4d013b916af52e36b92c2e9698be1497e196cf6a4749276b297ece4b85bde78e75a664d45c0d7a9cc8a3c5
> secret_server_mac_key[00000103] 6a2388f8f93f0017262f6dc1c4125f81e53ab57cc515c201448fef22741da046999765c4e4a869fd8bc133e5aaedc91d
> secret_client_key[00000108] d3c48665ddb67ca4825c1b1965dd10e85b784a662216a636ee66a48c52132bd2
> secret_server_key[0000010b] 0df5c0b7dbb40165336f849fee59c4a77c2a7b095dafc25470087acaffb68781
> secret_client_iv[00000109] 5476a3304c00d980e94f8c106ca3b801
> secret_server_iv[0000010c] ee431d1c96ecc5344954a65b08d5ce4b
# record constructed
   00000000 : 16 03 03 00 25 10 00 00 21 20 1A 15 B0 3F 91 F5 | ....%...! ...?..
   00000010 : A1 40 74 BB F2 5B CD F3 13 9E 6D 9D EF 2B B8 79 | .@t..[....m..+.y
   00000020 : 76 4B BE F1 A0 F6 4A 6A F4 70 -- -- -- -- -- -- | vK....Jj.p
# write record content type 0x14(20) (change_cipher_spec)
# record constructed
   00000000 : 16 03 03 00 25 10 00 00 21 20 1A 15 B0 3F 91 F5 | ....%...! ...?..
   00000010 : A1 40 74 BB F2 5B CD F3 13 9E 6D 9D EF 2B B8 79 | .@t..[....m..+.y
   00000020 : 76 4B BE F1 A0 F6 4A 6A F4 70 14 03 03 00 01 01 | vK....Jj.p......
# write record content type 0x16(22) (handshake)
# write handshake type 0x14(20) (finished)
> finished
  key   1c3539884706c10602a1c8321b408b7eac0a66ff3a7005a3fa45dd895be411ee1a0c7eee5b267e0744b5bdb739a99990
  hash  5033211673df1ad0fb69bbe0d3b15f124437b73da616e5870c518ffb3bc7cf0d732d73a3b6ab3e59a788da4070863f96
  maced b71117c3097dd46e25a23dd0
> verify data
   00000000 : B7 11 17 C3 09 7D D4 6E 25 A2 3D D0 -- -- -- -- | .....}.n%.=.
  > secret (internal) 0x00000106
  > algorithm sha384 size 12
  > verify data b71117c3097dd46e25a23dd0
> encrypt
 > aad 0000000000000000160303
 > enc aes-256-cbc
 > enckey[00000108] d3c48665ddb67ca4825c1b1965dd10e85b784a662216a636ee66a48c52132bd2
 > iv 5476a3304c00d980e94f8c106ca3b801
 > mac sha384
 > mackey[00000102] adec776cba4d013b916af52e36b92c2e9698be1497e196cf6a4749276b297ece4b85bde78e75a664d45c0d7a9cc8a3c5
 > record no 0
 > plaintext
   00000000 : 14 00 00 0C B7 11 17 C3 09 7D D4 6E 25 A2 3D D0 | .........}.n%.=.
 > cbcmaced
   00000000 : 6A 82 08 87 C3 73 1A E6 BD 4E FA 91 8E DE 53 7D | j....s...N....S}
   00000010 : B4 4B B5 0A 6C 9C 52 03 C7 63 D9 FC F6 8F D9 B9 | .K..l.R..c......
   00000020 : 70 B3 32 84 C7 CE 91 73 5C FA 5E A2 BC CB F6 34 | p.2....s\.^....4
   00000030 : 5E 3F B5 B1 F9 20 78 27 BA 8F B0 0C BB D8 DF 61 | ^?... x'.......a
   00000040 : 30 AE 18 BF DC 29 03 05 12 F5 1D 08 54 7F C7 5E | 0....)......T..^
   00000050 : 0B 43 48 DC 68 A6 23 BE C4 2E 6A D2 B0 00 33 57 | .CH.h.#...j...3W
# record constructed
   00000000 : 16 03 03 00 25 10 00 00 21 20 1A 15 B0 3F 91 F5 | ....%...! ...?..
   00000010 : A1 40 74 BB F2 5B CD F3 13 9E 6D 9D EF 2B B8 79 | .@t..[....m..+.y
   00000020 : 76 4B BE F1 A0 F6 4A 6A F4 70 14 03 03 00 01 01 | vK....Jj.p......
   00000030 : 16 03 03 00 60 6A 82 08 87 C3 73 1A E6 BD 4E FA | ....`j....s...N.
   00000040 : 91 8E DE 53 7D B4 4B B5 0A 6C 9C 52 03 C7 63 D9 | ...S}.K..l.R..c.
   00000050 : FC F6 8F D9 B9 70 B3 32 84 C7 CE 91 73 5C FA 5E | .....p.2....s\.^
   00000060 : A2 BC CB F6 34 5E 3F B5 B1 F9 20 78 27 BA 8F B0 | ....4^?... x'...
   00000070 : 0C BB D8 DF 61 30 AE 18 BF DC 29 03 05 12 F5 1D | ....a0....).....
   00000080 : 08 54 7F C7 5E 0B 43 48 DC 68 A6 23 BE C4 2E 6A | .T..^.CH.h.#...j
   00000090 : D2 B0 00 33 57 -- -- -- -- -- -- -- -- -- -- -- | ...3W
[ns] read 0x11a
   00000000 : 16 03 03 00 AA 04 00 00 A6 00 00 1C 20 00 A0 6F | ............ ..o
   00000010 : A9 92 5B DD F6 37 7A F9 EA C1 0F 8A F5 E9 77 7E | ..[..7z.......w~
   00000020 : C4 B8 A2 0B 85 09 54 2F FA 6E AB 03 1C 41 C9 58 | ......T/.n...A.X
   00000030 : FC 0D B9 6B 27 47 EA C0 50 CD DB 1D A1 43 76 90 | ...k'G..P....Cv.
   00000040 : 1F C8 56 DA E1 04 6E D8 6B 8B E7 22 C1 71 2F B7 | ..V...n.k..".q/.
   00000050 : ED 76 D4 4D AB 6E 25 06 2E B9 50 47 7E 76 5A CD | .v.M.n%...PG~vZ.
   00000060 : 56 C7 5A 2C 60 FC 71 EA 5D 99 8A 21 1C 7B 01 2A | V.Z,`.q.]..!.{.*
   00000070 : 20 56 B1 8B 86 73 FF 6A 71 A5 E9 5A F4 B5 A6 32 |  V...s.jq..Z...2
   00000080 : 9E 3F 5E 30 5D 5B 37 8F FB 1D 05 ED 61 E0 EB B1 | .?^0][7.....a...
   00000090 : C7 1C E6 9A D5 99 96 7D 0E E0 E4 B3 0B 63 28 51 | .......}.....c(Q
   000000A0 : 45 0B E4 D3 2A 81 CD 3F 82 1E 5D 6C 2E 7F 96 14 | E...*..?..]l....
   000000B0 : 03 03 00 01 01 16 03 03 00 60 0B F3 55 42 A9 47 | .........`..UB.G
   000000C0 : F3 97 DC E9 D5 F7 85 CA 51 39 76 19 E2 78 A7 83 | ........Q9v..x..
   000000D0 : 7B 7F 0B C9 42 82 5C E8 AD 90 66 83 32 07 19 17 | {...B.\...f.2...
   000000E0 : 29 A5 06 CB 16 D6 4B 0A 9B C8 63 48 C2 B5 BD 8F | ).....K...cH....
   000000F0 : D5 6B 8F EB 00 65 5D B6 FB 74 59 81 9E F0 B1 44 | .k...e]..tY....D
   00000100 : 6B 79 4A 87 88 C5 7F BA BD 56 3C 80 60 4A 5F F8 | kyJ......V<.`J_.
   00000110 : A2 BF 69 A1 65 53 D6 7A B1 C8 -- -- -- -- -- -- | ..i.eS.z..
# record (server) [size 0x11a pos 0x0]
   00000000 : 16 03 03 00 AA 04 00 00 A6 00 00 1C 20 00 A0 6F | ............ ..o
   00000010 : A9 92 5B DD F6 37 7A F9 EA C1 0F 8A F5 E9 77 7E | ..[..7z.......w~
   00000020 : C4 B8 A2 0B 85 09 54 2F FA 6E AB 03 1C 41 C9 58 | ......T/.n...A.X
   00000030 : FC 0D B9 6B 27 47 EA C0 50 CD DB 1D A1 43 76 90 | ...k'G..P....Cv.
   00000040 : 1F C8 56 DA E1 04 6E D8 6B 8B E7 22 C1 71 2F B7 | ..V...n.k..".q/.
   00000050 : ED 76 D4 4D AB 6E 25 06 2E B9 50 47 7E 76 5A CD | .v.M.n%...PG~vZ.
   00000060 : 56 C7 5A 2C 60 FC 71 EA 5D 99 8A 21 1C 7B 01 2A | V.Z,`.q.]..!.{.*
   00000070 : 20 56 B1 8B 86 73 FF 6A 71 A5 E9 5A F4 B5 A6 32 |  V...s.jq..Z...2
   00000080 : 9E 3F 5E 30 5D 5B 37 8F FB 1D 05 ED 61 E0 EB B1 | .?^0][7.....a...
   00000090 : C7 1C E6 9A D5 99 96 7D 0E E0 E4 B3 0B 63 28 51 | .......}.....c(Q
   000000A0 : 45 0B E4 D3 2A 81 CD 3F 82 1E 5D 6C 2E 7F 96 -- | E...*..?..]l...
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x00aa(170)
 > handshake type 0x04(4) (new_session_ticket)
  > length 0x0000a6(166)
  > ticket timeline 0x00001c20 (7200 secs)
  > ticket age add 0x00a06fa9
  > ticket nonce 5bddf6377af9eac10f8af5e9777ec4b8a20b8509542ffa6eab031c41c958fc0db96b2747eac050cddb1da14376901fc856dae1046ed86b8be722c1712fb7ed76d44dab6e25062eb950477e765acd56c75a2c60fc71ea5d998a211c7b012a2056b18b8673ff6a71a5e95af4b5a6329e3f5e305d5b378ffb1d05ed61e0ebb1c71ce69ad599967d0ee0e4b30b632851450be4d3
  > session ticket
  > ticket extensions
# record (server) [size 0x11a pos 0xaf]
   00000000 : 14 03 03 00 01 01 -- -- -- -- -- -- -- -- -- -- | ......
> record content type 0x14(20) (change_cipher_spec)
 > record version 0x0303 (TLS v1.2)
 > len 0x0001(1)
# record (server) [size 0x11a pos 0xb5]
   00000000 : 16 03 03 00 60 0B F3 55 42 A9 47 F3 97 DC E9 D5 | ....`..UB.G.....
   00000010 : F7 85 CA 51 39 76 19 E2 78 A7 83 7B 7F 0B C9 42 | ...Q9v..x..{...B
   00000020 : 82 5C E8 AD 90 66 83 32 07 19 17 29 A5 06 CB 16 | .\...f.2...)....
   00000030 : D6 4B 0A 9B C8 63 48 C2 B5 BD 8F D5 6B 8F EB 00 | .K...cH.....k...
   00000040 : 65 5D B6 FB 74 59 81 9E F0 B1 44 6B 79 4A 87 88 | e]..tY....DkyJ..
   00000050 : C5 7F BA BD 56 3C 80 60 4A 5F F8 A2 BF 69 A1 65 | ....V<.`J_...i.e
   00000060 : 53 D6 7A B1 C8 -- -- -- -- -- -- -- -- -- -- -- | S.z..
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x0060(96)
> decrypt
 > aad 0000000000000000160303
 > enc aes-256-cbc
 > enckey[0000010b] 0df5c0b7dbb40165336f849fee59c4a77c2a7b095dafc25470087acaffb68781
 > iv ee431d1c96ecc5344954a65b08d5ce4b
 > mac sha384
 > mackey[00000103] 6a2388f8f93f0017262f6dc1c4125f81e53ab57cc515c201448fef22741da046999765c4e4a869fd8bc133e5aaedc91d
 > record no 0
 > ciphertext
   00000000 : 0B F3 55 42 A9 47 F3 97 DC E9 D5 F7 85 CA 51 39 | ..UB.G........Q9
   00000010 : 76 19 E2 78 A7 83 7B 7F 0B C9 42 82 5C E8 AD 90 | v..x..{...B.\...
   00000020 : 66 83 32 07 19 17 29 A5 06 CB 16 D6 4B 0A 9B C8 | f.2...).....K...
   00000030 : 63 48 C2 B5 BD 8F D5 6B 8F EB 00 65 5D B6 FB 74 | cH.....k...e]..t
   00000040 : 59 81 9E F0 B1 44 6B 79 4A 87 88 C5 7F BA BD 56 | Y....DkyJ......V
   00000050 : 3C 80 60 4A 5F F8 A2 BF 69 A1 65 53 D6 7A B1 C8 | <.`J_...i.eS.z..
 > plaintext 0x0(0)
   00000000 : 14 00 00 0C 33 88 DF 03 60 84 02 BD AC 29 6D 16 | ....3...`....)m.
 > handshake type 0x14(20) (finished)
  > length 0x00000c(12)
> finished
  key   1c3539884706c10602a1c8321b408b7eac0a66ff3a7005a3fa45dd895be411ee1a0c7eee5b267e0744b5bdb739a99990
  hash  e62d1ce778adb60eca9e030a70c7e10319f27f252fb934660f6c4a83d643c3b3aab38841af1986b19c31ff00bfa3a94b
  maced 3388df03608402bdac296d16
 > verify data true
    00000000 : 33 88 DF 03 60 84 02 BD AC 29 6D 16 -- -- -- -- | 3...`....)m.
   > secret (internal) 0x00000106
   > algorithm sha384 size 12
   > verify data 3388df03608402bdac296d16
   > maced       3388df03608402bdac296d16
[00000000][async_tls_client] connect
# write record content type 0x17(23) (application_data)
> encrypt
 > aad 0000000000000001170303
 > enc aes-256-cbc
 > enckey[00000108] d3c48665ddb67ca4825c1b1965dd10e85b784a662216a636ee66a48c52132bd2
 > iv 5476a3304c00d980e94f8c106ca3b801
 > mac sha384
 > mackey[00000102] adec776cba4d013b916af52e36b92c2e9698be1497e196cf6a4749276b297ece4b85bde78e75a664d45c0d7a9cc8a3c5
 > record no 1
 > plaintext
   00000000 : 68 65 6C 6C 6F 17 -- -- -- -- -- -- -- -- -- -- | hello.
 > cbcmaced
   00000000 : D6 C4 E8 29 58 C7 DD 23 1F 66 0D 25 B9 39 0B FD | ...)X..#.f.%.9..
   00000010 : CA 2B C1 68 F2 E2 B5 5E 2E 0D F0 C1 78 24 6B E6 | .+.h...^....x$k.
   00000020 : 92 AE BD 91 98 5C 29 AA 40 51 D9 CD 29 2D D7 AE | .....\).@Q..)-..
   00000030 : CF F7 00 D4 C4 D4 F1 82 DF EE 35 11 5C E8 FD 7D | ..........5.\..}
   00000040 : F2 EB 82 3B 99 99 28 AD 02 6D A8 E2 78 39 23 87 | ...;..(..m..x9#.
# record constructed
   00000000 : 17 03 03 00 50 D6 C4 E8 29 58 C7 DD 23 1F 66 0D | ....P...)X..#.f.
   00000010 : 25 B9 39 0B FD CA 2B C1 68 F2 E2 B5 5E 2E 0D F0 | %.9...+.h...^...
   00000020 : C1 78 24 6B E6 92 AE BD 91 98 5C 29 AA 40 51 D9 | .x$k......\).@Q.
   00000030 : CD 29 2D D7 AE CF F7 00 D4 C4 D4 F1 82 DF EE 35 | .)-............5
   00000040 : 11 5C E8 FD 7D F2 EB 82 3B 99 99 28 AD 02 6D A8 | .\..}...;..(..m.
   00000050 : E2 78 39 23 87 -- -- -- -- -- -- -- -- -- -- -- | .x9#.
received response: [472][len 0]
# write record content type 0x15(21) (alert)
> encrypt
 > aad 0000000000000002150303
 > enc aes-256-cbc
 > enckey[00000108] d3c48665ddb67ca4825c1b1965dd10e85b784a662216a636ee66a48c52132bd2
 > iv 5476a3304c00d980e94f8c106ca3b801
 > mac sha384
 > mackey[00000102] adec776cba4d013b916af52e36b92c2e9698be1497e196cf6a4749276b297ece4b85bde78e75a664d45c0d7a9cc8a3c5
 > record no 2
 > plaintext
   00000000 : 01 00 -- -- -- -- -- -- -- -- -- -- -- -- -- -- | ..
 > cbcmaced
   00000000 : AB DF C9 0C B0 3D 68 67 1F 35 FA 16 B4 1C E9 62 | .....=hg.5.....b
   00000010 : DD A9 FC E2 35 75 3C A6 28 8A 43 EB 0C BA 54 50 | ....5u<.(.C...TP
   00000020 : AB F2 31 89 89 69 38 59 66 14 6C 1E 99 A5 78 A0 | ..1..i8Yf.l...x.
   00000030 : AD 28 C0 B7 3A 1A 0D 9E 19 2C 1D 60 FE 4D 21 2B | .(..:....,.`.M!+
   00000040 : 77 FE 04 85 88 C4 F4 4D A4 AC F2 01 41 86 35 58 | w......M....A.5X
# record constructed
   00000000 : 15 03 03 00 50 AB DF C9 0C B0 3D 68 67 1F 35 FA | ....P.....=hg.5.
   00000010 : 16 B4 1C E9 62 DD A9 FC E2 35 75 3C A6 28 8A 43 | ....b....5u<.(.C
   00000020 : EB 0C BA 54 50 AB F2 31 89 89 69 38 59 66 14 6C | ...TP..1..i8Yf.l
   00000030 : 1E 99 A5 78 A0 AD 28 C0 B7 3A 1A 0D 9E 19 2C 1D | ...x..(..:....,.
   00000040 : 60 FE 4D 21 2B 77 FE 04 85 88 C4 F4 4D A4 AC F2 | `.M!+w......M...
   00000050 : 01 41 86 35 58 -- -- -- -- -- -- -- -- -- -- -- | .A.5X
- event_loop_break_concurrent : break 1/1
[ns] read 0x55
   00000000 : 15 03 03 00 50 15 28 A8 87 4F 13 FB 46 1B 54 7B | ....P.(..O..F.T{
   00000010 : 9D 61 C3 41 0D 34 4F C2 12 77 80 40 67 2E 5F 75 | .a.A.4O..w.@g._u
   00000020 : 35 78 58 27 2B 84 27 A3 89 69 69 AE 1B 2F F2 FC | 5xX'+.'..ii../..
   00000030 : 8F 2A 3D 8B 05 51 A9 03 49 D5 BD 1D 9E EB 0B 79 | .*=..Q..I......y
   00000040 : A5 4A 09 BC 5F D3 DF FD 36 72 A5 3F A2 FE B7 5D | .J.._...6r.?...]
   00000050 : 25 5C 44 BC 50 -- -- -- -- -- -- -- -- -- -- -- | %\D.P
# record (server) [size 0x55 pos 0x0]
   00000000 : 15 03 03 00 50 15 28 A8 87 4F 13 FB 46 1B 54 7B | ....P.(..O..F.T{
   00000010 : 9D 61 C3 41 0D 34 4F C2 12 77 80 40 67 2E 5F 75 | .a.A.4O..w.@g._u
   00000020 : 35 78 58 27 2B 84 27 A3 89 69 69 AE 1B 2F F2 FC | 5xX'+.'..ii../..
   00000030 : 8F 2A 3D 8B 05 51 A9 03 49 D5 BD 1D 9E EB 0B 79 | .*=..Q..I......y
   00000040 : A5 4A 09 BC 5F D3 DF FD 36 72 A5 3F A2 FE B7 5D | .J.._...6r.?...]
   00000050 : 25 5C 44 BC 50 -- -- -- -- -- -- -- -- -- -- -- | %\D.P
> record content type 0x15(21) (alert)
 > record version 0x0303 (TLS v1.2)
 > len 0x0050(80)
> decrypt
 > aad 0000000000000001150303
 > enc aes-256-cbc
 > enckey[0000010b] 0df5c0b7dbb40165336f849fee59c4a77c2a7b095dafc25470087acaffb68781
 > iv ee431d1c96ecc5344954a65b08d5ce4b
 > mac sha384
 > mackey[00000103] 6a2388f8f93f0017262f6dc1c4125f81e53ab57cc515c201448fef22741da046999765c4e4a869fd8bc133e5aaedc91d
 > record no 1
 > ciphertext
   00000000 : 15 28 A8 87 4F 13 FB 46 1B 54 7B 9D 61 C3 41 0D | .(..O..F.T{.a.A.
   00000010 : 34 4F C2 12 77 80 40 67 2E 5F 75 35 78 58 27 2B | 4O..w.@g._u5xX'+
   00000020 : 84 27 A3 89 69 69 AE 1B 2F F2 FC 8F 2A 3D 8B 05 | .'..ii../...*=..
   00000030 : 51 A9 03 49 D5 BD 1D 9E EB 0B 79 A5 4A 09 BC 5F | Q..I......y.J.._
   00000040 : D3 DF FD 36 72 A5 3F A2 FE B7 5D 25 5C 44 BC 50 | ...6r.?...]%\D.P
 > plaintext 0x0(0)
   00000000 : 01 00 -- -- -- -- -- -- -- -- -- -- -- -- -- -- | ..
 > alert
 > alert level 1 warning
 > alert desc  0 close_notify
- event_loop_test_broken : broken detected
[00000000][async_tls_client] client 127.0.0.1:9000
````

[TOC](README.md)
