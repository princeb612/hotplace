#### client

````
$ ./test-netclient -v -d -P tls12 -T
socket 3 created family 2(AF_INET) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
connect SO_ERROR 0 return 0
epoll handle 4 created
epoll handle 4 bind 3
- event_loop_new tid 2284c700
# write record content type 0x16(22) (handshake)
# write 0x7ffd0c845050 handshake type 0x01(1) (client_hello)
 # handshake
 > handshake type 0x01(1) (client_hello)
  > length 0x0000a0(160)
# record (client)
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x00a4(164)
# record constructed
   00000000 : 16 03 03 00 A4 01 00 00 A0 03 03 68 2A 69 63 67 | ...........h*icg
   00000010 : A6 77 B6 71 62 CB C4 8C BF 9A 94 86 C1 49 BA FB | .w.qb........I..
   00000020 : D8 40 46 B7 21 29 08 1E 73 BE 7A 00 00 36 13 01 | .@F.!)..s.z..6..
   00000030 : 13 02 13 03 13 04 13 05 C0 23 C0 24 C0 27 C0 28 | .........#.$.'.(
   00000040 : C0 2B C0 2C C0 2F C0 30 C0 5C C0 5D C0 60 C0 61 | .+.,./.0.\.].`.a
   00000050 : C0 72 C0 73 C0 76 C0 77 C0 AC C0 AD C0 AE C0 AF | .r.s.v.w........
   00000060 : CC A8 CC A9 01 00 00 41 00 0B 00 02 01 00 00 0A | .......A........
   00000070 : 00 0C 00 0A 00 1D 00 17 00 1E 00 19 00 18 00 0D | ................
   00000080 : 00 1E 00 1C 04 03 05 03 06 03 08 07 08 08 04 01 | ................
   00000090 : 05 01 06 01 08 09 08 0A 08 0B 08 04 08 05 08 06 | ................
   000000A0 : 00 23 00 00 FF 01 00 01 00 -- -- -- -- -- -- -- | .#.......
[ns] read 0x4eb
   00000000 : 16 03 03 00 3D 02 00 00 39 03 03 DE D5 2F 83 BE | ....=...9..../..
   00000010 : E2 14 EB 1A C5 EA 81 F1 E4 DA 4B D1 E6 5C C7 2E | ..........K..\..
   00000020 : 07 13 D0 44 4F 57 4E 47 52 44 01 00 C0 27 00 00 | ...DOWNGRD...'..
   00000030 : 11 FF 01 00 01 00 00 0B 00 04 03 00 01 02 00 23 | ...............#
   00000040 : 00 00 16 03 03 03 6A 0B 00 03 66 00 03 63 00 03 | ......j...f..c..
   00000050 : 60 30 82 03 5C 30 82 02 44 A0 03 02 01 02 02 14 | `0..\0..D.......
   00000060 : 63 A6 71 10 79 D6 A6 48 59 DA 67 A9 04 E8 E3 5F | c.q.y..HY.g...._
   00000070 : E2 03 A3 26 30 0D 06 09 2A 86 48 86 F7 0D 01 01 | ...&0...*.H.....
   00000080 : 0B 05 00 30 59 31 0B 30 09 06 03 55 04 06 13 02 | ...0Y1.0...U....
   00000090 : 4B 52 31 0B 30 09 06 03 55 04 08 0C 02 47 47 31 | KR1.0...U....GG1
   000000A0 : 0B 30 09 06 03 55 04 07 0C 02 59 49 31 0D 30 0B | .0...U....YI1.0.
   000000B0 : 06 03 55 04 0A 0C 04 54 65 73 74 31 0D 30 0B 06 | ..U....Test1.0..
   000000C0 : 03 55 04 0B 0C 04 54 65 73 74 31 12 30 10 06 03 | .U....Test1.0...
   000000D0 : 55 04 03 0C 09 54 65 73 74 20 52 6F 6F 74 30 1E | U....Test Root0.
   000000E0 : 17 0D 32 34 30 38 32 39 30 36 32 37 31 37 5A 17 | ..240829062717Z.
   000000F0 : 0D 32 35 30 38 32 39 30 36 32 37 31 37 5A 30 54 | .250829062717Z0T
   00000100 : 31 0B 30 09 06 03 55 04 06 13 02 4B 52 31 0B 30 | 1.0...U....KR1.0
   00000110 : 09 06 03 55 04 08 0C 02 47 47 31 0B 30 09 06 03 | ...U....GG1.0...
   00000120 : 55 04 07 0C 02 59 49 31 0D 30 0B 06 03 55 04 0A | U....YI1.0...U..
   00000130 : 0C 04 54 65 73 74 31 0D 30 0B 06 03 55 04 0B 0C | ..Test1.0...U...
   00000140 : 04 54 65 73 74 31 0D 30 0B 06 03 55 04 03 0C 04 | .Test1.0...U....
   00000150 : 54 65 73 74 30 82 01 22 30 0D 06 09 2A 86 48 86 | Test0.."0...*.H.
   00000160 : F7 0D 01 01 01 05 00 03 82 01 0F 00 30 82 01 0A | ............0...
   00000170 : 02 82 01 01 00 AD 9A 29 67 5F F3 A4 79 B4 C6 E6 | .......)g_..y...
   00000180 : 32 73 D8 D7 ED 88 94 15 83 E4 31 00 04 6C B5 8C | 2s........1..l..
   00000190 : AC 87 AB 74 44 13 76 CA 0B 74 29 40 9E 97 2A 01 | ...tD.v..t)@..*.
   000001A0 : D7 8B 46 26 6E 19 35 4D C0 D3 B5 EA 0E 93 3A 06 | ..F&n.5M......:.
   000001B0 : E8 E5 85 B5 27 05 63 DB 28 B8 92 DA 5A 14 39 0F | ....'.c.(...Z.9.
   000001C0 : DA 68 6D 6F 0A FB 52 DC 08 0F 54 D3 E4 A2 28 9D | .hmo..R...T...(.
   000001D0 : A0 71 50 82 E0 DB CA D1 94 DD 42 98 3A 09 33 A8 | .qP.......B.:.3.
   000001E0 : D9 EF FB D2 35 43 B1 22 A2 BE 41 6D BA 91 DC 0B | ....5C."..Am....
   000001F0 : 31 4E 88 F9 4D 9C 61 2D EC B2 13 0A C2 91 8E A2 | 1N..M.a-........
   00000200 : D6 E9 40 B9 32 B9 80 8F B3 18 A3 33 13 23 D5 D0 | ..@.2......3.#..
   00000210 : 7E D9 D0 7F 93 E0 2D 4D 90 C5 58 24 56 D5 C9 10 | ~.....-M..X$V...
   00000220 : 13 4A B2 99 23 7D 34 B9 8E 97 19 69 6F CE C6 3F | .J..#}4....io..?
   00000230 : D6 17 A7 D2 43 E0 36 CB 51 7B 2F 18 8B C2 33 F8 | ....C.6.Q{/...3.
   00000240 : 57 CF D1 61 0B 7C ED 37 35 E3 13 7A 24 2E 77 08 | W..a.|.75..z$.w.
   00000250 : C2 E3 D9 E6 17 D3 A5 C6 34 5A DA 86 A7 F8 02 36 | ........4Z.....6
   00000260 : 1D 66 63 CF E9 C0 3D 82 FB 39 A2 8D 92 01 4A 83 | .fc...=..9....J.
   00000270 : CF E2 76 3D 87 02 03 01 00 01 A3 21 30 1F 30 1D | ..v=.......!0.0.
   00000280 : 06 03 55 1D 11 04 16 30 14 82 12 74 65 73 74 2E | ..U....0...test.
   00000290 : 70 72 69 6E 63 65 62 36 31 32 2E 70 65 30 0D 06 | princeb612.pe0..
   000002A0 : 09 2A 86 48 86 F7 0D 01 01 0B 05 00 03 82 01 01 | .*.H............
   000002B0 : 00 00 A5 F5 54 18 AB AD 36 38 C8 FC 0B 66 60 DD | ....T...68...f`.
   000002C0 : 9F 75 9D 86 5B 79 2F EE 57 F1 79 1C 15 A1 34 23 | .u..[y/.W.y...4#
   000002D0 : D0 1C A9 58 51 A4 D0 08 F5 D8 F7 49 E9 C5 B5 65 | ...XQ......I...e
   000002E0 : 91 51 2D 6D E4 3B 0E 77 02 1F 45 8E 34 E5 BB EB | .Q-m.;.w..E.4...
   000002F0 : F6 9D DF 4A 40 60 21 B3 8E 16 33 3F F4 B6 90 D3 | ...J@`!...3?....
   00000300 : 3C 34 CE E6 D9 47 07 A7 57 14 0C F9 78 0B 36 72 | <4...G..W...x.6r
   00000310 : A9 88 07 07 93 B4 D7 FE 29 5E E8 41 37 20 A5 03 | ........)^.A7 ..
   00000320 : C7 97 CB 82 CA DB 14 E5 8B 96 1F A9 E9 20 3D 6B | ............. =k
   00000330 : 25 AE F4 89 4C 60 8D E9 14 33 47 4B 88 54 A2 47 | %...L`...3GK.T.G
   00000340 : 19 81 C8 7B 0E 32 52 2B 91 88 AD 0F 6D 73 30 8C | ...{.2R+....ms0.
   00000350 : 00 AF D5 FC 46 46 AF 3A C2 17 89 EC C8 83 AE DA | ....FF.:........
   00000360 : E6 69 63 E0 9C 84 22 C5 7A DE E8 23 6B 53 9D 6F | .ic...".z..#kS.o
   00000370 : 94 D2 7F 5C BE 1D 0C DE 0E 07 0D 52 A5 43 8C E8 | ...\.......R.C..
   00000380 : 05 EF C0 FF F0 73 FA DC 5A 51 4C 24 09 65 45 7D | .....s..ZQL$.eE}
   00000390 : AB 52 8B 7E 5D F0 FB DE A7 3D 43 C5 AF 76 E3 6E | .R.~]....=C..v.n
   000003A0 : F9 A1 DC 78 A2 BD 54 41 04 99 E5 56 32 BA 02 FD | ...x..TA...V2...
   000003B0 : 72 16 03 03 01 2C 0C 00 01 28 03 00 1D 20 B5 26 | r....,...(... .&
   000003C0 : 7B DB 89 9E FE 6C 72 51 EE DF 9C 3F 4A 40 95 78 | {....lrQ...?J@.x
   000003D0 : FE 22 32 77 21 F9 BC 67 C1 32 95 CC 3E 06 04 01 | ."2w!..g.2..>...
   000003E0 : 01 00 A3 9B F5 8C F2 D8 98 4D 29 5A 2A 8C 64 42 | .........M)Z*.dB
   000003F0 : 27 E2 3C F3 03 BA 11 8C 1E C2 2B 04 4A 85 09 24 | '.<.......+.J..$
   00000400 : B0 4D E8 36 88 BB 07 98 07 CF DC CB D0 28 B4 8D | .M.6.........(..
   00000410 : 7F FD 6A B1 49 AF 53 F3 DC 21 04 58 67 87 2A 3D | ..j.I.S..!.Xg.*=
   00000420 : 78 12 B7 CE F1 C1 D3 10 9A EF FC B9 21 4A 23 D8 | x...........!J#.
   00000430 : 22 50 65 D1 BB 8F 05 A3 B0 2C 81 CC FE 7C EA AD | "Pe......,...|..
   00000440 : D9 3D E4 14 27 5F 63 48 21 DD B7 6C D9 3C CB B2 | .=..'_cH!..l.<..
   00000450 : 7E 44 EE 26 87 44 6F FB 7A 61 36 6E 42 F1 E8 82 | ~D.&.Do.za6nB...
   00000460 : 87 85 47 AD C4 A8 1B F7 DA 17 23 F1 09 37 B2 B9 | ..G.......#..7..
   00000470 : 00 8D DE E6 CC 3F F0 FC B2 FB 21 48 3A C5 39 55 | .....?....!H:.9U
   00000480 : 59 7A 26 75 5E F6 7E CF C7 76 CE 2E 32 A6 0D DC | Yz&u^.~..v..2...
   00000490 : FA 87 50 3E C2 83 60 1E 8B 19 E8 7A 1E 60 A1 6C | ..P>..`....z.`.l
   000004A0 : 5F B6 6B D5 3C 5D 9C 95 49 2F A3 96 94 3E 42 22 | _.k.<]..I/...>B"
   000004B0 : 11 BC 45 3C AF C2 A4 13 5A 61 4C 1E 53 39 23 38 | ..E<....ZaL.S9#8
   000004C0 : 71 A5 94 3D E3 83 3A 54 FC 5A 29 9A E8 D8 02 21 | q..=..:T.Z)....!
   000004D0 : D7 22 D5 7D 72 07 EB 1F A0 9A 3F 9C CD 2C 8C AB | .".}r.....?..,..
   000004E0 : 70 85 16 03 03 00 04 0E 00 00 00 -- -- -- -- -- | p..........
# record (server) [size 0x4eb pos 0x0]
   00000000 : 16 03 03 00 3D 02 00 00 39 03 03 DE D5 2F 83 BE | ....=...9..../..
   00000010 : E2 14 EB 1A C5 EA 81 F1 E4 DA 4B D1 E6 5C C7 2E | ..........K..\..
   00000020 : 07 13 D0 44 4F 57 4E 47 52 44 01 00 C0 27 00 00 | ...DOWNGRD...'..
   00000030 : 11 FF 01 00 01 00 00 0B 00 04 03 00 01 02 00 23 | ...............#
   00000040 : 00 00 -- -- -- -- -- -- -- -- -- -- -- -- -- -- | ..
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x003d(61)
# read 0x7ffd0c845050 handshake type 0x02(2) (server_hello)
 > handshake type 0x02(2) (server_hello)
  > length 0x000039(57)
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
  > version 0x0303 (TLS v1.2)
  > random
    ded52f83bee214eb1ac5ea81f1e4da4bd1e65cc72e0713d0444f574e47524401
  > session id
  > cipher suite 0xc027 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  > compression method 0 null
  > extension len 0x11(17)
openssl version 30300020
# record (server) [size 0x4eb pos 0x42]
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
# read 0x7ffd0c845050 handshake type 0x0b(11) (certificate)
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

# record (server) [size 0x4eb pos 0x3b1]
   00000000 : 16 03 03 01 2C 0C 00 01 28 03 00 1D 20 B5 26 7B | ....,...(... .&{
   00000010 : DB 89 9E FE 6C 72 51 EE DF 9C 3F 4A 40 95 78 FE | ....lrQ...?J@.x.
   00000020 : 22 32 77 21 F9 BC 67 C1 32 95 CC 3E 06 04 01 01 | "2w!..g.2..>....
   00000030 : 00 A3 9B F5 8C F2 D8 98 4D 29 5A 2A 8C 64 42 27 | ........M)Z*.dB'
   00000040 : E2 3C F3 03 BA 11 8C 1E C2 2B 04 4A 85 09 24 B0 | .<.......+.J..$.
   00000050 : 4D E8 36 88 BB 07 98 07 CF DC CB D0 28 B4 8D 7F | M.6.........(...
   00000060 : FD 6A B1 49 AF 53 F3 DC 21 04 58 67 87 2A 3D 78 | .j.I.S..!.Xg.*=x
   00000070 : 12 B7 CE F1 C1 D3 10 9A EF FC B9 21 4A 23 D8 22 | ...........!J#."
   00000080 : 50 65 D1 BB 8F 05 A3 B0 2C 81 CC FE 7C EA AD D9 | Pe......,...|...
   00000090 : 3D E4 14 27 5F 63 48 21 DD B7 6C D9 3C CB B2 7E | =..'_cH!..l.<..~
   000000A0 : 44 EE 26 87 44 6F FB 7A 61 36 6E 42 F1 E8 82 87 | D.&.Do.za6nB....
   000000B0 : 85 47 AD C4 A8 1B F7 DA 17 23 F1 09 37 B2 B9 00 | .G.......#..7...
   000000C0 : 8D DE E6 CC 3F F0 FC B2 FB 21 48 3A C5 39 55 59 | ....?....!H:.9UY
   000000D0 : 7A 26 75 5E F6 7E CF C7 76 CE 2E 32 A6 0D DC FA | z&u^.~..v..2....
   000000E0 : 87 50 3E C2 83 60 1E 8B 19 E8 7A 1E 60 A1 6C 5F | .P>..`....z.`.l_
   000000F0 : B6 6B D5 3C 5D 9C 95 49 2F A3 96 94 3E 42 22 11 | .k.<]..I/...>B".
   00000100 : BC 45 3C AF C2 A4 13 5A 61 4C 1E 53 39 23 38 71 | .E<....ZaL.S9#8q
   00000110 : A5 94 3D E3 83 3A 54 FC 5A 29 9A E8 D8 02 21 D7 | ..=..:T.Z)....!.
   00000120 : 22 D5 7D 72 07 EB 1F A0 9A 3F 9C CD 2C 8C AB 70 | ".}r.....?..,..p
   00000130 : 85 -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- | .
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x012c(300)
# read 0x7ffd0c845050 handshake type 0x0c(12) (server_key_exchange)
 > handshake type 0x0c(12) (server_key_exchange)
  > length 0x000128(296)
  > curve info 3 (named_curve)
  > curve 0x001d x25519
  > public key
   > public key len 32
      00000000 : B5 26 7B DB 89 9E FE 6C 72 51 EE DF 9C 3F 4A 40 | .&{....lrQ...?J@
      00000010 : 95 78 FE 22 32 77 21 F9 BC 67 C1 32 95 CC 3E 06 | .x."2w!..g.2..>.
  > signature
   > 0x0401 rsa_pkcs1_sha256
   > signature len 256
     00000000 : A3 9B F5 8C F2 D8 98 4D 29 5A 2A 8C 64 42 27 E2 | .......M)Z*.dB'.
     00000010 : 3C F3 03 BA 11 8C 1E C2 2B 04 4A 85 09 24 B0 4D | <.......+.J..$.M
     00000020 : E8 36 88 BB 07 98 07 CF DC CB D0 28 B4 8D 7F FD | .6.........(....
     00000030 : 6A B1 49 AF 53 F3 DC 21 04 58 67 87 2A 3D 78 12 | j.I.S..!.Xg.*=x.
     00000040 : B7 CE F1 C1 D3 10 9A EF FC B9 21 4A 23 D8 22 50 | ..........!J#."P
     00000050 : 65 D1 BB 8F 05 A3 B0 2C 81 CC FE 7C EA AD D9 3D | e......,...|...=
     00000060 : E4 14 27 5F 63 48 21 DD B7 6C D9 3C CB B2 7E 44 | ..'_cH!..l.<..~D
     00000070 : EE 26 87 44 6F FB 7A 61 36 6E 42 F1 E8 82 87 85 | .&.Do.za6nB.....
     00000080 : 47 AD C4 A8 1B F7 DA 17 23 F1 09 37 B2 B9 00 8D | G.......#..7....
     00000090 : DE E6 CC 3F F0 FC B2 FB 21 48 3A C5 39 55 59 7A | ...?....!H:.9UYz
     000000A0 : 26 75 5E F6 7E CF C7 76 CE 2E 32 A6 0D DC FA 87 | &u^.~..v..2.....
     000000B0 : 50 3E C2 83 60 1E 8B 19 E8 7A 1E 60 A1 6C 5F B6 | P>..`....z.`.l_.
     000000C0 : 6B D5 3C 5D 9C 95 49 2F A3 96 94 3E 42 22 11 BC | k.<]..I/...>B"..
     000000D0 : 45 3C AF C2 A4 13 5A 61 4C 1E 53 39 23 38 71 A5 | E<....ZaL.S9#8q.
     000000E0 : 94 3D E3 83 3A 54 FC 5A 29 9A E8 D8 02 21 D7 22 | .=..:T.Z)....!."
     000000F0 : D5 7D 72 07 EB 1F A0 9A 3F 9C CD 2C 8C AB 70 85 | .}r.....?..,..p.
# record (server) [size 0x4eb pos 0x4e2]
   00000000 : 16 03 03 00 04 0E 00 00 00 -- -- -- -- -- -- -- | .........
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x0004(4)
# read 0x7ffd0c845050 handshake type 0x0e(14) (server_hello_done)
 > handshake type 0x0e(14) (server_hello_done)
  > length 0x000000(0)
# write record content type 0x16(22) (handshake)
# write 0x7ffd0c845050 handshake type 0x10(16) (client_key_exchange)
> SKE
X25519 (public key)
curve X25519
 x
   00:b5:26:7b:db:89:9e:fe:6c:72:51:ee:df:9c:3f:4a:
   40:95:78:fe:22:32:77:21:f9:bc:67:c1:32:95:cc:3e:
   06
   tSZ724me_mxyUe7fnD9KQJV4_iIydyH5vGfBMpXMPgY
   h'b5267bdb899efe6c7251eedf9c3f4a409578fe22327721f9bc67c13295cc3e06'

> CKE
X25519 (private key)
curve X25519
 x
   00:aa:f2:82:ef:3f:5d:4b:15:9e:16:75:9e:95:c7:cc:
   06:00:33:3f:52:4f:b7:ad:26:01:59:ff:f9:0c:55:fd:
   0b
   qvKC7z9dSxWeFnWelcfMBgAzP1JPt60mAVn_-QxV_Qs
   h'aaf282ef3f5d4b159e16759e95c7cc0600333f524fb7ad260159fff90c55fd0b'
 d (private)
   00:48:b8:20:9f:75:ae:2e:c9:b3:26:b9:fe:45:55:e1:
   61:df:04:c3:f4:a0:14:51:e5:50:de:e8:91:e9:2b:82:
   44
   SLggn3WuLsmzJrn-RVXhYd8Ew_SgFFHlUN7okekrgkQ
   h'48b8209f75ae2ec9b326b9fe4555e161df04c3f4a01451e550dee891e92b8244'

 # handshake
 > handshake type 0x10(16) (client_key_exchange)
  > length 0x000021(33)
> hmac alg 5
> client hello random 682a696367a677b67162cbc48cbf9a9486c149bafbd84046b72129081e73be7a
> server hello random ded52f83bee214eb1ac5ea81f1e4da4bd1e65cc72e0713d0444f574e47524401
> pre master secret 2d6fc7095735f370c49da35811bf296d7d9163f85902ce6cc0bd4e9efc960309
# CLIENT_RANDOM 682a696367a677b67162cbc48cbf9a9486c149bafbd84046b72129081e73be7a 64839861ed7cee78fa1f2487d02e84922dd6e0343822fbb8dab6a4c88295dc026d7804efee07356d173eb3d74c79397c
> secret_client_mac_key[00000102] 119549061078cf72b380867ec01c7edfa2cdac07ad3e093c76a7f27b5b2846e1
> secret_server_mac_key[00000103] d7968ed474510a20e79c11dc26bcfb5443dd05309971d3d96c5e23ffd7fabbfa
> secret_client_key[00000108] a4e0a728efad6f7fc0bb11d889877b5e
> secret_server_key[0000010b] ec819755ebac08dc51d6a4a757c24a5a
> secret_client_iv[00000109] 7ed3b850335095beb2aec2bfa7f694d4
> secret_server_iv[0000010c] 2c1afefc12c64e7bfbe2107bec8baf9e
# record (client)
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x0025(37)
# record constructed
   00000000 : 16 03 03 00 25 10 00 00 21 20 AA F2 82 EF 3F 5D | ....%...! ....?]
   00000010 : 4B 15 9E 16 75 9E 95 C7 CC 06 00 33 3F 52 4F B7 | K...u......3?RO.
   00000020 : AD 26 01 59 FF F9 0C 55 FD 0B -- -- -- -- -- -- | .&.Y...U..
# write record content type 0x14(20) (change_cipher_spec)
# record (client)
> record content type 0x14(20) (change_cipher_spec)
 > record version 0x0303 (TLS v1.2)
 > len 0x0001(1)
# record constructed
   00000000 : 16 03 03 00 25 10 00 00 21 20 AA F2 82 EF 3F 5D | ....%...! ....?]
   00000010 : 4B 15 9E 16 75 9E 95 C7 CC 06 00 33 3F 52 4F B7 | K...u......3?RO.
   00000020 : AD 26 01 59 FF F9 0C 55 FD 0B 14 03 03 00 01 01 | .&.Y...U........
> change_cipher_spec client
# write record content type 0x16(22) (handshake)
# write 0x7ffd0c845050 handshake type 0x14(20) (finished)
> finished
  key   64839861ed7cee78fa1f2487d02e84922dd6e0343822fbb8dab6a4c88295dc026d7804efee07356d173eb3d74c79397c
  hash  bc1bd4e9b7594eca7be36770d85b2a2facf1efa52b77c3797e12010ed9c3331b
  maced e43f74b9e56ee5cd2e02d313
> verify data
   00000000 : E4 3F 74 B9 E5 6E E5 CD 2E 02 D3 13 -- -- -- -- | .?t..n......
  > secret (internal) 0x00000106
  > algorithm sha256 size 12
  > verify data e43f74b9e56ee5cd2e02d313
 # handshake
 > handshake type 0x14(20) (finished)
  > length 0x00000c(12)
> encrypt mac_then_encrypt
 > aad 0000000000000000160303
 > enc aes-128-cbc
 > enckey[00000108] a4e0a728efad6f7fc0bb11d889877b5e
 > iv 69171b67bb439cc1e73b0c39dc82a5dd
 > mac sha256
 > mackey[00000102] 119549061078cf72b380867ec01c7edfa2cdac07ad3e093c76a7f27b5b2846e1
 > record no 0
 > plaintext
   00000000 : 14 00 00 0C E4 3F 74 B9 E5 6E E5 CD 2E 02 D3 13 | .....?t..n......
 > cbcmaced
   00000000 : 69 17 1B 67 BB 43 9C C1 E7 3B 0C 39 DC 82 A5 DD | i..g.C...;.9....
   00000010 : D4 7B D2 42 E0 DA A8 03 C8 3C 13 C4 D4 B3 C9 09 | .{.B.....<......
   00000020 : C5 B5 BC 71 B7 49 AA 0E 53 F0 87 07 84 25 E6 DC | ...q.I..S....%..
   00000030 : 71 FB FE 9E 69 C7 34 E0 6C 7B AA 2C D7 AA CA 4D | q...i.4.l{.,...M
   00000040 : 36 C6 81 67 27 FF 43 36 F5 B5 8A CD 54 0E 64 C9 | 6..g'.C6....T.d.
# record (client)
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x0050(80)
# record constructed
   00000000 : 16 03 03 00 25 10 00 00 21 20 AA F2 82 EF 3F 5D | ....%...! ....?]
   00000010 : 4B 15 9E 16 75 9E 95 C7 CC 06 00 33 3F 52 4F B7 | K...u......3?RO.
   00000020 : AD 26 01 59 FF F9 0C 55 FD 0B 14 03 03 00 01 01 | .&.Y...U........
   00000030 : 16 03 03 00 50 69 17 1B 67 BB 43 9C C1 E7 3B 0C | ....Pi..g.C...;.
   00000040 : 39 DC 82 A5 DD D4 7B D2 42 E0 DA A8 03 C8 3C 13 | 9.....{.B.....<.
   00000050 : C4 D4 B3 C9 09 C5 B5 BC 71 B7 49 AA 0E 53 F0 87 | ........q.I..S..
   00000060 : 07 84 25 E6 DC 71 FB FE 9E 69 C7 34 E0 6C 7B AA | ..%..q...i.4.l{.
   00000070 : 2C D7 AA CA 4D 36 C6 81 67 27 FF 43 36 F5 B5 8A | ,...M6..g'.C6...
   00000080 : CD 54 0E 64 C9 -- -- -- -- -- -- -- -- -- -- -- | .T.d.
[ns] read 0x10a
   00000000 : 16 03 03 00 AA 04 00 00 A6 00 00 1C 20 00 A0 1A | ............ ...
   00000010 : A1 D8 AE ED 51 4A 5E E7 ED 14 D6 4C 59 0D 90 41 | ....QJ^....LY..A
   00000020 : 6C F0 7A 72 00 D5 90 45 89 D4 13 B5 4A 8F 65 59 | l.zr...E....J.eY
   00000030 : E0 2C F4 0C 30 B8 6A 9E 73 07 3F DE 58 42 AF 02 | .,..0.j.s.?.XB..
   00000040 : 05 D9 C3 B0 77 DB 58 76 1A B7 E2 A6 00 89 38 AF | ....w.Xv......8.
   00000050 : 82 77 F7 3F 03 73 B3 4A FB 42 C7 E6 55 49 52 0E | .w.?.s.J.B..UIR.
   00000060 : 19 28 A6 A6 9C 7C 4D DB B7 F0 04 2C 89 3E E5 87 | .(...|M....,.>..
   00000070 : 4A 41 E7 66 7B F3 0F 76 E9 61 AA C5 5A 89 54 3F | JA.f{..v.a..Z.T?
   00000080 : D7 2E 07 78 13 D1 CA 83 A6 C1 54 A9 88 01 4C 3E | ...x......T...L>
   00000090 : FC CA 4A 89 9F FB BD AB 2E 39 5E AB C7 D4 5A 47 | ..J......9^...ZG
   000000A0 : 0E 04 81 02 78 70 08 99 91 81 DB 35 20 69 C3 14 | ....xp.....5 i..
   000000B0 : 03 03 00 01 01 16 03 03 00 50 21 C9 65 CB 87 CA | .........P!.e...
   000000C0 : 4A 1E E1 FE 1E 3A 49 CA E5 A5 0D D9 3C CE 9B 23 | J....:I.....<..#
   000000D0 : 7A 34 AA 7B D5 86 0E E2 01 51 99 20 8F 43 37 4E | z4.{.....Q. .C7N
   000000E0 : 65 63 3D 45 53 A3 6E D6 0C A2 32 D9 8F 7F DE CA | ec=ES.n...2.....
   000000F0 : 72 BA 20 CD 5F 8A C6 D2 38 B6 8E 5D 91 19 35 9B | r. ._...8..]..5.
   00000100 : 79 7E B0 15 A4 42 97 47 1D 8B -- -- -- -- -- -- | y~...B.G..
# record (server) [size 0x10a pos 0x0]
   00000000 : 16 03 03 00 AA 04 00 00 A6 00 00 1C 20 00 A0 1A | ............ ...
   00000010 : A1 D8 AE ED 51 4A 5E E7 ED 14 D6 4C 59 0D 90 41 | ....QJ^....LY..A
   00000020 : 6C F0 7A 72 00 D5 90 45 89 D4 13 B5 4A 8F 65 59 | l.zr...E....J.eY
   00000030 : E0 2C F4 0C 30 B8 6A 9E 73 07 3F DE 58 42 AF 02 | .,..0.j.s.?.XB..
   00000040 : 05 D9 C3 B0 77 DB 58 76 1A B7 E2 A6 00 89 38 AF | ....w.Xv......8.
   00000050 : 82 77 F7 3F 03 73 B3 4A FB 42 C7 E6 55 49 52 0E | .w.?.s.J.B..UIR.
   00000060 : 19 28 A6 A6 9C 7C 4D DB B7 F0 04 2C 89 3E E5 87 | .(...|M....,.>..
   00000070 : 4A 41 E7 66 7B F3 0F 76 E9 61 AA C5 5A 89 54 3F | JA.f{..v.a..Z.T?
   00000080 : D7 2E 07 78 13 D1 CA 83 A6 C1 54 A9 88 01 4C 3E | ...x......T...L>
   00000090 : FC CA 4A 89 9F FB BD AB 2E 39 5E AB C7 D4 5A 47 | ..J......9^...ZG
   000000A0 : 0E 04 81 02 78 70 08 99 91 81 DB 35 20 69 C3 -- | ....xp.....5 i.
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x00aa(170)
# read 0x7ffd0c845050 handshake type 0x04(4) (new_session_ticket)
 > handshake type 0x04(4) (new_session_ticket)
  > length 0x0000a6(166)
  > ticket timeline 0x00001c20 (7200 secs)
  > ticket age add 0x00a01aa1
  > ticket nonce
  > session ticket
# record (server) [size 0x10a pos 0xaf]
   00000000 : 14 03 03 00 01 01 -- -- -- -- -- -- -- -- -- -- | ......
> record content type 0x14(20) (change_cipher_spec)
 > record version 0x0303 (TLS v1.2)
 > len 0x0001(1)
> change_cipher_spec server
# record (server) [size 0x10a pos 0xb5]
   00000000 : 16 03 03 00 50 21 C9 65 CB 87 CA 4A 1E E1 FE 1E | ....P!.e...J....
   00000010 : 3A 49 CA E5 A5 0D D9 3C CE 9B 23 7A 34 AA 7B D5 | :I.....<..#z4.{.
   00000020 : 86 0E E2 01 51 99 20 8F 43 37 4E 65 63 3D 45 53 | ....Q. .C7Nec=ES
   00000030 : A3 6E D6 0C A2 32 D9 8F 7F DE CA 72 BA 20 CD 5F | .n...2.....r. ._
   00000040 : 8A C6 D2 38 B6 8E 5D 91 19 35 9B 79 7E B0 15 A4 | ...8..]..5.y~...
   00000050 : 42 97 47 1D 8B -- -- -- -- -- -- -- -- -- -- -- | B.G..
> record content type 0x16(22) (handshake)
 > record version 0x0303 (TLS v1.2)
 > len 0x0050(80)
> decrypt mac_then_encrypt
 > aad 0000000000000000160303
 > enc aes-128-cbc
 > enckey[0000010b] ec819755ebac08dc51d6a4a757c24a5a
 > iv 21c965cb87ca4a1ee1fe1e3a49cae5a5
 > mac sha256
 > mackey[00000103] d7968ed474510a20e79c11dc26bcfb5443dd05309971d3d96c5e23ffd7fabbfa
 > record no 0
 > ciphertext
   00000000 : 0D D9 3C CE 9B 23 7A 34 AA 7B D5 86 0E E2 01 51 | ..<..#z4.{.....Q
   00000010 : 99 20 8F 43 37 4E 65 63 3D 45 53 A3 6E D6 0C A2 | . .C7Nec=ES.n...
   00000020 : 32 D9 8F 7F DE CA 72 BA 20 CD 5F 8A C6 D2 38 B6 | 2.....r. ._...8.
   00000030 : 8E 5D 91 19 35 9B 79 7E B0 15 A4 42 97 47 1D 8B | .]..5.y~...B.G..
 > plaintext 0x0(0)
   00000000 : 14 00 00 0C D3 8B 88 CE 5C 41 A0 4A 1B B9 FD D0 | ........\A.J....
# read 0x7ffd0c845050 handshake type 0x14(20) (finished)
 > handshake type 0x14(20) (finished)
  > length 0x00000c(12)
> finished
  key   64839861ed7cee78fa1f2487d02e84922dd6e0343822fbb8dab6a4c88295dc026d7804efee07356d173eb3d74c79397c
  hash  55a1037bef5940514e6cf639017e45fb91d606abc8a5b9de4b136a92f0a274e1
  maced d38b88ce5c41a04a1bb9fdd0
 > verify data true
    00000000 : D3 8B 88 CE 5C 41 A0 4A 1B B9 FD D0 -- -- -- -- | ....\A.J....
   > secret (internal) 0x00000106
   > algorithm sha256 size 12
   > verify data d38b88ce5c41a04a1bb9fdd0
   > maced       d38b88ce5c41a04a1bb9fdd0
[00000000][tls_client2] connect
# write record content type 0x17(23) (application_data)
> encrypt mac_then_encrypt
 > aad 0000000000000001170303
 > enc aes-128-cbc
 > enckey[00000108] a4e0a728efad6f7fc0bb11d889877b5e
 > iv 92baa8c89020577b2db79eb496ff245d
 > mac sha256
 > mackey[00000102] 119549061078cf72b380867ec01c7edfa2cdac07ad3e093c76a7f27b5b2846e1
 > record no 1
 > plaintext
   00000000 : 68 65 6C 6C 6F 17 -- -- -- -- -- -- -- -- -- -- | hello.
 > cbcmaced
   00000000 : 92 BA A8 C8 90 20 57 7B 2D B7 9E B4 96 FF 24 5D | ..... W{-.....$]
   00000010 : 44 BE 31 D8 63 30 33 C9 55 AB C6 56 D8 AF 77 1B | D.1.c03.U..V..w.
   00000020 : F8 9E C4 70 B9 B6 A7 8B 2B F4 95 A4 7D 0C 3B 45 | ...p....+...}.;E
   00000030 : 68 27 EB B8 07 A4 26 E2 94 1D 18 7D 65 2F 8E 87 | h'....&....}e/..
# record (client)
> record content type 0x17(23) (application_data)
 > record version 0x0303 (TLS v1.2)
 > len 0x0040(64)
# record constructed
   00000000 : 17 03 03 00 40 92 BA A8 C8 90 20 57 7B 2D B7 9E | ....@..... W{-..
   00000010 : B4 96 FF 24 5D 44 BE 31 D8 63 30 33 C9 55 AB C6 | ...$]D.1.c03.U..
   00000020 : 56 D8 AF 77 1B F8 9E C4 70 B9 B6 A7 8B 2B F4 95 | V..w....p....+..
   00000030 : A4 7D 0C 3B 45 68 27 EB B8 07 A4 26 E2 94 1D 18 | .}.;Eh'....&....
   00000040 : 7D 65 2F 8E 87 -- -- -- -- -- -- -- -- -- -- -- | }e/..
received response: [3][len 0]
# write record content type 0x15(21) (alert)
> encrypt mac_then_encrypt
 > aad 0000000000000002150303
 > enc aes-128-cbc
 > enckey[00000108] a4e0a728efad6f7fc0bb11d889877b5e
 > iv 89b49ba03935bf24c0e96ccd4434ecec
 > mac sha256
 > mackey[00000102] 119549061078cf72b380867ec01c7edfa2cdac07ad3e093c76a7f27b5b2846e1
 > record no 2
 > plaintext
   00000000 : 01 00 -- -- -- -- -- -- -- -- -- -- -- -- -- -- | ..
 > cbcmaced
   00000000 : 89 B4 9B A0 39 35 BF 24 C0 E9 6C CD 44 34 EC EC | ....95.$..l.D4..
   00000010 : 3D ED 58 68 5D 98 87 01 D2 18 26 E6 C0 3D C3 57 | =.Xh].....&..=.W
   00000020 : D5 5D 95 D8 80 FE 23 66 1D D8 37 0C 1C A7 9B 48 | .]....#f..7....H
   00000030 : AE EA CE DC 54 6F 21 E1 B9 4D 3E 0A 0D 4F 53 47 | ....To!..M>..OSG
# record (client)
> record content type 0x15(21) (alert)
 > record version 0x0303 (TLS v1.2)
 > len 0x0040(64)
# record constructed
   00000000 : 15 03 03 00 40 89 B4 9B A0 39 35 BF 24 C0 E9 6C | ....@....95.$..l
   00000010 : CD 44 34 EC EC 3D ED 58 68 5D 98 87 01 D2 18 26 | .D4..=.Xh].....&
   00000020 : E6 C0 3D C3 57 D5 5D 95 D8 80 FE 23 66 1D D8 37 | ..=.W.]....#f..7
   00000030 : 0C 1C A7 9B 48 AE EA CE DC 54 6F 21 E1 B9 4D 3E | ....H....To!..M>
   00000040 : 0A 0D 4F 53 47 -- -- -- -- -- -- -- -- -- -- -- | ..OSG
epoll handle 4 unbind 3
- event_loop_break_concurrent : break 1/1
- event_loop_test_broken : broken detected
[00000000][tls_client2] client 127.0.0.1:9000
================================================================================
report
@ test case "" success 2
--------------------------------------------------------------------------------
result|errorcode |test function       |time       |message
 pass |0x00000000|tls_client2         |0.000352334|connect
 pass |0x00000000|tls_client2         |2.001320831|client 127.0.0.1:9000
--------------------------------------------------------------------------------
# pass 2
--------------------------------------------------------------------------------
brief
pass fail skip low case
   2    0    0   0
--------------------------------------------------------------------------------
sort by time (top 2)
--------------------------------------------------------------------------------
result|errorcode |test function       |time       |message
 pass |0x00000000|tls_client2         |2.001320831|client 127.0.0.1:9000
 pass |0x00000000|tls_client2         |0.000352334|connect
--------------------------------------------------------------------------------
help
-v           verbose
-d           debug/trace
-D arg       trace level 0|2
-l           log file
-t           log time
-b arg       bufsize (1500)
-a arg       address (127.0.0.1)
-p arg       port (9000)
-P arg     v protocol tcp|udp|tls|tls13|tls12|dtls (1 tcp, 2 udp, 3 tls, 4 dtls)
-c arg       count (1)
-T           use trial
-h           HTTP/1.1
-m arg       message
-etm         TLS 1.2 EtM (trial_tls_client_socket)
````

[TOC](README.md)
