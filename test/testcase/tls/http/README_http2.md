#### HTTP/2

$ ./test-httpserver2.exe -r --debug &

````
[test case] http/2 powered by http_server and libssl
flag 00000001
min proto version 00000303
max proto version 00000304
socket 512 created family 2(AF_INET) type 1(SOCK_STREAM) protocol 6(IPPROTO_TCP)
iocp handle 00000204 created
- event_loop_new tid 00006124
- event_loop_new tid 000056a0
- event_loop_new tid 00007a9c
- event_loop_new tid 0000677c
TLS 00000304 00000010 handshake start
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS read client hello:(NONE)
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write server hello:(NONE)
SERVER_HANDSHAKE_TRAFFIC_SECRET e3d93634084c3563a9158c0dd798b45bce974ded17ecb84c60646f0551118ff5 c61c37cb99ac81524791ab2bb185c0f1a7ff1a4c48e93d5875028d50d4f0b940
CLIENT_HANDSHAKE_TRAFFIC_SECRET e3d93634084c3563a9158c0dd798b45bce974ded17ecb84c60646f0551118ff5 84ddc65354be31fcbae31b3d2ffd03a640c198ddeaa70c0d0abba33515bec736
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write change cipher spec:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 write encrypted extensions:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write certificate:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 write server certificate verify:TLS_AES_128_GCM_SHA256
EXPORTER_SECRET e3d93634084c3563a9158c0dd798b45bce974ded17ecb84c60646f0551118ff5 9ed0fe4f15b289d31198e46e92c31dff838f5fecbc2e6b7de1a2688197dd653c
SERVER_TRAFFIC_SECRET_0 e3d93634084c3563a9158c0dd798b45bce974ded17ecb84c60646f0551118ff5 217fe8a3bbb07530fb65b8efd540397e5f195d10db541833801771f1767632e8
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write finished:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 early data:TLS_AES_128_GCM_SHA256
TLS 00000304 00004004 SSL_read:callback:fatal:certificate unknown
TLS 00000304 00002002 SSL_accept:exit:error
TLS 00000304 00000010 handshake start
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS read client hello:(NONE)
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write server hello:(NONE)
SERVER_HANDSHAKE_TRAFFIC_SECRET 5f8ae41b1513965c566f57af03f20586571246376178a18126df3842905bb18b fe0ccb864cf6c93db53450a2782f966834ee9951796efeee62f439e7cd9f1324
CLIENT_HANDSHAKE_TRAFFIC_SECRET 5f8ae41b1513965c566f57af03f20586571246376178a18126df3842905bb18b cdf711a6e6f3accce917638e9f523337d2df0355495c1eff67066756ef0d2101
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write change cipher spec:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 write encrypted extensions:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write certificate:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 write server certificate verify:TLS_AES_128_GCM_SHA256
EXPORTER_SECRET 5f8ae41b1513965c566f57af03f20586571246376178a18126df3842905bb18b 33a97477d16ef72bc5a55bde8b02403e185ace5d897311d5125719e775f36d65
SERVER_TRAFFIC_SECRET_0 5f8ae41b1513965c566f57af03f20586571246376178a18126df3842905bb18b 01cdeedeea6ca5a42eb50fcfab2c7fdaaed8159e54dc4eef15018d17cb1a266e
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write finished:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 early data:TLS_AES_128_GCM_SHA256
TLS 00000304 00004004 SSL_read:callback:fatal:certificate unknown
TLS 00000304 00002002 SSL_accept:exit:error
TLS 00000304 00000010 handshake start
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS read client hello:(NONE)
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write server hello:(NONE)
SERVER_HANDSHAKE_TRAFFIC_SECRET 060252a6b68f1421a10d978a20c1d495ac2a65782643e688725b50263b8bfcfa aca37f9b4b6cc4b556b2d4f41e77ec5ac8c3f8d6b848eb98ec05728a3fd66e37
CLIENT_HANDSHAKE_TRAFFIC_SECRET 060252a6b68f1421a10d978a20c1d495ac2a65782643e688725b50263b8bfcfa 8a62a9043a953ef1385c46800908a23861e254c2ffd6b4baf35f5c124349c4ef
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write change cipher spec:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 write encrypted extensions:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write certificate:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 write server certificate verify:TLS_AES_128_GCM_SHA256
EXPORTER_SECRET 060252a6b68f1421a10d978a20c1d495ac2a65782643e688725b50263b8bfcfa 0912558fc48d2117b7248d359adc55dfcdeb76524a92d483803b0d87c2af0a9d
SERVER_TRAFFIC_SECRET_0 060252a6b68f1421a10d978a20c1d495ac2a65782643e688725b50263b8bfcfa 4c847438048e173fdf162ccc1ca903897e1818ab66d5e6ccbfa7a5eaec3d877a
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write finished:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 early data:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 early data:TLS_AES_128_GCM_SHA256
CLIENT_TRAFFIC_SECRET_0 060252a6b68f1421a10d978a20c1d495ac2a65782643e688725b50263b8bfcfa 653a4da8c8272ca0c9e044c8500ce096feea945f4c9dd306d24336230d007b7e
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS read finished:TLS_AES_128_GCM_SHA256
TLS 00000304 00000020 handshake done
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write session ticket:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write session ticket:TLS_AES_128_GCM_SHA256
TLS 00000304 00002002 SSL_accept:exit:SSL negotiation finished successfully
iocp handle 00000204 bind 640
[ns] read 640
  00000000 : 50 52 49 20 2A 20 48 54 54 50 2F 32 2E 30 0D 0A | PRI * HTTP/2.0..
  00000010 : 0D 0A 53 4D 0D 0A 0D 0A 00 00 18 04 00 00 00 00 | ..SM............
  00000020 : 00 00 01 00 01 00 00 00 02 00 00 00 00 00 04 00 | ................
  00000030 : 60 00 00 00 06 00 04 00 00 00 00 04 08 00 00 00 | `...............
  00000040 : 00 00 00 EF 00 01 -- -- -- -- -- -- -- -- -- -- | ......
[ns] read 640
  00000000 : 00 01 D7 01 25 00 00 00 01 80 00 00 00 FF 82 41 | ....%..........A
  00000010 : 8A A0 E4 1D 13 9D 09 B8 F8 00 0F 87 84 40 87 41 | .............@.A
  00000020 : 48 B1 27 5A D1 FF B8 FE 71 1C F3 50 55 2F 4F 61 | H.'Z....q..PU/Oa
  00000030 : E9 2F F3 F7 DE 0F E4 2C BB FC FD 29 FC DE 9E C3 | ./.....,...)....
  00000040 : D2 6B 69 FE 7E FB C1 FC 85 97 7F 9F A5 3F 9D 27 | .ki.~........?.'
  00000050 : 4B 10 FF 77 6C 1D 52 7F 3F 7D E0 FE 44 D7 F3 40 | K..wl.R.?}..D..@
  00000060 : 8B 41 48 B1 27 5A D1 AD 49 E3 35 05 02 3F 30 40 | .AH.'Z..I.5..?0@
  00000070 : 8D 41 48 B1 27 5A D1 AD 5D 03 4C A7 B2 9F 88 FE | .AH.'Z..].L.....
  00000080 : 79 1A A9 0F E1 1F CF 40 92 B6 B9 AC 1C 85 58 D5 | y......@......X.
  00000090 : 20 A4 B6 C2 AD 61 7B 5A 54 25 1F 01 31 7A D5 D0 |  ....a{ZT%..1z..
  000000A0 : 7F 66 A2 81 B0 DA E0 53 FA E4 6A A4 3F 84 29 A7 | .f.....S..j.?.).
  000000B0 : 7A 81 02 E0 FB 53 91 AA 71 AF B5 3C B8 D7 F6 A4 | z....S..q..<....
  000000C0 : 35 D7 41 79 16 3C C6 4B 0D B2 EA EC B8 A7 F5 9B | 5.Ay.<.K........
  000000D0 : 1E FD 19 FE 94 A0 DD 4A A6 22 93 A9 FF B5 2F 4F | .......J."..../O
  000000E0 : 61 E9 2B 01 65 D5 C0 B8 17 02 9B 87 28 EC 33 0D | a.+.e.......(.3.
  000000F0 : B2 EA EC B9 53 E5 49 7C A5 89 D3 4D 1F 43 AE BA | ....S.I|...M.C..
  00000100 : 0C 41 A4 C7 A9 8F 33 A6 9A 3F DF 9A 68 FA 1D 75 | .A....3..?..h..u
  00000110 : D0 62 0D 26 3D 4C 79 A6 8F BE D0 01 77 FE 8D 48 | .b.&=Ly.....w..H
  00000120 : E6 2B 03 EE 69 7E 8D 48 E6 2B 1E 0B 1D 7F 46 A4 | .+..i~.H.+....F.
  00000130 : 73 15 81 D7 54 DF 5F 2C 7C FD F6 80 0B BD F4 3A | s...T._,|......:
  00000140 : EB A0 C4 1A 4C 7A 98 41 A6 A8 B2 2C 5F 24 9C 75 | ....Lz.A...,_$.u
  00000150 : 4C 5F BE F0 46 CF DF 68 00 BB BF 40 8A 41 48 B4 | L_..F..h...@.AH.
  00000160 : A5 49 27 59 06 49 7F 83 A8 F5 17 40 8A 41 48 B4 | .I'Y.I.....@.AH.
  00000170 : A5 49 27 5A 93 C8 5F 86 A8 7D CD 30 D2 5F 40 8A | .I'Z.._..}.0._@.
  00000180 : 41 48 B4 A5 49 27 5A D4 16 CF 02 3F 31 40 8A 41 | AH..I'Z....?1@.A
  00000190 : 48 B4 A5 49 27 5A 42 A1 3F 86 90 E4 B6 92 D4 9F | H..I'ZB.?.......
  000001A0 : 50 92 9B D9 AB FA 52 42 CB 40 D2 5F A5 23 B3 E9 | P.....RB.@._.#..
  000001B0 : 4F 68 4C 9F 51 9C EA 75 B3 6D FA EA 7F BE D0 01 | OhL.Q..u.m......
  000001C0 : 77 FE 8B 52 DC 37 7D F6 80 0B BD F4 5A BE FB 40 | w..R.7}.....Z..@
  000001D0 : 05 DD 40 86 AE C3 1E C3 27 D7 85 B6 00 7D 28 6F | ..@.....'....}(o
[h2] read 640
  00000000 : 50 52 49 20 2A 20 48 54 54 50 2F 32 2E 30 0D 0A | PRI * HTTP/2.0..
  00000010 : 0D 0A 53 4D 0D 0A 0D 0A 00 00 18 04 00 00 00 00 | ..SM............
  00000020 : 00 00 01 00 01 00 00 00 02 00 00 00 00 00 04 00 | ................
  00000030 : 60 00 00 00 06 00 04 00 00 -- -- -- -- -- -- -- | `........
- http/2 frame type 4 SETTINGS
 > length 0x18(24) type 4 flags 00 stream identifier 00000000
 > flags [ ]
 > identifier 1 value 65536 (0x00010000)
 > identifier 2 value 0 (0x00000000)
 > identifier 4 value 6291456 (0x00600000)
 > identifier 6 value 262144 (0x00040000)
[h2] read 640
  00000000 : 00 00 04 08 00 00 00 00 00 00 EF 00 01 -- -- -- | .............
[ns] read 640
  00000000 : 00 00 00 04 01 00 00 00 00 -- -- -- -- -- -- -- | .........
- http/2 frame type 8 WINDOW_UPDATE
 > length 0x04(4) type 8 flags 00 stream identifier 00000000
 > flags [ ]
 > window size increment 15663105
[h2] read 640
  00000000 : 00 00 00 04 01 00 00 00 00 -- -- -- -- -- -- -- | .........
[h2] read 640
  00000000 : 00 01 D7 01 25 00 00 00 01 80 00 00 00 FF 82 41 | ....%..........A
  00000010 : 8A A0 E4 1D 13 9D 09 B8 F8 00 0F 87 84 40 87 41 | .............@.A
  00000020 : 48 B1 27 5A D1 FF B8 FE 71 1C F3 50 55 2F 4F 61 | H.'Z....q..PU/Oa
  00000030 : E9 2F F3 F7 DE 0F E4 2C BB FC FD 29 FC DE 9E C3 | ./.....,...)....
  00000040 : D2 6B 69 FE 7E FB C1 FC 85 97 7F 9F A5 3F 9D 27 | .ki.~........?.'
  00000050 : 4B 10 FF 77 6C 1D 52 7F 3F 7D E0 FE 44 D7 F3 40 | K..wl.R.?}..D..@
  00000060 : 8B 41 48 B1 27 5A D1 AD 49 E3 35 05 02 3F 30 40 | .AH.'Z..I.5..?0@
  00000070 : 8D 41 48 B1 27 5A D1 AD 5D 03 4C A7 B2 9F 88 FE | .AH.'Z..].L.....
  00000080 : 79 1A A9 0F E1 1F CF 40 92 B6 B9 AC 1C 85 58 D5 | y......@......X.
  00000090 : 20 A4 B6 C2 AD 61 7B 5A 54 25 1F 01 31 7A D5 D0 |  ....a{ZT%..1z..
  000000A0 : 7F 66 A2 81 B0 DA E0 53 FA E4 6A A4 3F 84 29 A7 | .f.....S..j.?.).
  000000B0 : 7A 81 02 E0 FB 53 91 AA 71 AF B5 3C B8 D7 F6 A4 | z....S..q..<....
  000000C0 : 35 D7 41 79 16 3C C6 4B 0D B2 EA EC B8 A7 F5 9B | 5.Ay.<.K........
  000000D0 : 1E FD 19 FE 94 A0 DD 4A A6 22 93 A9 FF B5 2F 4F | .......J."..../O
  000000E0 : 61 E9 2B 01 65 D5 C0 B8 17 02 9B 87 28 EC 33 0D | a.+.e.......(.3.
  000000F0 : B2 EA EC B9 53 E5 49 7C A5 89 D3 4D 1F 43 AE BA | ....S.I|...M.C..
  00000100 : 0C 41 A4 C7 A9 8F 33 A6 9A 3F DF 9A 68 FA 1D 75 | .A....3..?..h..u
  00000110 : D0 62 0D 26 3D 4C 79 A6 8F BE D0 01 77 FE 8D 48 | .b.&=Ly.....w..H
  00000120 : E6 2B 03 EE 69 7E 8D 48 E6 2B 1E 0B 1D 7F 46 A4 | .+..i~.H.+....F.
  00000130 : 73 15 81 D7 54 DF 5F 2C 7C FD F6 80 0B BD F4 3A | s...T._,|......:
  00000140 : EB A0 C4 1A 4C 7A 98 41 A6 A8 B2 2C 5F 24 9C 75 | ....Lz.A...,_$.u
  00000150 : 4C 5F BE F0 46 CF DF 68 00 BB BF 40 8A 41 48 B4 | L_..F..h...@.AH.
  00000160 : A5 49 27 59 06 49 7F 83 A8 F5 17 40 8A 41 48 B4 | .I'Y.I.....@.AH.
  00000170 : A5 49 27 5A 93 C8 5F 86 A8 7D CD 30 D2 5F 40 8A | .I'Z.._..}.0._@.
  00000180 : 41 48 B4 A5 49 27 5A D4 16 CF 02 3F 31 40 8A 41 | AH..I'Z....?1@.A
  00000190 : 48 B4 A5 49 27 5A 42 A1 3F 86 90 E4 B6 92 D4 9F | H..I'ZB.?.......
  000001A0 : 50 92 9B D9 AB FA 52 42 CB 40 D2 5F A5 23 B3 E9 | P.....RB.@._.#..
  000001B0 : 4F 68 4C 9F 51 9C EA 75 B3 6D FA EA 7F BE D0 01 | OhL.Q..u.m......
  000001C0 : 77 FE 8B 52 DC 37 7D F6 80 0B BD F4 5A BE FB 40 | w..R.7}.....Z..@
  000001D0 : 05 DD 40 86 AE C3 1E C3 27 D7 85 B6 00 7D 28 6F | ..@.....'....}(o
- http/2 frame type 4 SETTINGS
 > length 0x00(0) type 4 flags 01 stream identifier 00000000
 > flags [ ACK ]
insert entry[0] :authority=localhost:9000
insert entry[1] sec-ch-ua="Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
insert entry[2] sec-ch-ua-mobile=?0
insert entry[3] sec-ch-ua-platform="Windows"
insert entry[4] upgrade-insecure-requests=1
insert entry[5] user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
insert entry[6] accept=text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
insert entry[7] sec-fetch-site=none
insert entry[8] sec-fetch-mode=navigate
insert entry[9] sec-fetch-user=?1
insert entry[10] sec-fetch-dest=document
insert entry[11] accept-encoding=gzip, deflate, br, zstd
insert entry[12] accept-language=ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
insert entry[13] priority=u=0, i
- http/2 frame type 1 HEADERS
 > length 0x1d7(471) type 1 flags 25 stream identifier 00000001
 > flags [ END_STREAM END_HEADERS PRIORITY ]
 > stream dependency E:1 00000000
 > weight ff
 > fragment
   00000000 : 82 41 8A A0 E4 1D 13 9D 09 B8 F8 00 0F 87 84 40 | .A.............@
   00000010 : 87 41 48 B1 27 5A D1 FF B8 FE 71 1C F3 50 55 2F | .AH.'Z....q..PU/
   00000020 : 4F 61 E9 2F F3 F7 DE 0F E4 2C BB FC FD 29 FC DE | Oa./.....,...)..
   00000030 : 9E C3 D2 6B 69 FE 7E FB C1 FC 85 97 7F 9F A5 3F | ...ki.~........?
   00000040 : 9D 27 4B 10 FF 77 6C 1D 52 7F 3F 7D E0 FE 44 D7 | .'K..wl.R.?}..D.
   00000050 : F3 40 8B 41 48 B1 27 5A D1 AD 49 E3 35 05 02 3F | .@.AH.'Z..I.5..?
   00000060 : 30 40 8D 41 48 B1 27 5A D1 AD 5D 03 4C A7 B2 9F | 0@.AH.'Z..].L...
   00000070 : 88 FE 79 1A A9 0F E1 1F CF 40 92 B6 B9 AC 1C 85 | ..y......@......
   00000080 : 58 D5 20 A4 B6 C2 AD 61 7B 5A 54 25 1F 01 31 7A | X. ....a{ZT%..1z
   00000090 : D5 D0 7F 66 A2 81 B0 DA E0 53 FA E4 6A A4 3F 84 | ...f.....S..j.?.
   000000A0 : 29 A7 7A 81 02 E0 FB 53 91 AA 71 AF B5 3C B8 D7 | ).z....S..q..<..
   000000B0 : F6 A4 35 D7 41 79 16 3C C6 4B 0D B2 EA EC B8 A7 | ..5.Ay.<.K......
   000000C0 : F5 9B 1E FD 19 FE 94 A0 DD 4A A6 22 93 A9 FF B5 | .........J."....
   000000D0 : 2F 4F 61 E9 2B 01 65 D5 C0 B8 17 02 9B 87 28 EC | /Oa.+.e.......(.
   000000E0 : 33 0D B2 EA EC B9 53 E5 49 7C A5 89 D3 4D 1F 43 | 3.....S.I|...M.C
   000000F0 : AE BA 0C 41 A4 C7 A9 8F 33 A6 9A 3F DF 9A 68 FA | ...A....3..?..h.
   00000100 : 1D 75 D0 62 0D 26 3D 4C 79 A6 8F BE D0 01 77 FE | .u.b.&=Ly.....w.
   00000110 : 8D 48 E6 2B 03 EE 69 7E 8D 48 E6 2B 1E 0B 1D 7F | .H.+..i~.H.+....
   00000120 : 46 A4 73 15 81 D7 54 DF 5F 2C 7C FD F6 80 0B BD | F.s...T._,|.....
   00000130 : F4 3A EB A0 C4 1A 4C 7A 98 41 A6 A8 B2 2C 5F 24 | .:....Lz.A...,_$
   00000140 : 9C 75 4C 5F BE F0 46 CF DF 68 00 BB BF 40 8A 41 | .uL_..F..h...@.A
   00000150 : 48 B4 A5 49 27 59 06 49 7F 83 A8 F5 17 40 8A 41 | H..I'Y.I.....@.A
   00000160 : 48 B4 A5 49 27 5A 93 C8 5F 86 A8 7D CD 30 D2 5F | H..I'Z.._..}.0._
   00000170 : 40 8A 41 48 B4 A5 49 27 5A D4 16 CF 02 3F 31 40 | @.AH..I'Z....?1@
   00000180 : 8A 41 48 B4 A5 49 27 5A 42 A1 3F 86 90 E4 B6 92 | .AH..I'ZB.?.....
   00000190 : D4 9F 50 92 9B D9 AB FA 52 42 CB 40 D2 5F A5 23 | ..P.....RB.@._.#
   000001A0 : B3 E9 4F 68 4C 9F 51 9C EA 75 B3 6D FA EA 7F BE | ..OhL.Q..u.m....
   000001B0 : D0 01 77 FE 8B 52 DC 37 7D F6 80 0B BD F4 5A BE | ..w..R.7}.....Z.
   000001C0 : FB 40 05 DD 40 86 AE C3 1E C3 27 D7 85 B6 00 7D | .@..@.....'....}
   000001D0 : 28 6F -- -- -- -- -- -- -- -- -- -- -- -- -- -- | (o
 > :method: GET
 > :authority: localhost:9000
 > :scheme: https
 > :path: /
 > sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
 > sec-ch-ua-mobile: ?0
 > sec-ch-ua-platform: "Windows"
 > upgrade-insecure-requests: 1
 > user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
 > accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
 > sec-fetch-site: none
 > sec-fetch-mode: navigate
 > sec-fetch-user: ?1
 > sec-fetch-dest: document
 > accept-encoding: gzip, deflate, br, zstd
 > accept-language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
 > priority: u=0, i
- http/2 frame type 1 HEADERS
 > length 0x10(16) type 1 flags 04 stream identifier 00000001
 > flags [ END_HEADERS ]
 > fragment
   00000000 : 88 0F 10 87 49 7C A5 89 D3 4D 1F 0F 0D 82 13 E1 | ....I|...M......
 > :status: 200
 > content-type: text/html
 > content-length: 291

- http/2 frame type 0 DATA
 > length 0x123(291) type 0 flags 01 stream identifier 00000001
 > flags [ END_STREAM ]
 > data
   00000000 : 3C 21 44 4F 43 54 59 50 45 20 68 74 6D 6C 3E 0A | <!DOCTYPE html>.
   00000010 : 3C 68 74 6D 6C 3E 0A 3C 68 65 61 64 3E 0A 20 20 | <html>.<head>.
   00000020 : 3C 74 69 74 6C 65 3E 74 65 73 74 3C 2F 74 69 74 | <title>test</tit
   00000030 : 6C 65 3E 0A 20 20 3C 6D 65 74 61 20 63 68 61 72 | le>.  <meta char
   00000040 : 73 65 74 3D 22 55 54 46 2D 38 22 3E 0A 3C 2F 68 | set="UTF-8">.</h
   00000050 : 65 61 64 3E 0A 3C 62 6F 64 79 3E 0A 20 20 3C 70 | ead>.<body>.  <p
   00000060 : 3E 48 65 6C 6C 6F 20 77 6F 72 6C 64 3C 2F 70 3E | >Hello world</p>
   00000070 : 0A 20 20 3C 75 6C 3E 0A 20 20 20 20 3C 6C 69 3E | .  <ul>.    <li>
   00000080 : 3C 61 20 68 72 65 66 3D 22 2F 61 70 69 2F 68 74 | <a href="/api/ht
   00000090 : 6D 6C 22 3E 68 74 6D 6C 20 72 65 73 70 6F 6E 73 | ml">html respons
   000000A0 : 65 3C 2F 61 3E 3C 2F 6C 69 3E 0A 20 20 20 20 3C | e</a></li>.    <
   000000B0 : 6C 69 3E 3C 61 20 68 72 65 66 3D 22 2F 61 70 69 | li><a href="/api
   000000C0 : 2F 6A 73 6F 6E 22 3E 6A 73 6F 6E 20 72 65 73 70 | /json">json resp
   000000D0 : 6F 6E 73 65 3C 2F 61 3E 3C 2F 6C 69 3E 0A 20 20 | onse</a></li>.
   000000E0 : 20 20 3C 6C 69 3E 3C 61 20 68 72 65 66 3D 22 2F |   <li><a href="/
   000000F0 : 61 70 69 2F 74 65 73 74 22 3E 72 65 73 70 6F 6E | api/test">respon
   00000100 : 73 65 3C 2F 61 3E 3C 2F 6C 69 3E 0A 20 20 3C 2F | se</a></li>.  </
   00000110 : 75 6C 3E 0A 3C 2F 62 6F 64 79 3E 0A 3C 2F 68 74 | ul>.</body>.</ht
   00000120 : 6D 6C 3E -- -- -- -- -- -- -- -- -- -- -- -- -- | ml>

[ns] read 640
  00000000 : 00 00 80 01 25 00 00 00 03 80 00 00 00 DB 82 CB | ....%...........
  00000010 : 87 04 89 62 51 F7 31 0F 52 E6 21 FF C8 C6 CA C9 | ...bQ.1.R.!.....
  00000020 : 53 B1 35 23 98 AC 0F B9 A5 FA 35 23 98 AC 78 2C | S.5#......5#..x,
  00000030 : 75 FD 1A 91 CC 56 07 5D 53 7D 1A 91 CC 56 11 DE | u....V.]S}...V..
  00000040 : 6F F7 E6 9A 3E 8D 48 E6 2B 1F 3F 5F 2C 7C FD F6 | o...>.H.+.?_,|..
  00000050 : 80 0B BD 7F 06 88 40 E9 2A C7 B0 D3 1A AF 7F 06 | ......@.*.......
  00000060 : 85 A8 EB 10 F6 23 7F 05 84 35 23 98 BF 73 90 9D | .....#...5#..s..
  00000070 : 29 AD 17 18 62 83 90 74 4E 74 26 E3 E0 00 18 C5 | )...b..tNt&.....
  00000080 : C4 7F 04 85 B6 00 FD 28 6F -- -- -- -- -- -- -- | .......(o
[h2] read 640
  00000000 : 00 00 80 01 25 00 00 00 03 80 00 00 00 DB 82 CB | ....%...........
  00000010 : 87 04 89 62 51 F7 31 0F 52 E6 21 FF C8 C6 CA C9 | ...bQ.1.R.!.....
  00000020 : 53 B1 35 23 98 AC 0F B9 A5 FA 35 23 98 AC 78 2C | S.5#......5#..x,
  00000030 : 75 FD 1A 91 CC 56 07 5D 53 7D 1A 91 CC 56 11 DE | u....V.]S}...V..
  00000040 : 6F F7 E6 9A 3E 8D 48 E6 2B 1F 3F 5F 2C 7C FD F6 | o...>.H.+.?_,|..
  00000050 : 80 0B BD 7F 06 88 40 E9 2A C7 B0 D3 1A AF 7F 06 | ......@.*.......
  00000060 : 85 A8 EB 10 F6 23 7F 05 84 35 23 98 BF 73 90 9D | .....#...5#..s..
  00000070 : 29 AD 17 18 62 83 90 74 4E 74 26 E3 E0 00 18 C5 | )...b..tNt&.....
  00000080 : C4 7F 04 85 B6 00 FD 28 6F -- -- -- -- -- -- -- | .......(o
index [13] :authority=localhost:9000
index [10] sec-ch-ua-platform="Windows"
index [8] user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
index [12] sec-ch-ua="Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
index [11] sec-ch-ua-mobile=?0
index [7] accept=text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
index [7] accept=text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
index [6] sec-fetch-site=none
index [7] accept=text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
index [6] sec-fetch-site=none
index [5] sec-fetch-mode=navigate
insert entry[14] accept=image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
insert entry[15] accept=same-origin
insert entry[16] accept=no-cors
insert entry[17] sec-fetch-site=image
insert entry[18] referer=https://localhost:9000/
insert entry[19] sec-fetch-mode=u=1, i
- http/2 frame type 1 HEADERS
 > length 0x80(128) type 1 flags 25 stream identifier 00000003
 > flags [ END_STREAM END_HEADERS PRIORITY ]
 > stream dependency E:1 00000000
 > weight db
 > fragment
   00000000 : 82 CB 87 04 89 62 51 F7 31 0F 52 E6 21 FF C8 C6 | .....bQ.1.R.!...
   00000010 : CA C9 53 B1 35 23 98 AC 0F B9 A5 FA 35 23 98 AC | ..S.5#......5#..
   00000020 : 78 2C 75 FD 1A 91 CC 56 07 5D 53 7D 1A 91 CC 56 | x,u....V.]S}...V
   00000030 : 11 DE 6F F7 E6 9A 3E 8D 48 E6 2B 1F 3F 5F 2C 7C | ..o...>.H.+.?_,|
   00000040 : FD F6 80 0B BD 7F 06 88 40 E9 2A C7 B0 D3 1A AF | ........@.*.....
   00000050 : 7F 06 85 A8 EB 10 F6 23 7F 05 84 35 23 98 BF 73 | .......#...5#..s
   00000060 : 90 9D 29 AD 17 18 62 83 90 74 4E 74 26 E3 E0 00 | ..)...b..tNt&...
   00000070 : 18 C5 C4 7F 04 85 B6 00 FD 28 6F -- -- -- -- -- | .........(o
 > :method: GET
 > :authority: localhost:9000
 > :scheme: https
 > :path: /favicon.ico
 > sec-ch-ua-platform: "Windows"
 > user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
 > sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
 > sec-ch-ua-mobile: ?0
 > accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
 > accept: same-origin
 > accept: no-cors
 > sec-fetch-site: image
 > referer: https://localhost:9000/
 > accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
 > sec-fetch-site: none
 > sec-fetch-mode: u=1, i
index [13] accept=text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
index [10] sec-fetch-user=?1
index [8] accept-encoding=gzip, deflate, br, zstd
index [12] sec-fetch-site=none
index [11] sec-fetch-mode=navigate
index [7] accept-language=ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
index [7] accept-language=ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
index [6] priority=u=0, i
index [7] accept-language=ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
index [6] priority=u=0, i
index [5] accept=image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
insert entry[20] accept-language=same-origin
insert entry[21] accept-language=no-cors
insert entry[22] priority=image
insert entry[23] accept=u=1, i
- http/2 frame type 1 HEADERS
 > length 0x10(16) type 1 flags 04 stream identifier 00000003
 > flags [ END_HEADERS ]
 > fragment
   00000000 : 8D 0F 10 87 49 7C A5 89 D3 4D 1F 0F 0D 82 65 FF | ....I|...M....e.
 > :status: 404
 > content-type: text/html
 > content-length: 39

- http/2 frame type 0 DATA
 > length 0x27(39) type 0 flags 01 stream identifier 00000003
 > flags [ END_STREAM ]
 > data
   00000000 : 3C 68 74 6D 6C 3E 3C 62 6F 64 79 3E 34 30 34 20 | <html><body>404
   00000010 : 4E 6F 74 20 46 6F 75 6E 64 3C 2F 62 6F 64 79 3E | Not Found</body>
   00000020 : 3C 2F 68 74 6D 6C 3E -- -- -- -- -- -- -- -- -- | </html>

TLS 00000304 00000010 handshake start
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS read client hello:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write server hello:TLS_AES_128_GCM_SHA256
SERVER_HANDSHAKE_TRAFFIC_SECRET f3d7566bf62c987da13f62746c7abd59790c39ec48022438bc0c98b0d5b20688 363ead2736ed8bc30086824016dce913e733593c348e75fed0d8330b369254f7
CLIENT_HANDSHAKE_TRAFFIC_SECRET f3d7566bf62c987da13f62746c7abd59790c39ec48022438bc0c98b0d5b20688 4b1a3d5e96ce90f954d644d9ea78e09288063d1be8646544c6f00851f7be98e7
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write change cipher spec:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 write encrypted extensions:TLS_AES_128_GCM_SHA256
EXPORTER_SECRET f3d7566bf62c987da13f62746c7abd59790c39ec48022438bc0c98b0d5b20688 bd10f880f8b81bca919c1aa526be9d33f143ff5fb7d33c06de27d0892e3c087c
SERVER_TRAFFIC_SECRET_0 f3d7566bf62c987da13f62746c7abd59790c39ec48022438bc0c98b0d5b20688 2e7c95c2f567b682e613c608b9fa05acc8681c8ba404a5f5e8ee12360840a326
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write finished:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 early data:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 early data:TLS_AES_128_GCM_SHA256
CLIENT_TRAFFIC_SECRET_0 f3d7566bf62c987da13f62746c7abd59790c39ec48022438bc0c98b0d5b20688 8d4ec3dfc408b1eeaf3d856f994535f3d6a7f5804902dec22c3c17005c76e104
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS read finished:TLS_AES_128_GCM_SHA256
TLS 00000304 00000020 handshake done
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write session ticket:TLS_AES_128_GCM_SHA256
TLS 00000304 00002002 SSL_accept:exit:SSL negotiation finished successfully
iocp handle 00000204 bind 660
TLS 00000304 00004008 SSL_write:callback:warning:close notify
TLS 00000304 00004008 SSL_write:callback:warning:close notify
TLS 00000304 00000010 handshake start
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS read client hello:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write server hello:TLS_AES_128_GCM_SHA256
SERVER_HANDSHAKE_TRAFFIC_SECRET da445878bd727912794a3957ea64112bd20b74e92fef5177850b85055b9969dc 94b2e4c5bb4c620c7c4c52ff7e190ddab01dbf9369961a02c17b354dfb06df59
CLIENT_HANDSHAKE_TRAFFIC_SECRET da445878bd727912794a3957ea64112bd20b74e92fef5177850b85055b9969dc 75cfcc02e6ff1b71442b864181bd6322e0e2eb674057e755f2341a48556f7573
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write change cipher spec:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 write encrypted extensions:TLS_AES_128_GCM_SHA256
EXPORTER_SECRET da445878bd727912794a3957ea64112bd20b74e92fef5177850b85055b9969dc 0ca745bb522897181dcb7e3d99db4b36d9ad8e8b8b0a1b1648a60e435587096b
SERVER_TRAFFIC_SECRET_0 da445878bd727912794a3957ea64112bd20b74e92fef5177850b85055b9969dc f2c453d9025120aa0e490fb2e8586acea5f8534f5d623d03d5d2ff7363eae129
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write finished:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 early data:TLS_AES_128_GCM_SHA256
TLS 00000304 00004004 SSL_read:callback:fatal:certificate unknown
TLS 00000304 00002002 SSL_accept:exit:error
TLS 00000304 00000010 handshake start
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS read client hello:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write server hello:TLS_AES_128_GCM_SHA256
SERVER_HANDSHAKE_TRAFFIC_SECRET 44b612097beeece79198b35a9599ea408fea42ec6200c5a5a531206af7caddc1 58bf064530b619b43d7cdaf28b04b8ef9f721772f3d85f8cf2097c192e5d8712
CLIENT_HANDSHAKE_TRAFFIC_SECRET 44b612097beeece79198b35a9599ea408fea42ec6200c5a5a531206af7caddc1 5cef063663e932a411cfd753ca9bc0731fa51b85010fd9ee243f068480a00c16
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write change cipher spec:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 write encrypted extensions:TLS_AES_128_GCM_SHA256
EXPORTER_SECRET 44b612097beeece79198b35a9599ea408fea42ec6200c5a5a531206af7caddc1 57b7f379af6b6abe7eddf7c5870887050a9628f190d956654626c1325faa36e9
SERVER_TRAFFIC_SECRET_0 44b612097beeece79198b35a9599ea408fea42ec6200c5a5a531206af7caddc1 b0141f92010ff97c70ea22f3be22d2dee948bd68db128750c32d1ddeccb197bd
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write finished:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 early data:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 early data:TLS_AES_128_GCM_SHA256
CLIENT_TRAFFIC_SECRET_0 44b612097beeece79198b35a9599ea408fea42ec6200c5a5a531206af7caddc1 55ae7c492f9123f9f4241a4330298a4e90bf347e348c2f29a217abe7fda879b5
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS read finished:TLS_AES_128_GCM_SHA256
TLS 00000304 00000020 handshake done
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write session ticket:TLS_AES_128_GCM_SHA256
TLS 00000304 00002002 SSL_accept:exit:SSL negotiation finished successfully
iocp handle 00000204 bind 668
[ns] read 668
  00000000 : 50 52 49 20 2A 20 48 54 54 50 2F 32 2E 30 0D 0A | PRI * HTTP/2.0..
  00000010 : 0D 0A 53 4D 0D 0A 0D 0A 00 00 18 04 00 00 00 00 | ..SM............
  00000020 : 00 00 01 00 01 00 00 00 02 00 00 00 00 00 04 00 | ................
  00000030 : 60 00 00 00 06 00 04 00 00 00 00 04 08 00 00 00 | `...............
  00000040 : 00 00 00 EF 00 01 -- -- -- -- -- -- -- -- -- -- | ......
[ns] read 668
  00000000 : 00 01 F6 01 25 00 00 00 01 80 00 00 00 FF 82 41 | ....%..........A
  00000010 : 8A A0 E4 1D 13 9D 09 B8 F8 00 0F 87 04 87 60 75 | ..............`u
  00000020 : 99 89 D3 4D 1F 40 87 41 48 B1 27 5A D1 FF B8 FE | ...M.@.AH.'Z....
  00000030 : 71 1C F3 50 55 2F 4F 61 E9 2F F3 F7 DE 0F E4 2C | q..PU/Oa./.....,
  00000040 : BB FC FD 29 FC DE 9E C3 D2 6B 69 FE 7E FB C1 FC | ...).....ki.~...
  00000050 : 85 97 7F 9F A5 3F 9D 27 4B 10 FF 77 6C 1D 52 7F | .....?.'K..wl.R.
  00000060 : 3F 7D E0 FE 44 D7 F3 40 8B 41 48 B1 27 5A D1 AD | ?}..D..@.AH.'Z..
  00000070 : 49 E3 35 05 02 3F 30 40 8D 41 48 B1 27 5A D1 AD | I.5..?0@.AH.'Z..
  00000080 : 5D 03 4C A7 B2 9F 88 FE 79 1A A9 0F E1 1F CF 40 | ].L.....y......@
  00000090 : 92 B6 B9 AC 1C 85 58 D5 20 A4 B6 C2 AD 61 7B 5A | ......X. ....a{Z
  000000A0 : 54 25 1F 01 31 7A D5 D0 7F 66 A2 81 B0 DA E0 53 | T%..1z...f.....S
  000000B0 : FA E4 6A A4 3F 84 29 A7 7A 81 02 E0 FB 53 91 AA | ..j.?.).z....S..
  000000C0 : 71 AF B5 3C B8 D7 F6 A4 35 D7 41 79 16 3C C6 4B | q..<....5.Ay.<.K
  000000D0 : 0D B2 EA EC B8 A7 F5 9B 1E FD 19 FE 94 A0 DD 4A | ...............J
  000000E0 : A6 22 93 A9 FF B5 2F 4F 61 E9 2B 01 65 D5 C0 B8 | ."..../Oa.+.e...
  000000F0 : 17 02 9B 87 28 EC 33 0D B2 EA EC B9 53 E5 49 7C | ....(.3.....S.I|
  00000100 : A5 89 D3 4D 1F 43 AE BA 0C 41 A4 C7 A9 8F 33 A6 | ...M.C...A....3.
  00000110 : 9A 3F DF 9A 68 FA 1D 75 D0 62 0D 26 3D 4C 79 A6 | .?..h..u.b.&=Ly.
  00000120 : 8F BE D0 01 77 FE 8D 48 E6 2B 03 EE 69 7E 8D 48 | ....w..H.+..i~.H
  00000130 : E6 2B 1E 0B 1D 7F 46 A4 73 15 81 D7 54 DF 5F 2C | .+....F.s...T._,
  00000140 : 7C FD F6 80 0B BD F4 3A EB A0 C4 1A 4C 7A 98 41 | |......:....Lz.A
  00000150 : A6 A8 B2 2C 5F 24 9C 75 4C 5F BE F0 46 CF DF 68 | ...,_$.uL_..F..h
  00000160 : 00 BB BF 40 8A 41 48 B4 A5 49 27 59 06 49 7F 88 | ...@.AH..I'Y.I..
  00000170 : 40 E9 2A C7 B0 D3 1A AF 40 8A 41 48 B4 A5 49 27 | @.*.....@.AH..I'
  00000180 : 5A 93 C8 5F 86 A8 7D CD 30 D2 5F 40 8A 41 48 B4 | Z.._..}.0._@.AH.
  00000190 : A5 49 27 5A D4 16 CF 02 3F 31 40 8A 41 48 B4 A5 | .I'Z....?1@.AH..
  000001A0 : 49 27 5A 42 A1 3F 86 90 E4 B6 92 D4 9F 73 90 9D | I'ZB.?.......s..
  000001B0 : 29 AD 17 18 62 83 90 74 4E 74 26 E3 E0 00 18 50 | )...b..tNt&....P
  000001C0 : 92 9B D9 AB FA 52 42 CB 40 D2 5F A5 23 B3 E9 4F | .....RB.@._.#..O
  000001D0 : 68 4C 9F 51 9C EA 75 B3 6D FA EA 7F BE D0 01 77 | hL.Q..u.m......w
  000001E0 : FE 8B 52 DC 37 7D F6 80 0B BD F4 5A BE FB 40 05 | ..R.7}.....Z..@.
  000001F0 : DD 40 86 AE C3 1E C3 27 D7 85 B6 00 7D 28 6F -- | .@.....'....}(o
[h2] read 668
  00000000 : 50 52 49 20 2A 20 48 54 54 50 2F 32 2E 30 0D 0A | PRI * HTTP/2.0..
  00000010 : 0D 0A 53 4D 0D 0A 0D 0A 00 00 18 04 00 00 00 00 | ..SM............
  00000020 : 00 00 01 00 01 00 00 00 02 00 00 00 00 00 04 00 | ................
  00000030 : 60 00 00 00 06 00 04 00 00 -- -- -- -- -- -- -- | `........
- http/2 frame type 4 SETTINGS
 > length 0x18(24) type 4 flags 00 stream identifier 00000000
 > flags [ ]
 > identifier 1 value 65536 (0x00010000)
 > identifier 2 value 0 (0x00000000)
 > identifier 4 value 6291456 (0x00600000)
 > identifier 6 value 262144 (0x00040000)
[h2] read 668
  00000000 : 00 00 04 08 00 00 00 00 00 00 EF 00 01 -- -- -- | .............
[ns] read 668
  00000000 : 00 00 00 04 01 00 00 00 00 -- -- -- -- -- -- -- | .........
- http/2 frame type 8 WINDOW_UPDATE
 > length 0x04(4) type 8 flags 00 stream identifier 00000000
 > flags [ ]
 > window size increment 15663105
[h2] read 668
  00000000 : 00 01 F6 01 25 00 00 00 01 80 00 00 00 FF 82 41 | ....%..........A
  00000010 : 8A A0 E4 1D 13 9D 09 B8 F8 00 0F 87 04 87 60 75 | ..............`u
  00000020 : 99 89 D3 4D 1F 40 87 41 48 B1 27 5A D1 FF B8 FE | ...M.@.AH.'Z....
  00000030 : 71 1C F3 50 55 2F 4F 61 E9 2F F3 F7 DE 0F E4 2C | q..PU/Oa./.....,
  00000040 : BB FC FD 29 FC DE 9E C3 D2 6B 69 FE 7E FB C1 FC | ...).....ki.~...
  00000050 : 85 97 7F 9F A5 3F 9D 27 4B 10 FF 77 6C 1D 52 7F | .....?.'K..wl.R.
  00000060 : 3F 7D E0 FE 44 D7 F3 40 8B 41 48 B1 27 5A D1 AD | ?}..D..@.AH.'Z..
  00000070 : 49 E3 35 05 02 3F 30 40 8D 41 48 B1 27 5A D1 AD | I.5..?0@.AH.'Z..
  00000080 : 5D 03 4C A7 B2 9F 88 FE 79 1A A9 0F E1 1F CF 40 | ].L.....y......@
  00000090 : 92 B6 B9 AC 1C 85 58 D5 20 A4 B6 C2 AD 61 7B 5A | ......X. ....a{Z
  000000A0 : 54 25 1F 01 31 7A D5 D0 7F 66 A2 81 B0 DA E0 53 | T%..1z...f.....S
  000000B0 : FA E4 6A A4 3F 84 29 A7 7A 81 02 E0 FB 53 91 AA | ..j.?.).z....S..
  000000C0 : 71 AF B5 3C B8 D7 F6 A4 35 D7 41 79 16 3C C6 4B | q..<....5.Ay.<.K
  000000D0 : 0D B2 EA EC B8 A7 F5 9B 1E FD 19 FE 94 A0 DD 4A | ...............J
  000000E0 : A6 22 93 A9 FF B5 2F 4F 61 E9 2B 01 65 D5 C0 B8 | ."..../Oa.+.e...
  000000F0 : 17 02 9B 87 28 EC 33 0D B2 EA EC B9 53 E5 49 7C | ....(.3.....S.I|
  00000100 : A5 89 D3 4D 1F 43 AE BA 0C 41 A4 C7 A9 8F 33 A6 | ...M.C...A....3.
  00000110 : 9A 3F DF 9A 68 FA 1D 75 D0 62 0D 26 3D 4C 79 A6 | .?..h..u.b.&=Ly.
  00000120 : 8F BE D0 01 77 FE 8D 48 E6 2B 03 EE 69 7E 8D 48 | ....w..H.+..i~.H
  00000130 : E6 2B 1E 0B 1D 7F 46 A4 73 15 81 D7 54 DF 5F 2C | .+....F.s...T._,
  00000140 : 7C FD F6 80 0B BD F4 3A EB A0 C4 1A 4C 7A 98 41 | |......:....Lz.A
  00000150 : A6 A8 B2 2C 5F 24 9C 75 4C 5F BE F0 46 CF DF 68 | ...,_$.uL_..F..h
  00000160 : 00 BB BF 40 8A 41 48 B4 A5 49 27 59 06 49 7F 88 | ...@.AH..I'Y.I..
  00000170 : 40 E9 2A C7 B0 D3 1A AF 40 8A 41 48 B4 A5 49 27 | @.*.....@.AH..I'
  00000180 : 5A 93 C8 5F 86 A8 7D CD 30 D2 5F 40 8A 41 48 B4 | Z.._..}.0._@.AH.
  00000190 : A5 49 27 5A D4 16 CF 02 3F 31 40 8A 41 48 B4 A5 | .I'Z....?1@.AH..
  000001A0 : 49 27 5A 42 A1 3F 86 90 E4 B6 92 D4 9F 73 90 9D | I'ZB.?.......s..
  000001B0 : 29 AD 17 18 62 83 90 74 4E 74 26 E3 E0 00 18 50 | )...b..tNt&....P
  000001C0 : 92 9B D9 AB FA 52 42 CB 40 D2 5F A5 23 B3 E9 4F | .....RB.@._.#..O
  000001D0 : 68 4C 9F 51 9C EA 75 B3 6D FA EA 7F BE D0 01 77 | hL.Q..u.m......w
  000001E0 : FE 8B 52 DC 37 7D F6 80 0B BD F4 5A BE FB 40 05 | ..R.7}.....Z..@.
  000001F0 : DD 40 86 AE C3 1E C3 27 D7 85 B6 00 7D 28 6F -- | .@.....'....}(o
insert entry[0] :authority=localhost:9000
insert entry[1] sec-ch-ua="Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
insert entry[2] sec-ch-ua-mobile=?0
insert entry[3] sec-ch-ua-platform="Windows"
insert entry[4] upgrade-insecure-requests=1
insert entry[5] user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
insert entry[6] accept=text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
insert entry[7] sec-fetch-site=same-origin
insert entry[8] sec-fetch-mode=navigate
insert entry[9] sec-fetch-user=?1
insert entry[10] sec-fetch-dest=document
insert entry[11] referer=https://localhost:9000/
insert entry[12] accept-encoding=gzip, deflate, br, zstd
insert entry[13] accept-language=ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
insert entry[14] priority=u=0, i
- http/2 frame type 1 HEADERS
 > length 0x1f6(502) type 1 flags 25 stream identifier 00000001
 > flags [ END_STREAM END_HEADERS PRIORITY ]
 > stream dependency E:1 00000000
 > weight ff
 > fragment
   00000000 : 82 41 8A A0 E4 1D 13 9D 09 B8 F8 00 0F 87 04 87 | .A..............
   00000010 : 60 75 99 89 D3 4D 1F 40 87 41 48 B1 27 5A D1 FF | `u...M.@.AH.'Z..
   00000020 : B8 FE 71 1C F3 50 55 2F 4F 61 E9 2F F3 F7 DE 0F | ..q..PU/Oa./....
   00000030 : E4 2C BB FC FD 29 FC DE 9E C3 D2 6B 69 FE 7E FB | .,...).....ki.~.
   00000040 : C1 FC 85 97 7F 9F A5 3F 9D 27 4B 10 FF 77 6C 1D | .......?.'K..wl.
   00000050 : 52 7F 3F 7D E0 FE 44 D7 F3 40 8B 41 48 B1 27 5A | R.?}..D..@.AH.'Z
   00000060 : D1 AD 49 E3 35 05 02 3F 30 40 8D 41 48 B1 27 5A | ..I.5..?0@.AH.'Z
   00000070 : D1 AD 5D 03 4C A7 B2 9F 88 FE 79 1A A9 0F E1 1F | ..].L.....y.....
   00000080 : CF 40 92 B6 B9 AC 1C 85 58 D5 20 A4 B6 C2 AD 61 | .@......X. ....a
   00000090 : 7B 5A 54 25 1F 01 31 7A D5 D0 7F 66 A2 81 B0 DA | {ZT%..1z...f....
   000000A0 : E0 53 FA E4 6A A4 3F 84 29 A7 7A 81 02 E0 FB 53 | .S..j.?.).z....S
   000000B0 : 91 AA 71 AF B5 3C B8 D7 F6 A4 35 D7 41 79 16 3C | ..q..<....5.Ay.<
   000000C0 : C6 4B 0D B2 EA EC B8 A7 F5 9B 1E FD 19 FE 94 A0 | .K..............
   000000D0 : DD 4A A6 22 93 A9 FF B5 2F 4F 61 E9 2B 01 65 D5 | .J."..../Oa.+.e.
   000000E0 : C0 B8 17 02 9B 87 28 EC 33 0D B2 EA EC B9 53 E5 | ......(.3.....S.
   000000F0 : 49 7C A5 89 D3 4D 1F 43 AE BA 0C 41 A4 C7 A9 8F | I|...M.C...A....
   00000100 : 33 A6 9A 3F DF 9A 68 FA 1D 75 D0 62 0D 26 3D 4C | 3..?..h..u.b.&=L
   00000110 : 79 A6 8F BE D0 01 77 FE 8D 48 E6 2B 03 EE 69 7E | y.....w..H.+..i~
   00000120 : 8D 48 E6 2B 1E 0B 1D 7F 46 A4 73 15 81 D7 54 DF | .H.+....F.s...T.
   00000130 : 5F 2C 7C FD F6 80 0B BD F4 3A EB A0 C4 1A 4C 7A | _,|......:....Lz
   00000140 : 98 41 A6 A8 B2 2C 5F 24 9C 75 4C 5F BE F0 46 CF | .A...,_$.uL_..F.
   00000150 : DF 68 00 BB BF 40 8A 41 48 B4 A5 49 27 59 06 49 | .h...@.AH..I'Y.I
   00000160 : 7F 88 40 E9 2A C7 B0 D3 1A AF 40 8A 41 48 B4 A5 | ..@.*.....@.AH..
   00000170 : 49 27 5A 93 C8 5F 86 A8 7D CD 30 D2 5F 40 8A 41 | I'Z.._..}.0._@.A
   00000180 : 48 B4 A5 49 27 5A D4 16 CF 02 3F 31 40 8A 41 48 | H..I'Z....?1@.AH
   00000190 : B4 A5 49 27 5A 42 A1 3F 86 90 E4 B6 92 D4 9F 73 | ..I'ZB.?.......s
   000001A0 : 90 9D 29 AD 17 18 62 83 90 74 4E 74 26 E3 E0 00 | ..)...b..tNt&...
   000001B0 : 18 50 92 9B D9 AB FA 52 42 CB 40 D2 5F A5 23 B3 | .P.....RB.@._.#.
   000001C0 : E9 4F 68 4C 9F 51 9C EA 75 B3 6D FA EA 7F BE D0 | .OhL.Q..u.m.....
   000001D0 : 01 77 FE 8B 52 DC 37 7D F6 80 0B BD F4 5A BE FB | .w..R.7}.....Z..
   000001E0 : 40 05 DD 40 86 AE C3 1E C3 27 D7 85 B6 00 7D 28 | @..@.....'....}(
   000001F0 : 6F -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- | o
 > :method: GET
 > :authority: localhost:9000
 > :scheme: https
 > :path: /api/html
 > sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
 > sec-ch-ua-mobile: ?0
 > sec-ch-ua-platform: "Windows"
 > upgrade-insecure-requests: 1
 > user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
 > accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
 > sec-fetch-site: same-origin
 > sec-fetch-mode: navigate
 > sec-fetch-user: ?1
 > sec-fetch-dest: document
 > referer: https://localhost:9000/
 > accept-encoding: gzip, deflate, br, zstd
 > accept-language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
 > priority: u=0, i
- http/2 frame type 1 HEADERS
 > length 0x10(16) type 1 flags 04 stream identifier 00000001
 > flags [ END_HEADERS ]
 > fragment
   00000000 : 88 0F 10 87 49 7C A5 89 D3 4D 1F 0F 0D 82 65 AF | ....I|...M....e.
 > :status: 200
 > content-type: text/html
 > content-length: 34

- http/2 frame type 0 DATA
 > length 0x22(34) type 0 flags 01 stream identifier 00000001
 > flags [ END_STREAM ]
 > data
   00000000 : 3C 68 74 6D 6C 3E 3C 62 6F 64 79 3E 70 61 67 65 | <html><body>page
   00000010 : 20 2D 20 6F 6B 3C 62 6F 64 79 3E 3C 2F 68 74 6D |  - ok<body></htm
   00000020 : 6C 3E -- -- -- -- -- -- -- -- -- -- -- -- -- -- | l>

[h2] read 668
  00000000 : 00 00 00 04 01 00 00 00 00 -- -- -- -- -- -- -- | .........
- http/2 frame type 4 SETTINGS
 > length 0x00(0) type 4 flags 01 stream identifier 00000000
 > flags [ ACK ]
TLS 00000304 00000010 handshake start
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:before SSL initialization:(NONE)
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS read client hello:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write server hello:TLS_AES_128_GCM_SHA256
SERVER_HANDSHAKE_TRAFFIC_SECRET 5c7f64c0b798e7b0d8142b51d26d69ad04aa212af7a650df688db819310970f0 423f965b36fa8698b4b5c0e0d2fd834a84da7191adbf6e6f10c26f68d11516cb
CLIENT_HANDSHAKE_TRAFFIC_SECRET 5c7f64c0b798e7b0d8142b51d26d69ad04aa212af7a650df688db819310970f0 be05093a8d578daa4efdf051ab0fea471c6a182bffb0176931da5c9e445ebd7e
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write change cipher spec:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 write encrypted extensions:TLS_AES_128_GCM_SHA256
EXPORTER_SECRET 5c7f64c0b798e7b0d8142b51d26d69ad04aa212af7a650df688db819310970f0 e8c36075a474b8a43f833728bb8c2eeff55e85797354a8e5aeec84c983bba762
SERVER_TRAFFIC_SECRET_0 5c7f64c0b798e7b0d8142b51d26d69ad04aa212af7a650df688db819310970f0 920e7a9fd9d0788f6f45f2564be2e28defb2672f460bbdcfbad6256895c7b23e
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write finished:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 early data:TLS_AES_128_GCM_SHA256
TLS 00000304 00002001 SSL_accept:loop:TLSv1.3 early data:TLS_AES_128_GCM_SHA256
CLIENT_TRAFFIC_SECRET_0 5c7f64c0b798e7b0d8142b51d26d69ad04aa212af7a650df688db819310970f0 fa396a936a9d64f804cb22c183003954ad30e15441c1b7bd532fd0eb4129c415
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS read finished:TLS_AES_128_GCM_SHA256
TLS 00000304 00000020 handshake done
TLS 00000304 00002001 SSL_accept:loop:SSLv3/TLS write session ticket:TLS_AES_128_GCM_SHA256
TLS 00000304 00002002 SSL_accept:exit:SSL negotiation finished successfully
iocp handle 00000204 bind 640
[ns] read 668
  00000000 : 00 00 1F 01 25 00 00 00 03 80 00 00 00 FF 82 CC | ....%...........
  00000010 : 87 04 87 60 75 99 8E 88 3D 5F CB CA C9 C8 C7 C6 | ...`u...=_......
  00000020 : C5 C4 C3 C2 C1 C0 BF BE -- -- -- -- -- -- -- -- | ........
[h2] read 668
  00000000 : 00 00 1F 01 25 00 00 00 03 80 00 00 00 FF 82 CC | ....%...........
  00000010 : 87 04 87 60 75 99 8E 88 3D 5F CB CA C9 C8 C7 C6 | ...`u...=_......
  00000020 : C5 C4 C3 C2 C1 C0 BF BE -- -- -- -- -- -- -- -- | ........
index [14] :authority=localhost:9000
index [13] sec-ch-ua="Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
index [12] sec-ch-ua-mobile=?0
index [11] sec-ch-ua-platform="Windows"
index [10] upgrade-insecure-requests=1
index [9] user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
index [8] accept=text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
index [7] sec-fetch-site=same-origin
index [6] sec-fetch-mode=navigate
index [5] sec-fetch-user=?1
index [4] sec-fetch-dest=document
index [3] referer=https://localhost:9000/
index [2] accept-encoding=gzip, deflate, br, zstd
index [1] accept-language=ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
index [0] priority=u=0, i
- http/2 frame type 1 HEADERS
 > length 0x1f(31) type 1 flags 25 stream identifier 00000003
 > flags [ END_STREAM END_HEADERS PRIORITY ]
 > stream dependency E:1 00000000
 > weight ff
 > fragment
   00000000 : 82 CC 87 04 87 60 75 99 8E 88 3D 5F CB CA C9 C8 | .....`u...=_....
   00000010 : C7 C6 C5 C4 C3 C2 C1 C0 BF BE -- -- -- -- -- -- | ..........
 > :method: GET
 > :authority: localhost:9000
 > :scheme: https
 > :path: /api/json
 > sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
 > sec-ch-ua-mobile: ?0
 > sec-ch-ua-platform: "Windows"
 > upgrade-insecure-requests: 1
 > user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
 > accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
 > sec-fetch-site: same-origin
 > sec-fetch-mode: navigate
 > sec-fetch-user: ?1
 > sec-fetch-dest: document
 > referer: https://localhost:9000/
 > accept-encoding: gzip, deflate, br, zstd
 > accept-language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
 > priority: u=0, i
index [14] :authority=localhost:9000
index [13] sec-ch-ua="Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
index [12] sec-ch-ua-mobile=?0
index [11] sec-ch-ua-platform="Windows"
index [10] upgrade-insecure-requests=1
index [9] user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
index [8] accept=text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
index [7] sec-fetch-site=same-origin
index [6] sec-fetch-mode=navigate
index [5] sec-fetch-user=?1
index [4] sec-fetch-dest=document
index [3] referer=https://localhost:9000/
index [2] accept-encoding=gzip, deflate, br, zstd
index [1] accept-language=ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
index [0] priority=u=0, i
- http/2 frame type 1 HEADERS
 > length 0x14(20) type 1 flags 04 stream identifier 00000003
 > flags [ END_HEADERS ]
 > fragment
   00000000 : 88 0F 10 8B 1D 75 D0 62 0D 26 3D 4C 74 41 EA 0F | .....u.b.&=LtA..
   00000010 : 0D 82 0B 7F -- -- -- -- -- -- -- -- -- -- -- -- | ....
 > :status: 200
 > content-type: application/json
 > content-length: 15

- http/2 frame type 0 DATA
 > length 0x0f(15) type 0 flags 01 stream identifier 00000003
 > flags [ END_STREAM ]
 > data
   00000000 : 7B 22 72 65 73 75 6C 74 22 3A 22 6F 6B 22 7D -- | {"result":"ok"}

[ns] read 668
  00000000 : 00 00 1E 01 25 00 00 00 05 80 00 00 00 FF 82 CC | ....%...........
  00000010 : 87 04 86 60 75 99 84 95 09 CB CA C9 C8 C7 C6 C5 | ...`u...........
  00000020 : C4 C3 C2 C1 C0 BF BE -- -- -- -- -- -- -- -- -- | .......
[h2] read 668
  00000000 : 00 00 1E 01 25 00 00 00 05 80 00 00 00 FF 82 CC | ....%...........
  00000010 : 87 04 86 60 75 99 84 95 09 CB CA C9 C8 C7 C6 C5 | ...`u...........
  00000020 : C4 C3 C2 C1 C0 BF BE -- -- -- -- -- -- -- -- -- | .......
index [14] :authority=localhost:9000
index [13] sec-ch-ua="Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
index [12] sec-ch-ua-mobile=?0
index [11] sec-ch-ua-platform="Windows"
index [10] upgrade-insecure-requests=1
index [9] user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
index [8] accept=text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
index [7] sec-fetch-site=same-origin
index [6] sec-fetch-mode=navigate
index [5] sec-fetch-user=?1
index [4] sec-fetch-dest=document
index [3] referer=https://localhost:9000/
index [2] accept-encoding=gzip, deflate, br, zstd
index [1] accept-language=ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
index [0] priority=u=0, i
- http/2 frame type 1 HEADERS
 > length 0x1e(30) type 1 flags 25 stream identifier 00000005
 > flags [ END_STREAM END_HEADERS PRIORITY ]
 > stream dependency E:1 00000000
 > weight ff
 > fragment
   00000000 : 82 CC 87 04 86 60 75 99 84 95 09 CB CA C9 C8 C7 | .....`u.........
   00000010 : C6 C5 C4 C3 C2 C1 C0 BF BE -- -- -- -- -- -- -- | .........
 > :method: GET
 > :authority: localhost:9000
 > :scheme: https
 > :path: /api/test
 > sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
 > sec-ch-ua-mobile: ?0
 > sec-ch-ua-platform: "Windows"
 > upgrade-insecure-requests: 1
 > user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
 > accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
 > sec-fetch-site: same-origin
 > sec-fetch-mode: navigate
 > sec-fetch-user: ?1
 > sec-fetch-dest: document
 > referer: https://localhost:9000/
 > accept-encoding: gzip, deflate, br, zstd
 > accept-language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
 > priority: u=0, i
index [14] :authority=localhost:9000
index [13] sec-ch-ua="Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"
index [12] sec-ch-ua-mobile=?0
index [11] sec-ch-ua-platform="Windows"
index [10] upgrade-insecure-requests=1
index [9] user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
index [8] accept=text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
index [7] sec-fetch-site=same-origin
index [6] sec-fetch-mode=navigate
index [5] sec-fetch-user=?1
index [4] sec-fetch-dest=document
index [3] referer=https://localhost:9000/
index [2] accept-encoding=gzip, deflate, br, zstd
index [1] accept-language=ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
index [0] priority=u=0, i
- http/2 frame type 1 HEADERS
 > length 0x10(16) type 1 flags 04 stream identifier 00000005
 > flags [ END_HEADERS ]
 > fragment
   00000000 : 88 0F 10 87 49 7C A5 89 D3 4D 1F 0F 0D 82 69 CF | ....I|...M....i.
 > :status: 200
 > content-type: text/html
 > content-length: 46

- http/2 frame type 0 DATA
 > length 0x2e(46) type 0 flags 01 stream identifier 00000005
 > flags [ END_STREAM ]
 > data
   00000000 : 3C 68 74 6D 6C 3E 3C 62 6F 64 79 3E 3C 70 72 65 | <html><body><pre
   00000010 : 3E 2F 61 70 69 2F 74 65 73 74 3C 2F 70 72 65 3E | >/api/test</pre>
   00000020 : 3C 2F 62 6F 64 79 3E 3C 2F 68 74 6D 6C 3E -- -- | </body></html>

[ns] read 668
  00000000 : 00 00 04 08 00 00 00 00 00 00 00 00 5F -- -- -- | ............_
[h2] read 668
  00000000 : 00 00 04 08 00 00 00 00 00 00 00 00 5F -- -- -- | ............_
- http/2 frame type 8 WINDOW_UPDATE
 > length 0x04(4) type 8 flags 00 stream identifier 00000000
 > flags [ ]
 > window size increment 95
TLS 00000304 00004008 SSL_write:callback:warning:close notify
TLS 00000304 00004008 SSL_write:callback:warning:close notify

- event_loop_break_concurrent : break 1/4
- event_loop_test_broken : broken detected
- event_loop_break_concurrent : break 1/3
- event_loop_test_broken : broken detected
- event_loop_break_concurrent : break 1/2
- event_loop_test_broken : broken detected
- event_loop_break_concurrent : break 1/1
- event_loop_test_broken : broken detected
````

[TOC](README.md)
